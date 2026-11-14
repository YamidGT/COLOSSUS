"""One bounded investigation/repair cycle with independent tool-driven gates."""

import base64
import json
from collections import Counter
from importlib.resources import files as resources

from colossus.contracts.core import DomainError, content_hash, new_id, utcnow
from colossus.contracts.models import Candidate, EvidenceManifest, GateResult
from colossus.detection.service import dsvw_checks, finding_from_signal, static_scan
from colossus.gateway.source import tree_hash
from colossus.repair.patch import apply_proposal
from colossus.repair.service import propose
from colossus.verification.policy import REQUIRED_CHECKS, validate_gates


class CycleEngine:
    def __init__(self, store, artifacts, launcher, broker, onboarding, runtime):
        self.store, self.artifacts, self.launcher, self.broker, self.onboarding, self.runtime = (
            store,
            artifacts,
            launcher,
            broker,
            onboarding,
            runtime,
        )

    def update_cycle(self, cycle_id, **changes):
        value = self.store.get("cycle", cycle_id)
        self.store.put("cycle", cycle_id, value | changes, value["project_id"], value["revision"])
        return self.store.get("cycle", cycle_id)

    def check_cancel(self, cycle_id):
        import time

        cycle = self.store.get("cycle", cycle_id)
        if cycle["cancel_requested"]:
            raise DomainError("cancelled", "Operator cancelled the cycle", 409)
        if time.time() >= cycle["deadline"]:
            raise DomainError("cycle_timeout", "Cycle deadline reached", 409)

    async def run(self, cycle_id):
        cycle = self.update_cycle(cycle_id, status="INVESTIGATING", started_at=utcnow())
        project_id = cycle["project_id"]
        project = self.store.get("project", project_id)
        manifest = json.loads(self.artifacts.get(project["source"]["manifest_hash"]))
        if manifest["recipe_id"] != "dsvw-python-v1":
            raise DomainError(
                "unsupported_probe_profile",
                "No protected functional/security oracle installed for this runtime",
                422,
            )
        source = json.loads(self.artifacts.get(project["source"]["source_id"]))
        files = {p: base64.b64decode(v) for p, v in source["files"].items()}
        recipe = project["mirror"]["recipe"]
        case_id = new_id()
        self.update_cycle(cycle_id, case_ids=[case_id])
        case = {
            "case_id": case_id,
            "cycle_id": cycle_id,
            "project_id": project_id,
            "status": "INVESTIGATING",
            "title": "SQL query construction repair",
            "created_at": utcnow(),
            "finding_refs": [],
            "candidate_id": None,
            "diff_ref": None,
            "gate_results": [],
            "assurance_summary": {"profile": project["assurance_profile"], "formal": "UNSUPPORTED"},
            "evidence_manifest_hash": None,
            "destination_id": "local-web-v1",
            "expected_deployment_generation": project.get("deployment", {}).get("generation", 0),
            "allowed_actions": [],
        }
        self.store.put("case", case_id, case, project_id)
        active = []

        def evidence(value):
            return self.onboarding.evidence(project_id, value)

        try:
            self.check_cancel(cycle_id)
            scan = await static_scan(self.launcher, project_id, source["files"])
            scan_id = evidence(scan)
            findings = []
            for signal in scan["findings"]:
                finding = finding_from_signal(
                    signal, project["source"]["manifest_hash"], scan_id
                ).model_dump()
                self.store.put(
                    "finding", finding["finding_id"], finding | {"cycle_id": cycle_id}, project_id
                )
                findings.append((finding, signal))
            selected = next(
                (
                    (f, s)
                    for f, s in findings
                    if s["cwe"] == "CWE-89"
                    and "SELECT id, username, name, surname FROM users" in s["expression"]
                ),
                None,
            )
            if selected is None:
                self.update_cycle(
                    cycle_id,
                    status="NO_CHANGE",
                    finished_at=utcnow(),
                    reason="No supported repair case found; static findings remain visible",
                )
                self.store.put(
                    "case",
                    case_id,
                    case | {"status": "NO_CHANGE", "reason": "No supported SQL repair case"},
                    project_id,
                )
                return {"status": "NO_CHANGE", "case_id": case_id}
            finding, signal = selected
            baseline = await self.launcher.call(
                "/targets",
                {"project_id": project_id, "artifact_digest": manifest["artifact_digest"]},
            )
            active.append(baseline)
            baseline_started = utcnow()
            baseline_checks = await dsvw_checks(
                self.launcher, project_id, baseline["environment_id"], recipe["port"]
            )
            baseline_finished = utcnow()
            baseline_id = evidence(baseline_checks)
            if not baseline_checks["functional_pass"]:
                raise DomainError(
                    "baseline_unhealthy",
                    "Original application failed protected positive workflows",
                    503,
                )
            if not baseline_checks["vulnerability_confirmed"]:
                raise DomainError(
                    "unconfirmed_finding",
                    "Bounded reproducer did not confirm the selected finding",
                    409,
                )
            finding |= {
                "status": "confirmed",
                "evidence_ids": finding["evidence_ids"] + [baseline_id],
            }
            self.store.put(
                "finding", finding["finding_id"], finding | {"cycle_id": cycle_id}, project_id
            )
            case |= {"finding_refs": [finding["finding_id"]], "status": "PATCHING"}
            self.store.put("case", case_id, case, project_id)
            self.update_cycle(cycle_id, status="PATCHING")
            feedback = None
            for attempt in range(self.runtime.max_candidates):
                self.check_cancel(cycle_id)
                proposal = await propose(
                    self.broker, project_id, case_id, files, finding, signal, feedback
                )
                self.store.put("proposal", proposal.proposal_id, proposal.model_dump(), project_id)
                scope_started = utcnow()
                try:
                    patched, diff = apply_proposal(
                        files,
                        proposal,
                        manifest["allowed_patch_paths"],
                        manifest["protected_paths"],
                    )
                except DomainError as exc:
                    feedback = {"reason": exc.code}
                    evidence(
                        {
                            "proposal_id": proposal.proposal_id,
                            "attempt": attempt + 1,
                            "rejected": exc.code,
                        }
                    )
                    continue
                scope_finished = utcnow()
                encoded = {p: base64.b64encode(v).decode() for p, v in patched.items()}
                self.update_cycle(cycle_id, status="VERIFYING")
                build_started = utcnow()
                image = await self.launcher.call(
                    "/package", {"files": encoded, "argv": recipe["command"]}
                )
                target = await self.launcher.call(
                    "/targets",
                    {"project_id": project_id, "artifact_digest": image["artifact_digest"]},
                )
                active.append(target)
                candidate_id = new_id()
                checks_started = utcnow()
                checks = await dsvw_checks(
                    self.launcher, project_id, target["environment_id"], recipe["port"]
                )
                checks_finished = utcnow()
                checks_id = evidence(checks)
                static_started = utcnow()
                candidate_scan = await static_scan(self.launcher, project_id, encoded)
                static_finished = utcnow()
                static_id = evidence(candidate_scan)
                counts_before = Counter(s["cwe"] for s in scan["findings"])
                counts_after = Counter(s["cwe"] for s in candidate_scan["findings"])
                static_ok = not candidate_scan["parse_failures"] and all(
                    n <= counts_before[cwe] for cwe, n in counts_after.items()
                )
                candidate_hash = tree_hash(patched)
                diff_id = self.artifacts.put(diff.encode())
                self.store.put(
                    "artifact",
                    content_hash({"project_id": project_id, "artifact_id": diff_id}),
                    {"artifact_id": diff_id, "media_type": "text/plain"},
                    project_id,
                )
                candidate = Candidate(
                    candidate_id=candidate_id,
                    proposal_id=proposal.proposal_id,
                    source_tree_hash=candidate_hash,
                    diff_hash=diff_id,
                    artifact_digest=image["artifact_digest"],
                    manifest_hash=project["source"]["manifest_hash"],
                    build_evidence_ids=[evidence(image), checks_id],
                )
                self.store.put("candidate", candidate_id, candidate.model_dump(), project_id)
                now = utcnow()
                timings = {
                    "scope-base-v1": (scope_started, scope_finished),
                    "baseline-reproduction-v1": (baseline_started, baseline_finished),
                    "build-readiness-v1": (build_started, checks_finished),
                    "dsvw-security-v1": (checks_started, checks_finished),
                    "dsvw-functional-v1": (checks_started, checks_finished),
                    "static-regression-v1": (static_started, static_finished),
                    "artifact-binding-v1": (now, now),
                }
                gates = []
                for profile, category, passed, refs in [
                    ("scope-base-v1", "policy", True, [evidence(proposal.model_dump())]),
                    ("baseline-reproduction-v1", "security", True, [baseline_id]),
                    (
                        "build-readiness-v1",
                        "build",
                        checks["responses"]["home"].get("status") == 200,
                        [checks_id],
                    ),
                    ("dsvw-security-v1", "security", checks["security_pass"], [checks_id]),
                    ("dsvw-functional-v1", "functional", checks["functional_pass"], [checks_id]),
                    ("static-regression-v1", "static", static_ok, [static_id]),
                    (
                        "artifact-binding-v1",
                        "policy",
                        image["tree_sha256"] == candidate_hash,
                        [evidence(image)],
                    ),
                ]:
                    gates.append(
                        GateResult(
                            gate_id=new_id(),
                            case_id=case_id,
                            candidate_id=candidate_id,
                            candidate_hash=candidate_hash,
                            check_profile_id=profile,
                            category=category,
                            status="pass" if passed else "fail",
                            scope=["DSVW id-query repair"],
                            tool_version="colossus-v1",
                            command_profile_hash=content_hash(
                                {
                                    "profile": profile,
                                    "harness": resources("colossus.detection")
                                    .joinpath("service.py")
                                    .read_text(),
                                }
                            ),
                            started_at=timings[profile][0],
                            finished_at=timings[profile][1],
                            evidence_ids=refs,
                            reason="Protected check passed" if passed else "Protected check failed",
                        )
                    )
                gates.append(
                    GateResult(
                        gate_id=new_id(),
                        case_id=case_id,
                        candidate_id=candidate_id,
                        candidate_hash=candidate_hash,
                        check_profile_id="formal-coverage-v1",
                        category="formal",
                        status="not_applicable",
                        proof_outcome="UNSUPPORTED",
                        scope=["Ordinary Python SQL adapter"],
                        assumptions=["No approved linked proof obligation for this component"],
                        tool_version="colossus-v1",
                        command_profile_hash=content_hash(
                            {"profile": "tested", "formal": "UNSUPPORTED"}
                        ),
                        started_at=now,
                        finished_at=now,
                        evidence_ids=[],
                        reason="Tests do not establish a mathematical proof",
                    )
                )
                for gate in gates:
                    self.store.put("gate", gate.gate_id, gate.model_dump(), project_id)
                case |= {
                    "candidate_id": candidate_id,
                    "diff_ref": diff_id,
                    "gate_results": [g.model_dump() for g in gates],
                }
                self.store.put("case", case_id, case, project_id)
                try:
                    validate_gates(gates, candidate_hash, project["assurance_profile"])
                except DomainError as exc:
                    feedback = {
                        "reason": exc.code,
                        "checks": {g.check_profile_id: g.status for g in gates},
                    }
                    await self.launcher.call(
                        "/targets/stop",
                        {k: target[k] for k in ("project_id", "environment_id", "network_id")},
                    )
                    active.remove(target)
                    continue
                source_candidate_id = evidence(
                    source
                    | {
                        "files": encoded,
                        "tree_sha256": candidate_hash,
                        "origin": "generated_patch",
                        "proposal_id": proposal.proposal_id,
                    }
                )
                proof_summary = [
                    {"outcome": "UNSUPPORTED", "scope": "Python SQL adapter", "required": False}
                ]
                payload = dict(
                    manifest_id=new_id(),
                    case_id=case_id,
                    baseline_hash=source["tree_sha256"],
                    candidate_hash=candidate_hash,
                    artifact_digest=image["artifact_digest"],
                    diff_hash=diff_id,
                    target_manifest_hash=project["source"]["manifest_hash"],
                    policy_hash=manifest["policy_hash"],
                    spec_hashes=[],
                    harness_hashes=[
                        content_hash(
                            resources("colossus.detection").joinpath("service.py").read_text()
                        )
                    ],
                    test_hashes=[content_hash(recipe["test_profile_ids"])],
                    required_gate_ids=[
                        g.gate_id for g in gates if g.check_profile_id in REQUIRED_CHECKS
                    ],
                    gate_result_ids=[g.gate_id for g in gates],
                    assurance_profile=project["assurance_profile"],
                    proof_summary=proof_summary,
                    exclusions=[
                        "No whole-repository security proof",
                        *recipe["limitations"],
                        "Static coverage uses three AST rules; Semgrep/Bandit adapters are not installed",
                        "Other findings remain unresolved",
                    ],
                    model_call_ids=proposal.model_call_ids,
                    total_cost_micro_usd=self.store.budget(case_id)["committed_micro_usd"],
                    issued_at=utcnow(),
                )
                certificate = EvidenceManifest(**payload, content_hash=content_hash(payload))
                certificate_id = evidence(certificate.model_dump())
                self.store.put(
                    "evidence_manifest",
                    certificate.manifest_id,
                    certificate.model_dump(),
                    project_id,
                )
                case |= {
                    "status": "REVIEW_READY",
                    "evidence_manifest_hash": certificate_id,
                    "candidate_source_id": source_candidate_id,
                    "reason": "All required tested-profile gates passed; no formal proof claimed",
                    "updated_at": utcnow(),
                }
                self.store.put("case", case_id, case, project_id)
                self.update_cycle(
                    cycle_id,
                    status="REVIEW_READY",
                    reason="Verified candidate is ready for the deployment policy",
                )
                return {
                    "status": "REVIEW_READY",
                    "case_id": case_id,
                    "evidence_manifest_hash": certificate_id,
                }
            raise DomainError(
                "repair_exhausted",
                "No candidate passed all required gates within the attempt limit",
                409,
            )
        except BaseException as exc:
            case |= {
                "status": "CANCELLED"
                if isinstance(exc, DomainError) and exc.code == "cancelled"
                else "NEEDS_REVIEW",
                "reason": exc.message
                if isinstance(exc, DomainError)
                else "Execution infrastructure failed",
                "updated_at": utcnow(),
            }
            self.store.put("case", case_id, case, project_id)
            raise
        finally:
            for target in reversed(active):
                await self.launcher.call(
                    "/targets/stop",
                    {k: target[k] for k in ("project_id", "environment_id", "network_id")},
                )
