"""Bind verified cases to the deployment authority and refresh the observed mirror."""

import base64
import json
from datetime import UTC, datetime, timedelta

from colossus.contracts.core import DomainError, new_id, utcnow
from colossus.contracts.models import Authorization, EvidenceManifest, GateResult, TargetManifest
from colossus.detection.service import dsvw_checks
from colossus.gateway.source import tree_hash


class DeploymentCoordinator:
    def __init__(self, store, artifacts, deployer, launcher, onboarding, engine):
        self.store, self.artifacts, self.deployer, self.launcher, self.onboarding, self.engine = (
            store,
            artifacts,
            deployer,
            launcher,
            onboarding,
            engine,
        )

    async def synchronize_destination(self, project_id):
        state = await self.deployer.call("/destinations/" + project_id)
        ref = self.onboarding.evidence(project_id, state)
        current = state.get("current") or {}
        summary = {
            "deployment_id": state.get("deployment_id"),
            "project_id": project_id,
            "generation": state["generation"],
            "status": state["status"],
            "artifact_digest": current.get("artifact_digest"),
            "environment_id": current.get("environment_id"),
            "known_vulnerable_baseline": current.get("known_vulnerable_baseline"),
            "previous_digest": (state.get("previous") or {}).get("artifact_digest"),
            "state_evidence_id": ref,
        }
        self.onboarding.update(project_id, deployment=summary)
        if summary["deployment_id"]:
            self.store.put("deployment", summary["deployment_id"], summary, project_id)
        return state

    async def refresh(self, project_id, state):
        slot = state.get("current")
        if not slot:
            raise DomainError(
                "destination_unavailable", "No deployed artifact exists to refresh", 503
            )
        project = self.store.get("project", project_id)
        old_mirror = project.get("mirror", {})
        self.onboarding.update(project_id, mirror=old_mirror | {"state": "STALE"})
        source = json.loads(self.artifacts.get(slot["source_id"]))
        files = {p: base64.b64decode(v, validate=True) for p, v in source["files"].items()}
        source_hash = tree_hash(files)
        manifest = TargetManifest.model_validate(slot.get("base_manifest") or slot["manifest"])
        if source_hash != slot.get("candidate_tree_hash", manifest.tree_sha256):
            raise DomainError(
                "mirror_source_mismatch", "Source evidence differs from the deployed artifact", 409
            )
        mirror = await self.launcher.call(
            "/targets", {"project_id": project_id, "artifact_digest": slot["artifact_digest"]}
        )
        try:
            check = await dsvw_checks(
                self.launcher, project_id, mirror["environment_id"], slot["port"]
            )
            if not check["functional_pass"] or (
                not slot["known_vulnerable_baseline"] and not check["security_pass"]
            ):
                raise DomainError(
                    "mirror_refresh_failed", "New mirror failed its required behavior checks", 503
                )
            evidence_id = self.onboarding.evidence(project_id, check)
            value = manifest.model_dump() | {
                "manifest_id": new_id(),
                "revision": manifest.revision + 1,
                "tree_sha256": source_hash,
                "artifact_digest": slot["artifact_digest"],
                "services": [
                    s.model_dump() | {"artifact_digest": slot["artifact_digest"]}
                    for s in manifest.services
                ],
                "setup_provenance": manifest.setup_provenance
                + [
                    {
                        "source_id": slot["source_id"],
                        "observed_deployment_generation": state["generation"],
                        "readiness_evidence_id": evidence_id,
                        "origin": "observed_deployment",
                    }
                ],
            }
            refreshed = TargetManifest.model_validate(value)
            manifest_hash = self.onboarding.evidence(project_id, refreshed.model_dump())
            self.store.put("manifest", refreshed.manifest_id, refreshed.model_dump(), project_id)
            recipe = old_mirror["recipe"]
            self.onboarding.update(
                project_id,
                setup_state="READY",
                source={
                    "commit": refreshed.commit,
                    "tree_sha256": source_hash,
                    "source_id": slot["source_id"],
                    "manifest_hash": manifest_hash,
                    "manifest_id": refreshed.manifest_id,
                },
                mirror=mirror
                | {
                    "state": "READY",
                    "port": slot["port"],
                    "recipe": recipe,
                    "readiness_evidence_id": evidence_id,
                },
                reason=None,
                reason_code=None,
            )
        except BaseException:
            await self.launcher.call(
                "/targets/stop",
                {k: mirror[k] for k in ("project_id", "environment_id", "network_id")},
            )
            raise
        if old_mirror.get("environment_id"):
            await self.launcher.call(
                "/targets/stop",
                {k: old_mirror[k] for k in ("project_id", "environment_id", "network_id")},
            )
        return manifest_hash

    async def promote(self, case_id, mode="preauthorized_policy", actor="lab-auto-v1"):
        case = self.store.get("case", case_id)
        project_id = case["project_id"]
        project = self.store.get("project", project_id)
        if case["status"] not in {"REVIEW_READY", "PROMOTION_QUEUED"}:
            raise DomainError("case_not_ready", "Case is not eligible for promotion", 409)
        if mode == "preauthorized_policy" and project["owner_policy_id"] != "lab-auto-v1":
            raise DomainError("review_required", "Owner approval is required for this project", 409)
        certificate = EvidenceManifest.model_validate_json(
            self.artifacts.get(case["evidence_manifest_hash"])
        )
        if certificate.target_manifest_hash != project["source"]["manifest_hash"]:
            raise DomainError(
                "stale_candidate", "Current source changed after candidate verification", 409
            )
        manifest = TargetManifest.model_validate_json(
            self.artifacts.get(certificate.target_manifest_hash)
        )
        gates = [
            GateResult.model_validate(
                {
                    k: v
                    for k, v in self.store.get("gate", gate_id, project_id).items()
                    if k != "revision"
                }
            )
            for gate_id in certificate.gate_result_ids
        ]
        state = await self.deployer.call("/destinations/" + project_id)
        if not state["current"]:
            state = await self.deployer.call("/initialize", manifest.model_dump())
        if state["generation"] != case["expected_deployment_generation"]:
            raise DomainError(
                "stale_generation", "Case approval targets an old destination generation", 409
            )
        now = datetime.now(UTC)
        authorization = Authorization(
            authorization_id=new_id(),
            project_id=project_id,
            evidence_manifest_hash=case["evidence_manifest_hash"],
            destination_id=case["destination_id"],
            expected_deployment_generation=state["generation"],
            mode=mode,
            actor_or_policy_id=actor,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=30)).isoformat(),
        )
        self.store.put(
            "authorization", authorization.authorization_id, authorization.model_dump(), project_id
        )
        self.store.put(
            "case",
            case_id,
            case | {"status": "PROMOTING", "authorization_id": authorization.authorization_id},
            project_id,
        )
        self.engine.update_cycle(case["cycle_id"], status="PROMOTING")
        try:
            result = await self.deployer.call(
                "/promote",
                {
                    "authorization": authorization.model_dump(),
                    "certificate": certificate.model_dump(),
                    "manifest": manifest.model_dump(),
                    "gates": [g.model_dump() for g in gates],
                    "source_id": case["candidate_source_id"],
                },
            )
            result_id = self.onboarding.evidence(project_id, result)
            state = await self.synchronize_destination(project_id)
            self.engine.update_cycle(case["cycle_id"], status="REFRESHING")
            manifest_hash = await self.refresh(project_id, state)
            case = self.store.get("case", case_id)
            self.store.put(
                "case",
                case_id,
                case
                | {
                    "status": "COMPLETE",
                    "deployment_evidence_id": result_id,
                    "refreshed_manifest_hash": manifest_hash,
                    "updated_at": utcnow(),
                },
                project_id,
            )
            self.engine.update_cycle(
                case["cycle_id"],
                status="COMPLETE",
                finished_at=utcnow(),
                reason="Verified artifact promoted, observed and mirrored",
            )
            self.onboarding.update(project_id, active_cycle_id=None)
            return {
                "status": "COMPLETE",
                "case_id": case_id,
                "generation": state["generation"],
                "manifest_hash": manifest_hash,
            }
        except BaseException:
            # The route may have committed before a response was lost. Always observe it.
            await self.deployer.call("/abort", {"project_id": project_id})
            state = await self.synchronize_destination(project_id)
            case = self.store.get("case", case_id)
            state_name = (
                "RECOVERY_FAILED" if state["status"] == "RECOVERY_FAILED" else "NEEDS_REVIEW"
            )
            self.store.put(
                "case",
                case_id,
                case
                | {
                    "status": state_name,
                    "reason": "Deployment interrupted; observed destination recorded, reconciliation required",
                },
                project_id,
            )
            project = self.store.get("project", project_id)
            self.onboarding.update(project_id, mirror=project["mirror"] | {"state": "STALE"})
            raise

    async def rollback(self, project_id, expected_generation):
        await self.deployer.call(
            "/rollback", {"project_id": project_id, "expected_generation": expected_generation}
        )
        state = await self.synchronize_destination(project_id)
        manifest_hash = await self.refresh(project_id, state)
        return {
            "status": "ROLLED_BACK",
            "generation": state["generation"],
            "manifest_hash": manifest_hash,
            "known_vulnerable_baseline": state["current"]["known_vulnerable_baseline"],
        }
