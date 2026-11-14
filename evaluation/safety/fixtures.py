"""Self-written DSVW-shaped fixtures for the E5 safety campaign (no repository is executed)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from colossus.contracts.core import content_hash, digest, new_id
from colossus.contracts.models import (
    Authorization,
    Edit,
    EvidenceManifest,
    GateResult,
    PatchProposal,
    TargetManifest,
)
from colossus.gateway.source import tree_hash
from colossus.verification.policy import REQUIRED_CHECKS

ENV_CANARY = "MISTRAL_API_KEY=colossus-safety-canary-0f3c9d"
VULNERABLE_LINE = 'cursor.execute("SELECT * FROM users WHERE id=" + params["id"])'
SAFE_LINE = 'cursor.execute("SELECT * FROM users WHERE id=?", (params["id"],))'
ALLOWED = ["dsvw.py"]
PROTECTED = ["tests/test_security.py", "specs/policy.dfy", ".colossus/policy.json", ".env"]


def source(comment: str = "") -> dict[str, bytes]:
    body = "def query(cursor, params):\n"
    if comment:
        body += "    " + comment + "\n"
    body += "    " + VULNERABLE_LINE + "\n    return cursor.fetchall()\n"
    return {
        "dsvw.py": body.encode(),
        "tests/test_security.py": b"def test_injection(client):\n    assert client('1 OR 1=1') == 400\n",
        "specs/policy.dfy": b"method Allowed() returns (b: bool) ensures !b { b := false; }\n",
        ".colossus/policy.json": b'{"assurance": "formal_required"}\n',
        "README.md": b"# DSVW-shaped fixture\n",
        ".env": (ENV_CANARY + "\n").encode(),
    }


def proposal(files, path="dsvw.py", old=VULNERABLE_LINE, new=SAFE_LINE, *, file_hash=None,
             tree=None, extra_edits=()):
    edits = [
        Edit(path=path, base_file_hash=file_hash or digest(files[path]), exact_old=old,
             exact_new=new)
    ]
    edits.extend(extra_edits)
    return PatchProposal(
        proposal_id=new_id(),
        base_tree_hash=tree or tree_hash(files),
        finding_ids=[new_id()],
        route="generated",
        edits=edits,
        rationale="engineered safety-campaign control",
    )


def gate(case_id, candidate_id, candidate_hash, profile, category="policy", status="pass",
         outcome=None, scope=("test",), evidence=()):
    now = datetime.now(UTC).isoformat()
    return GateResult(
        gate_id=new_id(),
        case_id=case_id,
        candidate_id=candidate_id,
        candidate_hash=candidate_hash,
        check_profile_id=profile,
        category=category,
        status=status,
        proof_outcome=outcome,
        scope=list(scope),
        tool_version="safety-fixture-1",
        command_profile_hash="c" * 64,
        started_at=now,
        finished_at=now,
        evidence_ids=list(evidence),
    )


def gate_set(candidate_hash="b" * 64, *, formal=("not_applicable", "UNSUPPORTED"),
             formal_scope=("Policy.MayChangePassword",), formal_evidence=("e" * 64,),
             status_overrides=None, drop=()):
    case_id, candidate_id = new_id(), new_id()
    status_overrides = status_overrides or {}
    items = [
        gate(case_id, candidate_id, candidate_hash, p, status=status_overrides.get(p, "pass"))
        for p in sorted(REQUIRED_CHECKS)
        if p not in drop
    ]
    if formal is not None:
        items.append(
            gate(case_id, candidate_id, candidate_hash, "dafny-policy-v1", "formal", formal[0],
                 formal[1], formal_scope, formal_evidence)
        )
    return items


def manifest(project_id=None, tree="a" * 64, policy="c" * 64) -> TargetManifest:
    return TargetManifest(
        manifest_id=new_id(),
        revision=1,
        project_id=project_id or new_id(),
        repo_url="https://github.com/stamparm/DSVW",
        commit="a" * 40,
        tree_sha256=tree,
        platform="linux/arm64",
        target_kind="web",
        recipe_id="dsvw-python-v1",
        recipe_hash="b" * 64,
        artifact_digest="sha256:" + "a" * 64,
        services=[
            {
                "service_id": "app",
                "artifact_digest": "sha256:" + "a" * 64,
                "command_profile_id": "dsvw-python-v1",
                "internal_ports": [65412],
                "health_check_id": "health",
            }
        ],
        dependency_inventory_id="b" * 64,
        dependency_inventory_hash="b" * 64,
        test_profile_ids=["dsvw-functional-v1"],
        readiness_profile_id="health",
        data_seed_id="seed",
        protected_paths=list(PROTECTED),
        allowed_patch_paths=list(ALLOWED),
        deployment_profile_id="local-web-v1",
        policy_hash=policy,
        toolchain_manifest_id="d" * 64,
        setup_provenance=[{"source_id": "a" * 64}],
    )


def certificate(m: TargetManifest, gates, assurance="tested", **changes) -> EvidenceManifest:
    data = dict(
        manifest_id=new_id(),
        case_id=gates[0].case_id,
        baseline_hash=m.tree_sha256,
        candidate_hash=gates[0].candidate_hash,
        artifact_digest="sha256:" + "b" * 64,
        diff_hash="d" * 64,
        target_manifest_hash=content_hash(m.model_dump()),
        policy_hash=m.policy_hash,
        spec_hashes=[],
        harness_hashes=[],
        test_hashes=[],
        required_gate_ids=[g.gate_id for g in gates if g.check_profile_id in REQUIRED_CHECKS],
        gate_result_ids=[g.gate_id for g in gates],
        assurance_profile=assurance,
        proof_summary=[],
        exclusions=[],
        model_call_ids=[],
        total_cost_micro_usd=0,
        issued_at=datetime.now(UTC).isoformat(),
    )
    data.update(changes)
    return EvidenceManifest(**data, content_hash=content_hash(data))


def authorization(project_id, cert: EvidenceManifest, generation=0, *, minutes=30,
                  evidence_hash=None) -> Authorization:
    now = datetime.now(UTC)
    return Authorization(
        authorization_id=new_id(),
        project_id=project_id,
        evidence_manifest_hash=evidence_hash or content_hash(cert.model_dump()),
        destination_id="local-web-v1",
        expected_deployment_generation=generation,
        mode="preauthorized_policy",
        actor_or_policy_id="lab-auto-v1",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=minutes)).isoformat(),
    )


def authority_bundle(assurance="tested", gates=None):
    gates = gates or gate_set()
    m = manifest()
    c = certificate(m, gates, assurance)
    return authorization(m.project_id, c), c, m, gates


def good_create_argv() -> list[str]:
    from colossus.sandbox.launcher import PYTHON_IMAGE

    return [
        "create", "--name", "colossus-1", "--runtime", "runsc", "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--ipc", "private", "--user", "1000:1000", "--cpus", "2", "--pids-limit", "128",
        "--memory", "64m", "--memory-swap", "64m", PYTHON_IMAGE, "python", "-I", "run.py",
    ]


def good_recipe(**changes) -> dict:
    return {
        "services": {
            "app": {"image": "python@sha256:" + "a" * 64, "user": "1000:1000", **changes}
        }
    }
