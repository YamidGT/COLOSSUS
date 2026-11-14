from datetime import UTC, datetime, timedelta

import pytest

from colossus.contracts.core import DomainError, content_hash, new_id
from colossus.contracts.models import Authorization, EvidenceManifest, GateResult, TargetManifest
from colossus.deployment.service import LabDeployer, validate_authority
from colossus.verification.policy import REQUIRED_CHECKS


def inputs():
    project_id, case_id, candidate_id = new_id(), new_id(), new_id()
    manifest = TargetManifest(
        manifest_id=new_id(),
        revision=1,
        project_id=project_id,
        repo_url="https://github.com/stamparm/DSVW",
        commit="a" * 40,
        tree_sha256="a" * 64,
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
        protected_paths=[],
        allowed_patch_paths=["dsvw.py"],
        deployment_profile_id="local-web-v1",
        policy_hash="c" * 64,
        toolchain_manifest_id="d" * 64,
        setup_provenance=[{"source_id": "a" * 64}],
    )
    now = datetime.now(UTC)
    gates = [
        GateResult(
            gate_id=new_id(),
            case_id=case_id,
            candidate_id=candidate_id,
            candidate_hash="b" * 64,
            check_profile_id=profile,
            category="policy",
            status="pass",
            scope=["test"],
            tool_version="1",
            command_profile_hash="a" * 64,
            started_at=now.isoformat(),
            finished_at=now.isoformat(),
            evidence_ids=[],
        )
        for profile in REQUIRED_CHECKS
    ]
    gates.append(
        GateResult(
            gate_id=new_id(),
            case_id=case_id,
            candidate_id=candidate_id,
            candidate_hash="b" * 64,
            check_profile_id="formal",
            category="formal",
            status="not_applicable",
            proof_outcome="UNSUPPORTED",
            scope=["test"],
            tool_version="1",
            command_profile_hash="a" * 64,
            started_at=now.isoformat(),
            finished_at=now.isoformat(),
            evidence_ids=[],
        )
    )
    data = dict(
        manifest_id=new_id(),
        case_id=case_id,
        baseline_hash="a" * 64,
        candidate_hash="b" * 64,
        artifact_digest="sha256:" + "b" * 64,
        diff_hash="d" * 64,
        target_manifest_hash=content_hash(manifest.model_dump()),
        policy_hash=manifest.policy_hash,
        spec_hashes=[],
        harness_hashes=[],
        test_hashes=[],
        required_gate_ids=[g.gate_id for g in gates[:-1]],
        gate_result_ids=[g.gate_id for g in gates],
        assurance_profile="tested",
        proof_summary=[],
        exclusions=["No formal proof"],
        model_call_ids=[],
        total_cost_micro_usd=0,
        issued_at=now.isoformat(),
    )
    certificate = EvidenceManifest(**data, content_hash=content_hash(data))
    authorization = Authorization(
        authorization_id=new_id(),
        project_id=project_id,
        evidence_manifest_hash=content_hash(certificate.model_dump()),
        destination_id="local-web-v1",
        expected_deployment_generation=0,
        mode="preauthorized_policy",
        actor_or_policy_id="lab-auto-v1",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=30)).isoformat(),
    )
    return authorization, certificate, manifest, gates


def test_deployer_rejects_stale_tampered_and_expired_authority():
    a, c, m, g = inputs()
    validate_authority(a, c, m, g, 0)
    with pytest.raises(DomainError, match="Deployment changed"):
        validate_authority(a, c, m, g, 1)
    with pytest.raises(DomainError, match="hash is invalid"):
        validate_authority(
            a, c.model_copy(update={"artifact_digest": "sha256:" + "e" * 64}), m, g, 0
        )
    with pytest.raises(DomainError, match="expired"):
        validate_authority(a.model_copy(update={"expires_at": a.issued_at}), c, m, g, 0)
    with pytest.raises(DomainError, match="different evidence"):
        validate_authority(a.model_copy(update={"evidence_manifest_hash": "f" * 64}), c, m, g, 0)


class Launcher:
    def __init__(self):
        self.created, self.stopped = [], []

    async def call(self, path, body):
        if path == "/targets":
            slot = dict(
                project_id=body["project_id"],
                environment_id=new_id(),
                network_id=new_id(),
                artifact_digest=body["artifact_digest"],
            )
            self.created.append(slot)
            return slot
        if path == "/targets/stop":
            self.stopped.append(body["environment_id"])
            return {"stopped": True}
        raise AssertionError(path)


@pytest.mark.asyncio
async def test_promotion_commits_exact_route_once_and_rollback_validates_previous(tmp_path):
    a, c, m, gates = inputs()
    launcher = Launcher()
    deployer = LabDeployer(tmp_path / "deploy.sqlite", launcher, observation_seconds=0)

    async def checks(project_id, slot):
        return {"functional_pass": True, "security_pass": not slot["known_vulnerable_baseline"]}

    deployer.checks = checks
    await deployer.initialize(m)
    result = await deployer.promote(a, c, m, gates, "b" * 64)
    assert result["generation"] == 1 and result["candidate_digest"] == c.artifact_digest
    assert result["deployment_id"] != a.authorization_id
    from colossus.control.store import Store

    records = Store(tmp_path / "controller.sqlite")
    records.put("authorization", a.authorization_id, a.model_dump(), m.project_id)
    records.put("deployment", result["deployment_id"], result, m.project_id)
    records.close()
    assert await deployer.promote(a, c, m, gates, "b" * 64) == result
    assert len(launcher.created) == 2
    restored = await deployer.rollback(m.project_id, 1)
    assert (
        restored["generation"] == 2 and restored["current"]["artifact_digest"] == m.artifact_digest
    )
    assert restored["current"]["known_vulnerable_baseline"] is True
    retired = await deployer.retire(m.project_id)
    assert retired["status"] == "RETIRED" and retired["current"] is None
    assert retired["previous"] is None and retired["generation"] == 3
    assert set(launcher.stopped) == {slot["environment_id"] for slot in launcher.created}
    assert await deployer.retire(m.project_id) == retired
    with pytest.raises(DomainError, match="No healthy lab route"):
        await deployer.request(m.project_id)
    deployer.close()


@pytest.mark.asyncio
async def test_failed_canary_cannot_replace_route_and_restart_discards_pending_slot(tmp_path):
    a, c, m, gates = inputs()
    launcher = Launcher()
    deployer = LabDeployer(tmp_path / "deploy.sqlite", launcher, observation_seconds=0)

    async def checks(project_id, slot):
        return {"functional_pass": slot["known_vulnerable_baseline"], "security_pass": False}

    deployer.checks = checks
    before = await deployer.initialize(m)
    with pytest.raises(DomainError, match="synthetic"):
        await deployer.promote(a, c, m, gates, "b" * 64)
    after = deployer.state(m.project_id)
    assert after["current"] == before["current"] and after["generation"] == 0
    assert after["status"] == "ROLLED_BACK" and len(launcher.stopped) == 1
    pending = dict(after)
    pending["intent"] = {"target": launcher.created[-1]}
    pending["status"] = "OBSERVING"
    deployer.save(pending, 0)
    await deployer.reconcile()
    assert deployer.state(m.project_id)["intent"] is None
    assert deployer.state(m.project_id)["current"] == before["current"]
    deployer.close()
