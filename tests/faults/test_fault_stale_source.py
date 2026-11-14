"""I11 source changes during verification -> a stale candidate cannot promote."""

import pytest
from faultkit import (
    FakeRPC,
    RecordingLauncher,
    approval,
    authority_inputs,
    make_authorization,
    make_certificate,
    make_worker,
    ready_project,
    review_ready_case,
    task_count,
)

from colossus.contracts.core import DomainError, content_hash
from colossus.deployment.service import LabDeployer, validate_authority


def stored_certificate(env, target_manifest_hash):
    certificate = make_certificate(target_manifest_hash=target_manifest_hash)
    return env.artifacts.put(certificate.model_dump_json().encode())


def no_deployer_calls():
    def handler(path, body):
        raise AssertionError("deployer contacted for a stale candidate: " + path)

    return FakeRPC(handler)


async def test_source_change_after_approval_blocks_promotion(env):
    verified_manifest = "1" * 64
    project_id = ready_project(env.store, manifest_hash=verified_manifest)
    key = stored_certificate(env, verified_manifest)
    _, case_id = review_ready_case(env, project_id, certificate_key=key)
    env.controller.approve(case_id, approval(env.store, case_id), "approve-1", "owner")
    assert env.store.get("case", case_id)["status"] == "PROMOTION_QUEUED"

    worker = make_worker(env, deployer=no_deployer_calls())
    # Source poller observes a new upstream revision while the promote task waits.
    worker.onboarding.update(
        project_id,
        source=env.store.get("project", project_id)["source"] | {"manifest_hash": "2" * 64},
    )
    with pytest.raises(DomainError) as exc:
        await worker.deployment.promote(case_id, "owner_approval", "owner")
    assert exc.value.code == "stale_candidate"
    assert env.store.get("case", case_id)["status"] == "PROMOTION_QUEUED"
    assert env.store.list("authorization", project_id) == []


async def test_lab_policy_auto_promotion_also_rejects_stale_source(env):
    project_id = ready_project(env.store, owner_policy_id="lab-auto-v1", manifest_hash="2" * 64)
    key = stored_certificate(env, "1" * 64)
    _, case_id = review_ready_case(env, project_id, certificate_key=key)
    worker = make_worker(env, deployer=no_deployer_calls())
    with pytest.raises(DomainError, match="source changed"):
        await worker.deployment.promote(case_id)
    assert env.store.get("case", case_id)["status"] == "REVIEW_READY"


def test_approval_bound_to_superseded_evidence_is_refused(env):
    project_id = ready_project(env.store)
    _, case_id = review_ready_case(env, project_id, certificate_key="1" * 64)
    stale = approval(env.store, case_id)
    case = env.store.get("case", case_id)
    # Re-verification against the new source rebinds the case to new evidence.
    env.store.put("case", case_id, case | {"evidence_manifest_hash": "2" * 64}, project_id)
    with pytest.raises(DomainError) as exc:
        env.controller.approve(case_id, stale, "approve-1", "owner")
    assert exc.value.code == "stale_review"
    fresh = approval(env.store, case_id) | {"evidence_manifest_hash": "1" * 64}
    with pytest.raises(DomainError) as exc:
        env.controller.approve(case_id, fresh, "approve-2", "owner")
    assert exc.value.code == "approval_binding"
    assert task_count(env.store, "queued") == 0


def test_deployer_rejects_candidate_verified_against_previous_source():
    a, c, m, gates = authority_inputs(tree="1" * 64)
    validate_authority(a, c, m, gates, 0)
    moved = m.model_copy(update={"tree_sha256": "2" * 64, "commit": "b" * 40})
    with pytest.raises(DomainError) as exc:
        validate_authority(a, c, moved, gates, 0)
    assert exc.value.code == "stale_manifest"
    # Even if the certificate is re-bound to the new manifest, its baseline is the old tree.
    rebound = make_certificate(
        **(
            c.model_dump(exclude={"content_hash"})
            | {"target_manifest_hash": content_hash(moved.model_dump())}
        )
    )
    with pytest.raises(DomainError) as exc:
        validate_authority(make_authorization(m.project_id, rebound), rebound, moved, gates, 0)
    assert exc.value.code == "stale_source"


async def test_deployer_promote_with_stale_source_leaves_route_untouched(tmp_path):
    a, c, m, gates = authority_inputs(tree="1" * 64)
    launcher = RecordingLauncher()
    deployer = LabDeployer(tmp_path / "deploy.sqlite", launcher, observation_seconds=0)

    async def checks(project_id, slot):
        return {"functional_pass": True, "security_pass": True}

    deployer.checks = checks
    before = await deployer.initialize(m)
    moved = m.model_copy(update={"tree_sha256": "2" * 64})
    with pytest.raises(DomainError, match="differs from the verified manifest"):
        await deployer.promote(a, c, moved, gates, "b" * 64)
    after = deployer.state(m.project_id)
    assert after == before and after["intent"] is None
    assert len(launcher.created) == 1  # only the baseline
    deployer.close()
