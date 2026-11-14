"""Controller restart with outstanding work, outbox replay and I07 crash windows."""

import asyncio
import json

import pytest
from faultkit import (
    DIGEST_A,
    DIGEST_B,
    FakeRPC,
    RecordingLauncher,
    approval,
    authority_inputs,
    destination,
    make_deployer,
    make_worker,
    ready_project,
    restart,
    review_ready_case,
    task_count,
    task_row,
)

from colossus.contracts.core import DomainError, utcnow
from colossus.deployment.service import LabDeployer


def test_queued_outbox_survives_restart_and_is_delivered_once(env):
    project_id = ready_project(env.store)
    receipt = env.controller.run(project_id, "run-1", "operator")
    restart(env)
    # Retried request after restart: same receipt, no second task in the outbox.
    assert env.controller.run(project_id, "run-1", "operator") == receipt
    assert task_count(env.store) == 1
    task = env.store.claim("new-worker")
    assert task["id"] == receipt["resource_ids"]["task_id"]
    assert task["payload"] == {
        "cycle_id": receipt["resource_ids"]["cycle_id"],
        "operation_id": receipt["operation_id"],
    }
    assert task["attempt"] == 1
    assert env.store.claim("other-worker") is None


async def test_restart_fails_running_task_closed_without_replay(env):
    project_id = ready_project(env.store)
    receipt = env.controller.run(project_id, "run-1", "operator")
    cycle_id = receipt["resource_ids"]["cycle_id"]
    task = env.store.claim("dead-worker")
    restart(env)

    observed = {"state": destination(project_id, generation=0, digest=DIGEST_A)}
    launcher = FakeRPC()
    worker = make_worker(env, deployer=make_deployer(observed), launcher=launcher)
    await worker.reconcile()

    row = task_row(env.store, task["id"])
    assert row["state"] == "failed"
    assert json.loads(row["result"]) == {
        "reason": "controller_restarted",
        "termination_confirmed": True,
    }
    terminate = [body for path, body in launcher.calls if path == "/terminate-work"]
    assert terminate and "env-a" in terminate[0]["keep"]
    assert env.store.get("cycle", cycle_id)["status"] == "INFRA_FAILED"
    project = env.store.get("project", project_id)
    assert project["active_cycle_id"] is None
    assert project["mirror"]["state"] == "READY"  # observed digest matches the mirror
    assert env.store.operation(receipt["operation_id"])["reason_code"] == "controller_restarted"
    assert env.store.claim("new-worker") is None
    assert worker.state == "idle"
    # A second reconcile pass (another restart) is a no-op.
    await worker.reconcile()
    assert task_row(env.store, task["id"]) == row


async def test_restart_keeps_in_flight_model_charge_as_uncertain(env):
    project_id = ready_project(env.store)
    env.store.reserve("call-1", "case-1", 700, 1000, 1000)
    env.store.put(
        "model_call",
        "call-1",
        {"call_id": "call-1", "task_id": "case-1", "status": "in_flight", "created_at": utcnow()},
        project_id,
    )
    restart(env)
    worker = make_worker(env)
    await worker.reconcile()
    assert env.store.get("model_call", "call-1")["status"] == "uncertain"
    assert env.store.get("model_call", "call-1")["reason_code"] == "controller_restarted"
    budget = env.store.budget("case-1")
    assert budget["committed_micro_usd"] == 700 and budget["uncertain_micro_usd"] == 700
    with pytest.raises(DomainError, match="budget"):
        env.store.reserve("call-2", "case-1", 400, 1000, 1000)


@pytest.mark.xfail(
    strict=True,
    reason="Worker.reconcile (worker.py:103-104) calls store.reconcile(call, None) for a call "
    "whose charge was already settled (crash between broker.py:80 and the model_call write); "
    "Store.reconcile raises cost_conflict and controller startup aborts",
)
async def test_restart_after_settled_charge_but_before_call_record(env):
    project_id = ready_project(env.store)
    env.store.reserve("call-1", "case-1", 700, 1000, 1000)
    env.store.put(
        "model_call",
        "call-1",
        {"call_id": "call-1", "task_id": "case-1", "status": "in_flight", "created_at": utcnow()},
        project_id,
    )
    env.store.reconcile("call-1", 250)  # Broker settled; process died before the record write.
    restart(env)
    worker = make_worker(env)
    await worker.reconcile()
    assert worker.state == "idle"
    assert env.store.budget("case-1")["settled_micro_usd"] == 250


def promote_crash_setup(env):
    """Case approved, promote task running, deployer committed generation 1, controller died."""
    project_id = ready_project(env.store)
    cycle_id, case_id = review_ready_case(env, project_id)
    decision = approval(env.store, case_id)
    receipt = env.controller.approve(case_id, decision, "approve-1", "owner")
    task = env.store.claim("dead-worker")
    assert task["kind"] == "promote"
    case = env.store.get("case", case_id)
    env.store.put("case", case_id, case | {"status": "PROMOTING"}, project_id)
    observed = {
        "state": destination(
            project_id,
            generation=1,
            digest=DIGEST_B,
            env="env-b",
            previous=destination(project_id)["current"],
        )
    }
    restart(env)
    return project_id, cycle_id, case_id, receipt | {"decision": decision}, task, observed


async def test_crash_after_deployer_commit_reconciles_generation_once(env):
    project_id, cycle_id, case_id, receipt, task, observed = promote_crash_setup(env)
    deployer = make_deployer(observed)
    worker = make_worker(env, deployer=deployer)
    await worker.reconcile()

    project = env.store.get("project", project_id)
    assert project["deployment"]["generation"] == 1
    assert project["deployment"]["artifact_digest"] == DIGEST_B
    assert project["deployment"]["previous_digest"] == DIGEST_A
    assert project["mirror"]["state"] == "STALE"
    assert "/promote" not in deployer.paths()
    assert task_row(env.store, task["id"])["state"] == "failed"
    assert env.store.get("cycle", cycle_id)["status"] == "INFRA_FAILED"
    assert env.store.operation(receipt["operation_id"])["status"] == "failed"
    # No path re-issues the promotion: queue is empty, re-approval and direct replay refuse.
    assert env.store.claim("new-worker") is None
    with pytest.raises(DomainError, match="not eligible"):
        await worker.deployment.promote(case_id, "owner_approval", "owner")
    with pytest.raises(DomainError) as exc:
        env.controller.approve(case_id, approval(env.store, case_id), "approve-2", "owner")
    assert exc.value.code == "stale_review"
    # Same key replays the original receipt instead of enqueueing again.
    replay = env.controller.approve(case_id, receipt["decision"], "approve-1", "owner")
    assert replay["operation_id"] == receipt["operation_id"]
    assert task_count(env.store, "queued") == 0
    assert "/promote" not in deployer.paths()


@pytest.mark.xfail(
    strict=True,
    reason="Worker.reconcile/failed (worker.py:65-139) leave an interrupted promotion's case in "
    "PROMOTING; it is not marked NEEDS_REVIEW and Controller.actions omits it (service.py:481)",
)
async def test_crash_mid_promotion_surfaces_case_for_review(env):
    project_id, _, case_id, _, _, observed = promote_crash_setup(env)
    worker = make_worker(env, deployer=make_deployer(observed))
    await worker.reconcile()
    assert env.store.get("case", case_id)["status"] in {"NEEDS_REVIEW", "RECOVERY_FAILED"}
    assert any(a["case_id"] == case_id for a in env.controller.actions(project_id))


def promoted_events(path):
    import sqlite3

    db = sqlite3.connect(path)
    try:
        rows = [json.loads(r[0]) for r in db.execute("SELECT data FROM events")]
    finally:
        db.close()
    return [r for r in rows if r["status"] == "PROMOTED"]


async def test_deployer_kill_during_canary_then_restart_promotes_exactly_once(tmp_path):
    a, c, m, gates = authority_inputs()
    path = tmp_path / "deploy.sqlite"
    launcher = RecordingLauncher()
    hold = asyncio.Event()

    async def checks(project_id, slot):
        if not slot["known_vulnerable_baseline"]:
            await hold.wait()
        return {"functional_pass": True, "security_pass": True}

    first = LabDeployer(path, launcher, observation_seconds=0)
    first.checks = checks
    await first.initialize(m)
    stuck = asyncio.create_task(first.promote(a, c, m, gates, "b" * 64))
    for _ in range(200):
        if first.state(m.project_id)["status"] == "OBSERVING":
            break
        await asyncio.sleep(0.01)
    staged = first.state(m.project_id)["intent"]["target"]

    # The process is treated as dead; a new deployer reconciles from durable state.
    second = LabDeployer(path, launcher, observation_seconds=0)
    second.checks = checks
    await second.reconcile()
    state = second.state(m.project_id)
    assert state["intent"] is None and state["generation"] == 0
    assert state["status"] == "ROLLED_BACK" and state["current"]["artifact_digest"] == DIGEST_A
    assert staged["environment_id"] in launcher.stopped

    # A promoter that was only suspended must not switch the route after reconciliation.
    hold.set()
    with pytest.raises(BaseException):  # noqa: B017 - any failure is acceptable, success is not
        await stuck
    assert second.state(m.project_id)["generation"] == 0
    assert promoted_events(path) == []

    # The unconsumed authorization promotes once; a lost response replays the stored decision.
    result = await second.promote(a, c, m, gates, "b" * 64)
    assert result["generation"] == 1
    created = len(launcher.created)
    third = LabDeployer(path, launcher, observation_seconds=0)
    third.checks = checks
    assert await third.promote(a, c, m, gates, "b" * 64) == result
    assert len(launcher.created) == created
    assert len(promoted_events(path)) == 1
    for d in (first, second, third):
        d.close()
