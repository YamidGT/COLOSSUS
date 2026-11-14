"""I06 duplicate delivery / expired lease, plus cancellation and deadline reconciliation."""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from faultkit import (
    expire_lease,
    make_worker,
    ready_project,
    task_count,
    task_row,
)

from colossus.contracts.core import DomainError, new_id
from colossus.control.service import TERMINAL_CYCLES
from colossus.control.store import Store


def queue_one(store):
    with store.transaction() as db:
        return store.enqueue(db, "p-" + new_id(), "build", {"operation_id": "x"}, time.time() + 60)


def test_duplicate_delivery_across_controller_connections_has_one_owner(env):
    task_id = queue_one(env.store)
    path = env.tmp_path / "state.db"
    stores = [Store(path) for _ in range(8)]
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(lambda i: stores[i].claim(f"worker-{i}"), range(8)))
    finally:
        for s in stores:
            s.close()
    won = [c for c in claims if c is not None]
    assert len(won) == 1 and won[0]["id"] == task_id and won[0]["attempt"] == 1
    row = task_row(env.store, task_id)
    assert row["state"] == "running" and row["lease_owner"] == won[0]["lease_owner"]
    claimed = [e for e in env.store.audit() if e["kind"] == "task.claimed"]
    assert len(claimed) == 1


def test_duplicate_result_for_same_attempt_is_discarded(env):
    task_id = queue_one(env.store)
    task = env.store.claim("worker")
    env.store.complete_task(task_id, "worker", task["attempt"], {"verdict": "first"}, True)
    with pytest.raises(DomainError) as exc:
        env.store.complete_task(task_id, "worker", task["attempt"], {"verdict": "second"}, False)
    assert exc.value.code == "stale_task"
    row = task_row(env.store, task_id)
    assert row["state"] == "succeeded" and '"first"' in row["result"]


def test_wrong_owner_or_attempt_cannot_publish(env):
    task_id = queue_one(env.store)
    task = env.store.claim("worker")
    for owner, attempt in (("intruder", task["attempt"]), ("worker", task["attempt"] + 1)):
        with pytest.raises(DomainError, match="expired or superseded"):
            env.store.complete_task(task_id, owner, attempt, {"verdict": "forged"}, True)
        assert not env.store.heartbeat(task_id, owner, attempt)
    assert task_row(env.store, task_id)["state"] == "running"


async def run_process(worker, task, during):
    """Drive the real Worker.process with an executor that never finishes on its own."""
    release = asyncio.Event()

    async def execute(_task):
        during()
        await release.wait()
        return {"status": "LATE_RESULT"}

    worker.execute = execute
    await asyncio.wait_for(worker.process(task), timeout=30)
    release.set()


async def test_expired_lease_settles_once_and_late_result_is_discarded(env):
    project_id = ready_project(env.store)
    receipt = env.controller.run(project_id, "run-1", "operator")
    cycle_id = receipt["resource_ids"]["cycle_id"]
    worker = make_worker(env)
    task = env.store.claim(worker.owner)

    await run_process(worker, task, lambda: expire_lease(env.store, task["id"]))

    row = task_row(env.store, task["id"])
    assert row["state"] == "failed" and "cycle_timeout" in row["result"]
    assert env.store.get("cycle", cycle_id)["status"] == "TIMEOUT"
    assert env.store.get("project", project_id)["active_cycle_id"] is None
    operation = env.store.operation(receipt["operation_id"])
    assert operation["status"] == "failed" and operation["reason_code"] == "cycle_timeout"
    launcher = worker.services.clients["launcher"]
    assert "/terminate-work" in launcher.paths()

    # The original executor now produces its result; it must not be accepted.
    with pytest.raises(DomainError) as exc:
        env.store.complete_task(task["id"], worker.owner, task["attempt"], {"pass": True}, True)
    assert exc.value.code == "stale_task"
    assert task_row(env.store, task["id"]) == row
    assert env.store.claim("second-worker") is None
    assert task_count(env.store, "succeeded") == 0
    assert env.store.verify_audit()


async def test_cancellation_is_reconciled_by_running_worker(env):
    project_id = ready_project(env.store)
    receipt = env.controller.run(project_id, "run-1", "operator")
    cycle_id = receipt["resource_ids"]["cycle_id"]
    worker = make_worker(env)
    task = env.store.claim(worker.owner)
    cancel = {}

    def request_cancel():
        cancel["receipt"] = env.controller.cancel(cycle_id, "cancel-1", "operator")

    await run_process(worker, task, request_cancel)

    cycle = env.store.get("cycle", cycle_id)
    assert cycle["status"] == "CANCELLED" and cycle["finished_at"]
    assert env.store.get("project", project_id)["active_cycle_id"] is None
    assert env.store.operation(receipt["operation_id"])["reason_code"] == "cancelled"
    row = task_row(env.store, task["id"])
    assert row["state"] == "failed" and "cancelled" in row["result"]
    # Duplicate cancel with the same key is the same receipt; a new cancel is refused.
    assert env.controller.cancel(cycle_id, "cancel-1", "operator") == cancel["receipt"]
    with pytest.raises(DomainError, match="already finished"):
        env.controller.cancel(cycle_id, "cancel-2", "operator")


@pytest.mark.xfail(
    strict=True,
    reason="Controller.cancel (service.py:156-176) never finishes its own operation receipt; "
    "it stays 'accepted' after the worker has reconciled the cancellation",
)
async def test_cancel_receipt_reaches_a_terminal_status(env):
    project_id = ready_project(env.store)
    cycle_id = env.controller.run(project_id, "run-1", "operator")["resource_ids"]["cycle_id"]
    worker = make_worker(env)
    task = env.store.claim(worker.owner)
    cancel = {}

    def request_cancel():
        cancel["receipt"] = env.controller.cancel(cycle_id, "cancel-1", "operator")

    await run_process(worker, task, request_cancel)
    assert env.store.get("cycle", cycle_id)["status"] == "CANCELLED"
    assert env.store.operation(cancel["receipt"]["operation_id"])["status"] != "accepted"


@pytest.mark.xfail(
    strict=True,
    reason="Store.claim (store.py:294-296) marks a queued task 'expired' at its deadline but "
    "nothing reconciles its cycle/project/operation; the project stays bound to a dead cycle",
)
def test_queued_task_past_deadline_releases_project(env):
    project_id = ready_project(env.store)
    receipt = env.controller.run(project_id, "run-1", "operator")
    cycle_id = receipt["resource_ids"]["cycle_id"]
    with env.store.lock:
        env.store.connection.execute("UPDATE tasks SET deadline=?", (time.time() - 1,))
    assert env.store.claim("worker") is None
    assert task_count(env.store, "expired") == 1
    cycle = env.store.get("cycle", cycle_id)
    project = env.store.get("project", project_id)
    assert cycle["status"] in TERMINAL_CYCLES
    assert project["active_cycle_id"] is None
    assert env.store.operation(receipt["operation_id"])["status"] == "failed"
