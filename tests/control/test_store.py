import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from colossus.contracts.core import DomainError, new_id
from colossus.control.store import Store


@pytest.fixture
def store(tmp_path):
    state = Store(tmp_path / "state.db")
    yield state
    state.close()


def test_operation_receipt_and_intent_commit_once(store):
    project_id = new_id()

    def action(db, operation_id):
        store._put(db, "project", project_id, {"status": "NEW"}, project_id)
        store.enqueue(db, project_id, "setup", {"operation_id": operation_id}, time.time() + 60)
        return {"project_id": project_id}

    first = store.mutate("operator", "enroll-1", "enroll", {"repo": "a/b"}, action)
    assert store.mutate("operator", "enroll-1", "enroll", {"repo": "a/b"}, action) == first
    assert len(store.list("project")) == 1
    assert store.connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    with pytest.raises(DomainError, match="different request"):
        store.mutate("operator", "enroll-1", "enroll", {"repo": "a/c"}, action)
    assert store.verify_audit()


def test_failed_intent_rolls_back_receipt_records_and_audit(store):
    def action(db, operation_id):
        store._put(db, "project", new_id(), {"status": "NEW"}, None)
        raise RuntimeError("disk failure")

    with pytest.raises(RuntimeError):
        store.mutate("operator", "failed", "enroll", {}, action)
    assert store.list("project") == []
    assert store.audit() == []
    assert store.connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 0


def test_concurrent_budget_reservations_cannot_overspend(tmp_path):
    stores = [Store(tmp_path / "shared.db") for _ in range(2)]

    def reserve(i):
        try:
            stores[i % 2].reserve(new_id(), "same-case", 60, 100, 100)
            return True
        except DomainError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        accepted = list(pool.map(reserve, range(10)))
    assert sum(accepted) == 1
    assert stores[0].budget()["committed_micro_usd"] == 60
    for s in stores:
        s.close()


def test_unknown_provider_charge_stays_reserved(store):
    store.reserve("call1", "case", 70, 100, 100)
    store.reconcile("call1", None)
    with pytest.raises(DomainError, match="budget"):
        store.reserve("call2", "case", 40, 100, 100)
    store.reconcile("call1", 20)
    store.reconcile("call1", 20)
    assert store.budget()["settled_micro_usd"] == 20
    store.reserve("call2", "case", 40, 100, 100)
    assert store.budget()["committed_micro_usd"] == 60


def test_expired_worker_cannot_publish_or_renew(store):
    with store.transaction() as db:
        task_id = store.enqueue(db, "project", "build", {}, time.time() + 60)
    task = store.claim("worker")
    store.connection.execute(
        "UPDATE tasks SET lease_expires=? WHERE id=?", (time.time() - 1, task_id)
    )
    assert not store.heartbeat(task_id, "worker", task["attempt"])
    with pytest.raises(DomainError, match="expired"):
        store.complete_task(task_id, "worker", task["attempt"], {"pass": True}, True)
    assert store.claim("other") is None  # No requeue before launcher termination is confirmed.


def test_generation_cas_rejects_stale_writer(store):
    state = store.put("deployment", "d", {"generation": 1}, "p")
    store.put("deployment", "d", {"generation": 2}, "p", expected_revision=state["revision"])
    with pytest.raises(DomainError, match="changed"):
        store.put("deployment", "d", {"generation": 3}, "p", expected_revision=state["revision"])
    assert store.get("deployment", "d")["generation"] == 2


def test_paused_project_tasks_wait_for_resume(store):
    import time

    from colossus.contracts.core import new_id

    project_id = new_id()
    store.put("project", project_id, {"admission_state": "paused"}, project_id)
    with store.transaction() as db:
        store.enqueue(db, project_id, "onboard", {}, time.time() + 100)
    assert store.claim("worker") is None
    store.put("project", project_id, {"admission_state": "active"}, project_id)
    assert store.claim("worker")["project_id"] == project_id


def test_pausing_admission_does_not_block_requested_rollback(store):
    project_id = "paused-recovery-project"
    store.put("project", project_id, {"admission_state": "paused"}, project_id)
    with store.transaction() as db:
        store.enqueue(db, project_id, "onboard", {}, time.time() + 100)
        recovery = store.enqueue(db, project_id, "rollback", {}, time.time() + 100)
    assert store.claim("recovery-worker")["id"] == recovery
    assert store.claim("another-worker") is None
