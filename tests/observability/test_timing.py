import hashlib
import time

from colossus.control.store import Store
from colossus.observability.timing import stage_timings


def _enqueue(store, project_id, kind, payload):
    with store.transaction() as db:
        return store.enqueue(db, project_id, kind, payload, time.time() + 600)


def test_stage_timings_from_store_records(tmp_path):
    store = Store(tmp_path / "c.sqlite")
    build = _enqueue(store, "p1", "build", {"cache_state": "cold"})
    verify = _enqueue(store, "p1", "verify", {"warm": True})
    other = _enqueue(store, "p2", "build", {})

    task = store.claim("worker-1")
    assert task["id"] == build
    store.complete_task(build, "worker-1", task["attempt"], {"ok": True}, True)
    task = store.claim("worker-1")
    assert task["id"] == verify

    summary = stage_timings(store, "p1")
    rows = {r["task_id"]: r for r in summary["tasks"]}
    assert set(rows) == {build, verify}
    done = rows[build]
    assert done["cold_warm"] == "cold" and done["success"] is True
    assert done["queue_wait_seconds"] is not None and done["queue_wait_seconds"] >= 0
    assert done["run_seconds"] is not None and done["run_seconds"] >= 0
    assert done["clock"] == "wall"
    running = rows[verify]
    assert running["cold_warm"] == "warm"
    assert running["ended_at"] is None and running["run_seconds"] is None
    assert summary["stages"]["build"]["completed"] == 1
    assert summary["stages"]["verify"]["completed"] == 0
    assert summary["stages"]["verify"]["run_seconds_median"] is None
    assert stage_timings(store)["stages"]["build"]["count"] == 2
    assert stage_timings(store)["stages"]["build"]["unknown"] == 1
    assert other in {r["task_id"] for r in stage_timings(store)["tasks"]}


def test_retries_are_counted_and_timing_is_read_only(tmp_path):
    path = tmp_path / "c.sqlite"
    store = Store(path)
    task_id = _enqueue(store, "p1", "build", {})
    store.claim("w1", lease_seconds=60)
    with store.transaction() as db:  # simulate lease loss and requeue
        db.execute("UPDATE tasks SET state='queued' WHERE id=?", (task_id,))
    task = store.claim("w2")
    store.complete_task(task_id, "w2", task["attempt"], {}, False)

    store.connection.execute("PRAGMA wal_checkpoint(FULL)")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    events = len(store.audit())
    row = stage_timings(store, "p1")["tasks"][0]
    assert row["attempts"] == 2 and [c["attempt"] for c in row["claims"]] == [1, 2]
    assert row["success"] is False
    assert stage_timings(store, "p1")["stages"]["build"]["retried"] == 1
    store.connection.execute("PRAGMA wal_checkpoint(FULL)")
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert len(store.audit()) == events
