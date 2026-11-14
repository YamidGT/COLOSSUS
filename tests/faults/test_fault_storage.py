"""I15 storage/audit write failure -> no new authority-changing action; recovery still tried."""

import sqlite3
import time

import pytest
from faultkit import (
    FakeRPC,
    approval,
    authority_inputs,
    destination,
    fail_audit_writes,
    make_certificate,
    make_worker,
    ready_project,
    restore_audit_writes,
    review_ready_case,
    task_count,
    task_row,
)


def counts(store):
    with store.lock:
        db = store.connection
        return (
            db.execute("SELECT COUNT(*) FROM operations").fetchone()[0],
            db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0],
            db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
        )


def test_audit_failure_blocks_approval_and_its_promotion_task(env):
    project_id = ready_project(env.store)
    _, case_id = review_ready_case(env, project_id)
    decision = approval(env.store, case_id)
    before = counts(env.store)
    fail_audit_writes(env.store)
    with pytest.raises(sqlite3.DatabaseError, match="injected audit"):
        env.controller.approve(case_id, decision, "approve-1", "owner")
    assert counts(env.store) == before
    assert env.store.get("case", case_id)["status"] == "REVIEW_READY"
    restore_audit_writes(env.store)
    # Once storage recovers, the same idempotency key is still usable exactly once.
    receipt = env.controller.approve(case_id, decision, "approve-1", "owner")
    assert env.controller.approve(case_id, decision, "approve-1", "owner") == receipt
    assert task_count(env.store, "queued") == 1
    assert env.store.verify_audit()


def test_audit_failure_blocks_rollback_and_run_intents(env):
    project_id = ready_project(env.store)
    env.store.put(
        "project",
        project_id,
        env.store.get("project", project_id) | {"deployment": {"generation": 2}},
        project_id,
    )
    fail_audit_writes(env.store)
    before = counts(env.store)
    with pytest.raises(sqlite3.DatabaseError):
        env.controller.rollback(project_id, 2, "rb-1", "owner")
    with pytest.raises(sqlite3.DatabaseError):
        env.controller.run(project_id, "run-1", "owner")
    assert counts(env.store) == before
    project = env.store.get("project", project_id)
    assert project.get("maintenance_operation_id") is None and project["active_cycle_id"] is None


def test_audit_failure_prevents_claiming_and_publishing_task_results(env):
    with env.store.transaction() as db:
        task_id = env.store.enqueue(db, "p", "build", {"operation_id": "o"}, time.time() + 60)
    running = env.store.claim("worker")
    with env.store.transaction() as db:
        queued = env.store.enqueue(db, "p", "build", {"operation_id": "o2"}, time.time() + 60)
    fail_audit_writes(env.store)
    with pytest.raises(sqlite3.DatabaseError):
        env.store.claim("worker-2")
    assert task_row(env.store, queued)["state"] == "queued"
    assert task_row(env.store, queued)["attempt"] == 0
    with pytest.raises(sqlite3.DatabaseError):
        env.store.complete_task(task_id, "worker", running["attempt"], {"pass": True}, True)
    assert task_row(env.store, task_id)["state"] == "running"
    assert task_row(env.store, task_id)["result"] is None


def test_audit_failure_blocks_budget_reservation(env):
    fail_audit_writes(env.store)
    with pytest.raises(sqlite3.DatabaseError):
        env.store.reserve("call-1", "case-1", 10, 100, 100)
    restore_audit_writes(env.store)
    assert env.store.budget()["calls"] == 0


def lab_case(env):
    """A REVIEW_READY lab-policy case whose evidence binds the project's current manifest."""
    _, _, manifest, _ = authority_inputs()
    manifest_key = env.artifacts.put(manifest.model_dump_json().encode())
    project_id = ready_project(env.store, owner_policy_id="lab-auto-v1", manifest_hash=manifest_key)
    certificate = make_certificate(target_manifest_hash=manifest_key)
    key = env.artifacts.put(certificate.model_dump_json().encode())
    _, case_id = review_ready_case(env, project_id, certificate_key=key)
    return project_id, case_id


async def test_storage_failure_before_authorization_never_reaches_deployer(env):
    project_id, case_id = lab_case(env)
    calls = []

    def handler(path, body):
        calls.append(path)
        if path.startswith("/destinations/"):
            return destination(project_id)
        raise AssertionError("authority-changing call under storage failure: " + path)

    worker = make_worker(env, deployer=FakeRPC(handler))
    fail_audit_writes(env.store)
    with pytest.raises(sqlite3.DatabaseError):
        await worker.deployment.promote(case_id)
    assert calls == ["/destinations/" + project_id]
    restore_audit_writes(env.store)
    assert env.store.list("authorization", project_id) == []
    assert env.store.get("case", case_id)["status"] == "REVIEW_READY"


async def test_storage_failure_after_route_call_still_attempts_recovery(env):
    project_id, case_id = lab_case(env)
    calls = []

    def handler(path, body):
        calls.append(path)
        if path.startswith("/destinations/") or path == "/abort":
            return destination(project_id)
        if path == "/promote":
            # Storage dies while the deployer request is in flight and the response is lost.
            fail_audit_writes(env.store)
            raise ConnectionError("response lost")
        raise AssertionError(path)

    worker = make_worker(env, deployer=FakeRPC(handler))
    with pytest.raises(BaseException):  # noqa: B017 - storage error masks the lost response
        await worker.deployment.promote(case_id)
    assert calls.count("/promote") == 1
    assert "/abort" in calls[calls.index("/promote") :]
