"""Shared fakes for controller fault-injection tests. No network, docker or model calls."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from colossus.contracts.core import content_hash, new_id, utcnow
from colossus.contracts.models import Authorization, EvidenceManifest, GateResult, TargetManifest
from colossus.contracts.runtime import RuntimeConfig
from colossus.control.artifacts import ArtifactStore
from colossus.control.service import Controller
from colossus.control.store import Store
from colossus.verification.policy import REQUIRED_CHECKS

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class FakeRPC:
    """Records every call; `handler(path, body)` returns the response or raises."""

    def __init__(self, handler=None):
        self.calls: list[tuple[str, dict | None]] = []
        self.handler = handler or (lambda path, body: {})

    async def call(self, path, body=None):
        self.calls.append((path, body))
        return self.handler(path, body)

    def paths(self):
        return [path for path, _ in self.calls]


def destination(project_id, generation=0, digest=DIGEST_A, env="env-a", previous=None):
    return {
        "project_id": project_id,
        "deployment_id": "dep-" + str(generation),
        "generation": generation,
        "status": "PROMOTED" if generation else "BASELINE",
        "current": {
            "project_id": project_id,
            "environment_id": env,
            "network_id": "net-" + env,
            "artifact_digest": digest,
            "known_vulnerable_baseline": generation == 0,
        },
        "previous": previous,
        "intent": None,
    }


def make_deployer(state_ref: dict):
    """A deployer fake whose observed state is whatever `state_ref['state']` holds."""

    def handler(path, body):
        if path == "/destinations":
            return [state_ref["state"]]
        if path.startswith("/destinations/") or path == "/abort":
            return state_ref["state"]
        if path == "/promote":
            raise AssertionError("controller replayed a promotion")
        raise AssertionError(path)

    return FakeRPC(handler)


@pytest.fixture
def env(tmp_path):
    store = Store(tmp_path / "state.db")
    artifacts = ArtifactStore(tmp_path / "artifacts")
    runtime = RuntimeConfig()
    controller = Controller(store, runtime)
    ns = SimpleNamespace(
        tmp_path=tmp_path,
        store=store,
        artifacts=artifacts,
        runtime=runtime,
        controller=controller,
    )
    yield ns
    store.close()


def ready_project(store, owner_policy_id="review-v1", manifest_hash="a" * 64):
    project_id = new_id()
    store.put(
        "project",
        project_id,
        dict(
            project_id=project_id,
            display_name="owner/repo",
            repo_url="https://github.com/owner/repo",
            requested_ref=None,
            subdir=None,
            setup_state="READY",
            admission_state="active",
            created_at=utcnow(),
            source={"manifest_hash": manifest_hash, "source_id": "s" * 64},
            mirror={
                "state": "READY",
                "project_id": project_id,
                "environment_id": "env-a",
                "network_id": "net-env-a",
                "artifact_digest": DIGEST_A,
            },
            deployment={},
            active_cycle_id=None,
            owner_policy_id=owner_policy_id,
            deployment_profile_id="local-web-v1",
            assurance_profile="tested",
            requirement_ids=[],
            start_cycle=False,
            reason=None,
            reason_code=None,
        ),
        project_id,
    )
    return project_id


def make_worker(env, deployer=None, launcher=None, gateway=None):
    from colossus.control.worker import Worker

    services = SimpleNamespace(
        clients={
            "gateway": gateway or FakeRPC(),
            "launcher": launcher or FakeRPC(),
            "deployer": deployer or FakeRPC(lambda path, body: {"current": None}),
        }
    )
    return Worker(env.store, env.artifacts, services, env.controller, env.runtime)


def task_count(store, state=None):
    sql, args = "SELECT COUNT(*) FROM tasks", ()
    if state:
        sql, args = sql + " WHERE state=?", (state,)
    with store.lock:
        return store.connection.execute(sql, args).fetchone()[0]


def task_row(store, task_id):
    with store.lock:
        return dict(
            store.connection.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        )


def expire_lease(store, task_id):
    with store.lock:
        store.connection.execute(
            "UPDATE tasks SET lease_expires=? WHERE id=?", (time.time() - 1, task_id)
        )


def fail_audit_writes(store):
    """Inject a storage fault: every audit append aborts its transaction."""
    with store.lock:
        store.connection.execute(
            "CREATE TRIGGER inject_audit_fault BEFORE INSERT ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'injected audit storage failure'); END"
        )


def restore_audit_writes(store):
    with store.lock:
        store.connection.execute("DROP TRIGGER IF EXISTS inject_audit_fault")


def authority_inputs(tree="a" * 64, baseline=None, generation=0):
    """Valid deployer inputs (mirrors tests/deployment/test_authority.py)."""
    project_id, case_id, candidate_id = new_id(), new_id(), new_id()
    manifest = TargetManifest(
        manifest_id=new_id(),
        revision=1,
        project_id=project_id,
        repo_url="https://github.com/stamparm/DSVW",
        commit="a" * 40,
        tree_sha256=tree,
        platform="linux/arm64",
        target_kind="web",
        recipe_id="dsvw-python-v1",
        recipe_hash="b" * 64,
        artifact_digest=DIGEST_A,
        services=[
            {
                "service_id": "app",
                "artifact_digest": DIGEST_A,
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

    def gate(profile, category, status, **extra):
        return GateResult(
            gate_id=new_id(),
            case_id=case_id,
            candidate_id=candidate_id,
            candidate_hash="b" * 64,
            check_profile_id=profile,
            category=category,
            status=status,
            scope=["test"],
            tool_version="1",
            command_profile_hash="a" * 64,
            started_at=now.isoformat(),
            finished_at=now.isoformat(),
            evidence_ids=[],
            **extra,
        )

    gates = [gate(profile, "policy", "pass") for profile in REQUIRED_CHECKS]
    gates.append(gate("formal", "formal", "not_applicable", proof_outcome="UNSUPPORTED"))
    certificate = make_certificate(
        case_id=case_id,
        baseline_hash=baseline or tree,
        target_manifest_hash=content_hash(manifest.model_dump()),
        policy_hash=manifest.policy_hash,
        required_gate_ids=[g.gate_id for g in gates[:-1]],
        gate_result_ids=[g.gate_id for g in gates],
    )
    authorization = make_authorization(project_id, certificate, generation)
    return authorization, certificate, manifest, gates


def make_certificate(**fields):
    data = (
        dict(
            manifest_id=new_id(),
            case_id=new_id(),
            baseline_hash="a" * 64,
            candidate_hash="b" * 64,
            artifact_digest=DIGEST_B,
            diff_hash="d" * 64,
            target_manifest_hash="a" * 64,
            policy_hash="c" * 64,
            spec_hashes=[],
            harness_hashes=[],
            test_hashes=[],
            required_gate_ids=[],
            gate_result_ids=[],
            assurance_profile="tested",
            proof_summary=[],
            exclusions=["No formal proof"],
            model_call_ids=[],
            total_cost_micro_usd=0,
            issued_at=datetime.now(UTC).isoformat(),
        )
        | fields
    )
    return EvidenceManifest(**data, content_hash=content_hash(data))


def make_authorization(project_id, certificate, generation=0):
    now = datetime.now(UTC)
    return Authorization(
        authorization_id=new_id(),
        project_id=project_id,
        evidence_manifest_hash=content_hash(certificate.model_dump()),
        destination_id="local-web-v1",
        expected_deployment_generation=generation,
        mode="preauthorized_policy",
        actor_or_policy_id="lab-auto-v1",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=30)).isoformat(),
    )


def restart(env):
    """Simulate a controller process restart: drop the connection, reopen the same SQLite file."""
    env.store.close()
    env.store = Store(env.tmp_path / "state.db")
    env.controller = Controller(env.store, env.runtime)
    return env


def settle_queued_cycle_task(store):
    """Mark the queued cycle task as already run so a later promote task is next in line."""
    with store.lock:
        store.connection.execute(
            "UPDATE tasks SET state='succeeded',result='{}' WHERE kind='cycle' AND state='queued'"
        )


def review_ready_case(env, project_id, certificate_key="e" * 64, generation=0):
    """Start a cycle and attach a REVIEW_READY case to it, as the cycle engine would."""
    receipt = env.controller.run(project_id, "run-" + new_id(), "operator")
    cycle_id = receipt["resource_ids"]["cycle_id"]
    settle_queued_cycle_task(env.store)
    case_id = new_id()
    env.store.put(
        "case",
        case_id,
        dict(
            case_id=case_id,
            project_id=project_id,
            cycle_id=cycle_id,
            status="REVIEW_READY",
            title="fault case",
            candidate_id="cand-1",
            candidate_source_id="c" * 64,
            evidence_manifest_hash=certificate_key,
            expected_deployment_generation=generation,
            destination_id="local-web-v1",
            created_at=utcnow(),
        ),
        project_id,
    )
    return cycle_id, case_id


def approval(store, case_id):
    case = store.get("case", case_id)
    return {
        "expected_revision": case["revision"],
        "candidate_id": case["candidate_id"],
        "evidence_manifest_hash": case["evidence_manifest_hash"],
        "expected_deployment_generation": case["expected_deployment_generation"],
    }


def reserve_worker(
    path,
    barrier,
    results,
    worker_index,
    attempts,
    amount,
    global_cap,
    case_cap,
    max_calls,
    same_case,
):
    """Child-process body for the cross-process budget race (must be importable for spawn)."""
    from pathlib import Path

    from colossus.contracts.core import DomainError

    store = Store(Path(path))
    accepted = 0
    barrier.wait()
    for attempt in range(attempts):
        case_id = "case-shared" if same_case else f"case-{worker_index}-{attempt}"
        try:
            store.reserve(new_id(), case_id, amount, global_cap, case_cap, max_calls)
            accepted += 1
        except DomainError as exc:
            assert exc.code == "budget_stop"
    store.close()
    results.put(accepted)


class RecordingLauncher:
    """Launcher fake for LabDeployer: creates and stops slots, nothing else."""

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
