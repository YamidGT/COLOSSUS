import base64
import json

import pytest

from colossus.contracts.core import DomainError, digest
from colossus.contracts.models import Enrollment
from colossus.contracts.runtime import RuntimeConfig
from colossus.control.artifacts import ArtifactStore
from colossus.control.scheduler import Scheduler
from colossus.control.service import Controller
from colossus.control.store import Store
from colossus.intel.watcher import IntelWatcher


def result(*, unavailable=False):
    raw = json.dumps({"id": "GHSA-test", "aliases": ["CVE-2026-1000"]}).encode()
    return {
        "feeds": [
            {
                "source": "osv",
                "status": "unavailable" if unavailable else "fresh",
                "fetched_at": "2026-11-14T00:00:00Z",
                "error": "offline" if unavailable else None,
                "raw_content_hash": digest(raw),
                "raw_base64": base64.b64encode(raw).decode(),
            }
        ],
        "events": []
        if unavailable
        else [
            {
                "source": "osv",
                "source_url": "https://api.osv.dev/v1/vulns/GHSA-test",
                "raw_content_hash": digest(raw),
                "fetched_at": "2026-11-14T00:00:00Z",
                "advisory_id": "GHSA-test",
                "aliases": ["CVE-2026-1000"],
                "package": "example",
                "ecosystem": "PyPI",
                "version": "1.0",
                "affected_status": "affected",
            }
        ],
        "incomplete": ["offline"] if unavailable else [],
    }


@pytest.fixture
def platform(tmp_path):
    store = Store(tmp_path / "state.sqlite")
    artifacts = ArtifactStore(tmp_path / "artifacts")
    runtime = RuntimeConfig(feed_poll_seconds=60, t1_seconds=120, t2_seconds=240)
    controller = Controller(store, runtime)
    receipt = controller.enroll(
        Enrollment(repo_url="https://github.com/stamparm/DSVW"), "enroll", "test"
    )
    pid = receipt["resource_ids"]["project_id"]
    inventory = artifacts.put(json.dumps({"packages": [], "scope": "stdlib-only runtime"}).encode())
    manifest = artifacts.put(json.dumps({"dependency_inventory_hash": inventory}).encode())
    p = store.get("project", pid)
    store.put(
        "project",
        pid,
        p
        | {
            "setup_state": "READY",
            "mirror": {"state": "READY"},
            "source": {"manifest_hash": manifest},
        },
        pid,
    )
    yield store, artifacts, runtime, controller, pid
    store.close()


def test_feed_snapshot_replay_is_identical_without_admission_or_live_state_writes(platform):
    store, artifacts, runtime, _, pid = platform
    watcher = IntelWatcher(store, artifacts, None, runtime)
    first = watcher.ingest(pid, "a" * 64, result(), now=1000)
    assert len(first["changed_events"]) == 1
    assert watcher.ingest(pid, "a" * 64, result(), now=1010)["changed_events"] == []
    before = store.list("feed", pid)
    replay = watcher.ingest(
        pid, "a" * 64, json.loads(artifacts.get(first["snapshot_id"])), replay=True
    )
    assert replay["events"][0]["replay"] is True and replay["trigger"] is None
    assert store.list("feed", pid) == before
    broken = result()
    broken["feeds"][0]["raw_base64"] = base64.b64encode(b"corrupt").decode()
    with pytest.raises(DomainError, match="hash"):
        watcher.ingest(pid, "a" * 64, broken)


def test_outage_retains_last_good_snapshot_and_project_scopes_freshness(platform):
    store, artifacts, runtime, controller, pid = platform
    watcher = IntelWatcher(store, artifacts, None, runtime)
    first = watcher.ingest(pid, "a" * 64, result(), now=1000)
    watcher.ingest(pid, "a" * 64, result(unavailable=True), now=1100)
    feed = store.list("feed", pid)[0]
    assert feed["status"] == "stale" and feed["last_success_snapshot_id"] == first["snapshot_id"]
    assert feed["age_seconds"] == 100 and store.list("intel_event", pid)
    assert controller.feed_freshness("unrelated") == []


@pytest.mark.asyncio
async def test_advisory_trigger_is_coalesced_while_busy_and_survives_scheduler_restart(platform):
    store, artifacts, runtime, controller, pid = platform

    class Gateway:
        calls = 0

        async def call(self, path, payload):
            assert path == "/intel" and payload == {"pins": []}
            self.calls += 1
            return result()

    gateway = Gateway()
    manual = controller.run(pid, "manual", "test")
    first = Scheduler(store, artifacts, gateway, controller, runtime)
    assert await first.tick(1000) == []
    assert gateway.calls == 1
    p = store.get("project", pid)
    store.put("project", pid, p | {"active_cycle_id": None}, pid)
    restarted = Scheduler(store, artifacts, gateway, controller, runtime)
    admitted = await restarted.tick(1010)
    assert len(admitted) == 1 and gateway.calls == 1
    cycle = store.get("cycle", admitted[0]["resource_ids"]["cycle_id"])
    assert cycle["tier"] == "T2" and cycle["trigger"] == "advisory"
    assert cycle["cycle_id"] != manual["resource_ids"]["cycle_id"]
    assert await restarted.tick(1011) == []


@pytest.mark.asyncio
async def test_paused_project_has_no_polling_or_recurring_admission(platform):
    store, artifacts, runtime, controller, pid = platform
    controller.admission(pid, True, "pause", "test")
    scheduler = Scheduler(store, artifacts, None, controller, runtime)
    assert await scheduler.tick(1000) == []
    assert store.list("schedule", pid) == []


@pytest.mark.asyncio
async def test_periodic_review_uses_persisted_deadline_and_does_not_run_immediately(platform):
    store, artifacts, runtime, controller, pid = platform

    class Gateway:
        async def call(self, path, payload):
            return {"feeds": [], "events": [], "incomplete": []}

    scheduler = Scheduler(store, artifacts, Gateway(), controller, runtime)
    assert await scheduler.tick(1000) == []
    schedule = store.list("schedule", pid)[0]
    admitted = await scheduler.tick(schedule["next_t1_at"])
    assert len(admitted) == 1
    assert store.get("cycle", admitted[0]["resource_ids"]["cycle_id"])["tier"] == "T1"
