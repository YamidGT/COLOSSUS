"""Durable recurrence and advisory coalescing; models never choose admission."""

import asyncio
import time

from colossus.contracts.core import DomainError, content_hash, utcnow
from colossus.intel.watcher import IntelWatcher


class Scheduler:
    def __init__(self, store, artifacts, gateway, controller, runtime):
        self.store, self.controller, self.runtime = store, controller, runtime
        self.intel = IntelWatcher(store, artifacts, gateway, runtime)
        self.state = "starting"

    def schedule(self, project_id, now):
        key = content_hash({"schedule": project_id})
        try:
            return key, self.store.get("schedule", key, project_id)
        except DomainError as exc:
            if exc.code != "not_found":
                raise
        stagger = int(key[:8], 16) % 60
        value = {
            "project_id": project_id,
            "next_feed_at": now,
            "next_t1_at": now + self.runtime.t1_seconds + stagger,
            "next_t2_at": now + self.runtime.t2_seconds + stagger,
            "pending_advisories": [],
            "last_error": None,
        }
        self.store.put("schedule", key, value, project_id)
        return key, value

    async def tick(self, now=None):
        now = time.time() if now is None else now
        admitted = []
        for project in self.store.list("project", limit=1000):
            pid = project["project_id"]
            if project["admission_state"] != "active" or project["setup_state"] != "READY":
                continue
            key, schedule = self.schedule(pid, now)
            if now >= schedule["next_feed_at"]:
                # Persist the next due time before I/O so restart does not hammer a failed source.
                schedule["next_feed_at"] = now + self.runtime.feed_poll_seconds
                self.store.put("schedule", key, schedule, pid)
                try:
                    result = await self.intel.refresh(project, now)
                    schedule["pending_advisories"] = sorted(
                        set(schedule["pending_advisories"]) | set(result["changed_events"])
                    )
                    schedule["last_error"] = None
                except (DomainError, ValueError, KeyError) as exc:
                    schedule["last_error"] = (
                        exc.code if isinstance(exc, DomainError) else "invalid_feed_result"
                    )
                self.store.put("schedule", key, schedule, pid)
            project = self.store.get("project", pid)
            if (
                project.get("active_cycle_id")
                or project.get("maintenance_operation_id")
                or project["admission_state"] != "active"
                or project.get("mirror", {}).get("state") != "READY"
            ):
                continue
            trigger, tier = None, None
            if schedule["pending_advisories"]:
                trigger, tier = "advisory", "T2"
                token = content_hash(schedule["pending_advisories"])
            elif now >= schedule["next_t2_at"]:
                trigger, tier, token = "schedule", "T2", str(schedule["next_t2_at"])
            elif now >= schedule["next_t1_at"]:
                trigger, tier, token = "schedule", "T1", str(schedule["next_t1_at"])
            if trigger:
                receipt = self.controller.run(
                    pid, f"recurrence:{pid}:{tier}:{token}", "scheduler", trigger, tier=tier
                )
                if "task_id" in receipt["resource_ids"]:
                    schedule["pending_advisories"] = []
                    schedule["next_t1_at"] = now + self.runtime.t1_seconds
                    if tier == "T2":
                        schedule["next_t2_at"] = now + self.runtime.t2_seconds
                    schedule["last_admitted_at"] = utcnow()
                    schedule["last_cycle_id"] = receipt["resource_ids"]["cycle_id"]
                    self.store.put("schedule", key, schedule, pid)
                    admitted.append(receipt)
        return admitted

    async def run(self, stop_event):
        while not stop_event.is_set():
            try:
                self.state = "polling"
                await self.tick()
                self.state = "idle"
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.state = "degraded"
                with self.store.transaction() as db:
                    self.store._event(
                        db, "scheduler.error", {"error_type": type(exc).__name__}, None, "scheduler"
                    )
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=5)
            except TimeoutError:
                pass
        self.state = "stopped"
