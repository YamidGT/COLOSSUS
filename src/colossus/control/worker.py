"""Single heavy-work dispatcher with leases, bounded execution and restart reconciliation."""

import asyncio
import json
import time

from colossus.contracts.core import DomainError, new_id, utcnow
from colossus.control.broker import Broker
from colossus.control.cycle import CycleEngine
from colossus.onboarding.service import Onboarding


class Worker:
    def __init__(self, store, artifacts, services, controller, runtime):
        self.store, self.services, self.controller, self.runtime = (
            store,
            services,
            controller,
            runtime,
        )
        self.owner = new_id()
        self.onboarding = Onboarding(
            store, artifacts, services.clients["gateway"], services.clients["launcher"]
        )
        self.broker = Broker(store, artifacts, services.clients["gateway"], runtime)
        self.engine = CycleEngine(
            store, artifacts, services.clients["launcher"], self.broker, self.onboarding, runtime
        )
        self.state = "starting"
        self.current_task_id = None
        self.stop_event = asyncio.Event()

    async def terminate(self, project_id):
        project = self.store.get("project", project_id)
        keep = [
            v["environment_id"]
            for v in (project.get("mirror", {}), project.get("deployment", {}))
            if v.get("environment_id")
        ]
        return await self.services.clients["launcher"].call(
            "/terminate-work", {"project_id": project_id, "keep": keep}
        )

    async def reconcile(self):
        with self.store.lock:
            tasks = [
                dict(r)
                for r in self.store.connection.execute(
                    "SELECT * FROM tasks WHERE state='running'"
                ).fetchall()
            ]
        for task in tasks:
            # Fail closed after a controller crash. Do not replay a deployment or inference call.
            await self.terminate(task["project_id"])
            task["payload"] = json.loads(task["payload"])
            await self.failed(
                task,
                "controller_restarted",
                "Prior worker interrupted; isolated jobs terminated and explicit retry required",
            )
            with self.store.transaction() as db:
                db.execute(
                    "UPDATE tasks SET state='failed',lease_expires=NULL,result=? WHERE id=? AND state='running'",
                    (
                        json.dumps(
                            {"reason": "controller_restarted", "termination_confirmed": True}
                        ),
                        task["id"],
                    ),
                )
        for call in self.store.list("model_call", limit=1000):
            if call["status"] in {"reserved", "in_flight"}:
                self.store.reconcile(call["call_id"], None)
                with self.store.lock:
                    project_id = self.store.connection.execute(
                        "SELECT project_id FROM records WHERE id=?", (call["call_id"],)
                    ).fetchone()[0]
                self.store.put(
                    "model_call",
                    call["call_id"],
                    call | {"status": "uncertain", "reason_code": "controller_restarted"},
                    project_id,
                )
        self.state = "idle"

    async def failed(self, task, code, message):
        project_id, payload = task["project_id"], task["payload"]
        if task["kind"] == "onboard":
            state = {
                "unsupported_stack": "UNSUPPORTED",
                "needs_configuration": "NEEDS_CONFIGURATION",
            }.get(code, "SETUP_FAILED")
            self.onboarding.update(project_id, setup_state=state, reason_code=code, reason=message)
        elif payload.get("cycle_id"):
            state = {
                "cancelled": "CANCELLED",
                "cycle_timeout": "TIMEOUT",
                "budget_stop": "BUDGET_STOP",
                "repair_exhausted": "REJECTED",
            }.get(code, "INFRA_FAILED")
            self.engine.update_cycle(
                payload["cycle_id"], status=state, reason=message, finished_at=utcnow()
            )
            self.onboarding.update(project_id, active_cycle_id=None)
        self.store.finish_operation(payload["operation_id"], "failed", code)

    async def execute(self, task):
        payload = task["payload"]
        if task["kind"] == "onboard":
            result = await self.onboarding.run(task["project_id"])
            project = self.store.get("project", task["project_id"])
            if project["start_cycle"] and project["admission_state"] == "active":
                self.controller.run(
                    task["project_id"], "onboard-cycle:" + task["id"], "scheduler", "source"
                )
            return result
        if task["kind"] == "cycle":
            result = await self.engine.run(payload["cycle_id"])
            if result["status"] == "NO_CHANGE":
                self.onboarding.update(task["project_id"], active_cycle_id=None)
            return result
        raise DomainError("unsupported_task", "Task executor is not installed", 422)

    async def process(self, task):
        self.current_task_id, self.state = task["id"], "running"
        self.store.finish_operation(task["payload"]["operation_id"], "running")
        work = asyncio.create_task(self.execute(task))
        try:
            while not work.done():
                await asyncio.wait({work}, timeout=2)
                if work.done():
                    break
                if not self.store.heartbeat(task["id"], self.owner, task["attempt"]):
                    raise DomainError("cycle_timeout", "Task lease or deadline expired", 409)
                if self.stop_event.is_set():
                    raise DomainError("controller_stopping", "Controller is stopping", 503)
                if task["payload"].get("cycle_id"):
                    self.engine.check_cancel(task["payload"]["cycle_id"])
            result = await work
            self.store.complete_task(task["id"], self.owner, task["attempt"], result, True)
            self.store.finish_operation(task["payload"]["operation_id"], "succeeded")
        except BaseException as exc:
            code = exc.code if isinstance(exc, DomainError) else "execution_failed"
            message = (
                exc.message
                if isinstance(exc, DomainError)
                else "Execution failed; inspect controller audit"
            )
            if not work.done():
                work.cancel()
                try:
                    await asyncio.wait_for(work, timeout=20)
                except BaseException:
                    pass
            await self.terminate(task["project_id"])
            await self.failed(task, code, message)
            try:
                self.store.complete_task(
                    task["id"],
                    self.owner,
                    task["attempt"],
                    {"reason": code, "termination_confirmed": True},
                    False,
                )
            except DomainError:
                # Expired attempts may only be settled after termination is established.
                with self.store.transaction() as db:
                    db.execute(
                        "UPDATE tasks SET state='failed',lease_expires=NULL,result=? WHERE id=? AND attempt=? AND lease_owner=? AND state='running'",
                        (
                            json.dumps({"reason": code, "termination_confirmed": True}),
                            task["id"],
                            task["attempt"],
                            self.owner,
                        ),
                    )
                    self.store._event(
                        db,
                        "task.terminated",
                        {"task_id": task["id"], "reason": code},
                        task["project_id"],
                        self.owner,
                    )
            if isinstance(exc, asyncio.CancelledError):
                raise
        finally:
            self.current_task_id, self.state = None, "idle"

    async def run(self):
        await self.reconcile()
        last_reap = 0
        while not self.stop_event.is_set():
            if time.monotonic() - last_reap >= self.runtime.reaper_seconds:
                await self.services.clients["launcher"].call("/reap", {})
                last_reap = time.monotonic()
            task = self.store.claim(self.owner)
            if task:
                await self.process(task)
            else:
                try:
                    await asyncio.wait_for(self.stop_event.wait(), timeout=0.5)
                except TimeoutError:
                    pass
        self.state = "stopped"
