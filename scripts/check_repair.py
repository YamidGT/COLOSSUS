"""One DSVW repair case, real model and sandbox gates; no multi-repo campaign."""

import asyncio
import json
import time
from pathlib import Path

from colossus.contracts.core import new_id
from colossus.contracts.models import Enrollment
from colossus.control.artifacts import ArtifactStore
from colossus.control.broker import Broker
from colossus.control.config import Settings
from colossus.control.cycle import CycleEngine
from colossus.control.service import Controller
from colossus.control.services import ServiceSupervisor
from colossus.control.store import Store
from colossus.onboarding.service import Onboarding


async def main():
    started = time.monotonic()
    settings = Settings.from_environment()
    settings.prepare()
    services = ServiceSupervisor(settings)
    store = Store(settings.data_dir / "state.sqlite3")
    artifacts = ArtifactStore(settings.data_dir / "artifacts")
    project_id, cycle_id = None, None
    receipts = []
    try:
        await services.start()
        controller = Controller(store, settings.runtime)
        receipt = controller.enroll(
            Enrollment(
                repo_url="https://github.com/stamparm/DSVW",
                requested_ref="9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908",
                owner_policy_id="review-v1",
            ),
            "repair-calibration-" + new_id(),
            "calibration",
        )
        receipts.append(receipt)
        project_id = receipt["resource_ids"]["project_id"]
        onboarding = Onboarding(
            store, artifacts, services.clients["gateway"], services.clients["launcher"]
        )
        await onboarding.run(project_id)
        print("DSVW setup ready; starting one bounded repair case", flush=True)
        receipt = controller.run(project_id, new_id(), "calibration")
        receipts.append(receipt)
        cycle_id = receipt["resource_ids"]["cycle_id"]
        broker = Broker(store, artifacts, services.clients["gateway"], settings.runtime)
        engine = CycleEngine(
            store, artifacts, services.clients["launcher"], broker, onboarding, settings.runtime
        )
        result = await engine.run(cycle_id)
        case = store.get("case", result["case_id"])
        report = {
            "result": result,
            "case": case,
            "cycle_id": cycle_id,
            "project_id": project_id,
            "elapsed_seconds": time.monotonic() - started,
            "budget": store.budget(case["case_id"]),
            "audit_valid": store.verify_audit(),
            "deployment": "not_attempted; review profile calibration",
        }
        out = Path("artifacts/bootstrap/repair.json")
        out.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k != "case"}, indent=2))
        print(
            json.dumps(
                {
                    "gates": [
                        {
                            "check": g["check_profile_id"],
                            "status": g["status"],
                            "proof_outcome": g["proof_outcome"],
                        }
                        for g in case["gate_results"]
                    ]
                },
                indent=2,
            )
        )
    finally:
        if project_id and "launcher" in services.clients:
            mirror = store.get("project", project_id).get("mirror", {})
            if mirror.get("environment_id"):
                await services.clients["launcher"].call(
                    "/targets/stop",
                    {k: mirror[k] for k in ("project_id", "environment_id", "network_id")},
                )
                onboarding.update(
                    project_id,
                    mirror={"state": "STOPPED", "reason": "Calibration teardown"},
                    active_cycle_id=None,
                    setup_state="SETUP_FAILED",
                    reason_code="calibration_only",
                    reason="Calibration finished; runtime deliberately removed",
                )
        for receipt in receipts:
            store.finish_operation(
                receipt["operation_id"],
                "succeeded"
                if cycle_id and store.get("cycle", cycle_id)["status"] == "REVIEW_READY"
                else "failed",
                "calibration_teardown",
            )
            with store.transaction() as db:
                db.execute(
                    "UPDATE tasks SET state='cancelled',result=? WHERE id=? AND state='queued'",
                    (
                        json.dumps({"reason": "executed_by_calibration_script"}),
                        receipt["resource_ids"].get("task_id"),
                    ),
                )
        await services.stop()
        store.close()


asyncio.run(main())
