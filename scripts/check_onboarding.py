"""Run one real DSVW setup; leave no running target after evidence export."""

import asyncio
import json
from pathlib import Path

from colossus.contracts.models import Enrollment
from colossus.control.artifacts import ArtifactStore
from colossus.control.config import Settings
from colossus.control.service import Controller
from colossus.control.services import ServiceSupervisor
from colossus.control.store import Store
from colossus.onboarding.service import Onboarding


async def main():
    settings = Settings.from_environment()
    settings.prepare()
    services = ServiceSupervisor(settings)
    store = Store(settings.data_dir / "state.sqlite3")
    artifacts = ArtifactStore(settings.data_dir / "artifacts")
    project_id = None
    try:
        await services.start()
        controller = Controller(store, settings.runtime)
        receipt = controller.enroll(
            Enrollment(
                repo_url="https://github.com/stamparm/DSVW",
                requested_ref="9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908",
            ),
            "calibration-onboard-v1",
            "calibration",
        )
        project_id = receipt["resource_ids"]["project_id"]
        service = Onboarding(
            store, artifacts, services.clients["gateway"], services.clients["launcher"]
        )
        result = await service.run(project_id)
        snapshot = controller.snapshot(project_id)
        report = {"result": result, "snapshot": snapshot, "audit_chain_valid": store.verify_audit()}
        out = Path("artifacts/bootstrap/onboarding.json")
        out.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        if project_id and "launcher" in services.clients:
            project = store.get("project", project_id)
            mirror = project.get("mirror", {})
            if mirror.get("environment_id"):
                await services.clients["launcher"].call(
                    "/targets/stop",
                    {k: mirror[k] for k in ("project_id", "environment_id", "network_id")},
                )
                service.update(
                    project_id,
                    mirror={"state": "STOPPED", "reason": "Calibration teardown"},
                    setup_state="SETUP_FAILED",
                    reason_code="calibration_only",
                    reason="Calibration completed; runtime deliberately removed",
                )
        await services.stop()
        store.close()


asyncio.run(main())
