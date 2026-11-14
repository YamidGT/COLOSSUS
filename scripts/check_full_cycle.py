"""DSVW-only lifecycle calibration with the standard five-minute canary window."""

import argparse
import asyncio
import json
import time
from pathlib import Path

from colossus.contracts.core import new_id
from colossus.contracts.models import Enrollment, PatchProposal
from colossus.control.artifacts import ArtifactStore
from colossus.control.broker import Broker
from colossus.control.config import Settings
from colossus.control.cycle import CycleEngine
from colossus.control.deployment import DeploymentCoordinator
from colossus.control.service import Controller
from colossus.control.services import ServiceSupervisor
from colossus.control.store import Store
from colossus.onboarding.service import Onboarding


async def main(replay_case=None):
    settings = Settings.from_environment()
    settings.prepare()
    services = ServiceSupervisor(settings)
    store = Store(settings.data_dir / "state.sqlite3")
    artifacts = ArtifactStore(settings.data_dir / "artifacts")
    receipts, project_id = [], None
    started = time.monotonic()
    try:
        await services.start()
        controller = Controller(store, settings.runtime)
        receipt = controller.enroll(
            Enrollment(
                repo_url="https://github.com/stamparm/DSVW",
                requested_ref="9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908",
            ),
            new_id(),
            "calibration",
        )
        receipts.append(receipt)
        project_id = receipt["resource_ids"]["project_id"]
        onboarding = Onboarding(
            store, artifacts, services.clients["gateway"], services.clients["launcher"]
        )
        await onboarding.run(project_id)
        print("DSVW setup ready", flush=True)
        broker = Broker(store, artifacts, services.clients["gateway"], settings.runtime)
        engine = CycleEngine(
            store, artifacts, services.clients["launcher"], broker, onboarding, settings.runtime
        )
        coordinator = DeploymentCoordinator(
            store,
            artifacts,
            services.clients["deployer"],
            services.clients["launcher"],
            onboarding,
            engine,
        )
        receipt = controller.run(project_id, new_id(), "calibration")
        receipts.append(receipt)
        cycle_id = receipt["resource_ids"]["cycle_id"]
        replay = None
        if replay_case:
            old_case = store.get("case", replay_case)
            old_candidate = store.get("candidate", old_case["candidate_id"])
            old_proposal = store.get("proposal", old_candidate["proposal_id"])
            replay = PatchProposal.model_validate(
                {k: v for k, v in old_proposal.items() if k != "revision"}
            )
        verified = await engine.run(cycle_id, replay_proposal=replay)
        print("Candidate verified; standard 300-second canary starting", flush=True)
        promotion = asyncio.create_task(coordinator.promote(verified["case_id"]))
        while not promotion.done():
            await asyncio.wait({promotion}, timeout=30)
            if not promotion.done():
                state = await services.clients["deployer"].call("/destinations/" + project_id)
                print(
                    json.dumps(
                        {
                            "deployment_status": state["status"],
                            "elapsed_seconds": round(time.monotonic() - started, 1),
                        }
                    ),
                    flush=True,
                )
        promoted = await promotion
        first_cycle_seconds = time.monotonic() - started
        routed = await services.clients["deployer"].call(
            "/request", {"project_id": project_id, "path": "/?id=1"}
        )
        assert routed["response"]["status"] == 200
        print("Promotion and mirror refresh complete; running the second cycle", flush=True)
        receipt = controller.run(project_id, new_id(), "calibration")
        receipts.append(receipt)
        second_id = receipt["resource_ids"]["cycle_id"]
        second = await engine.run(second_id)
        assert second["status"] == "NO_CHANGE", second
        onboarding.update(project_id, active_cycle_id=None)
        rollback_started = time.monotonic()
        rolled_back = await coordinator.rollback(project_id, promoted["generation"])
        recovery_seconds = time.monotonic() - rollback_started
        assert rolled_back["known_vulnerable_baseline"] is True
        case = store.get("case", verified["case_id"])
        report = {
            "repo": "stamparm/DSVW",
            "generation_mode": "replayed_proposal" if replay_case else "fresh_inference",
            "replayed_case_id": replay_case,
            "project_id": project_id,
            "cycle_id": cycle_id,
            "case_id": verified["case_id"],
            "promoted": promoted,
            "first_cycle_seconds": first_cycle_seconds,
            "second_cycle": second,
            "rollback": rolled_back,
            "recovery_seconds": recovery_seconds,
            "cost": store.budget(verified["case_id"]),
            "audit_valid": store.verify_audit(),
            "observation_seconds": settings.runtime.observation_seconds,
            "formal": "UNSUPPORTED for this Python component",
            "deployment_evidence_id": case.get("deployment_evidence_id"),
        }
        Path("artifacts/bootstrap/full-cycle.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    finally:
        if project_id and "launcher" in services.clients:
            if "deployer" in services.clients:
                await services.clients["deployer"].call("/abort", {"project_id": project_id})
            await services.clients["launcher"].call(
                "/terminate-work", {"project_id": project_id, "keep": []}
            )
            project = store.get("project", project_id)
            store.put(
                "project",
                project_id,
                project
                | {
                    "setup_state": "SETUP_FAILED",
                    "active_cycle_id": None,
                    "mirror": {"state": "STOPPED"},
                    "reason_code": "calibration_only",
                    "reason": "Lifecycle calibration ended; runtime deliberately removed",
                },
                project_id,
            )
        for receipt in receipts:
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


parser = argparse.ArgumentParser()
parser.add_argument("--replay-case")
args = parser.parse_args()
asyncio.run(main(args.replay_case))
