"""Exercise real Python dependency/setup RPCs with owned source; no extra public repo."""

import asyncio
import base64
import json
import tempfile
import time
from pathlib import Path

from colossus.contracts.core import new_id
from colossus.contracts.models import Enrollment
from colossus.control.artifacts import ArtifactStore
from colossus.control.config import Settings
from colossus.control.cycle import CycleEngine
from colossus.control.service import Controller
from colossus.control.services import ServiceSupervisor
from colossus.control.store import Store
from colossus.gateway.source import tree_hash
from colossus.onboarding.service import Onboarding


class OwnedSource:
    async def call(self, path, body):
        assert path == "/source"
        files = {
            name: Path("fixtures/onboarding", name).read_bytes()
            for name in ("app.py", "requirements.txt")
        }
        return {
            "files": {name: base64.b64encode(data).decode() for name, data in files.items()},
            "commit": "0" * 40,
            "tree_sha256": tree_hash(files),
            "origin": "owned_fixture; zero commit is a test identifier, not a GitHub revision",
        }


async def main():
    with tempfile.TemporaryDirectory(prefix="colossus-py-") as directory:
        settings = Settings(data_dir=Path(directory))
        settings.prepare()
        supervisor = ServiceSupervisor(settings)
        store = Store(settings.data_dir / "state.sqlite3")
        artifacts = ArtifactStore(settings.data_dir / "artifacts")
        controller = Controller(store, settings.runtime)
        target = None
        try:
            await supervisor.start()
            enrollment = Enrollment(
                repo_url="https://github.com/colossus-fixtures/python-setup",
                requested_ref="0" * 40,
                start_cycle=False,
            )
            receipt = controller.enroll(enrollment, new_id(), "owned-fixture-calibration")
            project_id = receipt["resource_ids"]["project_id"]
            onboarding = Onboarding(store, artifacts, OwnedSource(), supervisor.clients["launcher"])
            started = time.monotonic()
            await onboarding.run(project_id)
            project = store.get("project", project_id)
            target = project["mirror"]
            source = json.loads(artifacts.get(project["source"]["source_id"]))
            manifest = json.loads(artifacts.get(project["source"]["manifest_hash"]))
            inventory = json.loads(artifacts.get(manifest["dependency_inventory_hash"]))
            response = await supervisor.clients["launcher"].call(
                "/targets/request",
                {
                    "project_id": project_id,
                    "environment_id": target["environment_id"],
                    "port": 5000,
                    "path": "/",
                },
            )
            assert response["status"] == 200 and "initialized" in response["body"]
            assert len(inventory["packages"]) >= 7 and source["runtime_files"]
            assert "requirements.txt" in manifest["protected_paths"]
            assert project["setup_state"] == "READY"
            cycle_receipt = controller.run(project_id, new_id(), "owned-fixture-calibration")
            cycle_id = cycle_receipt["resource_ids"]["cycle_id"]
            cycle = await CycleEngine(
                store, artifacts, supervisor.clients["launcher"], None, onboarding, settings.runtime
            ).run(cycle_id)
            assert cycle["status"] == "NO_CHANGE" and cycle["coverage"]["repair"] == "UNSUPPORTED"
            report = {
                "kind": "owned_source_integration_fixture",
                "source_gateway": "fixture",
                "target_repositories_run": [],
                "model_calls": 0,
                "seconds": time.monotonic() - started,
                "manifest": manifest,
                "inventory": inventory,
                "response": response,
                "audit_valid": store.verify_audit(),
                "observation_cycle": cycle,
            }
            Path("artifacts/bootstrap/python-setup.json").write_text(
                json.dumps(report, indent=2) + "\n"
            )
            print(
                json.dumps(
                    {key: report[key] for key in ("kind", "seconds", "inventory", "audit_valid")},
                    indent=2,
                )
            )
        finally:
            if target:
                await supervisor.clients["launcher"].call(
                    "/targets/stop",
                    {key: target[key] for key in ("project_id", "environment_id", "network_id")},
                )
            await supervisor.stop()
            store.close()


if __name__ == "__main__":
    asyncio.run(main())
