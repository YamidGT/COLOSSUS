"""Read-only feed calibration against an already enrolled DSVW manifest."""

import asyncio
import json
from pathlib import Path

from colossus.control.artifacts import ArtifactStore
from colossus.control.config import Settings
from colossus.control.services import ServiceSupervisor
from colossus.control.store import Store
from colossus.intel.watcher import IntelWatcher


async def main():
    settings = Settings.from_environment()
    store = Store(settings.data_dir / "state.sqlite3")
    artifacts = ArtifactStore(settings.data_dir / "artifacts")
    services = ServiceSupervisor(settings)
    project = next(
        p
        for p in store.list("project")
        if p["repo_url"] == "https://github.com/stamparm/DSVW"
        and p.get("source", {}).get("manifest_hash")
    )
    try:
        await services.start()
        watcher = IntelWatcher(store, artifacts, services.clients["gateway"], settings.runtime)
        live = await watcher.refresh(project)
        snapshot = json.loads(artifacts.get(live["snapshot_id"]))
        replay = watcher.ingest(
            project["project_id"], project["source"]["manifest_hash"], snapshot, replay=True
        )
        report = {
            "repo": "stamparm/DSVW",
            "target_started": False,
            "model_calls": 0,
            "live": live,
            "replay_event_count": len(replay["events"]),
            "feeds": [
                {k: v for k, v in feed.items() if k not in {"data", "raw_base64"}}
                for feed in snapshot["feeds"]
            ],
        }
        output = Path("artifacts/bootstrap/intel.json")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        await services.stop()
        store.close()


asyncio.run(main())
