"""Exercise the real service boundary, immutable GitHub intake and bounded inference."""

import asyncio
import json
from pathlib import Path

from colossus.contracts.core import new_id
from colossus.contracts.models import Enrollment
from colossus.control.artifacts import ArtifactStore
from colossus.control.broker import Broker
from colossus.control.config import Settings
from colossus.control.services import ServiceSupervisor
from colossus.control.store import Store


async def main():
    settings = Settings.from_environment()
    settings.prepare()
    services = ServiceSupervisor(settings)
    store = Store(settings.data_dir / "state.sqlite3")
    artifacts = ArtifactStore(settings.data_dir / "artifacts")
    try:
        await services.start()
        source = await services.clients["gateway"].call(
            "/source", Enrollment(repo_url="https://github.com/stamparm/DSVW").model_dump()
        )
        project_id = new_id()
        job = await services.clients["launcher"].call(
            "/run",
            {
                "project_id": project_id,
                "role": "verify",
                "files": source["files"],
                "argv": ["python", "-m", "py_compile", "dsvw.py"],
                "timeout": 60,
            },
        )
        broker = Broker(store, artifacts, services.clients["gateway"], settings.runtime)
        call_id, result = await broker.complete(
            project_id,
            new_id(),
            [
                {"role": "system", "content": "Return only a JSON object with the field status."},
                {
                    "role": "user",
                    "content": "Set status to ready. This is a small API capability check.",
                },
            ],
            max_tokens=512,
        )
        report = {
            "source": {
                key: source[key]
                for key in ("repo_url", "commit", "source_archive_sha256", "tree_sha256")
            },
            "file_count": len(source["files"]),
            "sandbox_compile": job,
            "model": {
                "call_id": call_id,
                "status": result.status,
                "reason_code": result.reason_code,
                "model_returned": result.model_returned,
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "actual_cost_micro_usd": result.actual_cost_micro_usd,
            },
            "budget": store.budget(),
        }
        out = Path("artifacts/bootstrap/service-calibration.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        if job["exit_code"] != 0 or result.status != "succeeded":
            raise SystemExit("Service calibration did not pass; inspect recorded status.")
    finally:
        await services.stop()
        store.close()


asyncio.run(main())
