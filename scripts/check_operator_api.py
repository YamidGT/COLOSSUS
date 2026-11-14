"""Validate real API-to-worker setup using DSVW only, then tear down calibration state."""

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import httpx

from colossus.contracts.core import new_id
from colossus.control.config import Settings
from colossus.control.store import Store
from colossus.sandbox.launcher import SandboxLauncher

settings = Settings.from_environment()
settings.prepare()
port = 8789
log_path = settings.data_dir / "operator-calibration.log"
log = log_path.open("ab")
process = subprocess.Popen(
    [str(Path(".venv/bin/colossus").resolve()), "serve", "--port", str(port)],
    stdout=log,
    stderr=log,
    start_new_session=True,
)
project_id = None
headers = {"Authorization": "Bearer " + (settings.data_dir / "operator.token").read_text().strip()}
try:
    with httpx.Client(
        base_url=f"http://127.0.0.1:{port}/api/v1", headers=headers, timeout=10
    ) as client:
        for _ in range(60):
            if process.poll() is not None:
                raise RuntimeError(
                    "Controller exited before readiness; inspect local calibration log"
                )
            try:
                ready = client.get("/system/readiness").json()
                if ready.get("worker_alive"):
                    break
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("Controller worker did not become ready")
        response = client.post(
            "/projects",
            headers={"Idempotency-Key": "api-calibration-" + new_id()},
            json={
                "repo_url": "https://github.com/stamparm/DSVW",
                "requested_ref": "9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908",
            },
        )
        response.raise_for_status()
        receipt = response.json()
        project_id = receipt["resource_ids"]["project_id"]
        deadline = time.monotonic() + 90
        while True:
            snapshot = client.get(f"/projects/{project_id}/status").json()
            if snapshot["setup_state"] == "READY":
                break
            if (
                snapshot["setup_state"] in {"UNSUPPORTED", "SETUP_FAILED", "NEEDS_CONFIGURATION"}
                or time.monotonic() >= deadline
            ):
                raise RuntimeError("API onboarding failed: " + str(snapshot.get("reason")))
            time.sleep(0.5)
        operation = client.get("/operations/" + receipt["operation_id"]).json()
        assert operation["status"] == "succeeded", operation
        paused = client.post(
            f"/projects/{project_id}/pause", headers={"Idempotency-Key": new_id()}, json={}
        )
        paused.raise_for_status()
        refused = client.post(
            f"/projects/{project_id}/cycles", headers={"Idempotency-Key": new_id()}, json={}
        )
        assert refused.status_code == 409
        report = {
            "project_id": project_id,
            "setup_state": snapshot["setup_state"],
            "operation_status": operation["status"],
            "worker_alive": ready["worker_alive"],
            "paused_run_rejected": refused.status_code == 409,
            "artifact_digest": snapshot["mirror_summary"]["artifact_digest"],
            "model_calls": "none in this API setup calibration",
        }
        Path("artifacts/bootstrap/operator-api.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps(report, indent=2))
finally:
    os.killpg(process.pid, signal.SIGTERM) if process.poll() is None else None
    try:
        process.wait(timeout=40)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    log.close()
    if project_id:
        store = Store(settings.data_dir / "state.sqlite3")
        project = store.get("project", project_id)
        mirror = project.get("mirror", {})
        if mirror.get("environment_id"):
            launcher = SandboxLauncher(settings.docker_context)
            launcher.destroy(mirror["environment_id"])
            launcher.destroy_network(mirror["network_id"], project_id)
        store.put(
            "project",
            project_id,
            project
            | {
                "setup_state": "SETUP_FAILED",
                "mirror": {"state": "STOPPED"},
                "reason_code": "calibration_only",
                "reason": "API calibration completed; runtime deliberately removed",
            },
            project_id,
        )
        store.close()
