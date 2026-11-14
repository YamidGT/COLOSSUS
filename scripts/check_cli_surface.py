"""Exercise the real CLI against recorded runtime evidence, without starting target work."""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from colossus.control.config import Settings
from colossus.control.store import Store


def main():
    settings = Settings.from_environment()
    store = Store(settings.data_dir / "state.sqlite3")
    cases = [
        c for c in store.list("case", limit=1000) if c.get("candidate_id") and c.get("diff_ref")
    ]
    case = max(cases, key=lambda c: c["created_at"])
    store.close()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="colossus-cli-check-") as directory:
        logs = Path(directory) / "server.log"
        with logs.open("wb") as stream:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import uvicorn; from colossus.control.api import create_app; "
                    f"uvicorn.run(create_app(execute_tasks=False), host='127.0.0.1', port={port}, access_log=False)",
                ],
                stdout=stream,
                stderr=stream,
                start_new_session=True,
            )
        results = []
        try:
            with httpx.Client(trust_env=False, timeout=1) as client:
                for _ in range(50):
                    if process.poll() is not None:
                        raise RuntimeError("Read-only operator API did not start")
                    try:
                        if client.get(url + "/api/v1/projects").status_code == 401:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Read-only operator API readiness expired")
            output = Path(directory) / "report.json"
            commands = [
                ["projects"],
                ["status", case["project_id"]],
                ["actions", case["project_id"]],
                ["case", case["case_id"], "--diff"],
                ["report", case["cycle_id"], "--output", str(output)],
                ["ui", "--no-open"],
            ]
            for args in commands:
                run = subprocess.run(
                    [
                        str(Path(".venv/bin/colossus").resolve()),
                        "--api-url",
                        url,
                        "--json",
                        *args,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                value = json.loads(run.stdout)
                assert run.returncode == 0 and value["ok"], (args[0], run.returncode)
                results.append(
                    {
                        "command": args[0],
                        "exit_code": run.returncode,
                        "status": value["status"],
                        "one_json_envelope": True,
                    }
                )
                if args[0] == "case":
                    assert value["data"]["diff"]["artifact_id"] == case["diff_ref"]
            report = json.loads(output.read_text())
            assert report["cycle"]["cycle_id"] == case["cycle_id"]
            summary = {
                "kind": "live_cli_against_operator_api_and_existing_runtime_evidence",
                "case_id": case["case_id"],
                "project_id": case["project_id"],
                "commands": results,
                "artifact_binding": True,
                "report_binding": True,
                "target_jobs_started": 0,
                "model_calls": 0,
                "limitations": [
                    "API dispatch disabled in this check; lifecycle execution is measured separately",
                    "One-use browser code deliberately omitted from evidence",
                ],
            }
            destination = Path("evaluation/submission/cli-smoke.json")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps(summary, indent=2))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


if __name__ == "__main__":
    main()
