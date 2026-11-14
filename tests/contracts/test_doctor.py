import json
import os
import subprocess

from typer.testing import CliRunner

from colossus.cli.doctor import check_credentials, check_host, check_sandbox, overall
from colossus.cli.main import app


def test_missing_gvisor_blocks():
    (c,) = check_sandbox(
        lambda: {"ready": False, "context": "default", "reason": "gVisor runtime missing"}
    )
    assert c.state == "blocked" and "gVisor runtime missing" in c.observed


def test_ready_gvisor_ok():
    info = {
        "ready": True,
        "context": "c",
        "architecture": "aarch64",
        "cpus": 4,
        "server_version": "29",
    }
    assert check_sandbox(lambda: info)[0].state == "ok"


def test_preflight_crash_is_reported_not_raised():
    def boom():
        raise RuntimeError("daemon gone")

    assert check_sandbox(boom)[0].state == "blocked"


def test_missing_cgroup_controller_blocks(monkeypatch, tmp_path):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    checks = {c.check_id: c for c in check_host(str(tmp_path), read_text=lambda p: "cpu io")}
    assert checks["host.cgroup_v2"].state == "blocked"


def test_credentials_never_read_or_printed(tmp_path, monkeypatch):
    secret = "sk-test-DO-NOT-PRINT-123"
    env = tmp_path / ".env"
    env.write_text(f"MISTRAL_API_KEY={secret}\nGROQ_API_KEY=\n")
    os.chmod(env, 0o600)

    def forbidden_read(*args, **kwargs):
        raise AssertionError("doctor must not read provider values")

    monkeypatch.setattr("pathlib.Path.read_text", forbidden_read)
    checks = {c.check_id: c for c in check_credentials(tmp_path)}
    assert checks["credentials.mistral"].observed == "gateway check required"
    assert checks["credentials.groq"].state == "unknown"
    assert secret not in repr(checks)


def test_world_readable_env_blocks(tmp_path):
    env = tmp_path / ".env"
    env.write_text("MISTRAL_API_KEY=x\n")
    os.chmod(env, 0o644)
    checks = {c.check_id: c for c in check_credentials(tmp_path)}
    assert checks["credentials.env_permissions"].state == "blocked"
    assert overall(list(checks.values())) == "blocked"


def test_cli_doctor_json_hides_secret_and_exits_3(tmp_path, monkeypatch):
    secret = "sk-test-DO-NOT-PRINT-456"
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text(f"MISTRAL_API_KEY={secret}\n")
    os.chmod(tmp_path / ".env", 0o600)
    monkeypatch.setenv("COLOSSUS_HOME", str(tmp_path))
    monkeypatch.setenv("COLOSSUS_DOCKER_CONTEXT", "colossus-test-missing-context")
    res = CliRunner().invoke(app, ["--json", "doctor"])
    assert res.exit_code == 3
    assert secret not in res.output
    body = json.loads(res.output)
    ids = {c["check_id"]: c["state"] for c in body["checks"]}
    assert ids["sandbox.gvisor"] == "blocked"
    assert ids["repo.env_ignored"] == "ok"
    assert body["runtime_preflight"] == "blocked"
