import json
import os
import subprocess

from typer.testing import CliRunner

from colossus.cli.doctor import CheckState, Host, check_credentials, run_doctor, summarize
from colossus.cli.main import app


def fake_host(runtimes=("runc", "runsc"), rootless=True, cgroups="cpu memory pids io", disk_gib=100):
    def run(argv):
        if argv[:2] == ["docker", "version"]:
            return 0, "29.0.0\n"
        if argv[:2] == ["docker", "info"]:
            sec = '["name=seccomp","name=rootless"]' if rootless else '["name=seccomp"]'
            return 0, json.dumps({r: {} for r in runtimes}) + "|" + sec
        if argv[0] == "git":
            return 0, ""
        return 1, ""

    files = {"/proc/meminfo": "MemTotal: 25165824 kB\n", "/sys/fs/cgroup/cgroup.controllers": cgroups}

    def read_text(p):
        if p not in files:
            raise OSError(p)
        return files[p]

    return Host(machine=lambda: "x86_64", kernel=lambda: "6.8", cpu_count=lambda: 4,
                which=lambda t: f"/usr/bin/{t}", read_text=read_text, run=run,
                disk_free_bytes=lambda p: disk_gib * 1024**3)


def by_id(checks):
    return {c.check_id: c for c in checks}


def test_missing_gvisor_blocks(tmp_path):
    checks = by_id(run_doctor(tmp_path, str(tmp_path), fake_host(runtimes=("runc",))))
    assert checks["runtime.gvisor"].state is CheckState.BLOCKED
    assert summarize(list(checks.values())) == ("blocked", 3)


def test_build_backend_stays_blocked_until_validated(tmp_path):
    checks = by_id(run_doctor(tmp_path, str(tmp_path), fake_host()))
    assert checks["runtime.untrusted_build_backend"].state is CheckState.BLOCKED


def test_missing_cgroup_controller_blocks(tmp_path):
    checks = by_id(run_doctor(tmp_path, str(tmp_path), fake_host(cgroups="cpu io")))
    assert checks["host.cgroup_v2"].state is CheckState.BLOCKED


def test_low_disk_blocks(tmp_path):
    checks = by_id(run_doctor(tmp_path, str(tmp_path), fake_host(disk_gib=5)))
    assert checks["host.disk_free"].state is CheckState.BLOCKED


def test_credentials_never_printed(tmp_path):
    secret = "sk-test-DO-NOT-PRINT-123"
    env = tmp_path / ".env"
    env.write_text(f"MISTRAL_API_KEY={secret}\nGROQ_API_KEY=\n")
    os.chmod(env, 0o600)
    checks = by_id(check_credentials(tmp_path))
    assert checks["credentials.mistral"].observed == "configured"
    assert checks["credentials.groq"].observed == "missing"
    assert secret not in repr(checks) and "sk-" not in repr(checks)


def test_world_readable_env_blocks(tmp_path):
    env = tmp_path / ".env"
    env.write_text("MISTRAL_API_KEY=x\n")
    os.chmod(env, 0o644)
    assert by_id(check_credentials(tmp_path))["credentials.env_permissions"].state is CheckState.BLOCKED


def test_cli_json_envelope_and_exit_code(tmp_path, monkeypatch):
    secret = "sk-test-DO-NOT-PRINT-456"
    (tmp_path / ".env").write_text(f"MISTRAL_API_KEY={secret}\n")
    os.chmod(tmp_path / ".env", 0o600)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    monkeypatch.setenv("COLOSSUS_HOME", str(tmp_path))
    res = CliRunner().invoke(app, ["doctor", "--json"])
    assert secret not in res.output
    body = json.loads(res.output)
    assert set(body) == {"schema_version", "ok", "operation_id", "project_id", "cycle_id", "status",
                         "reason_code", "message", "action_url", "data"}
    assert res.exit_code in (0, 3)
    assert body["ok"] is (res.exit_code == 0)


def test_cli_rejects_unknown_profile():
    assert CliRunner().invoke(app, ["doctor", "--profile", "turbo"]).exit_code == 2
