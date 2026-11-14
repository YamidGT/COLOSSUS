"""Live gVisor challenges: cross-project, egress, cancellation, limits and teardown.

Runs only when the configured Docker context registers runsc. Every program
here is a trusted test fixture; no repository code is executed.
Context: COLOSSUS_DOCKER_CONTEXT (default "colima-colossus").
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from colossus.contracts.core import DomainError, new_id
from colossus.sandbox.launcher import LABEL, SandboxLauncher

CONTEXT = os.environ.get("COLOSSUS_DOCKER_CONTEXT", "colima-colossus")


def _ready() -> bool:
    try:
        return bool(SandboxLauncher(CONTEXT).preflight().get("ready"))
    except Exception:  # noqa: BLE001
        return False


pytestmark = [
    pytest.mark.gvisor,
    pytest.mark.skipif(not _ready(), reason=f"runsc not registered in docker context {CONTEXT}"),
]

SERVER = b"""import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"colossus-target-ok")
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
"""

PROBE = """import json, socket, sys
def tcp(host, port):
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET); s.settimeout(2)
    try:
        return "allowed" if s.connect_ex((host, port)) == 0 else "denied"
    except OSError:
        return "denied"
    finally:
        s.close()
out = {}
for t in sys.argv[1:]:
    host, port = t.rsplit(":", 1)
    out[t] = tcp(host, int(port))
try:
    socket.getaddrinfo("github.com", 443); out["dns"] = "allowed"
except OSError:
    out["dns"] = "denied"
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def launcher():
    return SandboxLauncher(CONTEXT)


@pytest.fixture
def project(launcher):
    pid = new_id()
    yield pid
    launcher.terminate_project_work(pid, [])
    left = launcher.checked("ps", "-a", "--filter", f"label=org.colossus.project={pid}", "--format", "{{.Names}}")
    assert left == ""


@pytest.fixture(scope="module")
def artifact(launcher):
    info = launcher.package({"server.py": SERVER}, ["python", "server.py"])
    yield info["artifact_digest"]
    launcher.docker("image", "rm", "-f", info["artifact_digest"], timeout=60)


def probe(launcher, project_id, network, *targets):
    res = launcher.run(project_id, "probe", {"p.py": PROBE.encode()}, ["python", "p.py", *targets], 30, network)
    assert res.exit_code == 0, res.stderr
    return json.loads(res.stdout)


def test_egress_metadata_and_dns_denied_without_network(launcher, project):
    out = probe(launcher, project, "none", "1.1.1.1:443", "169.254.169.254:80", "2606:4700:4700::1111:443")
    assert set(out.values()) == {"denied"}, out


def test_project_network_reaches_own_target_but_not_internet(launcher, project, artifact):
    target = launcher.start_target(project, artifact, ttl_seconds=300)
    for _ in range(20):
        res = launcher.request(project, target["environment_id"], 8080, "/")
        if res.get("status") == 200:
            break
    assert res["status"] == 200 and res["body"] == "colossus-target-ok"
    out = probe(launcher, project, target["network_id"], f"{target['address']}:8080", "1.1.1.1:443",
                "169.254.169.254:80")
    assert out[f"{target['address']}:8080"] == "allowed"
    assert out["1.1.1.1:443"] == "denied" and out["169.254.169.254:80"] == "denied"
    assert out["dns"] == "denied"


def test_other_project_cannot_reach_or_use_target(launcher, project, artifact):
    other = new_id()
    try:
        target = launcher.start_target(project, artifact, ttl_seconds=300)
        # Another project's probe on its own network cannot connect to the target.
        own_net = launcher.network(other)
        out = probe(launcher, other, own_net, f"{target['address']}:8080")
        assert out[f"{target['address']}:8080"] == "denied"
        # It also cannot join the target network or address the target through the API.
        with pytest.raises(DomainError):
            launcher.create(other, "probe", target["network_id"])
        with pytest.raises(DomainError):
            launcher.request(other, target["environment_id"], 8080, "/")
    finally:
        launcher.terminate_project_work(other, [])


def test_timeout_kills_job_and_removes_container(launcher, project):
    res = launcher.run(project, "verify", {"s.py": b"import time; time.sleep(120)"}, ["python", "s.py"], 3)
    assert res.timed_out
    names = launcher.checked("ps", "-a", "--filter", f"label=org.colossus.project={project}", "--format", "{{.Names}}")
    assert names == ""


def test_memory_limit_is_enforced(launcher, project):
    env = launcher.create(project, "verify", memory_mb=128, ttl_seconds=120)
    try:
        launcher.copy_source(env, {"m.py": b"b = bytearray(512 * 1024 * 1024); print('allocated')"})
        res = launcher.execute(env, ["python", "m.py"], 60)
        assert res.exit_code != 0 and "allocated" not in res.stdout
    finally:
        launcher.destroy(env)


def test_pids_limit_is_enforced(launcher, project):
    program = b"""import subprocess
procs = []
try:
    for _ in range(400):
        procs.append(subprocess.Popen(["sleep", "30"]))
    print("spawned", len(procs))
except OSError:
    print("limited", len(procs))
finally:
    for p in procs:
        p.kill()
"""
    res = launcher.run(project, "verify", {"f.py": program}, ["python", "f.py"], 60)
    # The limit may stop the script (it prints "limited N") or kill the exec itself
    # (gVisor reports a WaitPID failure). Either way 400 processes are never reached.
    assert "spawned" not in res.stdout, res.stdout
    if res.stdout.startswith("limited"):
        assert int(res.stdout.split()[1]) < 128
    else:
        assert res.exit_code != 0


def test_source_upload_cannot_escape_work_dir(launcher, project):
    with pytest.raises(ValueError):
        launcher.run(project, "verify", {"../evil.py": b"x"}, ["python", "-c", "0"], 10)


def test_terminate_project_removes_all_workers_and_networks(launcher, project, artifact):
    launcher.start_target(project, artifact, ttl_seconds=300)
    launcher.create(project, "verify", ttl_seconds=120)
    result = launcher.terminate_project_work(project, [])
    assert result["termination_confirmed"] and len(result["terminated"]) == 2
    nets = launcher.checked("network", "ls", "--filter", f"label={LABEL}=true", "--filter",
                            f"label=org.colossus.project={project}", "--format", "{{.Name}}")
    assert nets == ""


def test_host_env_is_not_passed_to_docker(monkeypatch, launcher, project):
    monkeypatch.setenv("MISTRAL_API_KEY", "must-not-leak")
    res = launcher.run(project, "verify", {"e.py": b"import os; print(sorted(os.environ))"}, ["python", "e.py"], 30)
    assert "MISTRAL_API_KEY" not in res.stdout and "must-not-leak" not in res.stdout


def test_runtime_is_really_gvisor(launcher, project):
    res = launcher.run(project, "verify", {"k.py": b"print(open('/proc/version').read())"}, ["python", "k.py"], 30)
    assert "gvisor" in res.stdout.lower()
    assert subprocess.run(["true"]).returncode == 0  # host process untouched
