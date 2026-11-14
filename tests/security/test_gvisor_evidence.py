"""Live gVisor checks for evidence export, scratch caps, reaping, isolation and redirects.

Runs only when the configured Docker context registers runsc. Every program is a
trusted test fixture; no repository code runs. Context: COLOSSUS_DOCKER_CONTEXT.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import time

import pytest

from colossus.contracts.core import DomainError, new_id
from colossus.sandbox import launcher as launcher_mod
from colossus.sandbox.launcher import LABEL, PYTHON_IMAGE, SandboxLauncher

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

REDIRECT_SERVER = b"""import http.server
HITS = []
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/away":
            self.send_response(302); self.send_header("Location", "http://1.1.1.1/x"); self.end_headers()
        elif self.path == "/self":
            self.send_response(302); self.send_header("Location", "/hit"); self.end_headers()
        elif self.path == "/hit":
            HITS.append(1); self.send_response(200); self.end_headers(); self.wfile.write(b"hit")
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(str(len(HITS)).encode())
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
"""

TCP = """import json, socket, sys
out = {}
for t in sys.argv[1:]:
    host, port = t.rsplit(":", 1)
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET); s.settimeout(2)
    try:
        out[t] = "allowed" if s.connect_ex((host, int(port))) == 0 else "denied"
    except OSError:
        out[t] = "denied"
    finally:
        s.close()
print(json.dumps(out))
"""

FILL = """import errno, json, sys
path, written, err = sys.argv[1], 0, None
chunk = b"x" * (1 << 20)
try:
    with open(path, "wb") as f:
        while written < (2 << 30):
            f.write(chunk); f.flush(); written += len(chunk)
except OSError as e:
    err = e.errno
print(json.dumps({"written": written, "errno": err}))
"""


@pytest.fixture(scope="module")
def launcher():
    return SandboxLauncher(CONTEXT)


@pytest.fixture
def project(launcher):
    pid = new_id()
    yield pid
    for name in launcher.checked(
        "ps", "-a", "--filter", f"label=org.colossus.project={pid}", "--format", "{{.Names}}"
    ).splitlines():
        launcher.destroy(name)  # also removes quarantined (paused) workers
    launcher.terminate_project_work(pid, [])
    left = launcher.checked(
        "ps", "-a", "--filter", f"label=org.colossus.project={pid}", "--format", "{{.Names}}"
    )
    nets = launcher.checked(
        "network", "ls", "--filter", f"label=org.colossus.project={pid}", "--format", "{{.Name}}"
    )
    assert left == "" and nets == ""


@pytest.fixture(scope="module")
def redirect_artifact(launcher):
    info = launcher.package({"server.py": REDIRECT_SERVER}, ["python", "server.py"])
    yield info["artifact_digest"]
    launcher.docker("image", "rm", "-f", info["artifact_digest"], timeout=60)


def _names(launcher, project_id):
    return launcher.checked(
        "ps", "-a", "--filter", f"label=org.colossus.project={project_id}", "--format",
        "{{.Names}}",
    ).splitlines()


def _ready_request(launcher, project_id, env, path="/"):
    for _ in range(30):
        res = launcher.request(project_id, env, 8080, path)
        if res.get("status"):
            return res
        time.sleep(0.5)
    return res


# 1. Evidence before teardown


def test_results_exported_before_teardown(launcher, project):
    job = b"import os; os.makedirs('/work/results'); open('/work/results/r.json','w').write('{\"ok\": 1}')"
    out = launcher.run_collect(project, "verify", {"j.py": job}, ["python", "j.py"], 30)
    assert out["evidence"] == "exported", out
    assert out["files"] == {"r.json": b'{"ok": 1}'}
    assert _names(launcher, project) == []


def test_export_failure_keeps_worker_quarantined_with_evidence(launcher, project):
    job = (
        b"import os; os.makedirs('/work/results'); open('/work/results/r.txt','w').write('kept');"
        b"os.symlink('/etc/passwd', '/work/results/link')"
    )
    out = launcher.run_collect(project, "verify", {"j.py": job}, ["python", "j.py"], 30)
    assert out["evidence"] == "quarantined" and out["error"] == "unsafe_export", out
    env = out["environment_id"]
    state = launcher.inspect(env)["State"]
    assert state["Paused"] and state["Status"] == "paused"
    assert env in launcher.quarantined()
    # Evidence is still inside the frozen worker.
    launcher.checked("unpause", env)
    res = launcher.execute(env, ["cat", "/work/results/r.txt"], 10, "/work")
    assert res.stdout == "kept"
    launcher.destroy(env)
    assert _names(launcher, project) == []


def test_reaper_keeps_expired_quarantine_and_full_quarantine_blocks_work(
    launcher, project, monkeypatch
):
    env = launcher.create(project, "verify", ttl_seconds=1)
    launcher.execute(env, ["sh", "-c", "echo e > /work/e"], 10, "/work")
    launcher.quarantine(env)
    time.sleep(2)
    assert env not in launcher.reap()
    assert env in _names(launcher, project)
    monkeypatch.setattr(launcher_mod, "MAX_QUARANTINE", len(launcher.quarantined()))
    with pytest.raises(DomainError) as err:
        launcher.create(project, "verify", ttl_seconds=30)
    assert err.value.code == "quarantine_full"
    assert _names(launcher, project) == [env]


# 2. Scratch/disk cap


@pytest.mark.parametrize(("path", "cap"), [("/tmp/fill", 64 << 20), ("/work/fill", 512 << 20)])
def test_scratch_fill_fails_inside_job_only(launcher, project, path, cap):
    host_before = shutil.disk_usage("/").free
    env = launcher.create(project, "verify", ttl_seconds=180)
    try:
        launcher.copy_source(env, {"f.py": FILL.encode()})
        res = launcher.execute(env, ["python", "f.py", path], 120)
        assert res.exit_code == 0, res.stderr
        out = json.loads(res.stdout)
        assert out["errno"] == 28, out  # ENOSPC inside the sandbox
        assert out["written"] <= cap
        # The worker itself is still usable after hitting the cap.
        assert launcher.execute(env, ["echo", "alive"], 10, "/work").stdout.strip() == "alive"
    finally:
        launcher.destroy(env)
    # tmpfs lives in sandbox memory: the host filesystem did not absorb the fill.
    assert host_before - shutil.disk_usage("/").free < 64 << 20


# 3. Orphan reconciliation


def test_reaper_removes_expired_managed_only(launcher, project):
    managed_env = launcher.create(project, "verify", ttl_seconds=1)
    managed_net = launcher.network(project, ttl_seconds=1)
    fresh_net = launcher.network(project, ttl_seconds=600)
    plain = "colossus-plain-" + new_id()
    plain_net = "colossus-net-plain-" + new_id()
    try:
        # Unmanaged look-alikes: COLOSSUS-like names and an expired label, but not managed=true.
        launcher.checked(
            "network", "create", "--internal", "--label", "org.colossus.expires=0", plain_net
        )
        launcher.docker(
            "create", "--runtime", "runc", "--network", "none", "--name", plain,
            "--label", f"{LABEL}=false", "--label", "org.colossus.expires=0",
            PYTHON_IMAGE, "true",
        )  # never started; created with runc to prove the reaper ignores it
        time.sleep(2)
        removed = launcher.reap()
        assert managed_env in removed and managed_net in removed
        assert fresh_net not in removed
        assert plain not in removed and plain_net not in removed
        assert launcher.docker("inspect", plain).exit_code == 0
        assert launcher.docker("network", "inspect", plain_net).exit_code == 0
        assert launcher.docker("inspect", managed_env).exit_code != 0
        assert launcher.docker("network", "inspect", managed_net).exit_code != 0
    finally:
        launcher.docker("rm", "-f", plain)
        launcher.docker("network", "rm", plain_net)
    assert launcher.docker("inspect", plain).exit_code != 0


# 4. Same-project network isolation and redirects


def test_two_networks_of_same_project_are_isolated(launcher, project, redirect_artifact):
    a = launcher.start_target(project, redirect_artifact, ttl_seconds=300)
    b = launcher.start_target(project, redirect_artifact, ttl_seconds=300)
    assert a["network_id"] != b["network_id"]
    assert _ready_request(launcher, project, a["environment_id"])["status"] == 200
    assert _ready_request(launcher, project, b["environment_id"])["status"] == 200
    ta, tb = f"{a['address']}:8080", f"{b['address']}:8080"
    res = launcher.run(project, "probe", {"t.py": TCP.encode()}, ["python", "t.py", ta, tb], 30,
                       b["network_id"])
    out = json.loads(res.stdout)
    assert out[tb] == "allowed" and out[ta] == "denied", out


def test_request_does_not_follow_redirects(launcher, project, redirect_artifact):
    t = launcher.start_target(project, redirect_artifact, ttl_seconds=300)
    env = t["environment_id"]
    assert _ready_request(launcher, project, env, "/count")["body"] == "0"
    away = launcher.request(project, env, 8080, "/away")
    assert away["status"] == 302 and away["headers"]["Location"] == "http://1.1.1.1/x"
    same = launcher.request(project, env, 8080, "/self")
    assert same["status"] == 302 and same["headers"]["Location"] == "/hit"
    # No second request reached /hit.
    assert launcher.request(project, env, 8080, "/count")["body"] == "0"


# 5. Extra boundary checks


def test_job_has_no_privileges_and_read_only_root(launcher, project):
    job = b"""import json, os, subprocess
st = dict(l.split(':\\t', 1) for l in open('/proc/self/status').read().splitlines() if ':\\t' in l)
out = {"uid": os.getuid(), "gid": os.getgid(), "cap_eff": st["CapEff"].strip(),
       "cap_bnd": st["CapBnd"].strip(), "nnp": st["NoNewPrivs"].strip()}
try:
    open('/root-write', 'w'); out["root_write"] = "allowed"
except OSError:
    out["root_write"] = "denied"
open('/tmp/x.sh', 'w').write('#!/bin/sh\\necho ran\\n'); os.chmod('/tmp/x.sh', 0o755)
try:
    subprocess.run(['/tmp/x.sh'], check=True, capture_output=True); out["tmp_exec"] = "allowed"
except (OSError, subprocess.CalledProcessError):
    out["tmp_exec"] = "denied"
print(json.dumps(out))
"""
    res = launcher.run(project, "verify", {"p.py": job}, ["python", "p.py"], 30)
    out = json.loads(res.stdout)
    assert out["uid"] == 1000 and out["gid"] == 1000
    assert int(out["cap_eff"], 16) == 0 and int(out["cap_bnd"], 16) == 0
    assert out["nnp"] == "1"
    assert out["root_write"] == "denied" and out["tmp_exec"] == "denied", out


def test_target_cannot_reach_host_gateway_or_ipv6(launcher, project, redirect_artifact):
    t = launcher.start_target(project, redirect_artifact, ttl_seconds=300)
    net = json.loads(launcher.checked("network", "inspect", t["network_id"]))[0]
    # Before inhibit_ipv4 the bridge gateway (x.x.0.1) was a host address and a host
    # listener on it was reachable from the job (observed "allowed"). Now the host has
    # no address in the case subnet at all.
    assert not [c for c in net["IPAM"]["Config"] if c.get("Gateway")]
    subnets = [ipaddress.ip_network(c["Subnet"]) for c in net["IPAM"]["Config"]]
    host_ips = [
        ipaddress.ip_address(a["local"])
        for link in json.loads(subprocess.run(["ip", "-j", "addr"], capture_output=True,
                                              text=True, check=True).stdout)
        for a in link.get("addr_info", [])
    ]
    assert not [ip for ip in host_ips for n in subnets if ip in n]
    gateways = [str(n.network_address + 1) for n in subnets] + ["172.17.0.1"]
    listeners, targets = [], []
    try:
        for ip in gateways:
            s = socket.socket()
            try:
                s.bind((ip, 0))  # bound to the bridge address only, never 0.0.0.0
            except OSError:
                s.close()
                continue
            s.listen(1)
            listeners.append(s)
            targets.append(f"{ip}:{s.getsockname()[1]}")
        targets.append("2606:4700:4700::1111:443")
        res = launcher.run(project, "probe", {"t.py": TCP.encode()}, ["python", "t.py", *targets],
                           30, t["network_id"])
        out = json.loads(res.stdout)
        assert listeners, "no host-side listener could be bound for the gateway check"
        assert set(out.values()) == {"denied"}, out
    finally:
        for s in listeners:
            s.close()
