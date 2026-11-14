"""Trusted probe run inside the sandbox by test_launcher_docker.py.

Prints one JSON line per check. Each check reports what actually happened.
"""

import json
import os
import socket
import sys
import time


def attempt(fn):
    try:
        fn()
        return "allowed"
    except Exception as exc:  # noqa: BLE001 - we report the denial reason
        return f"denied:{type(exc).__name__}"


def tcp(host, port):
    def go():
        with socket.create_connection((host, port), timeout=3):
            pass
    return go


def write(path):
    def go():
        with open(path, "w") as fh:
            fh.write("x")
    return go


def caps():
    for line in open("/proc/self/status"):
        if line.startswith("CapEff:"):
            return line.split()[1]
    return "unknown"


def cgroup_file(name):
    try:
        return open(f"/sys/fs/cgroup/{name}").read().strip()
    except OSError as exc:
        return f"unreadable:{type(exc).__name__}"


mode = sys.argv[1]
if mode == "isolation":
    report = {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "cap_eff": caps(),
        "egress_ip": attempt(tcp("1.1.1.1", 53)),
        "egress_ipv6": attempt(tcp("2606:4700:4700::1111", 53)),
        "dns": attempt(lambda: socket.getaddrinfo("github.com", 443)),
        "metadata": attempt(tcp("169.254.169.254", 80)),
        "write_root": attempt(write("/etc/colossus-test")),
        "write_in": attempt(write("/in/colossus-test")),
        "write_scratch": attempt(write("/scratch/ok")),
        "docker_sock": os.path.exists("/var/run/docker.sock"),
        "memory_max": cgroup_file("memory.max"),
        "pids_max": cgroup_file("pids.max"),
        "env_has_keys": sorted(k for k in os.environ if "KEY" in k or "TOKEN" in k),
    }
    print(json.dumps(report))
elif mode == "outputs":
    with open("/out/result.json", "w") as fh:
        json.dump({"ok": True}, fh)
    os.makedirs("/out/sub", exist_ok=True)
    with open("/out/sub/log.txt", "w") as fh:
        fh.write("hello")
    os.symlink("/etc/passwd", "/out/leak")
    with open("/out/big.bin", "wb") as fh:
        fh.write(b"0" * (2 * 1024 * 1024))
    print("done")
elif mode == "sleep":
    time.sleep(120)
elif mode == "fail":
    sys.exit(3)
