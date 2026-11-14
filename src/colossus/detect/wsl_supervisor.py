"""Runs INSIDE the bubblewrap sandbox (stdlib only, no network namespace beyond loopback).

Starts the target, plants a synthetic canary file, reports readiness, then relays HTTP GET
requests received as JSON lines on stdin to the target's loopback port. The relay is the only
channel; the host never connects to the target directly and the target has no egress at all.
"""

import http.client
import json
import secrets
import socket
import subprocess
import sys
import time

cfg = json.loads(sys.argv[1])
token = "colossus-canary-" + secrets.token_hex(8)
with open("/tmp/colossus-canary.txt", "w") as fh:
    fh.write(token + "\n")
proc = subprocess.Popen(
    cfg["cmd"], cwd=cfg["cwd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
ready = False
for _ in range(80):
    try:
        socket.create_connection(("127.0.0.1", cfg["port"]), timeout=0.5).close()
        ready = True
        break
    except OSError:
        time.sleep(0.25)
print(json.dumps({"ready": ready, "canary": token}), flush=True)
for line in sys.stdin:
    try:
        req = json.loads(line)
        conn = http.client.HTTPConnection("127.0.0.1", cfg["port"], timeout=10)
        conn.request("GET", req["path"])
        resp = conn.getresponse()
        body = resp.read(1_048_577)
        out = {
            "status": resp.status,
            "body": body[:1_048_576].decode(errors="replace"),
            "truncated": len(body) > 1_048_576,
        }
    except Exception as exc:  # report, never crash the relay
        out = {"status": 0, "body": "", "truncated": False, "error": type(exc).__name__}
    print(json.dumps(out), flush=True)
proc.kill()
