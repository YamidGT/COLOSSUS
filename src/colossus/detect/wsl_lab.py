"""Docker-free dynamic-probe lab: WSL2 + bubblewrap, target in a network-less sandbox.

    python -m colossus.detect.wsl_lab DSVW T1 [T2]

`WslLauncher` exposes the same `call("/targets/request", ...)` shape that the integrated
`ProbeRunner` expects, so probes run through the unchanged closed-profile runner. This is a
lane-B evaluation harness, not a replacement for the lane-A launcher: bubblewrap is a Linux
namespace sandbox (no gVisor), sharing the WSL2 kernel. Target sees no network but loopback,
cannot see /mnt or /home, and dies with its parent.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

from colossus.contracts.core import content_hash
from colossus.detect.eval_runs import (
    ROOT,
    DirectBroker,
    LocalScanLauncher,
    load_target,
    score,
)
from colossus.detect.probes import ProbeRunner
from colossus.detect.redteam import investigate
from colossus.gateway.model import ModelGateway, load_provider_key

DISTRO = "kali-linux"
# name -> (source dir in ~/lab, loopback port, command inside the sandbox)
TARGETS = {
    "DSVW": ("DSVW", 65412, ["/tmp/venv/bin/python", "dsvw.py", "--host=127.0.0.1", "--port=65412"]),
    "VAmPI": ("VAmPI", 5000, ["/tmp/venv/bin/python", "app.py"]),
}
LAUNCH = r"""#!/bin/bash
name=$1; dir=$2; cfg=$3
rm -rf ~/lab/run_$name; cp -r ~/lab/$dir ~/lab/run_$name
cp "$4" ~/lab/supervisor.py
exec bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /mnt --tmpfs /home --tmpfs /root \
  --tmpfs /tmp --bind ~/lab/run_$name /tmp/app --ro-bind ~/lab/venv313 /tmp/venv \
  --ro-bind ~/lab/supervisor.py /tmp/supervisor.py --unshare-pid --unshare-ipc --unshare-uts \
  --unshare-net --die-with-parent --new-session --chdir /tmp/app \
  /tmp/venv/bin/python /tmp/supervisor.py "$cfg"
"""


def wsl_path(p: Path) -> str:
    p = p.resolve()
    return f"/mnt/{p.drive[0].lower()}{p.as_posix()[2:]}"


class WslLauncher:
    def __init__(self, target: str):
        self.dir, self.port, self.cmd = TARGETS[target]
        self.name = target.lower()
        self.proc = None
        self.canary = None

    async def start(self) -> str:
        script = ROOT / "tmp" / "wsl_launch.sh"
        script.write_text(LAUNCH.replace("\r\n", "\n"), newline="\n")
        cfg = json.dumps({"cmd": self.cmd, "cwd": "/tmp/app", "port": self.port})
        supervisor = Path(__file__).with_name("wsl_supervisor.py")
        self.proc = await asyncio.create_subprocess_exec(
            "wsl", "-d", DISTRO, "--", "bash", wsl_path(script), self.name, self.dir, cfg,
            wsl_path(supervisor),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        hello = json.loads(await asyncio.wait_for(self.proc.stdout.readline(), 90))
        if not hello.get("ready"):
            raise RuntimeError("target did not become ready inside the sandbox")
        self.canary = hello["canary"]
        return self.canary

    async def call(self, path, body):
        assert path == "/targets/request"
        self.proc.stdin.write((json.dumps({"path": body["path"]}) + "\n").encode())
        await self.proc.stdin.drain()
        return json.loads(await asyncio.wait_for(self.proc.stdout.readline(), 30))

    async def stop(self):
        if self.proc and self.proc.returncode is None:
            self.proc.stdin.close()
            try:
                await asyncio.wait_for(self.proc.wait(), 10)
            except TimeoutError:
                self.proc.kill()


async def run(target: str, tier: str) -> dict:
    lab = WslLauncher(target)
    canary = await lab.start()
    try:
        files = load_target(ROOT / "tmp/targets" / target)
        evidence_log: list = []
        start = time.monotonic()
        async with httpx.AsyncClient() as client:
            broker = DirectBroker(
                ModelGateway(load_provider_key(ROOT / ".env"), client), 2_000_000,
                ROOT / "tmp/logs/gateway_calls.jsonl",
            )
            runner = ProbeRunner(lab, target, "wsl-lab", lab.port, canary_token=canary)
            res = await investigate(
                project_id=target, case_id=f"{target}-{tier}-probes", encoded_files=files,
                manifest_hash=content_hash({"t": target}), launcher=LocalScanLauncher(),
                evidence=lambda v: (evidence_log.append(v), content_hash(v))[1],
                broker=broker, runner=runner, tier=tier,
            )
        out = score(target, res["findings"])
        probes = [e["probe"] for e in evidence_log if e.get("probe")]
        out.update(
            target=target, tier=tier, seconds=round(time.monotonic() - start, 1),
            model_calls=broker.calls, cost_usd=broker.spent / 1e6,
            probes_run=len(probes), probes_confirmed=sum(1 for p in probes if p.get("confirmed")),
            probes_refused=sum(1 for p in probes if "refused" in p),
            probe_profiles=sorted({p.get("profile", "refused") for p in probes}),
            requests_sent=res["requests_sent"],
            confirmed_findings=sum(1 for f in res["findings"] if f.status == "confirmed"),
        )
        return out
    finally:
        await lab.stop()


if __name__ == "__main__":
    tgt, tiers = sys.argv[1], sys.argv[2:] or ["T1"]
    out_dir = ROOT / "tmp/results_probes"
    out_dir.mkdir(parents=True, exist_ok=True)
    for t in tiers:
        r = asyncio.run(run(tgt, t))
        (out_dir / f"{tgt}-{t}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(json.dumps(r), flush=True)
