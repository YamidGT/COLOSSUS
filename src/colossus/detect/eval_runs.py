"""Evaluate integrated red-team tiers against evaluator-only ground truth.

    python -m colossus.detect.evaluate DSVW T0 T1 T2

Standalone harness: it drives `investigate()` with the shared `ModelGateway` (GLM Flash, the
project default) behind a small spend cap, and a local launcher that runs only the static
scanner script (it reads target source, it never executes target code). Reported = findings
not suppressed by triage. Matching is by file and line window; unmatched reported findings
are *unadjudicated* (docs/evaluation.md), not automatically false positives.
"""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from colossus.contracts.core import content_hash
from colossus.detect.redteam import investigate
from colossus.gateway.model import ModelGateway, cost_micro_usd, load_provider_key

ROOT = Path(__file__).resolve().parents[3]
TRUTH = json.loads((ROOT / "evaluation/redteam/truth.json").read_text(encoding="utf-8"))
SKIP = {".git", "node_modules", ".venv", "__pycache__"}


def score(target: str, findings) -> dict:
    truth, win = TRUTH[target], TRUTH["window"]
    reported = [f for f in findings if f.disposition != "suppress"]

    def hits(item, fs):
        return [
            f
            for f in fs
            if f.location["file"] == item["file"]
            and abs(int(f.location["line"]) - item["line"]) <= item.get("window", win)
        ]

    found = [t["id"] for t in truth if hits(t, reported)]
    confirmed = [t["id"] for t in truth if any(f.status == "confirmed" for f in hits(t, reported))]
    matched = [f for f in reported if any(hits(t, [f]) for t in truth)]
    return {
        "truth_total": len(truth),
        "recall": round(len(found) / len(truth), 3),
        "found": found,
        "missed": [t["id"] for t in truth if t["id"] not in found],
        "confirmed_dynamic": confirmed,
        "reported": len(reported),
        "matched_reported": len(matched),
        "precision_vs_truth": round(len(matched) / len(reported), 3) if reported else None,
        "unadjudicated_reported": len(reported) - len(matched),
        "suppressed": len(findings) - len(reported),
    }


class LocalScanLauncher:
    """Runs the static-scan script exactly as the sandbox would, in a throwaway directory."""

    async def call(self, path, body):
        assert path == "/run" and body["argv"][:2] == ["python", "-I"]
        with tempfile.TemporaryDirectory() as tmp:
            for name, b64 in body["files"].items():
                dest = Path(tmp) / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(base64.b64decode(b64))
            script = Path(tmp) / body["argv"][2]
            script.write_text(
                script.read_text().replace(
                    "/work/source/_colossus_detector", (Path(tmp) / "_colossus_detector").as_posix()
                )
            )
            proc = subprocess.run(
                [sys.executable, "-I", body["argv"][2]],
                cwd=tmp, capture_output=True, text=True, timeout=body["timeout"], check=False,
            )
        return {"exit_code": proc.returncode, "truncated": False, "stdout": proc.stdout}


class DirectBroker:
    """Same `complete()` shape as control.broker.Broker, with a spend cap and JSONL log."""

    def __init__(self, gateway: ModelGateway, budget_micro_usd: int, log: Path):
        self.gateway, self.budget, self.log = gateway, budget_micro_usd, log
        self.spent, self.calls = 0, 0

    async def complete(self, project_id, case_id, messages, max_tokens=4096, reasoning="low"):
        if self.spent >= self.budget:
            raise RuntimeError("evaluation budget exhausted")
        result = await self.gateway.complete(messages, max_tokens=max_tokens, reasoning=reasoning)
        self.calls += 1
        self.spent += result.actual_cost_micro_usd or cost_micro_usd(
            result.input_tokens or 0, result.output_tokens or 0
        )
        self.log.parent.mkdir(parents=True, exist_ok=True)
        with self.log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "request_sha256": content_hash(messages), "status": result.status,
                "reason": result.reason_code, "model": result.model_returned,
                "in": result.input_tokens, "out": result.output_tokens,
                "cost_micro_usd": result.actual_cost_micro_usd, "seconds": result.elapsed_seconds,
            }) + "\n")
        return f"direct-{self.calls}", result


def load_target(root: Path) -> dict[str, str]:
    files = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if p.is_file() and not SKIP.intersection(rel.parts) and p.stat().st_size < 400_000:
            files[rel.as_posix()] = base64.b64encode(p.read_bytes()).decode()
    return files


async def run(target: str, tier: str) -> dict:
    files = load_target(ROOT / "tmp/targets" / target)
    evidence_log: list = []
    start = time.monotonic()
    async with httpx.AsyncClient() as client:
        broker = None
        if tier != "T0":
            key = load_provider_key(ROOT / ".env")
            broker = DirectBroker(ModelGateway(key, client), 2_000_000, ROOT / "tmp/logs/gateway_calls.jsonl")
        res = await investigate(
            project_id=target, case_id=f"{target}-{tier}", encoded_files=files,
            manifest_hash=content_hash({"t": target}), launcher=LocalScanLauncher(),
            evidence=lambda v: (evidence_log.append(v), content_hash(v))[1],
            broker=broker, runner=None, tier=tier,
        )
    out = score(target, res["findings"])
    out.update(
        target=target, tier=tier, seconds=round(time.monotonic() - start, 1),
        model_calls=broker.calls if broker else 0,
        cost_usd=(broker.spent if broker else 0) / 1e6, excluded_tools=res["excluded_tools"],
    )
    return out


if __name__ == "__main__":
    tgt, tiers = sys.argv[1], sys.argv[2:] or ["T0"]
    out_dir = ROOT / "tmp/results_runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    for t in tiers:
        r = asyncio.run(run(tgt, t))
        (out_dir / f"{tgt}-{t}-{__import__('time').time_ns()}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(json.dumps(r), flush=True)
