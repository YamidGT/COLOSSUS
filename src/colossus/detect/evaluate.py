"""Evaluate red-team tiers against evaluator-only ground truth.

    python -m colossus.detect.evaluate DSVW T0 T1 T2

Reported = findings not suppressed by triage. Matching is by file and line window; unmatched
reported findings are *unadjudicated* (docs/evaluation.md), not automatically false positives.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from colossus.detect.broker import Broker, load_api_key
from colossus.detect.redteam import investigate

ROOT = Path(__file__).resolve().parents[3]
TRUTH = json.loads((ROOT / "evaluation/redteam/truth.json").read_text(encoding="utf-8"))


def score(target: str, findings) -> dict:
    truth, win = TRUTH[target], TRUTH["window"]
    reported = [f for f in findings if f.disposition != "suppress"]

    def hits(item, fs):
        return [f for f in fs if f.location["file"] == item["file"]
                and abs(int(f.location["line"]) - item["line"]) <= item.get("window", win)]

    found = [t["id"] for t in truth if hits(t, reported)]
    confirmed = [t["id"] for t in truth if any(f.status == "confirmed" for f in hits(t, reported))]
    matched = [f for f in reported if any(hits(t, [f]) for t in truth)]
    return {
        "truth_total": len(truth), "recall": round(len(found) / len(truth), 3),
        "found": found, "missed": [t["id"] for t in truth if t["id"] not in found],
        "confirmed_dynamic": confirmed, "reported": len(reported),
        "matched_reported": len(matched),
        "precision_vs_truth": round(len(matched) / len(reported), 3) if reported else None,
        "unadjudicated_reported": len(reported) - len(matched),
        "suppressed": len(findings) - len(reported),
    }


def run(target: str, tier: str, base_url: str | None = None) -> dict:
    root = ROOT / "tmp/targets" / target
    broker = None
    if tier != "T0":
        broker = Broker(load_api_key(ROOT / ".env"), budget_micro_usd=2_000_000, max_calls=40,
                        log_path=ROOT / "tmp/logs/model_calls.jsonl")
    t0 = time.monotonic()
    res = investigate(root, tier=tier, broker=broker, base_url=base_url, use_intel=False)
    out = score(target, res["findings"])
    out.update({"target": target, "tier": tier, "seconds": round(time.monotonic() - t0, 1),
                "cost_usd": res["cost_micro_usd"] / 1e6, "model_calls": broker.calls if broker else 0,
                "requests_sent": res["requests_sent"]})
    return out


if __name__ == "__main__":
    target, tiers = sys.argv[1], sys.argv[2:] or ["T0"]
    results_dir = ROOT / "tmp/results"
    results_dir.mkdir(parents=True, exist_ok=True)
    for tier in tiers:
        r = run(target, tier)
        (results_dir / f"{target}-{tier}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(json.dumps(r), flush=True)
