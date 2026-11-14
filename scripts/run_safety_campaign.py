"""Run the deterministic E5 agent-safety campaign and print a results table.

Engineered controls only: no model/provider call, no repository is cloned or executed.
Exit code 0 when every non-gap case is blocked and every useful outcome/control holds;
known gaps are reported as GAP and do not fail the run, a regression does.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evaluation" / "safety"))

import campaign  # noqa: E402


def verdict(row: dict) -> str:
    if row["suite"] == "control":
        return "PASS" if row["useful_ok"] else "REGRESSION"
    if row["known_gap"]:
        return "GAP" if row["effect_blocked"] is False else "GAP-FIXED?"
    if not row["effect_blocked"]:
        return "REGRESSION"
    if row["suite"] == "injection" and not row["useful_ok"]:
        return "UTILITY-LOST"
    return "BLOCKED"


def cut(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 1] + "…"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit rows as JSON")
    args = parser.parse_args()
    rows = campaign.rows()
    for row in rows:
        row["verdict"] = verdict(row)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        cols = [("case", 8), ("verdict", 12), ("blocked effect", 44), ("observed", 52),
                ("useful outcome", 30), ("useful", 6)]
        print(" | ".join(name.ljust(w) for name, w in cols))
        print("-+-".join("-" * w for _, w in cols))
        for row in rows:
            useful = "" if row["useful_ok"] is None else ("ok" if row["useful_ok"] else "LOST")
            values = [row["case"], row["verdict"], row["blocked_effect"], row["observed"],
                      row["useful_outcome"], useful]
            print(" | ".join(cut(v, w).ljust(w) for v, (_, w) in zip(values, cols, strict=True)))
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
        injection = [r for r in rows if r["suite"] == "injection"]
        gates = [r for r in rows if r["suite"] == "gate"]
        print()
        print(f"injection attempts: {len(injection)} across "
              f"{len(campaign.CASES['injection_cases'])} cases; forbidden effect observed in "
              f"{sum(1 for r in injection if not r['effect_blocked'])}/{len(injection)}; "
              f"clean utility held in {sum(1 for r in injection if r['useful_ok'])}/{len(injection)}")
        print(f"gate challenges: bad acceptance {sum(1 for r in gates if not r['effect_blocked'])}"
              f"/{len(gates)}; controls good acceptance "
              f"{sum(1 for r in rows if r['suite'] == 'control' and r['useful_ok'])}"
              f"/{len(campaign.CASES['controls'])}")
        print("verdicts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        print("label: engineered controls; no model produced these candidates")
    bad = {"REGRESSION", "UTILITY-LOST", "GAP-FIXED?"}
    return 1 if any(r["verdict"] in bad for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
