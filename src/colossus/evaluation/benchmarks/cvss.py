"""CVSS v3.0/v3.1 base vector validation and base score (FIRST specification).

Formulas follow https://www.first.org/cvss/v3.1/specification-document section 7 and
Appendix A (Roundup). v3.0 vectors use the v3.0 Roundup (ceil to one decimal).
"""

from __future__ import annotations

import math
import re
from typing import Any

from colossus.contracts.core import DomainError
from colossus.evaluation.benchmarks.common import last_nonempty_line, proportion

BASE_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_BASE_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}
_OPTIONAL_VALUES = {
    "E": {"X", "U", "P", "F", "H"},
    "RL": {"X", "O", "T", "W", "U"},
    "RC": {"X", "U", "R", "C"},
    "CR": {"X", "L", "M", "H"},
    "IR": {"X", "L", "M", "H"},
    "AR": {"X", "L", "M", "H"},
    "MAV": {"X", "N", "A", "L", "P"},
    "MAC": {"X", "L", "H"},
    "MPR": {"X", "N", "L", "H"},
    "MUI": {"X", "N", "R"},
    "MS": {"X", "U", "C"},
    "MC": {"X", "N", "L", "H"},
    "MI": {"X", "N", "L", "H"},
    "MA": {"X", "N", "L", "H"},
}
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_VECTOR = re.compile(r"CVSS:3\.[01]/[A-Z:/]+")


def parse_vector(vector: str) -> dict[str, str] | None:
    """Return ``{"version": "3.1", AV: ..}`` or ``None`` if the vector is not spec-valid."""
    text = vector.strip()
    if not text.startswith(("CVSS:3.1/", "CVSS:3.0/")):
        return None
    version, _, body = text[5:].partition("/")
    metrics: dict[str, str] = {}
    for part in body.split("/"):
        key, sep, value = part.partition(":")
        allowed = _BASE_VALUES.get(key) or _OPTIONAL_VALUES.get(key)
        if not sep or allowed is None or value not in allowed or key in metrics:
            return None
        metrics[key] = value
    if any(key not in metrics for key in BASE_ORDER):
        return None
    return {"version": version, **{key: metrics[key] for key in BASE_ORDER}}


def _roundup(value: float, version: str) -> float:
    if version == "3.0":
        return math.ceil(value * 10) / 10
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(metrics: dict[str, str]) -> float:
    version = metrics["version"]
    changed = metrics["S"] == "C"
    iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (_PR_C if changed else _PR_U)[metrics["PR"]]
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(raw, 10.0), version)


def extract_vector(response: str) -> tuple[str | None, bool]:
    """Read the vector from the last non-empty line, as the upstream prompt requires.

    Returns (vector, prefix_added). A bare ``AV:..`` line gets a ``CVSS:3.1/`` prefix,
    matching the upstream notebook's prefixing; that normalization is flagged per row.
    """
    line = last_nonempty_line(response).strip("*`_ ").rstrip(".")
    found = _VECTOR.search(line)
    if found:
        return found[0].rstrip("/"), False
    if line.startswith("AV:"):
        return "CVSS:3.1/" + line, True
    return None, False


def score_vsp(gold: dict[str, str], responses: dict[str, str | None]) -> dict[str, Any]:
    """Score CTI-VSP. Predicted score is always calculated from a validated vector.

    MAD is computed over valid predictions only and reported next to the invalid count;
    invalid outputs stay in the attempted denominator for validity and agreement.
    """
    rows: dict[str, dict[str, Any]] = {}
    for item_id, gt in gold.items():
        gt_metrics = parse_vector(gt)
        if gt_metrics is None:
            raise DomainError("vsp_gold_invalid", f"Gold vector for {item_id} invalid", 422)
        gt_score = base_score(gt_metrics)
        if item_id not in responses or responses[item_id] is None:
            rows[item_id] = {"outcome": "not_run", "reason": "no response"}
            continue
        vector, prefixed = extract_vector(responses[item_id] or "")
        metrics = parse_vector(vector) if vector else None
        if metrics is None:
            rows[item_id] = {
                "outcome": "invalid_output",
                "gold_vector": gt.strip(),
                "gold_score": gt_score,
                "prediction": vector,
                "valid_vector": False,
            }
            continue
        score = base_score(metrics)
        rows[item_id] = {
            "outcome": "scored",
            "gold_vector": gt.strip(),
            "gold_score": gt_score,
            "prediction": vector,
            "prefix_added": prefixed,
            "valid_vector": True,
            "predicted_score": score,
            "abs_error": round(abs(score - gt_score), 1),
            "component_agreement": {k: metrics[k] == gt_metrics[k] for k in BASE_ORDER},
            "version_match": metrics["version"] == gt_metrics["version"],
        }
    attempted = [r for r in rows.values() if r["outcome"] != "not_run"]
    valid = [r for r in attempted if r["valid_vector"]]
    per_component = {
        key: proportion(sum(r["component_agreement"][key] for r in valid), len(attempted))
        for key in BASE_ORDER
    }
    return {
        "rows": rows,
        "summary": {
            "locked": len(gold),
            "attempted": len(attempted),
            "not_run": len(rows) - len(attempted),
            "invalid_output": len(attempted) - len(valid),
            "vector_validity": proportion(len(valid), len(attempted)),
            "valid_only_mad": (sum(r["abs_error"] for r in valid) / len(valid) if valid else None),
            "valid_only_count": len(valid),
            "component_agreement_over_attempted": per_component,
            "prefix_added_count": sum(r.get("prefix_added", False) for r in valid),
        },
    }
