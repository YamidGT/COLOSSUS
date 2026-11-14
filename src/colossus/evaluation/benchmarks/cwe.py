"""CWE answer extraction, hierarchy loading and CTI-RCM scoring."""

from __future__ import annotations

import csv
import io
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from colossus.contracts.core import DomainError
from colossus.evaluation.benchmarks.common import last_nonempty_line, proportion, read_text

_CWE = re.compile(r"^CWE-(\d{1,5})$", re.IGNORECASE)
_RELATED = re.compile(r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:(\d+)")
RESEARCH_VIEW = "1000"


def normalize_cwe(value: str) -> str | None:
    match = _CWE.match(value.strip())
    return f"CWE-{int(match[1])}" if match else None


def extract_cwe(response: str) -> str | None:
    """Upstream prompt asks for the CWE ID alone on the last line.

    Only surrounding markdown emphasis/backticks and a trailing period are stripped; any
    other text on that line makes the output invalid (no searching the response body).
    """
    line = last_nonempty_line(response).strip("*`_ ").rstrip(".").strip("*`_ ")
    return normalize_cwe(line)


def load_cwe_hierarchy(path: str | Path, view: str = RESEARCH_VIEW) -> dict[str, set[str]]:
    """Parse MITRE's CWE CSV export (e.g. ``1000.csv`` from cwe.mitre.org/data/downloads).

    Returns child -> parents restricted to ``ChildOf`` edges in ``view``.
    """
    reader = csv.DictReader(io.StringIO(read_text(path)))
    if not reader.fieldnames or "CWE-ID" not in reader.fieldnames:
        raise DomainError("cwe_hierarchy_shape", "CWE CSV needs CWE-ID column", 422)
    if "Related Weaknesses" not in reader.fieldnames:
        raise DomainError("cwe_hierarchy_shape", "CWE CSV needs Related Weaknesses", 422)
    parents: dict[str, set[str]] = defaultdict(set)
    for row in reader:
        child = f"CWE-{int(row['CWE-ID'])}"
        for parent, row_view in _RELATED.findall(row.get("Related Weaknesses") or ""):
            if row_view == view:
                parents[child].add(f"CWE-{int(parent)}")
    return dict(parents)


def hierarchical_match(pred: str, gold: str, parents: dict[str, set[str]]) -> bool:
    """Exact, or a direct ChildOf neighbour (distance 1) in the pinned view."""
    return pred == gold or pred in parents.get(gold, set()) or gold in parents.get(pred, set())


def score_rcm(
    gold: dict[str, str],
    responses: dict[str, str | None],
    hierarchy: dict[str, set[str]] | None = None,
) -> dict[str, Any]:
    """Score CTI-RCM. ``gold`` covers the locked sample; missing responses are ``not_run``.

    Overall accuracy uses every attempted row (invalid outputs count as wrong). The
    upstream notebook divides by valid-prefixed outputs only; that figure is reported
    separately as ``upstream_valid_only_accuracy``.
    """
    rows: dict[str, dict[str, Any]] = {}
    for item_id, gt in gold.items():
        gt_norm = normalize_cwe(gt)
        if gt_norm is None:
            raise DomainError("rcm_gold_invalid", f"Gold label for {item_id} is not a CWE", 422)
        if item_id not in responses or responses[item_id] is None:
            rows[item_id] = {"outcome": "not_run", "reason": "no response"}
            continue
        pred = extract_cwe(responses[item_id] or "")
        row: dict[str, Any] = {
            "outcome": "invalid_output" if pred is None else "scored",
            "gold": gt_norm,
            "prediction": pred,
            "exact": pred == gt_norm,
        }
        if hierarchy is not None:
            row["hierarchical"] = pred is not None and hierarchical_match(pred, gt_norm, hierarchy)
        rows[item_id] = row
    attempted = [r for r in rows.values() if r["outcome"] != "not_run"]
    valid = [r for r in attempted if r["outcome"] == "scored"]
    summary: dict[str, Any] = {
        "locked": len(gold),
        "attempted": len(attempted),
        "not_run": len(rows) - len(attempted),
        "invalid_output": len(attempted) - len(valid),
        "exact_accuracy": proportion(sum(r["exact"] for r in attempted), len(attempted)),
        "invalid_rate": proportion(len(attempted) - len(valid), len(attempted)),
        "upstream_valid_only_accuracy": proportion(sum(r["exact"] for r in valid), len(valid)),
        "macro_f1": _macro_f1(attempted),
        "hierarchical_accuracy": None,
    }
    if hierarchy is not None:
        summary["hierarchical_accuracy"] = proportion(
            sum(r["hierarchical"] for r in attempted), len(attempted)
        )
    return {"rows": rows, "summary": summary}


def _macro_f1(rows: list[dict[str, Any]]) -> float | None:
    """Macro-F1 over gold classes; invalid outputs are a wrong prediction."""
    if not rows:
        return None
    labels = {r["gold"] for r in rows}
    scores = []
    for label in labels:
        tp = sum(r["gold"] == label and r["prediction"] == label for r in rows)
        fp = sum(r["gold"] != label and r["prediction"] == label for r in rows)
        fn = sum(r["gold"] == label and r["prediction"] != label for r in rows)
        scores.append(0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn))
    return sum(scores) / len(scores)
