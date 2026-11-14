"""Freeze/lock checks for benchmark samples.

Mirrors ``colossus.verify.campaign.assess_campaign``: candidate-only rosters are refused,
``scored_execution_allowed=True`` is refused, only ``status=frozen`` with nonnull hashes is
accepted, and every selected row stays visible. Rows without evidence are ``not_run``.
"""

from __future__ import annotations

import re
from typing import Any

from colossus.contracts.core import DomainError
from colossus.evaluation.benchmarks.common import BenchmarkItem
from colossus.evaluation.benchmarks.selection import MANIFEST_SCHEMA, manifest_hash

_SHA = re.compile(r"^[a-f0-9]{64}$")


def _check_common(manifest: Any) -> None:
    if not isinstance(manifest, dict):
        raise DomainError("benchmark_lock_shape", "Benchmark manifest must be an object", 422)
    if manifest.get("status") == "candidate_only":
        raise DomainError(
            "candidate_only", "Candidate-only roster is not a benchmark sample lock", 422
        )
    if manifest.get("scored_execution_allowed") is True:
        raise DomainError(
            "campaign_not_executed", "This adapter does not start scored execution", 422
        )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise DomainError("benchmark_lock_shape", "Unknown benchmark manifest schema", 422)


def _missing_hashes(manifest: dict[str, Any]) -> list[str]:
    missing = []
    if not _SHA.match(str((manifest.get("dataset") or {}).get("sha256") or "")):
        missing.append("dataset.sha256")
    items = manifest.get("items")
    if not isinstance(items, list) or not items:
        missing.append("items")
        return missing
    for row in items:
        if not isinstance(row, dict) or not row.get("item_id"):
            missing.append("items[].item_id")
            continue
        for key in ("content_sha256", "worker_view_sha256"):
            if not _SHA.match(str(row.get(key) or "")):
                missing.append(f"{row['item_id']}.{key}")
    return missing


def freeze_manifest(
    manifest: dict[str, Any], items: list[BenchmarkItem] | None = None
) -> dict[str, Any]:
    """Return a frozen copy. Refuses drafts that lack hashes or an evaluated selection.

    When ``items`` is given, every selected row's hashes are recomputed against them.
    """
    _check_common(manifest)
    if manifest.get("status") != "draft":
        raise DomainError("benchmark_lock_state", "Only a draft manifest can be frozen", 422)
    missing = _missing_hashes(manifest)
    if missing:
        raise DomainError(
            "benchmark_lock_incomplete", f"Cannot freeze; missing: {missing[:5]}", 422
        )
    if items is not None:
        verify_items(manifest, items)
    frozen = dict(manifest, status="frozen")
    frozen["manifest_sha256"] = manifest_hash(frozen)
    return frozen


def verify_items(manifest: dict[str, Any], items: list[BenchmarkItem]) -> None:
    by_id = {item.item_id: item for item in items}
    for row in manifest["items"]:
        item = by_id.get(row["item_id"])
        if item is None:
            raise DomainError("benchmark_lock_drift", f"{row['item_id']} missing", 422)
        if (
            item.content_hash != row["content_sha256"]
            or item.worker_view_hash != row["worker_view_sha256"]
        ):
            raise DomainError("benchmark_lock_drift", f"{row['item_id']} content changed", 422)


def assess_benchmark_lock(manifest: Any) -> dict[str, Any]:
    """Validate a lock without executing it. Every row is reported as ``not_run``."""
    _check_common(manifest)
    if manifest.get("status") != "frozen":
        raise DomainError("campaign_not_frozen", "Benchmark lock is not frozen", 422)
    missing = _missing_hashes(manifest)
    if missing:
        raise DomainError("benchmark_lock_incomplete", f"Frozen lock missing {missing[:5]}", 422)
    if manifest.get("manifest_sha256") != manifest_hash(manifest):
        raise DomainError("benchmark_lock_drift", "Manifest hash does not match content", 422)
    return {
        "suite": manifest["suite"],
        "executed": False,
        "scores": None,
        "rows": [
            {
                "suite": manifest["suite"],
                "item_id": row["item_id"],
                "outcome": "not_run",
                "reason": "scored benchmark execution was not started",
            }
            for row in manifest["items"]
        ],
    }


def result_rows(
    manifest: dict[str, Any], scored: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Join scorer output onto the locked sample, keeping unscored rows as ``not_run``.

    Scored ids outside the lock are refused rather than silently added.
    """
    assess_benchmark_lock(manifest)
    locked = [row["item_id"] for row in manifest["items"]]
    extra = set(scored) - set(locked)
    if extra:
        raise DomainError("benchmark_unlocked_rows", f"Rows not in lock: {sorted(extra)[:5]}", 422)
    rows = []
    for item_id in locked:
        row = scored.get(item_id)
        if row is None:
            rows.append({"item_id": item_id, "outcome": "not_run", "reason": "no evidence"})
        else:
            rows.append({"item_id": item_id, **row})
    return rows
