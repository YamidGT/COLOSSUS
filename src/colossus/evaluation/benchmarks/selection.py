"""Deterministic seeded subset selection and the benchmark sample manifest."""

from __future__ import annotations

import random
from typing import Any

from colossus.contracts.core import DomainError, content_hash
from colossus.evaluation.benchmarks.common import BenchmarkItem

SELECTION_METHOD = "python-random.Random(seed).sample(sorted(eligible_ids), n)"
MANIFEST_SCHEMA = "colossus.benchmark-sample/v1"


def select_ids(eligible_ids: list[str], n: int, seed: int) -> list[str]:
    """Sort stable IDs, then sample ``min(n, len)`` with a dedicated seeded RNG.

    Returned order is sorted so the manifest is independent of sampling order. If fewer
    than ``n`` are eligible, all are returned and the caller must report the actual size.
    """
    if n < 1:
        raise DomainError("selection_size", "Sample size must be positive", 422)
    ordered = sorted(set(eligible_ids))
    if len(ordered) != len(eligible_ids):
        raise DomainError("dataset_duplicate_id", "Eligible ids contain duplicates", 422)
    if len(ordered) <= n:
        return ordered
    return sorted(random.Random(seed).sample(ordered, n))


def build_manifest(
    *,
    suite: str,
    items: list[BenchmarkItem],
    eligible_ids: list[str],
    exclusions: dict[str, str],
    n: int,
    seed: int,
    dataset: dict[str, Any],
    contamination: dict[str, Any],
    eligibility_rule: dict[str, Any],
) -> dict[str, Any]:
    """Return a draft manifest. ``freeze_manifest`` turns it into a lock.

    ``dataset`` must name source_url, license and local sha256 of the file read.
    ``exclusions`` maps every non-eligible id to a disclosed reason.
    """
    by_id = {item.item_id: item for item in items}
    unknown = (set(eligible_ids) | set(exclusions)) - set(by_id)
    if unknown:
        raise DomainError("selection_unknown_id", f"Unknown ids: {sorted(unknown)[:5]}", 422)
    overlap = set(eligible_ids) & set(exclusions)
    if overlap:
        raise DomainError("selection_overlap", "An id is both eligible and excluded", 422)
    undisclosed = set(by_id) - set(eligible_ids) - set(exclusions)
    if undisclosed:
        raise DomainError(
            "hidden_exclusion",
            f"{len(undisclosed)} items are neither eligible nor disclosed as excluded",
            422,
        )
    for key in ("source_url", "license", "sha256"):
        if not dataset.get(key):
            raise DomainError("manifest_dataset", f"Dataset record needs {key}", 422)
    for key in ("training_exposure", "public_since"):
        if key not in contamination:
            raise DomainError("manifest_contamination", f"Contamination needs {key}", 422)
    selected = select_ids(eligible_ids, n, seed) if eligible_ids else []
    return {
        "schema": MANIFEST_SCHEMA,
        "suite": suite,
        "status": "draft",
        "scored_execution_allowed": False,
        "dataset": dict(dataset),
        "selection": {
            "method": SELECTION_METHOD,
            "seed": seed,
            "requested_size": n,
            "actual_size": len(selected),
            "eligible_count": len(eligible_ids),
            "total_items": len(by_id),
            "eligibility_rule": eligibility_rule,
        },
        "exclusions": [
            {"item_id": key, "reason": value} for key, value in sorted(exclusions.items())
        ],
        "items": [
            {
                "item_id": item_id,
                "content_sha256": by_id[item_id].content_hash,
                "worker_view_sha256": by_id[item_id].worker_view_hash,
            }
            for item_id in selected
        ],
        "contamination": dict(contamination),
        "disclosure": {
            "subset_of_public_benchmark": True,
            "comparable_to_upstream_full_results": False,
            "notes": [],
        },
    }


def manifest_hash(manifest: dict[str, Any]) -> str:
    body = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    return content_hash(body)
