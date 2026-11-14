"""Shared item shape, hashing and proportion intervals for benchmark adapters."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from colossus.contracts.core import DomainError, content_hash

MAX_DATASET_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class BenchmarkItem:
    """One benchmark case.

    ``worker_view`` is what a candidate model may see. ``gold`` is evaluator-only and
    must never be placed in a prompt. ``content_hash`` covers both, so a changed label
    or prompt changes the manifest.
    """

    suite: str
    item_id: str
    worker_view: dict[str, Any]
    gold: dict[str, Any]
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        return content_hash({"worker_view": self.worker_view, "gold": self.gold})

    @property
    def worker_view_hash(self) -> str:
        return content_hash(self.worker_view)


def file_sha256(path: str | Path) -> str:
    path = Path(path)
    if not path.is_file():
        raise DomainError("dataset_missing", f"Dataset file not found: {path}", 422)
    if path.stat().st_size > MAX_DATASET_BYTES:
        raise DomainError("dataset_too_large", "Dataset file exceeds size limit", 422)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_text(path: str | Path) -> str:
    file_sha256(path)
    try:
        return Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DomainError("dataset_encoding", "Dataset is not UTF-8", 422) from exc


def unique_items(items: list[BenchmarkItem]) -> list[BenchmarkItem]:
    seen: set[str] = set()
    for item in items:
        if item.item_id in seen:
            raise DomainError("dataset_duplicate_id", f"Duplicate item id {item.item_id}", 422)
        seen.add(item.item_id)
    return items


def wilson_interval(successes: int, total: int, z: float = 1.959964) -> tuple[float, float] | None:
    """Wilson score interval; ``None`` when the denominator is zero."""
    if total <= 0:
        return None
    if not 0 <= successes <= total:
        raise ValueError("successes must be within [0, total]")
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def proportion(successes: int, total: int) -> dict[str, Any]:
    return {
        "numerator": successes,
        "denominator": total,
        "rate": successes / total if total else None,
        "wilson95": wilson_interval(successes, total),
    }


def last_nonempty_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.strip():
            return line.strip()
    return ""
