"""CTIBench CTI-RCM / CTI-VSP loaders for locally provided official TSV files.

Official source: https://huggingface.co/datasets/AI4Sec/cti-bench (files ``cti-rcm.tsv``,
``cti-vsp.tsv``; columns URL, Description, Prompt, GT). License CC BY-NC-SA 4.0
(dataset card; repository https://github.com/maveryn/cti-bench LICENSE.txt). Paper
https://arxiv.org/abs/2406.07599.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any

from colossus.contracts.core import DomainError
from colossus.evaluation.benchmarks.common import BenchmarkItem, read_text, unique_items

COLUMNS = ("URL", "Description", "Prompt", "GT")
_CVE = re.compile(r"(CVE-\d{4}-\d{4,})")
SOURCE = {
    "source_url": "https://huggingface.co/datasets/AI4Sec/cti-bench",
    "license": "CC-BY-NC-SA-4.0",
    "citation": "https://arxiv.org/abs/2406.07599",
}
CONTAMINATION = {
    "public_since": "2024-06 (arXiv 2406.07599)",
    "training_exposure": "possible_unknown",
    "notes": "CVE descriptions and NVD labels are public; model training exposure unknown.",
}


def _load(path: str | Path, suite: str) -> list[BenchmarkItem]:
    text = read_text(path)
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if tuple(reader.fieldnames or ())[: len(COLUMNS)] != COLUMNS:
        raise DomainError("ctibench_shape", f"Expected columns {COLUMNS}", 422)
    items = []
    for index, row in enumerate(reader):
        if any(row.get(column) is None for column in COLUMNS):
            raise DomainError("ctibench_shape", f"Row {index} is truncated", 422)
        cve = _CVE.search(row["URL"] or "")
        # Upstream rows have no id column; row position within the pinned file is stable.
        item_id = f"{suite}:{index:04d}:{cve[1] if cve else 'nocve'}"
        items.append(
            BenchmarkItem(
                suite=suite,
                item_id=item_id,
                worker_view={"prompt": row["Prompt"]},
                gold={"gt": row["GT"].strip()},
                meta={"url": row["URL"], "row_index": index},
            )
        )
    return unique_items(items)


def load_rcm(path: str | Path) -> list[BenchmarkItem]:
    return _load(path, "cti-rcm")


def load_vsp(path: str | Path) -> list[BenchmarkItem]:
    return _load(path, "cti-vsp")


def gold_map(items: list[BenchmarkItem], ids: list[str]) -> dict[str, str]:
    by_id = {item.item_id: item for item in items}
    return {item_id: by_id[item_id].gold["gt"] for item_id in ids}


def dataset_record(path: str | Path, sha256: str, revision: str | None) -> dict[str, Any]:
    return {**SOURCE, "file": Path(path).name, "sha256": sha256, "revision": revision}
