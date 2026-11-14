"""Selection, manifest and lock behaviour on SYNTHETIC fixtures."""

import copy
import json
from pathlib import Path

import pytest

from colossus.contracts.core import DomainError
from colossus.evaluation.benchmarks import (
    assess_benchmark_lock,
    build_manifest,
    ctibench,
    freeze_manifest,
    result_rows,
    select_ids,
)
from colossus.evaluation.benchmarks.common import file_sha256, wilson_interval

ROOT = Path(__file__).parents[2]
FIX = ROOT / "fixtures" / "benchmarks" / "synthetic"


def _draft(n=3):
    path = FIX / "cti-rcm.synthetic.tsv"
    items = ctibench.load_rcm(path)
    ids = [item.item_id for item in items]
    manifest = build_manifest(
        suite="cti-rcm",
        items=items,
        eligible_ids=ids[:-1],
        exclusions={ids[-1]: "SYNTHETIC exclusion for test"},
        n=n,
        seed=42,
        dataset=ctibench.dataset_record(path, file_sha256(path), "synthetic"),
        contamination=ctibench.CONTAMINATION,
        eligibility_rule={"all_rows": True},
    )
    return items, manifest


def test_selection_is_deterministic_and_order_independent():
    ids = [f"x{i:03d}" for i in range(100)]
    first = select_ids(ids, 10, 42)
    assert first == select_ids(list(reversed(ids)), 10, 42)
    assert first == sorted(first) and len(first) == 10
    assert first != select_ids(ids, 10, 43)
    assert select_ids(ids[:5], 30, 42) == ids[:5]  # fewer than requested: all, size reported


def test_selection_pins_known_seed42_output():
    # Regression pin: changing the method silently would change every frozen sample.
    assert select_ids([f"x{i:03d}" for i in range(100)], 5, 42) == [
        "x003",
        "x014",
        "x035",
        "x081",
        "x094",
    ]


def test_hidden_exclusions_are_refused():
    items = ctibench.load_rcm(FIX / "cti-rcm.synthetic.tsv")
    with pytest.raises(DomainError) as caught:
        build_manifest(
            suite="cti-rcm",
            items=items,
            eligible_ids=[items[0].item_id],
            exclusions={},
            n=1,
            seed=42,
            dataset={"source_url": "u", "license": "l", "sha256": "0" * 64},
            contamination=ctibench.CONTAMINATION,
            eligibility_rule={},
        )
    assert caught.value.code == "hidden_exclusion"


def test_manifest_records_hashes_disclosure_and_contamination():
    _, manifest = _draft()
    assert manifest["status"] == "draft" and manifest["scored_execution_allowed"] is False
    assert manifest["selection"]["actual_size"] == 3
    assert manifest["selection"]["eligible_count"] == 5
    assert manifest["exclusions"][0]["reason"].startswith("SYNTHETIC")
    assert manifest["contamination"]["training_exposure"] == "possible_unknown"
    assert manifest["disclosure"]["comparable_to_upstream_full_results"] is False
    assert all(len(row["content_sha256"]) == 64 for row in manifest["items"])


def test_freeze_then_assess_keeps_every_row_not_run():
    items, manifest = _draft()
    lock = freeze_manifest(manifest, items)
    report = assess_benchmark_lock(lock)
    assert report["executed"] is False and report["scores"] is None
    assert [r["outcome"] for r in report["rows"]] == ["not_run"] * 3


def test_candidate_only_and_unfrozen_are_refused():
    _, manifest = _draft()
    with pytest.raises(DomainError) as caught:
        assess_benchmark_lock(dict(manifest, status="candidate_only"))
    assert caught.value.code == "candidate_only"
    with pytest.raises(DomainError) as caught:
        freeze_manifest(dict(manifest, status="candidate_only"))
    assert caught.value.code == "candidate_only"
    with pytest.raises(DomainError) as caught:
        assess_benchmark_lock(manifest)
    assert caught.value.code == "campaign_not_frozen"


def test_repository_candidate_roster_cannot_be_a_benchmark_lock():
    roster = json.loads((ROOT / "evaluation" / "repository-candidates.json").read_text())
    with pytest.raises(DomainError) as caught:
        assess_benchmark_lock(roster)
    assert caught.value.code == "candidate_only"


def test_scored_execution_flag_and_tampering_are_refused():
    items, manifest = _draft()
    lock = freeze_manifest(manifest, items)
    with pytest.raises(DomainError) as caught:
        assess_benchmark_lock(dict(lock, scored_execution_allowed=True))
    assert caught.value.code == "campaign_not_executed"
    tampered = copy.deepcopy(lock)
    tampered["items"].pop()
    with pytest.raises(DomainError) as caught:
        assess_benchmark_lock(tampered)
    assert caught.value.code == "benchmark_lock_drift"


def test_freeze_refuses_null_hashes_and_content_drift():
    items, manifest = _draft()
    broken = copy.deepcopy(manifest)
    broken["items"][0]["content_sha256"] = None
    with pytest.raises(DomainError) as caught:
        freeze_manifest(broken)
    assert caught.value.code == "benchmark_lock_incomplete"
    drifted = copy.deepcopy(manifest)
    drifted["items"][0]["content_sha256"] = "f" * 64
    with pytest.raises(DomainError) as caught:
        freeze_manifest(drifted, items)
    assert caught.value.code == "benchmark_lock_drift"
    empty = dict(manifest, items=[])
    with pytest.raises(DomainError):
        freeze_manifest(empty)


def test_result_rows_keep_unscored_rows_visible_and_refuse_extras():
    items, manifest = _draft()
    lock = freeze_manifest(manifest, items)
    first = lock["items"][0]["item_id"]
    rows = result_rows(lock, {first: {"outcome": "scored", "exact": True}})
    assert rows[0]["outcome"] == "scored"
    assert [r["outcome"] for r in rows[1:]] == ["not_run", "not_run"]
    with pytest.raises(DomainError):
        result_rows(lock, {"not-locked": {"outcome": "scored"}})


def test_wilson_interval():
    assert wilson_interval(0, 0) is None
    low, high = wilson_interval(5, 10)
    assert low == pytest.approx(0.2366, abs=1e-4) and high == pytest.approx(0.7634, abs=1e-4)
