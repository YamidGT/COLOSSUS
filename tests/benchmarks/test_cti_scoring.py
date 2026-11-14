"""CTIBench adapters on SYNTHETIC fixtures (fixtures/benchmarks/synthetic, not real data)."""

from pathlib import Path

import pytest

from colossus.contracts.core import DomainError
from colossus.evaluation.benchmarks import ctibench, cvss, cwe

FIX = Path(__file__).parents[2] / "fixtures" / "benchmarks" / "synthetic"


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ],
)
def test_cvss_base_scores_match_first_reference_values(vector, score):
    assert cvss.base_score(cvss.parse_vector(vector)) == score


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate
        "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Q",
    ],
)
def test_invalid_vectors_are_rejected(vector):
    assert cvss.parse_vector(vector) is None


def test_temporal_metrics_are_valid_but_ignored_for_base():
    parsed = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O")
    assert cvss.base_score(parsed) == 9.8


def test_rcm_loader_separates_prompt_from_gold():
    items = ctibench.load_rcm(FIX / "cti-rcm.synthetic.tsv")
    assert len(items) == 6
    assert set(items[0].worker_view) == {"prompt"}
    assert items[0].gold == {"gt": "CWE-79"}
    assert items[0].item_id == "cti-rcm:0000:CVE-0000-0000"


def test_loader_rejects_wrong_columns(tmp_path):
    bad = tmp_path / "bad.tsv"
    bad.write_text("Prompt\tGT\nx\tCWE-1\n")
    with pytest.raises(DomainError) as caught:
        ctibench.load_rcm(bad)
    assert caught.value.code == "ctibench_shape"


def test_rcm_scoring_keeps_invalid_and_not_run_rows():
    gold = {"a": "CWE-79", "b": "CWE-89", "c": "CWE-787", "d": "CWE-416"}
    responses = {
        "a": "Reasoning...\n**CWE-79**",
        "b": "The answer is CWE-89 probably",  # extra text on last line -> invalid
        "c": "x\nCWE-119.",  # parent of 787
    }
    hierarchy = cwe.load_cwe_hierarchy(FIX / "cwe-1000.synthetic.csv")
    assert hierarchy["CWE-787"] == {"CWE-119"}  # view 699 edge ignored
    report = cwe.score_rcm(gold, responses, hierarchy)
    s = report["summary"]
    assert report["rows"]["d"]["outcome"] == "not_run"
    assert report["rows"]["b"]["outcome"] == "invalid_output"
    assert (s["attempted"], s["invalid_output"], s["not_run"]) == (3, 1, 1)
    assert s["exact_accuracy"]["numerator"] == 1 and s["exact_accuracy"]["denominator"] == 3
    assert s["upstream_valid_only_accuracy"]["denominator"] == 2
    assert s["hierarchical_accuracy"]["numerator"] == 2


def test_vsp_scoring_reports_valid_only_mad_and_invalid_count():
    gold = {
        "a": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "b": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        "c": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "d": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    }
    responses = {
        "a": "summary\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "b": "summary\nAV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",  # bare, prefix added
        "c": "I think the score is 6.1",
    }
    report = cvss.score_vsp(gold, responses)
    s = report["summary"]
    assert report["rows"]["d"]["outcome"] == "not_run"
    assert report["rows"]["c"]["outcome"] == "invalid_output"
    assert report["rows"]["b"]["prefix_added"] is True
    assert report["rows"]["b"]["predicted_score"] == 7.1
    assert s["vector_validity"]["numerator"] == 2 and s["vector_validity"]["denominator"] == 3
    assert s["valid_only_mad"] == pytest.approx((0.0 + 1.6) / 2)
    assert s["component_agreement_over_attempted"]["C"]["numerator"] == 1


def test_gold_must_be_valid():
    with pytest.raises(DomainError):
        cvss.score_vsp({"a": "nonsense"}, {})
    with pytest.raises(DomainError):
        cwe.score_rcm({"a": "XSS"}, {})
