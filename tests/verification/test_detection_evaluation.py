import pytest

from colossus.contracts.core import new_id
from colossus.contracts.models import Finding
from colossus.detect.evaluate import score

COMMIT = "a" * 40
TRUTH = {
    "source_commit": COMMIT,
    "cases": [{"id": "sql", "file": "app.py", "line": 10, "cwe": "CWE-89"}],
}


def finding(**changes):
    return Finding(
        finding_id=new_id(),
        manifest_hash="b" * 64,
        fingerprint="c" * 64,
        title="Signal",
        cwe="CWE-89",
        location={"file": "app.py", "line": 10},
        source_tools=["fixture"],
        evidence_ids=["d" * 64],
    ).model_copy(update=changes)


def test_wrong_cwe_on_same_line_is_unadjudicated_not_a_true_positive():
    result = score([finding(cwe="CWE-79")], TRUTH, COMMIT)
    assert result["reference_recall"] == 0
    assert result["unadjudicated_reported"] == 1
    assert result["precision"] is None


def test_duplicate_signals_do_not_inflate_score_or_hide_confirmation():
    result = score(
        [finding(), finding(status="confirmed"), finding(disposition="suppress")], TRUTH, COMMIT
    )
    assert result["reference_recall"] == 1
    assert result["reported_unique"] == 1
    assert result["duplicate_records"] == 2
    assert result["confirmed_dynamic"] == ["sql"]
    empty = score([finding(disposition="suppress")], TRUTH, COMMIT)
    assert empty["reference_recall"] == 0 and empty["reference_match_rate"] is None


@pytest.mark.parametrize(
    "truth,commit",
    [
        (TRUTH, "e" * 40),
        ({"cases": TRUTH["cases"]}, COMMIT),
        (TRUTH | {"cases": []}, COMMIT),
        (TRUTH | {"cases": TRUTH["cases"] * 2}, COMMIT),
    ],
)
def test_unfrozen_stale_or_invalid_reference_cannot_be_scored(truth, commit):
    with pytest.raises(ValueError):
        score([finding()], truth, commit)
