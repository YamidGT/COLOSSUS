import pytest
from pydantic import ValidationError

from colossus.contracts.core import new_id, utcnow
from colossus.contracts.models import GateResult
from colossus.verify.outcomes import classify_cbmc, classify_crosshair, classify_dafny


def gate(status, outcome):
    return GateResult(
        gate_id=new_id(),
        case_id=new_id(),
        candidate_id=new_id(),
        candidate_hash="a" * 64,
        check_profile_id="formal-v1",
        category="formal",
        status=status,
        proof_outcome=outcome,
        scope=["recorded-output"],
        tool_version="not-invoked",
        command_profile_hash="b" * 64,
        started_at=utcnow(),
        finished_at=utcnow(),
        evidence_ids=[],
    )


def test_missing_tools_stay_unsupported():
    assert classify_dafny(tool_present=False, exit_code=0, stdout="0 errors") == (
        "not_applicable",
        "UNSUPPORTED",
    )
    assert classify_crosshair(tool_present=False, counterexample=None, explored=True)[1] == (
        "UNSUPPORTED"
    )
    assert classify_cbmc(tool_present=True, stdout="VERIFICATION SUCCESSFUL") == (
        "not_applicable",
        "UNSUPPORTED",
    )


def test_dafny_success_marker_is_proved_and_timeout_is_unknown():
    proved = classify_dafny(
        tool_present=True,
        exit_code=0,
        stdout="Dafny program verifier finished with 0 errors",
    )
    assert proved == ("pass", "PROVED")
    assert classify_dafny(tool_present=True, exit_code=None, stdout="") == ("timeout", "UNKNOWN")
    assert classify_dafny(tool_present=True, exit_code=1, stdout="Error: counterexample")[1] == (
        "COUNTEREXAMPLE"
    )
    assert classify_dafny(tool_present=True, exit_code=1, stdout="resolution error")[1] == "UNKNOWN"


def test_crosshair_without_a_counterexample_is_unknown():
    assert classify_crosshair(tool_present=True, counterexample=None, explored=True) == (
        "not_applicable",
        "UNKNOWN",
    )
    assert classify_crosshair(tool_present=True, counterexample="x = 1", explored=True) == (
        "fail",
        "COUNTEREXAMPLE",
    )


def test_unknown_cannot_be_recorded_as_a_formal_pass():
    status, outcome = classify_crosshair(tool_present=True, counterexample=None, explored=True)
    with pytest.raises(ValidationError, match="Formal pass"):
        gate("pass", outcome)
    gate(status, outcome)
