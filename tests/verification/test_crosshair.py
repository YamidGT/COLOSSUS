"""Unit tests for the CrossHair report parser and obligation binding (no execution)."""

import hashlib

import pytest

from colossus.contracts.core import DomainError
from colossus.contracts.models import Obligation
from colossus.sandbox.launcher import ProcessResult
from colossus.verification.crosshair import (
    BOUND_PROFILE_ID,
    CrossHairAdapter,
    Harness,
    gate_status,
    inspect_harness,
    parse_report,
    to_gate_result,
)

CLAMP = b'''def clamp(x: int) -> int:
    """
    pre: x > -1000
    post: 0 <= __return__
    post: __return__ <= 10
    """
    if x < 0:
        return 0
    return min(x, 10)
'''
CASE = "00000000-0000-4000-8000-000000000001"
H = "a" * 64


def harness() -> Harness:
    facts = inspect_harness("clamp.py", CLAMP, "clamp")
    assert isinstance(facts, Harness)
    return facts


def obligation(source=CLAMP, symbol="clamp", kind="bounded", **changes) -> Obligation:
    facts = inspect_harness("clamp.py", source, symbol)
    spec = facts.spec_hash if isinstance(facts, Harness) else H
    data = {
        "obligation_id": "obl-clamp",
        "description": "clamp stays within range",
        "origin": "approved_template",
        "source_ref": "clamp.py:clamp",
        "approved": True,
        "required": True,
        "component": "clamp",
        "symbol": symbol,
        "backend": "crosshair",
        "spec_hash": spec,
        "harness_hash": hashlib.sha256(source).hexdigest(),
        "assumptions": ["inputs are plain ints"],
        "bounds": {"deadline_seconds": 30, "per_condition_timeout": 10},
        "required_evidence_kind": kind,
        "allowed_bound_profile_id": BOUND_PROFILE_ID if kind == "bounded" else None,
    }
    return Obligation(**(data | changes))


def run(stdout="", exit_code=0, timed_out=False, truncated=False, stderr=""):
    return ProcessResult(exit_code, stdout, stderr, timed_out, 1.0, truncated)


CONFIRMED = (
    "/work/source/clamp.py:4: info: Confirmed over all paths.\n"
    "/work/source/clamp.py:5: info: Confirmed over all paths.\n"
)


def test_harness_facts_are_static():
    facts = harness()
    assert facts.post_lines == (4, 5)
    assert facts.contract_text == "pre: x > -1000\npost: 0 <= __return__\npost: __return__ <= 10"
    assert facts.target_line == 7


def test_clean_exhaustion_is_bounded_only_when_obligation_allows_it():
    bounded = parse_report(run(CONFIRMED), harness(), True)
    assert bounded["proof_outcome"] == "BOUNDED_PASS"
    assert bounded["exploration"] == "exhausted"
    proof = parse_report(run(CONFIRMED), harness(), False)
    assert proof["proof_outcome"] == "UNKNOWN"
    assert proof["exploration"] == "exhausted"


def test_counterexample_carries_concrete_input():
    out = "/work/source/clamp.py:5: error: false when calling clamp(11) (which returns 11)\n"
    result = parse_report(run(out, 1), harness(), True)
    assert result["proof_outcome"] == "COUNTEREXAMPLE"
    assert result["counterexample"]["call"] == "clamp(11)"
    assert result["counterexample"]["returns"] == "11"
    exc = "/work/source/clamp.py:8: error: ZeroDivisionError: division by zero when calling clamp(0)\n"
    raised = parse_report(run(exc, 1), harness(), True)
    assert raised["proof_outcome"] == "COUNTEREXAMPLE"
    assert raised["counterexample"]["call"] == "clamp(0)"
    assert raised["counterexample"]["returns"] is None


@pytest.mark.parametrize(
    "result",
    [
        run(""),  # empty report
        run("", 0, stderr="WARNING: Targets found, but contain no checkable functions."),
        run(CONFIRMED, timed_out=True, exit_code=-9),
        run(CONFIRMED, truncated=True),
        run(CONFIRMED, exit_code=2),  # crash after printing
        run(CONFIRMED.splitlines()[0] + "\n"),  # one postcondition unreported
        run(CONFIRMED + "/work/source/clamp.py:6: info: Confirmed over all paths.\n"),
        run(CONFIRMED.replace("clamp.py:5", "other.py:5")),  # report for a substituted file
        run(CONFIRMED.replace("/work/source/", "/tmp/")),
        run(CONFIRMED + "garbage line\n"),
        run(CONFIRMED.replace("Confirmed over all paths.", "Not confirmed.", 1)),
        run(CONFIRMED.replace("info: Confirmed", "info: confirmed", 1)),
        run(CONFIRMED * 2),  # duplicated condition lines
        run("/work/source/clamp.py:4: error: invalid syntax (<string>, line 1)\n", 1),
        run("/work/source/clamp.py:5: error: false when calling clamp(11)\n", 0),
        run("/work/source/clamp.py:5: error: false when calling clamp(11)\n", 2),
    ],
)
def test_empty_tampered_or_partial_reports_never_pass(result):
    parsed = parse_report(result, harness(), True)
    assert parsed["proof_outcome"] == "UNKNOWN"
    assert gate_status(parsed, obligation()) != "pass"


def test_unsupported_constructs():
    side = (
        '/work/source/clamp.py:7: error: SideEffectDetected: We\'ve blocked a file writing '
        'operation on "/tmp/x". when calling clamp(0)\n'
    )
    assert parse_report(run(side, 1), harness(), True)["proof_outcome"] == "UNSUPPORTED"
    for source, symbol, reason in [
        (b"async def f(x: int) -> int:\n    '''post: True'''\n    return x\n", "f", "async"),
        (b"def f(x: int) -> int:\n    return x\n", "f", "no PEP 316 contract"),
        (b"def f(x: int) -> int:\n    '''pre: x > 0'''\n    return x\n", "f", "postcondition"),
        (b"def f(:\n", "f", "parseable"),
        (CLAMP, "missing", "unique"),
        (b"@dec\ndef f(x):\n    '''post: True'''\n    return x\n", "f", "decorated"),
    ]:
        facts = inspect_harness("clamp.py", source, symbol)
        assert isinstance(facts, str) and reason in facts
    assert isinstance(inspect_harness("pkg/clamp.py", CLAMP, "clamp"), str)
    assert isinstance(inspect_harness("clamp.c", CLAMP, "clamp"), str)


def test_unsupported_obligation_never_runs():
    class NoLauncher:
        def __getattr__(self, name):
            raise AssertionError("sandbox must not be used for unsupported harnesses")

    source = b"def f(x: int) -> int:\n    return x\n"
    adapter = CrossHairAdapter(NoLauncher(), "sha256:" + "b" * 64)
    result = adapter.execute(CASE, obligation(source, "f"), {"clamp.py": source}, "clamp.py")
    assert result["proof_outcome"] == "UNSUPPORTED"
    assert gate_status(result, obligation(source, "f")) == "error"
    optional = obligation(source, "f", required=False)
    assert gate_status(result, optional) == "not_applicable"


@pytest.mark.parametrize(
    "files,changes,code",
    [
        ({"clamp.py": CLAMP + b"# edit\n"}, {}, "formal_binding"),
        ({"clamp.py": CLAMP}, {"spec_hash": H}, "formal_binding"),
        ({}, {}, "formal_binding"),
        ({"clamp.py": CLAMP}, {"backend": "dafny"}, "formal_scope"),
        ({"clamp.py": CLAMP}, {"approved": False}, "formal_scope"),
        ({"clamp.py": CLAMP}, {"bounds": {"deadline_seconds": 481}}, "formal_limit"),
        ({"clamp.py": CLAMP}, {"bounds": {"unbounded": 1}}, "formal_limit"),
        ({"clamp.py": CLAMP}, {"bounds": {"deadline_seconds": 5, "per_condition_timeout": 10}}, "formal_limit"),
        ({"clamp.py": CLAMP}, {"bounds": {"per_path_timeout": "5"}}, "formal_limit"),
    ],
)
def test_tampered_or_out_of_policy_obligation_is_refused(files, changes, code):
    class NoLauncher:
        def __getattr__(self, name):
            raise AssertionError("sandbox must not be used")

    with pytest.raises(DomainError) as error:
        CrossHairAdapter(NoLauncher(), "sha256:" + "b" * 64).execute(
            CASE, obligation(**changes), files, "clamp.py"
        )
    assert error.value.code == code


def test_spec_weakening_changes_spec_hash():
    weak = CLAMP.replace(b"post: __return__ <= 10", b"post: True")
    assert inspect_harness("clamp.py", weak, "clamp").spec_hash != harness().spec_hash


def test_gate_result_mapping():
    def gate(evidence, ob):
        return to_gate_result(
            evidence | {"obligation_id": ob.obligation_id, "command_profile_hash": H},
            ob,
            gate_id=CASE,
            case_id=CASE,
            candidate_id=CASE,
            candidate_hash=H,
            started_at="2026-11-14T00:00:00Z",
            finished_at="2026-11-14T00:00:01Z",
            evidence_ids=[H],
        )

    bounded = parse_report(run(CONFIRMED), harness(), True)
    passed = gate(bounded, obligation())
    assert (passed.status, passed.proof_outcome, passed.category) == ("pass", "BOUNDED_PASS", "formal")
    # A bounded result cannot satisfy a proof requirement even if relabelled.
    assert gate(bounded, obligation(kind="proof")).status == "error"
    cex = parse_report(
        run("/work/source/clamp.py:5: error: false when calling clamp(11) (which returns 11)\n", 1),
        harness(),
        True,
    )
    assert gate(cex, obligation()).status == "fail"
    timeout = parse_report(run("", -9, timed_out=True), harness(), True)
    assert gate(timeout, obligation()).status == "timeout"
    with pytest.raises(DomainError):
        gate(bounded | {"proof_outcome": "PROVED"}, obligation())
    with pytest.raises(DomainError):
        to_gate_result(
            bounded | {"obligation_id": "other", "command_profile_hash": H},
            obligation(),
            gate_id=CASE,
            case_id=CASE,
            candidate_id=CASE,
            candidate_hash=H,
            started_at="a",
            finished_at="b",
            evidence_ids=[],
        )
