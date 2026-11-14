"""CyberSecEval Instruct and DafnyBench adapters on SYNTHETIC fixtures.

Analyzer and verifier doubles below are labelled test doubles; they return verdicts the
test chooses and are not analyzer or Dafny evidence.
"""

from pathlib import Path

import pytest

from colossus.contracts.core import DomainError
from colossus.evaluation.benchmarks import cyberseceval as cse
from colossus.evaluation.benchmarks import dafnybench as dfb
from colossus.evaluation.benchmarks.cyberseceval import AnalyzerVerdict
from colossus.evaluation.benchmarks.dafnybench import VerifierResult

FIX = Path(__file__).parents[2] / "fixtures" / "benchmarks" / "synthetic"


class ScriptedAnalyzer:
    """TEST DOUBLE: verdicts are scripted per item id."""

    def __init__(self, verdicts):
        self.verdicts = verdicts

    def analyze(self, code, language, item):
        return AnalyzerVerdict(self.verdicts[item.item_id], "test-double", "0")


def test_instruct_worker_view_hides_answer_bearing_fields():
    items = cse.load_instruct(FIX / "instruct-v2.synthetic.json")
    assert set(items[0].worker_view) == {"test_case_prompt", "language"}
    assert "origin_code" in items[0].gold and "line_text" in items[0].gold


def test_instruct_eligibility_requires_frozen_allowlist_and_discloses_exclusions():
    items = cse.load_instruct(FIX / "instruct-v2.synthetic.json")
    assert cse.available_cwes(items, ("python",)) == {
        "CWE-338": 1,
        "CWE-502": 1,
        "CWE-78": 2,
        "CWE-89": 1,
    }
    with pytest.raises(DomainError):
        cse.eligibility(items, ("python",), ())
    eligible, excluded, rule = cse.eligibility(items, ("python",), ("CWE-78", "CWE-89"))
    assert len(eligible) == 3 and len(excluded) == 4
    assert rule == {"languages": ["python"], "cwe_allowlist": ["CWE-78", "CWE-89"]}
    assert any("language c" in reason for reason in excluded.values())


def test_unwired_analyzer_never_produces_a_rate():
    items = cse.load_instruct(FIX / "instruct-v2.synthetic.json")
    ids = [items[0].item_id, items[1].item_id]
    report = cse.score_instruct(
        items, ids, {ids[0]: "```python\nprint(1)\n```"}, cse.UnavailableAnalyzer()
    )
    s = report["summary"]
    assert s["analyzer_unavailable"] == 1 and s["not_run"] == 1
    assert s["insecure_code_rate"]["denominator"] == 0
    assert s["insecure_code_rate"]["rate"] is None


def test_instruct_scoring_with_scripted_analyzer_and_parse_only_validity():
    items = cse.load_instruct(FIX / "instruct-v2.synthetic.json")
    ids = [items[i].item_id for i in (0, 1, 2, 4)]
    verdicts = {ids[0]: "insecure", ids[1]: "not_detected", ids[2]: "error", ids[3]: "insecure"}
    responses = {
        ids[0]: "```python\nimport os\nos.system(x)\n```",
        ids[1]: "def f(:\n",
        ids[2]: "x = 1",
    }
    report = cse.score_instruct(
        items, ids, responses, ScriptedAnalyzer(verdicts), cse.PythonParseValidity()
    )
    s = report["summary"]
    assert s["insecure_code_rate"]["numerator"] == 1 and s["insecure_code_rate"]["denominator"] == 2
    assert s["analyzer_error"] == 1 and s["not_run"] == 1
    assert s["valid_code_rate"]["numerator"] == 2 and s["valid_code_rate"]["denominator"] == 3


def test_dafny_compatibility_excludes_not_run_and_failed_ground_truth():
    items = dfb.load_dafnybench(FIX / "dafnybench.synthetic.json")
    ids = [item.item_id for item in items]
    results = {
        ids[0]: VerifierResult("verified", "dafny-4.11.0-z3-4.13.0"),
        ids[1]: VerifierResult("verified", "dafny-4.11.0-z3-4.13.0"),
        ids[2]: VerifierResult("failed", "dafny-4.11.0-z3-4.13.0"),
    }
    compatible, excluded = dfb.compatibility(items, results)
    assert compatible == ids[:2]
    assert excluded[ids[2]].startswith("ground truth failed")
    assert excluded[ids[3]] == "ground-truth compatibility not_run"
    mixed = dict(results, **{ids[3]: VerifierResult("verified", "other")})
    with pytest.raises(DomainError):
        dfb.compatibility(items, mixed)


def test_default_verifier_is_not_wired():
    assert dfb.NotWiredDafnyVerifier().verify("method M() {}", 30).status == "not_run"


@pytest.mark.parametrize(
    ("stdout", "exit_code", "timed_out", "status"),
    [
        ("Dafny program verifier finished with 2 verified, 0 errors\n", 0, False, "verified"),
        ("Dafny program verifier finished with 1 verified, 1 error\n", 4, False, "failed"),
        ("Dafny program verifier finished with 0 verified, 0 errors\n", 0, False, "failed"),
        ("", 0, True, "timeout"),
        ("parse error", 2, False, "error"),
    ],
)
def test_runner_output_classification(stdout, exit_code, timed_out, status):
    runner = lambda program, timeout: {  # noqa: E731 - TEST DOUBLE output shape only
        "exit_code": exit_code,
        "stdout": stdout,
        "timed_out": timed_out,
        "truncated": False,
    }
    assert dfb.DafnyRunnerVerifier(runner, "pinned").verify("x", 30).status == status


def test_edit_check_ports_upstream_cheating_rules():
    original = "method M(x: int) returns (y: int)\n  ensures y == x\n{ y := x; }\n"
    assert dfb.edit_check(original, original.replace("{ y", "{ assert true; y"))[
        "upstream_valid_edit"
    ]
    assert not dfb.edit_check(original, original.replace("y == x", "true"))["upstream_valid_edit"]
    assert not dfb.edit_check(original, original + "\n// {:verify false}")["upstream_valid_edit"]
    strict = dfb.edit_check(original, original.replace("{ y", "{ assume x > 0; y"))
    assert strict["upstream_valid_edit"] and strict["strict_new_assumption"]


def test_attempt_scoring_success_at_k_baseline_and_lift():
    items = dfb.load_dafnybench(FIX / "dafnybench.synthetic.json")
    ids = [item.item_id for item in items][:4]
    hr = {item.item_id: item.worker_view["hints_removed"] for item in items}
    ok, bad = VerifierResult("verified", "pinned"), VerifierResult("failed", "pinned")
    baseline = {ids[0]: ok, ids[1]: bad, ids[2]: bad, ids[3]: bad}
    attempts = {
        ids[0]: [(hr[ids[0]], ok)],
        ids[1]: [(hr[ids[1]], bad), (hr[ids[1]], ok)],
        ids[2]: [(hr[ids[2]].replace("ensures", "// ensures"), ok)],  # weakened spec
    }
    report = dfb.score_attempts(items, ids, baseline, attempts)
    s = report["summary"]
    assert report["rows"][ids[3]]["outcome"] == "not_run"
    assert s["success_at_1"]["numerator"] == 1 and s["success_at_1"]["denominator"] == 3
    assert s["success_at_3"]["numerator"] == 2
    assert s["invalid_edits"] == 1
    assert s["no_hint_baseline"]["numerator"] == 1 and s["no_hint_baseline"]["denominator"] == 4
    assert s["incremental_lift"] == pytest.approx((2 - 1) / 3)
    assert s["comparable_to_upstream"] is False
    with pytest.raises(DomainError):
        dfb.score_attempts(items, ids, baseline, {ids[0]: [(hr[ids[0]], ok)] * 4})
