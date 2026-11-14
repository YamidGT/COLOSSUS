import json
import time
import uuid

import pytest

from colossus.contracts.models import GateResult
from colossus.control.store import Store
from colossus.observability.redact import redact
from colossus.observability.report import build_run_report, render_markdown, verify_report_hash

CASE_A = str(uuid.uuid5(uuid.NAMESPACE_URL, "colossus-test/case-a"))
CASE_B = str(uuid.uuid5(uuid.NAMESPACE_URL, "colossus-test/case-b"))
CAND = str(uuid.uuid5(uuid.NAMESPACE_URL, "colossus-test/cand-1"))
G_FUNC = str(uuid.uuid5(uuid.NAMESPACE_URL, "colossus-test/g-func"))
G_OB1 = str(uuid.uuid5(uuid.NAMESPACE_URL, "colossus-test/g-ob1"))
G_OB2 = str(uuid.uuid5(uuid.NAMESPACE_URL, "colossus-test/g-ob2"))
SECRET = "sk-REPORTSECRETVALUE99"
GH = "ghp_" + "A" * 36
GOLD = "GOLD-EXPECTED-PATCH-DO-NOT-SHOW"
H = "a" * 64
VERSIONS = {
    "source_repository": "https://github.com/example/vampi",
    "source_revision": "0123456789abcdef0123456789abcdef01234567",
    "implementation_revision": "908850e",
    "dafny": "4.9.1",
}


def gate(gate_id, case_id, category, status, outcome=None, scope=("ob-1",), tool="dafny 4.9.1"):
    return GateResult(
        gate_id=gate_id,
        case_id=case_id,
        candidate_id=CAND,
        candidate_hash=H,
        check_profile_id=f"{category}-v1",
        category=category,
        status=status,
        proof_outcome=outcome,
        scope=list(scope),
        tool_version=tool,
        command_profile_hash=H,
        started_at="2026-11-14T10:00:00Z",
        finished_at="2026-11-14T10:00:30.5Z",
        evidence_ids=[H],
    ).model_dump()


def model_call(call_id, case_id, actual):
    return {
        "call_id": call_id,
        "task_id": case_id,
        "provider": "mistral",
        "model_requested": "mistral-small-2503",
        "model_returned": "mistral-small-2503" if actual is not None else None,
        "template_version": "1",
        "model_profile_hash": H,
        "price_snapshot_id": "2026-10-01",
        "input_tokens": 1200 if actual is not None else None,
        "output_tokens": 300 if actual is not None else None,
        "reserved_cost_micro_usd": 5000,
        "actual_cost_micro_usd": actual,
        "status": "succeeded" if actual is not None else "uncertain",
        "messages": [{"role": "user", "content": "PROMPT-BODY-NOT-IN-REPORT"}],
        "created_at": "2026-11-14T10:00:0" + call_id[-1] + "Z",
    }


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "controller.sqlite")
    p = "p1"
    s.put(
        "cycle",
        "cy-1",
        {
            "cycle_id": "cy-1",
            "project_id": p,
            "status": "REVIEW_READY",
            "started_at": "2026-11-14T10:00:00Z",
            "finished_at": "2026-11-14T10:05:00Z",
        },
        p,
    )
    s.put(
        "case",
        CASE_A,
        {
            "case_id": CASE_A,
            "cycle_id": "cy-1",
            "status": "REVIEW_READY",
            "created_at": "2026-11-14T10:00:01Z",
            "candidate_id": CAND,
            "obligation_ids": ["ob-1", "ob-2", "ob-3"],
            "assurance_summary": {"formal": "UNKNOWN"},
            "manual_interventions": [{"reason": "approved review"}],
            "reason": f"retried after token={SECRET} and Authorization: Bearer {GH}",
            "gold_patch": GOLD,
        },
        p,
    )
    s.put(
        "case",
        CASE_B,
        {
            "case_id": CASE_B,
            "cycle_id": "cy-1",
            "status": "NO_CHANGE",
            "reason": "No supported SQL repair case",
            "created_at": "2026-11-14T10:00:02Z",
            "candidate_id": None,
        },
        p,
    )
    s.put(
        "case",
        "case-gold",
        {"case_id": "case-gold", "evaluator_only": True, "expected_outcome": GOLD},
        p,
    )
    s.put(
        "candidate",
        CAND,
        {
            "candidate_id": CAND,
            "source_tree_hash": H,
            "diff_hash": H,
            "artifact_digest": "sha256:" + H,
        },
        p,
    )
    s.put("gate", G_FUNC, gate(G_FUNC, CASE_A, "functional", "pass", scope=["tests"]), p)
    s.put("gate", G_OB1, gate(G_OB1, CASE_A, "formal", "pass", "PROVED", ["ob-1"]), p)
    s.put("gate", G_OB2, gate(G_OB2, CASE_A, "formal", "timeout", "UNKNOWN", ["ob-2"]), p)
    for call_id, actual in (("call-1", 4200), ("call-2", None)):
        s.reserve(call_id, CASE_A, 5000, 1_000_000, 100_000)
        s.reconcile(call_id, actual)
        s.put("model_call", call_id, model_call(call_id, CASE_A, actual), p)
    with s.transaction() as db:
        s.enqueue(db, p, "cycle", {"cache_state": "warm"}, time.time() + 600)
    task = s.claim("worker-1")
    s.complete_task(task["id"], "worker-1", task["attempt"], {}, True)
    s.mutate("operator", "approve-1", "approve", {"case": CASE_A}, lambda db, op: {"project_id": p})
    return s


def build(store, **kw):
    return build_run_report(
        store,
        "p1",
        versions=VERSIONS,
        exclusions=kw.pop("exclusions", [{"case_id": CASE_B, "reason": "no repair template"}]),
        run_id="run-1",
        generated_at="2026-11-14T11:00:00Z",
        **kw,
    )


def test_all_attempts_listed_with_explicit_exclusions(store):
    report = build(store)
    cases = {c["case_id"]: c for c in report["cases"]}
    assert set(cases) == {CASE_A, CASE_B}
    assert cases[CASE_B]["excluded"] is True
    assert cases[CASE_B]["exclusion_reason"] == "no repair template"
    assert report["exclusions"] == [{"case_id": CASE_B, "reason": "no repair template"}]
    assert report["summary"]["attempted_cases"] == 2
    assert report["summary"]["excluded_cases"] == 1
    with pytest.raises(ValueError, match="reason"):
        build(store, exclusions=[{"case_id": CASE_B}])
    with pytest.raises(ValueError, match="not attempted"):
        build(store, exclusions=[{"case_id": "ghost", "reason": "x"}])


def test_unknown_is_never_rendered_as_pass(store):
    report = build(store)
    case = next(c for c in report["cases"] if c["case_id"] == CASE_A)
    scope = {o["obligation_id"]: o for o in case["proof_scope"]}
    assert scope["ob-1"]["counts_as_pass"] is True and scope["ob-1"]["display"] == "PASS (PROVED)"
    assert scope["ob-2"]["proof_outcome"] == "UNKNOWN"
    assert scope["ob-2"]["counts_as_pass"] is False
    assert scope["ob-3"]["proof_outcome"] == "UNKNOWN"
    assert scope["ob-3"]["reason"] == "no formal gate result recorded"
    assert case["formal_summary"] == "UNKNOWN"
    assert report["summary"]["obligations_passed"] == 1
    assert report["summary"]["obligations_unknown"] == 2
    md = render_markdown(report)
    assert f"| ob-2 | {G_OB2} | UNKNOWN (not a pass) | no |" in md
    assert "| ob-3 | null | UNKNOWN (not a pass) | no |" in md
    assert "PASS (UNKNOWN)" not in md


def test_missing_cost_stays_null_and_uncertain(store):
    report = build(store)
    costs = next(c for c in report["cases"] if c["case_id"] == CASE_A)["costs"]
    calls = {c["call_id"]: c for c in costs["calls"]}
    assert calls["call-1"]["actual_micro_usd"] == 4200 and calls["call-1"]["uncertain"] is False
    assert calls["call-1"]["usage"] == {"unit": "tokens", "input": 1200, "output": 300}
    assert calls["call-2"]["actual_micro_usd"] is None and calls["call-2"]["uncertain"] is True
    assert costs["settled_micro_usd"] == 4200
    assert costs["actual_total_micro_usd"] is None
    assert costs["uncertain_reserved_micro_usd"] == 5000
    assert report["summary"]["actual_total_micro_usd"] is None
    assert report["summary"]["cost_uncertain"] is True
    no_calls = next(c for c in report["cases"] if c["case_id"] == CASE_B)["costs"]
    assert no_calls["actual_total_micro_usd"] == 0 and no_calls["uncertain"] is False
    assert "total null (unknown)" in render_markdown(report)


def test_redaction_and_evaluator_boundary(store):
    report = build(store)
    text = json.dumps(report) + render_markdown(report)
    for leaked in (SECRET, GH, GOLD, "PROMPT-BODY-NOT-IN-REPORT"):
        assert leaked not in text
    assert "case-gold" not in text
    assert report["summary"]["withheld_evaluator_records"] == 1
    assert "[redacted]" in text


def test_versions_timings_and_interventions(store):
    report = build(store)
    assert report["versions"]["missing"] == []
    assert report["versions"]["declared"]["source_revision"] == VERSIONS["source_revision"]
    assert report["versions"]["models"][0]["model_requested"] == "mistral-small-2503"
    assert {"check_profile_id": "formal-v1", "tool_version": "dafny 4.9.1"} in report["versions"][
        "tools"
    ]
    missing = build_run_report(store, "p1", versions={"source_revision": "abc"})
    assert missing["versions"]["missing"] == ["implementation_revision", "source_repository"]
    assert report["cycles"][0]["elapsed_seconds"] == 300.0
    case = next(c for c in report["cases"] if c["case_id"] == CASE_A)
    assert {g["elapsed_seconds"] for g in case["gates"]} == {30.5}
    assert case["manual_intervention_count"] == 1
    assert report["summary"]["manual_interventions"] is None  # case-b has no record
    assert report["summary"]["manual_interventions_unrecorded_cases"] == 1
    assert report["summary"]["operator_operations"] == 1
    stage = report["stage_timings"]["stages"]["cycle"]
    assert stage["completed"] == 1 and stage["warm"] == 1


def test_report_is_reproducible(store):
    first, second = build(store), build(store)
    assert first == second
    assert first["report_hash"] == second["report_hash"]
    assert verify_report_hash(first)
    assert render_markdown(first) == render_markdown(second)
    tampered = first | {"run_id": "run-2"}
    assert not verify_report_hash(tampered)
    later = build_run_report(store, "p1", versions=VERSIONS, generated_at="2026-11-15T00:00:00Z")
    assert later["report_hash"] != first["report_hash"]


def test_markdown_escapes_hostile_text(store):
    store.put(
        "case",
        "case-x",
        {"case_id": "case-x", "status": "FAILED", "reason": "a | b\n<script>x</script>"},
        "p1",
    )
    md = render_markdown(build(store))
    assert "<script>" not in md
    assert "a \\| b &lt;script&gt;" in md


def test_redact_text_covers_bearer_and_prefixed_tokens():
    out = redact(f"Authorization: Bearer {GH} gsk_{'b' * 30} AKIAABCDEFGHIJKLMNOP")
    assert GH not in out and "gsk_" not in out and "AKIA" not in out
