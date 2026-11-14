"""Redacted, reproducible run report (JSON + Markdown) built read-only from the Store.

Rules enforced here (docs/evaluation.md "Output", docs/deployment-observability.md):

* every attempted case is listed; an excluded case stays listed with its reason;
* source/model/tool versions are exact values or explicitly ``null`` and listed as missing;
* proof outcomes are reported per obligation; only PROVED/BOUNDED_PASS on a passing gate
  counts as a pass. UNKNOWN, UNSUPPORTED, COUNTEREXAMPLE and absent results never do;
* timings are only recorded values; a missing value is ``null``;
* costs are integer micro-USD; an unreconciled cost stays ``null`` and is flagged uncertain;
* evaluator-only/gold records and fields are withheld (only a count is reported);
* the whole report passes through ``redact`` and has a content hash over canonical JSON.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from colossus.contracts.core import content_hash
from colossus.observability.redact import redact
from colossus.observability.timing import iso_seconds, stage_timings

if TYPE_CHECKING:
    from colossus.control.store import Store

SCHEMA = "colossus.run_report/1"
PASSING_OUTCOMES = ("PROVED", "BOUNDED_PASS")
REQUIRED_VERSIONS = ("source_repository", "source_revision", "implementation_revision")
EVALUATOR_VISIBILITY = ("evaluator", "evaluator_only", "gold")
EVALUATOR_FIELDS = frozenset(
    {
        "gold",
        "gold_label",
        "gold_patch",
        "ground_truth",
        "oracle_truth",
        "expected_outcome",
        "evaluator_label",
        "evaluator_notes",
        "evaluator_only_artifacts",
    }
)
CONTENT_FIELDS = frozenset({"messages", "prompt", "prompts", "response_content", "raw_response"})
SYSTEM_ACTORS = frozenset({"controller"})


def _is_evaluator_only(record: dict) -> bool:
    return (
        record.get("evaluator_only") is True
        or record.get("visibility") in EVALUATOR_VISIBILITY
        or record.get("trust_boundary") == "evaluator"
    )


def _strip(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in EVALUATOR_FIELDS:
                continue
            out[key] = "[omitted]" if key in CONTENT_FIELDS else _strip(item)
        return out
    if isinstance(value, list):
        return [_strip(item) for item in value]
    return value


def _all(store: Store, kind: str, project_id: str) -> list[dict]:
    rows: list[dict] = []
    offset = 0
    while True:
        page = store.list(kind, project_id, limit=1000, offset=offset)
        rows.extend(page)
        if len(page) < 1000:
            break
        offset += 1000
    return rows


class _Reader:
    def __init__(self, store: Store, project_id: str):
        self.withheld = 0
        self.store = store
        self.project_id = project_id

    def records(self, kind: str, id_key: str) -> list[dict]:
        out = []
        for record in _all(self.store, kind, self.project_id):
            if _is_evaluator_only(record):
                self.withheld += 1
                continue
            out.append(_strip(record))
        return sorted(out, key=lambda r: (str(r.get("created_at") or ""), str(r.get(id_key))))


def _proof_label(outcome: str, counts: bool) -> str:
    return f"PASS ({outcome})" if counts else f"{outcome} (not a pass)"


def _obligations(case: dict, gates: list[dict]) -> list[dict]:
    rows = []
    seen = set()
    for gate in gates:
        if gate.get("category") != "formal":
            continue
        outcome = gate.get("proof_outcome") or "UNKNOWN"
        counts = gate.get("status") == "pass" and outcome in PASSING_OUTCOMES
        for obligation_id in sorted(gate.get("scope") or ["<unscoped>"]):
            seen.add(obligation_id)
            rows.append(
                {
                    "obligation_id": obligation_id,
                    "gate_id": gate.get("gate_id"),
                    "candidate_id": gate.get("candidate_id"),
                    "candidate_hash": gate.get("candidate_hash"),
                    "gate_status": gate.get("status"),
                    "proof_outcome": outcome,
                    "counts_as_pass": counts,
                    "display": _proof_label(outcome, counts),
                    "tool_version": gate.get("tool_version"),
                    "assumptions": sorted(gate.get("assumptions") or []),
                    "reason": gate.get("reason") or "",
                }
            )
    for obligation_id in sorted(case.get("obligation_ids") or []):
        if obligation_id not in seen:
            rows.append(
                {
                    "obligation_id": obligation_id,
                    "gate_id": None,
                    "candidate_id": case.get("candidate_id"),
                    "candidate_hash": None,
                    "gate_status": None,
                    "proof_outcome": "UNKNOWN",
                    "counts_as_pass": False,
                    "display": _proof_label("UNKNOWN", False),
                    "tool_version": None,
                    "assumptions": [],
                    "reason": "no formal gate result recorded",
                }
            )
    return sorted(rows, key=lambda r: (r["obligation_id"], str(r["gate_id"])))


def _elapsed(start: str | None, end: str | None) -> float | None:
    a, b = iso_seconds(start), iso_seconds(end)
    return None if a is None or b is None else round(b - a, 6)


def _costs(calls: list[dict]) -> dict:
    rows = []
    settled = 0
    uncertain_reserved = 0
    for call in calls:
        actual = call.get("actual_cost_micro_usd")
        reserved = call.get("reserved_cost_micro_usd")
        uncertain = actual is None
        if uncertain:
            uncertain_reserved += reserved or 0
        else:
            settled += actual
        rows.append(
            {
                "call_id": call.get("call_id"),
                "status": call.get("status"),
                "model_requested": call.get("model_requested"),
                "model_returned": call.get("model_returned"),
                "template_version": call.get("template_version"),
                # redact() masks any key containing "token", so usage counts
                # are carried under neutral keys.
                "usage": {
                    "unit": "tokens",
                    "input": call.get("input_tokens"),
                    "output": call.get("output_tokens"),
                },
                "elapsed_seconds": call.get("elapsed_seconds"),
                "reserved_micro_usd": reserved,
                "actual_micro_usd": actual,
                "uncertain": uncertain,
            }
        )
    any_uncertain = any(r["uncertain"] for r in rows)
    return {
        "calls": rows,
        "settled_micro_usd": settled,
        "uncertain": any_uncertain,
        "uncertain_reserved_micro_usd": uncertain_reserved,
        # A total is stated only when every charge is reconciled.
        "actual_total_micro_usd": None if any_uncertain else settled,
    }


def _interventions(case: dict) -> int | None:
    value = case.get("manual_interventions")
    if value is None:
        return None
    if isinstance(value, list):
        return len(value)
    if isinstance(value, int) and value >= 0:
        return value
    raise ValueError("manual_interventions must be a list or a nonnegative integer")


def build_run_report(
    store: Store,
    project_id: str,
    *,
    versions: dict[str, Any],
    exclusions: list[dict] | tuple = (),
    run_id: str | None = None,
    generated_at: str | None = None,
) -> dict:
    """Build the report. Pass ``generated_at`` explicitly; it is part of the hash."""
    reader = _Reader(store, project_id)
    cycles = reader.records("cycle", "cycle_id")
    cases = reader.records("case", "case_id")
    gates = reader.records("gate", "gate_id")
    candidates = reader.records("candidate", "candidate_id")
    calls = reader.records("model_call", "call_id")

    excluded: dict[str, str] = {}
    for item in exclusions:
        case_id, reason = item.get("case_id"), item.get("reason")
        if not case_id or not reason:
            raise ValueError("Every exclusion needs case_id and a reason")
        excluded[case_id] = reason

    case_rows = []
    case_ids = set()
    for case in cases:
        case_id = case["case_id"]
        case_ids.add(case_id)
        case_gates = [g for g in gates if g.get("case_id") == case_id]
        gate_rows = [
            {
                "gate_id": g.get("gate_id"),
                "category": g.get("category"),
                "check_profile_id": g.get("check_profile_id"),
                "status": g.get("status"),
                "tool_version": g.get("tool_version"),
                "started_at": g.get("started_at"),
                "finished_at": g.get("finished_at"),
                "elapsed_seconds": _elapsed(g.get("started_at"), g.get("finished_at")),
            }
            for g in case_gates
        ]
        case_candidates = [
            {
                "candidate_id": c.get("candidate_id"),
                "source_tree_hash": c.get("source_tree_hash"),
                "diff_hash": c.get("diff_hash"),
                "artifact_digest": c.get("artifact_digest"),
            }
            for c in candidates
            if c.get("candidate_id") == case.get("candidate_id")
        ]
        case_rows.append(
            {
                "case_id": case_id,
                "cycle_id": case.get("cycle_id"),
                "title": case.get("title"),
                "status": case.get("status"),
                "reason": case.get("reason"),
                "generation_mode": case.get("generation_mode"),
                "excluded": case_id in excluded,
                "exclusion_reason": excluded.get(case_id),
                "finding_refs": sorted(case.get("finding_refs") or []),
                "candidates": case_candidates,
                "gates": gate_rows,
                "proof_scope": _obligations(case, case_gates),
                "formal_summary": (case.get("assurance_summary") or {}).get("formal") or "UNKNOWN",
                "costs": _costs([c for c in calls if c.get("task_id") == case_id]),
                "store_budget": store.budget(case_id),
                "manual_intervention_count": _interventions(case),
            }
        )
    unknown_exclusions = sorted(set(excluded) - case_ids)
    if unknown_exclusions:
        raise ValueError(f"Exclusions name cases that were not attempted: {unknown_exclusions}")

    cycle_rows = [
        {
            "cycle_id": c.get("cycle_id"),
            "status": c.get("status"),
            "reason": c.get("reason"),
            "started_at": c.get("started_at"),
            "finished_at": c.get("finished_at"),
            "elapsed_seconds": _elapsed(c.get("started_at"), c.get("finished_at")),
        }
        for c in cycles
    ]

    model_versions = sorted(
        {
            (
                c.get("provider"),
                c.get("model_requested"),
                c.get("model_returned"),
                c.get("template_version"),
                c.get("model_profile_hash"),
                c.get("price_snapshot_id"),
            )
            for c in calls
        },
        key=lambda t: tuple(str(x) for x in t),
    )
    tool_versions = sorted(
        {(g.get("check_profile_id"), g.get("tool_version")) for g in gates},
        key=lambda t: tuple(str(x) for x in t),
    )
    declared = {key: versions.get(key) for key in REQUIRED_VERSIONS} | {
        k: v for k, v in versions.items() if k not in REQUIRED_VERSIONS
    }
    missing = sorted(k for k, v in declared.items() if v in (None, ""))

    operator_operations = sum(
        1
        for e in store.audit(project_id)
        if e["kind"] == "operation.accepted" and e["actor"] not in SYSTEM_ACTORS
    )
    timing = stage_timings(store, project_id)
    all_costs = _costs(calls)
    recorded = [r["manual_intervention_count"] for r in case_rows]

    report = {
        "schema": SCHEMA,
        "project_id": project_id,
        "run_id": run_id,
        "generated_at": generated_at,
        "versions": {
            "declared": dict(sorted(declared.items())),
            "missing": missing,
            "models": [
                dict(
                    zip(
                        (
                            "provider",
                            "model_requested",
                            "model_returned",
                            "template_version",
                            "model_profile_hash",
                            "price_snapshot_id",
                        ),
                        row,
                        strict=True,
                    )
                )
                for row in model_versions
            ],
            "tools": [{"check_profile_id": p, "tool_version": v} for p, v in tool_versions],
        },
        "summary": {
            "attempted_cases": len(case_rows),
            "excluded_cases": sum(r["excluded"] for r in case_rows),
            "obligations": sum(len(r["proof_scope"]) for r in case_rows),
            "obligations_passed": sum(
                o["counts_as_pass"] for r in case_rows for o in r["proof_scope"]
            ),
            "obligations_unknown": sum(
                o["proof_outcome"] == "UNKNOWN" for r in case_rows for o in r["proof_scope"]
            ),
            "settled_micro_usd": all_costs["settled_micro_usd"],
            "actual_total_micro_usd": all_costs["actual_total_micro_usd"],
            "cost_uncertain": all_costs["uncertain"],
            "manual_interventions": None if any(v is None for v in recorded) else sum(recorded),
            "manual_interventions_unrecorded_cases": sum(v is None for v in recorded),
            "operator_operations": operator_operations,
            "withheld_evaluator_records": reader.withheld,
        },
        "exclusions": [{"case_id": k, "reason": v} for k, v in sorted(excluded.items())],
        "cycles": cycle_rows,
        "cases": case_rows,
        "stage_timings": timing,
    }
    report = redact(report)
    report["report_hash"] = content_hash(report)
    return report


def verify_report_hash(report: dict) -> bool:
    body = {k: v for k, v in report.items() if k != "report_hash"}
    return content_hash(body) == report.get("report_hash")


def _md(value: Any) -> str:
    if value is None:
        return "null"
    text = str(value)
    text = text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = " ".join(text.split())
    return text[:300] + ("…" if len(text) > 300 else "")


def _micro(value: int | None) -> str:
    return "null (unknown)" if value is None else f"{value} µUSD"


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        f"# COLOSSUS run report: {_md(report['project_id'])}",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Run: {_md(report['run_id'])}",
        f"- Generated at: {_md(report['generated_at'])}",
        f"- Report hash: `{report['report_hash']}`",
        "",
        "## Summary",
        "",
        f"- Attempted cases: {s['attempted_cases']} (excluded: {s['excluded_cases']})",
        f"- Obligations: {s['obligations']}; passed: {s['obligations_passed']}; "
        f"UNKNOWN: {s['obligations_unknown']} (UNKNOWN is not a pass)",
        f"- Settled cost: {_micro(s['settled_micro_usd'])}; total: "
        f"{_micro(s['actual_total_micro_usd'])}; uncertain: {s['cost_uncertain']}",
        f"- Manual interventions: {_md(s['manual_interventions'])} "
        f"(cases without a record: {s['manual_interventions_unrecorded_cases']}); "
        f"operator operations: {s['operator_operations']}",
        f"- Evaluator-only records withheld: {s['withheld_evaluator_records']}",
        "",
        "## Versions",
        "",
    ]
    for key, value in report["versions"]["declared"].items():
        lines.append(f"- {_md(key)}: {_md(value)}")
    if report["versions"]["missing"]:
        lines.append(f"- MISSING: {', '.join(_md(m) for m in report['versions']['missing'])}")
    for model in report["versions"]["models"]:
        lines.append(
            f"- model: {_md(model['provider'])} requested={_md(model['model_requested'])} "
            f"returned={_md(model['model_returned'])} template={_md(model['template_version'])}"
        )
    for tool in report["versions"]["tools"]:
        lines.append(f"- tool: {_md(tool['check_profile_id'])} {_md(tool['tool_version'])}")
    lines += ["", "## Exclusions", ""]
    if report["exclusions"]:
        lines += [f"- {_md(e['case_id'])}: {_md(e['reason'])}" for e in report["exclusions"]]
    else:
        lines.append("- none")
    lines += ["", "## Cycles", "", "| cycle | status | elapsed s |", "|---|---|---|"]
    for cycle in report["cycles"]:
        lines.append(
            f"| {_md(cycle['cycle_id'])} | {_md(cycle['status'])} | "
            f"{_md(cycle['elapsed_seconds'])} |"
        )
    lines += ["", "## Cases", ""]
    for case in report["cases"]:
        flag = f" (EXCLUDED: {_md(case['exclusion_reason'])})" if case["excluded"] else ""
        lines += [
            f"### {_md(case['case_id'])}{flag}",
            "",
            f"- Status: {_md(case['status'])}; reason: {_md(case['reason'])}",
            f"- Formal summary: {_md(case['formal_summary'])}",
            f"- Cost: settled {_micro(case['costs']['settled_micro_usd'])}, total "
            f"{_micro(case['costs']['actual_total_micro_usd'])}, uncertain "
            f"{case['costs']['uncertain']}",
            f"- Manual interventions: {_md(case['manual_intervention_count'])}",
            "",
            "| obligation | gate | outcome | counts as pass |",
            "|---|---|---|---|",
        ]
        for o in case["proof_scope"]:
            lines.append(
                f"| {_md(o['obligation_id'])} | {_md(o['gate_id'])} | {_md(o['display'])} | "
                f"{'yes' if o['counts_as_pass'] else 'no'} |"
            )
        if not case["proof_scope"]:
            lines.append("| none | | | |")
        lines.append("")
    lines += [
        "## Stage timings (wall clock)",
        "",
        "| stage | count | completed | retried | "
        "cold | warm | unknown | queue median s | run median s |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, st in report["stage_timings"]["stages"].items():
        lines.append(
            f"| {_md(name)} | {st['count']} | {st['completed']} | {st['retried']} | "
            f"{st['cold']} | {st['warm']} | {st['unknown']} | "
            f"{_md(st['queue_seconds_median'])} | {_md(st['run_seconds_median'])} |"
        )
    return "\n".join(lines) + "\n"
