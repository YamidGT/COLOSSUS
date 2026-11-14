"""DafnyBench loader, pinned-verifier compatibility, selection inputs and attempt scoring.

Official source: https://github.com/sun-wendy/DafnyBench (Apache-2.0) and the HF mirror
https://huggingface.co/datasets/wendy-sun/DafnyBench (``test.json``: test_ID, test_file,
ground_truth, hints_removed). Paper https://arxiv.org/abs/2406.08467.

Verification goes through the ``DafnyVerifier`` port. ``colossus.verification.dafny`` today
exposes ``DafnyAdapter.execute`` for restricted *policy profiles* only; it has no entry
point for an arbitrary benchmark program. ``DafnyRunnerVerifier`` therefore wraps an
injected runner callable that a sandboxed general-program entry point (to be agreed with
session A/Daniel) must provide; ``NotWiredDafnyVerifier`` is the default and reports
``not_run``. Nothing here starts Dafny.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from colossus.contracts.core import DomainError
from colossus.evaluation.benchmarks.common import (
    BenchmarkItem,
    proportion,
    read_text,
    unique_items,
)

SUITE = "dafnybench"
MAX_ATTEMPTS = 3
SOURCE = {
    "source_url": "https://github.com/sun-wendy/DafnyBench",
    "license": "Apache-2.0",
    "citation": "https://arxiv.org/abs/2406.08467",
}
CONTAMINATION = {
    "public_since": "2024-06 (arXiv 2406.08467)",
    "training_exposure": "possible_unknown",
    "notes": "Ground-truth programs and upstream LLM reconstructions are public on GitHub.",
}
_SUMMARY = re.compile(r"Dafny program verifier finished with (\d+) verified, (\d+) errors?")

VerifierStatus = Literal["verified", "failed", "timeout", "error", "not_run"]


@dataclass(frozen=True)
class VerifierResult:
    status: VerifierStatus
    toolchain: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class DafnyVerifier(Protocol):
    def verify(self, program: str, timeout_seconds: int) -> VerifierResult: ...


class NotWiredDafnyVerifier:
    def verify(self, program: str, timeout_seconds: int) -> VerifierResult:
        return VerifierResult(
            "not_run",
            None,
            {"reason": "no general-program sandbox entry point in colossus.verification.dafny"},
        )


def classify_output(
    exit_code: int, stdout: str, timed_out: bool, truncated: bool
) -> VerifierStatus:
    """Same acceptance shape as ``verification.dafny.proof_passed``: exactly one summary,
    zero errors, clean exit. DafnyBench additionally rejects 'File contains no code'."""
    if timed_out:
        return "timeout"
    if truncated:
        return "error"
    summaries = _SUMMARY.findall(stdout)
    if len(summaries) != 1 or "File contains no code" in stdout:
        return "error" if exit_code and not summaries else "failed"
    verified, errors = (int(x) for x in summaries[0])
    return "verified" if exit_code == 0 and errors == 0 and verified > 0 else "failed"


class DafnyRunnerVerifier:
    """Adapter over a sandboxed runner returning ``ProcessResult``-shaped dicts
    (exit_code, stdout, timed_out, truncated), as ``SandboxLauncher.execute`` does."""

    def __init__(self, runner: Callable[[str, int], dict[str, Any]], toolchain: str):
        self.runner, self.toolchain = runner, toolchain

    def verify(self, program: str, timeout_seconds: int) -> VerifierResult:
        result = self.runner(program, timeout_seconds)
        status = classify_output(
            int(result.get("exit_code", 1)),
            str(result.get("stdout", "")),
            bool(result.get("timed_out")),
            bool(result.get("truncated")),
        )
        return VerifierResult(status, self.toolchain, {"exit_code": result.get("exit_code")})


def load_dafnybench(path: str | Path) -> list[BenchmarkItem]:
    try:
        records = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise DomainError("dafnybench_shape", "DafnyBench file is not JSON", 422) from exc
    if not isinstance(records, list):
        raise DomainError("dafnybench_shape", "DafnyBench file must be a list", 422)
    items = []
    for index, record in enumerate(records):
        keys = ("test_ID", "test_file", "ground_truth", "hints_removed")
        if not isinstance(record, dict) or any(not isinstance(record.get(k), str) for k in keys):
            raise DomainError("dafnybench_shape", f"Record {index} lacks {keys}", 422)
        items.append(
            BenchmarkItem(
                suite=SUITE,
                item_id=f"{SUITE}:{record['test_ID']}:{record['test_file']}",
                worker_view={"hints_removed": record["hints_removed"]},
                gold={"ground_truth": record["ground_truth"]},
                meta={"test_file": record["test_file"]},
            )
        )
    return unique_items(items)


def compatibility(
    items: list[BenchmarkItem], ground_truth_results: dict[str, VerifierResult]
) -> tuple[list[str], dict[str, str]]:
    """Ground truth must verify under the pinned verifier before an item is sampleable.
    Items without a result are excluded as ``compatibility not_run`` (disclosed)."""
    toolchains = {r.toolchain for r in ground_truth_results.values() if r.status != "not_run"}
    if len(toolchains) > 1:
        raise DomainError("dafny_toolchain_mixed", "Compatibility used several toolchains", 422)
    compatible, excluded = [], {}
    for item in items:
        result = ground_truth_results.get(item.item_id)
        if result is None or result.status == "not_run":
            excluded[item.item_id] = "ground-truth compatibility not_run"
        elif result.status != "verified":
            excluded[item.item_id] = f"ground truth {result.status} under pinned verifier"
        else:
            compatible.append(item.item_id)
    return compatible, excluded


def _spec_lines(program: str) -> list[str]:
    # Port of DafnyBench eval/utils.py check_no_cheating spec extraction.
    lines, in_doc = [], False
    for line in program.split("\n"):
        stripped = line.strip()
        if stripped.startswith("/*"):
            in_doc = not in_doc
        if (
            ("requires" in line or "ensures" in line)
            and not in_doc
            and not stripped.startswith("//")
        ):
            lines.append(stripped.replace(" ", ""))
        if stripped.endswith("*/"):
            in_doc = not in_doc
    return lines


def edit_check(original: str, candidate: str) -> dict[str, bool]:
    """Upstream checks (spec preserved; no ``{:verify false}``/``assume false``) plus a
    stricter COLOSSUS flag for any new assume/axiom attribute, reported separately."""
    upstream_ok = _spec_lines(original) == _spec_lines(candidate) and (
        "{:verify false}" not in candidate and "assume false" not in candidate
    )
    new_escape = any(
        candidate.count(token) > original.count(token) for token in ("assume", "{:axiom}")
    )
    return {"upstream_valid_edit": upstream_ok, "strict_new_assumption": new_escape}


def score_attempts(
    items: list[BenchmarkItem],
    locked_ids: list[str],
    baseline: dict[str, VerifierResult],
    attempts: dict[str, list[tuple[str, VerifierResult]]],
    max_attempts: int = MAX_ATTEMPTS,
) -> dict[str, Any]:
    """Success@1/@k with invalid edits counted as failures.

    ``baseline`` is the unchanged hints_removed program under the pinned verifier (the
    no-hint baseline). Lift = success@k - baseline over the same locked denominator.
    """
    by_id = {item.item_id: item for item in items}
    rows: dict[str, dict[str, Any]] = {}
    for item_id in locked_ids:
        base = baseline.get(item_id, VerifierResult("not_run"))
        tries = attempts.get(item_id)
        if tries is not None and len(tries) > max_attempts:
            raise DomainError("dafny_attempts", f"{item_id} exceeds {max_attempts} attempts", 422)
        row: dict[str, Any] = {"baseline": base.status}
        if not tries:
            row.update(outcome="not_run", first_success=None, attempts=[])
            rows[item_id] = row
            continue
        original = by_id[item_id].worker_view["hints_removed"]
        detail, first = [], None
        for number, (candidate, result) in enumerate(tries, start=1):
            check = edit_check(original, candidate)
            ok = result.status == "verified" and check["upstream_valid_edit"]
            detail.append({"attempt": number, "verifier": result.status, **check, "accepted": ok})
            if ok and first is None:
                first = number
        row.update(outcome="scored", first_success=first, attempts=detail)
        if any(a["verifier"] == "not_run" for a in detail):
            row["outcome"] = "incomplete"
        rows[item_id] = row
    attempted = [r for r in rows.values() if r["outcome"] == "scored"]
    base_known = [r for r in rows.values() if r["baseline"] != "not_run"]
    n = len(attempted)
    at1 = sum(r["first_success"] == 1 for r in attempted)
    atk = sum(r["first_success"] is not None for r in attempted)
    base_ok = sum(r["baseline"] == "verified" for r in attempted)
    all_tries = [a for r in attempted for a in r["attempts"]]
    return {
        "rows": rows,
        "summary": {
            "locked": len(locked_ids),
            "attempted": n,
            "not_run": sum(r["outcome"] == "not_run" for r in rows.values()),
            "incomplete": sum(r["outcome"] == "incomplete" for r in rows.values()),
            "success_at_1": proportion(at1, n),
            f"success_at_{max_attempts}": proportion(atk, n),
            "no_hint_baseline": proportion(
                sum(r["baseline"] == "verified" for r in base_known), len(base_known)
            ),
            "incremental_lift": (atk - base_ok) / n if n and len(base_known) == len(rows) else None,
            "invalid_edits": sum(not a["upstream_valid_edit"] for a in all_tries),
            "strict_new_assumption": sum(a["strict_new_assumption"] for a in all_tries),
            "timeouts": sum(a["verifier"] == "timeout" for a in all_tries),
            "comparable_to_upstream": False,
        },
    }
