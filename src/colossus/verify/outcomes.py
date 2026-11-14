"""Interpret recorded prover output. These functions do not invoke Dafny, CrossHair or CBMC."""

from __future__ import annotations

DAFNY_PROVED = "Dafny program verifier finished with 0 errors"


def classify_dafny(*, tool_present: bool, exit_code: int | None, stdout: str) -> tuple[str, str]:
    if not tool_present:
        return "not_applicable", "UNSUPPORTED"
    if exit_code is None:
        return "timeout", "UNKNOWN"
    if exit_code == 0 and DAFNY_PROVED in stdout:
        return "pass", "PROVED"
    if "counterexample" in stdout.lower():
        return "fail", "COUNTEREXAMPLE"
    return "fail", "UNKNOWN"


def classify_crosshair(
    *, tool_present: bool, counterexample: str | None, explored: bool
) -> tuple[str, str]:
    if not tool_present:
        return "not_applicable", "UNSUPPORTED"
    if counterexample:
        return "fail", "COUNTEREXAMPLE"
    if explored:
        return "not_applicable", "UNKNOWN"
    return "error", "UNKNOWN"


def classify_cbmc(*, tool_present: bool = False, stdout: str = "") -> tuple[str, str]:
    del tool_present, stdout
    return "not_applicable", "UNSUPPORTED"
