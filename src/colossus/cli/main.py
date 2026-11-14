"""COLOSSUS CLI (Typer). Only `doctor` is implemented; other commands follow docs/cli.md."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import typer

from colossus.contracts import SCHEMA_VERSION

from .doctor import CheckState, as_dicts, run_doctor, summarize

app = typer.Typer(add_completion=False, no_args_is_help=True, help="COLOSSUS recurring cyberdefence system")

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x9b]|\x1b\[[0-9;]*[A-Za-z]")


def _safe(text: str) -> str:
    """Strip control and ANSI sequences before printing to a terminal."""
    return _CONTROL.sub("", text)


def _repo_root() -> Path:
    return Path(os.environ.get("COLOSSUS_HOME", Path.cwd()))


@app.callback()
def main() -> None:
    """COLOSSUS operator CLI."""


@app.command()
def doctor(
    profile: str = typer.Option("standard", help="Runtime profile to check"),
    json_out: bool = typer.Option(False, "--json", help="Print one JSON object"),
    check_model: bool = typer.Option(False, "--check-model", help="Paid model capability check (not implemented)"),
) -> None:
    """Readiness checks for this host. No target code runs and no secrets are printed."""
    if profile != "standard":
        typer.echo(f"unknown profile {profile!r}; only 'standard' exists", err=True)
        raise typer.Exit(2)
    root = _repo_root()
    checks = run_doctor(root, str(root))
    if check_model:
        from .doctor import Check
        checks.append(Check("model.capability", CheckState.UNKNOWN, "not implemented; no call made"))
    status, code = summarize(checks)
    if json_out:
        typer.echo(json.dumps({
            "schema_version": SCHEMA_VERSION, "ok": code == 0, "operation_id": None, "project_id": None,
            "cycle_id": None, "status": status, "reason_code": "readiness_blocked" if code == 3 else None,
            "message": f"{sum(c.state is CheckState.BLOCKED for c in checks)} blocking checks",
            "action_url": None, "data": {"profile": profile, "checks": as_dicts(checks)},
        }, sort_keys=True))
    else:
        width = max(len(c.check_id) for c in checks)
        for c in checks:
            typer.echo(f"{c.state.value:<8} {c.check_id:<{width}}  {_safe(c.observed)}")
            if c.remedy and c.state is not CheckState.OK:
                typer.echo(f"{'':<8} {'':<{width}}  -> {_safe(c.remedy)}")
        typer.echo(f"\nstatus: {status}")
    raise typer.Exit(code)


if __name__ == "__main__":
    app()
