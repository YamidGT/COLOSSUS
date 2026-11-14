"""Terminal client for the same operator API used by the web action center."""

from __future__ import annotations

import functools
import json
import os
import re
import tempfile
import time
import webbrowser
from pathlib import Path
from typing import Annotated

import click
import typer

from colossus.cli import render
from colossus.cli.client import (
    EXIT_BLOCKED,
    EXIT_INTERRUPTED,
    EXIT_UNSUCCESSFUL,
    EXIT_USAGE,
    EXIT_WATCH_DEADLINE,
    ApiClient,
    CliError,
    validate_api_url,
)
from colossus.control.config import Settings

app = typer.Typer(
    no_args_is_help=True, help="Recurring repository defence with inspectable evidence."
)

TERMINAL_CYCLES = {
    "COMPLETE",
    "NO_FINDINGS",
    "NO_CHANGE",
    "REJECTED",
    "CANCELLED",
    "INFRA_FAILED",
    "TIMEOUT",
    "BUDGET_STOP",
}
SUCCESSFUL_CYCLES = {"COMPLETE", "NO_FINDINGS", "NO_CHANGE"}
POLL_SECONDS = 2.0
DEFAULT_WATCH_DEADLINE = 1800
MAX_PROJECT_PAGES = 50
MAX_INPUT_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
AMENDMENT_FIELDS = {
    "expected_revision",
    "requested_ref",
    "subdir",
    "owner_policy_id",
    "deployment_profile_id",
    "assurance_profile",
    "requirement_ids",
}


@app.callback()
def options(
    ctx: typer.Context,
    api_url: str = typer.Option("http://127.0.0.1:8787", envvar="COLOSSUS_API_URL"),
    as_json: bool = typer.Option(False, "--json"),
    no_color: bool = False,
    timeout: int = 30,
    idempotency_key: str | None = None,
):
    ctx.obj = dict(
        api_url=api_url.rstrip("/"),
        as_json=as_json,
        timeout=timeout,
        idempotency_key=idempotency_key,
    )
    if no_color:
        ctx.color = False


def client(ctx) -> ApiClient:
    if "client" not in ctx.obj:
        if ctx.obj["timeout"] <= 0:
            raise CliError(EXIT_USAGE, "invalid_timeout", "--timeout must be positive")
        ctx.obj["client"] = ApiClient(
            validate_api_url(ctx.obj["api_url"]),
            ctx.obj["timeout"],
            ctx.obj["idempotency_key"],
        )
    return ctx.obj["client"]


def project_url(ctx, project_id, case_id=None) -> str | None:
    if not project_id:
        return None
    url = f"{ctx.obj['api_url']}/projects/{project_id}"
    return url + f"/cases/{case_id}" if case_id else url


def finish(ctx, result: dict, code: int = 0, human: list[str] | None = None):
    secrets = ctx.obj["client"].secrets() if "client" in ctx.obj else []
    render.output(result, as_json=ctx.obj["as_json"], secrets=secrets, human=human)
    if code:
        raise typer.Exit(code)


def command(func):
    """Turn CliError into the JSON envelope / stderr diagnostic and its exit code."""

    @functools.wraps(func)
    def wrapper(ctx: typer.Context, *args, **kwargs):
        try:
            return func(ctx, *args, **kwargs)
        except CliError as exc:
            finish(
                ctx,
                render.envelope(
                    ok=False,
                    status="error",
                    reason_code=exc.reason_code,
                    message=exc.message,
                    data={"http_status": exc.http_status, "error": exc.data}
                    if exc.http_status
                    else None,
                ),
                exc.exit_code,
                human=[f"reason: {render.clean(exc.reason_code, 100)}"],
            )
        finally:
            if "client" in (ctx.obj or {}):
                ctx.obj["client"].close()

    return wrapper


def receipt_result(ctx, receipt: dict, status: str | None = None, message: str | None = None):
    ids = receipt.get("resource_ids") or {}
    project_id = ids.get("project_id")
    return render.envelope(
        ok=True,
        status=status or receipt.get("status", "accepted"),
        operation_id=receipt.get("operation_id"),
        project_id=project_id,
        cycle_id=ids.get("cycle_id"),
        reason_code=receipt.get("reason_code"),
        message=message,
        action_url=project_url(ctx, project_id),
        data=receipt,
    )


def receipt_lines(receipt: dict) -> list[str]:
    ids = receipt.get("resource_ids") or {}
    lines = [f"operation: {render.clean(receipt.get('operation_id'), 100)}"]
    lines += [f"{render.clean(k, 50)}: {render.clean(v, 100)}" for k, v in ids.items()]
    lines.append(f"status: {render.clean(receipt.get('status'), 50)}")
    return lines


def require_interactive_or_yes(yes: bool) -> None:
    """Fail before any request when a script would need a confirmation it cannot give."""
    if not yes and not render.is_tty():
        raise CliError(
            EXIT_USAGE,
            "confirmation_required",
            "This command needs confirmation; rerun with --yes in non-interactive use.",
        )


def confirm(yes: bool, consequence: str) -> None:
    """Ask once in a TTY; scripts must pass --yes. --yes never bypasses server checks."""
    if yes:
        return
    require_interactive_or_yes(yes)
    if not click.confirm(render.clean(consequence), default=False, err=True):
        raise CliError(EXIT_BLOCKED, "not_confirmed", "Not confirmed; nothing was sent.")


def read_json_file(path: Path, what: str) -> dict:
    try:
        if not path.is_file():
            raise CliError(EXIT_USAGE, "invalid_input", f"{what} file not found")
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise CliError(EXIT_USAGE, "invalid_input", f"{what} file is larger than 1 MiB")
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise CliError(EXIT_USAGE, "invalid_input", f"{what} file is not valid JSON") from None
    if not isinstance(value, dict):
        raise CliError(EXIT_USAGE, "invalid_input", f"{what} must be a JSON object")
    return value


def check_deadline(deadline: int) -> None:
    if deadline < 0:
        raise CliError(EXIT_USAGE, "invalid_deadline", "--deadline must be zero or positive")


def poll(ctx, fetch, describe, done, deadline: int):
    """Poll until done(value) or the deadline; Ctrl-C detaches without cancelling."""
    end = time.monotonic() + deadline
    last = None
    started = time.monotonic()
    try:
        while True:
            value = fetch()
            label = describe(value)
            if label != last:
                elapsed = int(time.monotonic() - started)
                render.diag(f"{label}    elapsed {elapsed // 60:02d}:{elapsed % 60:02d}")
                last = label
            if done(value):
                return value
            if time.monotonic() >= end:
                return None
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        return KeyboardInterrupt


def watch_cycle(ctx, cycle_id: str, project_id: str | None, deadline: int, operation_id=None):
    api = client(ctx)
    value = poll(
        ctx,
        lambda: api.request("GET", f"/cycles/{cycle_id}"),
        lambda c: str(c.get("status")) + (f" / {c['stage']}" if c.get("stage") else ""),
        lambda c: c.get("status") in TERMINAL_CYCLES,
        deadline,
    )
    base = dict(operation_id=operation_id, project_id=project_id, cycle_id=cycle_id)
    if value is KeyboardInterrupt:
        finish(
            ctx,
            render.envelope(
                ok=False,
                status="detached",
                reason_code="interrupted",
                message="Watcher detached; the cycle continues on the server. "
                f"Use `colossus cancel {cycle_id}` to stop it.",
                action_url=project_url(ctx, project_id),
                **base,
            ),
            EXIT_INTERRUPTED,
        )
    if value is None:
        finish(
            ctx,
            render.envelope(
                ok=False,
                status="watch_timeout",
                reason_code="watch_deadline",
                message="Watch deadline expired; the operation continues on the server.",
                action_url=project_url(ctx, project_id),
                **base,
            ),
            EXIT_WATCH_DEADLINE,
        )
    project_id = project_id or value.get("project_id")
    succeeded = value["status"] in SUCCESSFUL_CYCLES
    finish(
        ctx,
        render.envelope(
            ok=succeeded,
            status=value["status"],
            reason_code=None if succeeded else value.get("reason_code") or value["status"].lower(),
            message=f"Cycle finished: {value['status']}",
            action_url=project_url(ctx, project_id),
            data=value,
            **(base | {"project_id": project_id}),
        ),
        0 if succeeded else EXIT_UNSUCCESSFUL,
    )


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8787):
    """Start the operator API, credential gateway and isolated worker dispatcher."""
    if host not in {"127.0.0.1", "localhost"}:
        raise typer.BadParameter("Only loopback binding is supported")
    import uvicorn

    from colossus.control.api import create_app

    uvicorn.run(create_app(), host=host, port=port, access_log=False)


@app.command()
@command
def doctor(ctx: typer.Context, profile: str = "standard", check_model: bool = False):
    """Inspect configured local services without printing credentials."""
    import shutil

    from colossus.cli.doctor import as_dicts, overall, repo_root, run_checks
    from colossus.sandbox.launcher import SandboxLauncher

    if profile != "standard":
        raise typer.BadParameter("Only the standard profile exists")
    settings = Settings.from_environment()

    def preflight():
        if not shutil.which("docker"):
            return {
                "ready": False,
                "context": settings.docker_context,
                "reason": "docker CLI missing",
            }
        return SandboxLauncher(settings.docker_context, settings.sandbox_runtime).preflight()

    found = run_checks(repo_root(), preflight)
    checks = {
        "python": "ready",
        "docker_cli": "available" if shutil.which("docker") else "missing",
        "docker_context": settings.docker_context,
        "sandbox_runtime": settings.sandbox_runtime,
        "runtime_preflight": overall(found),
        "profile": profile,
        "model_capability": "not_checked",
        "pipeline": "under_construction",
        "checks": as_dicts(found),
    }
    if check_model:
        checks["model_capability"] = "gateway_not_connected"
    finish(
        ctx,
        render.envelope(
            ok=False,
            status="not_ready",
            reason_code="implementation_incomplete",
            message="Readiness checks completed; full product acceptance is still pending.",
            data=checks,
        ),
        EXIT_BLOCKED,
    )


@app.command()
@command
def ui(ctx: typer.Context, no_open: bool = False):
    """Create a one-use browser login code; provider keys are never displayed."""
    api = client(ctx)
    login = api.request("POST", "/sessions/codes")
    finish(
        ctx,
        render.envelope(
            ok=True,
            status="login_code_created",
            action_url=ctx.obj["api_url"],
            data=login,
        ),
        human=["Login code (expires in 60 seconds): " + render.clean(login["code"], 200)],
    )
    if not no_open:
        webbrowser.open(ctx.obj["api_url"])


@app.command()
@command
def enroll(
    ctx: typer.Context,
    url: str,
    ref: str | None = None,
    subdir: str | None = None,
    policy: str = "lab_auto",
    assurance: str = "tested",
    requirements: str | None = None,
    run: bool = False,
):
    """Enroll a repository; --run queues exactly one cycle once setup is ready."""
    if policy not in ("lab_auto", "review"):
        raise CliError(EXIT_USAGE, "invalid_input", "Policy must be lab_auto or review")
    receipt = client(ctx).request(
        "POST",
        "/projects",
        {
            "repo_url": url,
            "requested_ref": ref,
            "subdir": subdir,
            "owner_policy_id": "lab-auto-v1" if policy == "lab_auto" else "review-v1",
            "assurance_profile": assurance,
            "requirement_ids": [requirements] if requirements else [],
            "start_cycle": run,
        },
    )
    finish(
        ctx,
        receipt_result(ctx, receipt, message="Enrollment accepted"),
        human=receipt_lines(receipt),
    )


@app.command()
@command
def projects(ctx: typer.Context):
    """List projects with setup/admission state and attention count."""
    api = client(ctx)
    items, cursor = [], None
    for _ in range(MAX_PROJECT_PAGES):
        params = {"limit": 100} | ({"cursor": cursor} if cursor else {})
        page = api.request("GET", "/projects", params=params)
        items.extend(page.get("items") or [])
        cursor = page.get("next_cursor")
        if not cursor:
            break
    lines = [
        "  ".join(
            render.clean(p.get(k), 120)
            for k in ("project_id", "display_name", "setup_state", "admission_state")
        )
        + f"  attention={render.clean(p.get('attention_count'), 20)}"
        for p in items
    ] or ["No projects enrolled."]
    finish(
        ctx,
        render.envelope(
            ok=True, status="completed", data={"items": items, "truncated": bool(cursor)}
        ),
        human=lines,
    )


def status_lines(s: dict) -> list[str]:
    cycle = s.get("active_cycle") or {}
    c = render.clean
    lines = [
        f"{c(s.get('display_name'), 200)}  /  {c(s.get('project_id'), 100)}",
        f"Setup: {c(s.get('setup_state'), 60)}    Admission: {c(s.get('admission_state'), 60)}"
        f"    Revision: {c(s.get('revision'), 20)}",
        "Cycle: "
        + (f"{c(cycle.get('cycle_id'), 100)} {c(cycle.get('status'), 60)}" if cycle else "none"),
        f"Attention items: {c(s.get('attention_count'), 20)}",
    ]
    if s.get("reason"):
        lines.append("Reason: " + c(s["reason"], 500))
    return lines


@app.command()
@command
def status(
    ctx: typer.Context,
    project_id: str,
    watch: bool = False,
    deadline: int = typer.Option(DEFAULT_WATCH_DEADLINE, help="Watch deadline in seconds"),
):
    """Read setup, cycle, deployment, mirror, limits and action summary."""
    check_deadline(deadline)
    value = client(ctx).request("GET", f"/projects/{project_id}/status")
    cycle = value.get("active_cycle")
    if watch and cycle and cycle.get("status") not in TERMINAL_CYCLES:
        watch_cycle(ctx, cycle["cycle_id"], project_id, deadline)
        return
    finish(
        ctx,
        render.envelope(
            ok=True,
            status=str(value.get("setup_state") or "completed"),
            project_id=project_id,
            cycle_id=cycle.get("cycle_id") if cycle else None,
            action_url=project_url(ctx, project_id),
            data=value,
        ),
        human=status_lines(value),
    )


@app.command()
@command
def actions(ctx: typer.Context, project_id: str):
    """List attention items with IDs, reason, permitted actions and case link."""
    items = client(ctx).request("GET", f"/projects/{project_id}/actions").get("items") or []
    c = render.clean
    lines = []
    for item in items:
        allowed = ", ".join(
            c(a.get("action") if isinstance(a, dict) else a, 60)
            for a in item.get("allowed_actions") or []
        )
        lines.append(
            f"{c(item.get('action_id'), 100)}  [{c(item.get('kind'), 60)}] {c(item.get('title'), 200)}"
        )
        lines.append(f"  reason: {c(item.get('reason_code'), 80)} {c(item.get('reason'), 500)}")
        if allowed:
            lines.append(f"  allowed: {allowed}")
        if item.get("case_id"):
            lines.append("  case: " + c(project_url(ctx, project_id, item["case_id"]), 300))
    finish(
        ctx,
        render.envelope(
            ok=True,
            status="completed",
            project_id=project_id,
            action_url=project_url(ctx, project_id),
            data={"items": items},
        ),
        human=lines or ["No attention items."],
    )


@app.command()
@command
def case(ctx: typer.Context, case_id: str, diff: bool = False):
    """Inspect a case; --diff needs the server's bounded diff route."""
    api = client(ctx)
    if diff:
        api.require_route("case --diff", "GET", "/cases/{case_id}/diff")
    value = api.request("GET", f"/cases/{case_id}")
    data = {"case": value}
    if diff:
        data["diff"] = api.request("GET", f"/cases/{case_id}/diff")
    project_id = value.get("project_id")
    human = render.human_lines(value)
    if diff:
        text = data["diff"].get("text") or data["diff"].get("content") or ""
        human += ["--- diff ---", render.clean(text, 200 * 1024)]
        if data["diff"].get("truncated"):
            human.append("[diff truncated by server]")
    finish(
        ctx,
        render.envelope(
            ok=True,
            status=str(value.get("status") or "completed"),
            project_id=project_id,
            cycle_id=value.get("cycle_id"),
            action_url=project_url(ctx, project_id, case_id),
            data=data,
        ),
        human=human,
    )


@app.command(name="run")
@command
def run_cycle(
    ctx: typer.Context,
    project_id: str,
    trigger: str = "manual",
    watch: bool = False,
    deadline: int = typer.Option(DEFAULT_WATCH_DEADLINE, help="Watch deadline in seconds"),
):
    """Request one cycle; --watch follows it to a terminal status."""
    check_deadline(deadline)
    receipt = client(ctx).request("POST", f"/projects/{project_id}/cycles", {"trigger": trigger})
    cycle_id = (receipt.get("resource_ids") or {}).get("cycle_id")
    if watch and cycle_id:
        watch_cycle(ctx, cycle_id, project_id, deadline, receipt.get("operation_id"))
        return
    finish(
        ctx, receipt_result(ctx, receipt, message="Cycle requested"), human=receipt_lines(receipt)
    )


def simple_mutation(ctx, path: str, message: str, status: str | None = None):
    receipt = client(ctx).request("POST", path)
    finish(ctx, receipt_result(ctx, receipt, status, message), human=receipt_lines(receipt))


@app.command()
@command
def pause(ctx: typer.Context, project_id: str):
    """Stop admitting new work; an active cycle is not killed."""
    simple_mutation(ctx, f"/projects/{project_id}/pause", "Project paused for new work")


@app.command()
@command
def resume(ctx: typer.Context, project_id: str):
    """Resume admission of new work."""
    simple_mutation(ctx, f"/projects/{project_id}/resume", "Project admission resumed")


@app.command()
@command
def retry_setup(ctx: typer.Context, project_id: str):
    """Retry eligible failed setup; earlier attempts are retained."""
    simple_mutation(ctx, f"/projects/{project_id}/retry-setup", "Setup retry accepted")


@app.command()
@command
def cancel(ctx: typer.Context, cycle_id: str, yes: bool = False):
    """Request termination and reconciliation of a cycle."""
    confirm(yes, f"Cancel cycle {cycle_id} and reconcile any staged changes?")
    simple_mutation(
        ctx,
        f"/cycles/{cycle_id}/cancel",
        "Cancellation requested; the cycle stops after reconciliation.",
        "CANCEL_REQUESTED",
    )


@app.command()
@command
def configure(
    ctx: typer.Context,
    project_id: str,
    file: Annotated[Path, typer.Option("--file", help="JSON ProjectConfigAmendment")],
):
    """Submit a strict versioned configuration amendment."""
    body = read_json_file(file, "Configuration")
    extra = sorted(set(body) - AMENDMENT_FIELDS)
    if extra:
        raise CliError(
            EXIT_USAGE,
            "invalid_input",
            "Unsupported configuration fields: " + ", ".join(render.clean(k, 60) for k in extra),
        )
    if type(body.get("expected_revision")) is not int:
        raise CliError(EXIT_USAGE, "invalid_input", "expected_revision must be an integer")
    api = client(ctx)
    route = "/projects/{project_id}/configuration"
    api.require_route("configure", "POST", route)
    receipt = api.request("POST", f"/projects/{project_id}/configuration", body)
    finish(
        ctx,
        receipt_result(ctx, receipt, message="Configuration amendment accepted"),
        human=receipt_lines(receipt),
    )


@app.command()
@command
def approve(
    ctx: typer.Context,
    manifest_hash: str,
    destination: str = typer.Option(..., "--destination"),
    yes: bool = False,
):
    """Authorize exact evidence for one destination; gates cannot be overridden."""
    if not SHA256.fullmatch(manifest_hash):
        raise CliError(
            EXIT_USAGE, "invalid_input", "MANIFEST_HASH must be 64 lowercase hex characters"
        )
    require_interactive_or_yes(yes)
    api = client(ctx)
    api.require_route("approve", "GET", "/evidence/{manifest_hash}/review")
    api.require_route("approve", "POST", "/cases/{case_id}/approve")
    review = api.request("GET", f"/evidence/{manifest_hash}/review")
    if review.get("destination_id") != destination:
        raise CliError(
            EXIT_BLOCKED, "destination_mismatch", "Destination differs from the verified candidate"
        )
    confirm(
        yes,
        f"Approve candidate {review.get('candidate_id')} (evidence {manifest_hash}) for "
        f"{destination} at generation {review.get('expected_deployment_generation')}?",
    )
    body = {
        "candidate_id": review.get("candidate_id"),
        "evidence_manifest_hash": manifest_hash,
        "expected_deployment_generation": review.get("expected_deployment_generation"),
        "expected_revision": review.get("revision"),
    }
    receipt = api.request("POST", f"/cases/{review['case_id']}/approve", body)
    finish(
        ctx,
        receipt_result(ctx, receipt, message="Approval submitted"),
        human=receipt_lines(receipt),
    )


@app.command()
@command
def reject(
    ctx: typer.Context,
    case_id: str,
    candidate: str = typer.Option(..., "--candidate"),
    reason: str = typer.Option(..., "--reason"),
):
    """Reject the current review candidate with a recorded reason."""
    if not 1 <= len(reason.strip()) <= 2000:
        raise CliError(EXIT_USAGE, "invalid_input", "--reason must be 1 to 2000 characters")
    api = client(ctx)
    api.require_route("reject", "POST", "/cases/{case_id}/reject")
    current = api.request("GET", f"/cases/{case_id}")
    receipt = api.request(
        "POST",
        f"/cases/{case_id}/reject",
        {"candidate_id": candidate, "expected_revision": current.get("revision"), "reason": reason},
    )
    finish(
        ctx,
        receipt_result(ctx, receipt, message="Rejection recorded"),
        human=receipt_lines(receipt),
    )


@app.command()
@command
def rollback(ctx: typer.Context, deployment_id: str, yes: bool = False):
    """Request bounded recovery to the retained prior artifact."""
    require_interactive_or_yes(yes)
    api = client(ctx)
    api.require_route("rollback", "GET", "/deployments/{deployment_id}")
    api.require_route("rollback", "POST", "/deployments/{deployment_id}/rollback")
    deployment = api.request("GET", f"/deployments/{deployment_id}")
    if not deployment.get("previous_digest"):
        raise CliError(
            EXIT_BLOCKED,
            "rollback_unavailable",
            "No prior artifact is retained for this deployment.",
        )
    confirm(
        yes,
        f"Roll back deployment {deployment_id} (generation {deployment.get('generation')}) "
        f"to {deployment.get('previous_digest')}?",
    )
    receipt = api.request(
        "POST",
        f"/deployments/{deployment_id}/rollback",
        {"expected_generation": deployment.get("generation")},
    )
    finish(
        ctx,
        receipt_result(ctx, receipt, message="Rollback requested"),
        human=receipt_lines(receipt),
    )


@app.command()
@command
def report(
    ctx: typer.Context,
    run_id: str,
    output: Annotated[Path, typer.Option("--output", "-o")],
    force: bool = False,
):
    """Download the redacted report; refuses to overwrite unless --force."""
    if output.is_symlink() or output.is_dir():
        raise CliError(EXIT_USAGE, "invalid_output", "Output must be a regular file path")
    if output.exists() and not force:
        raise CliError(EXIT_USAGE, "output_exists", "Output exists; use --force to replace it")
    data = client(ctx).request("GET", f"/reports/{run_id}")
    tmp = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=output.parent, prefix=".colossus-report-")
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            if output.is_symlink() or output.is_dir():
                raise CliError(EXIT_USAGE, "invalid_output", "Output must be a regular file path")
            os.replace(tmp, output)
        else:
            # Atomic no-clobber even when the destination appears during the request.
            os.link(tmp, output)
    except FileExistsError:
        raise CliError(
            EXIT_USAGE, "output_exists", "Output exists; use --force to replace it"
        ) from None
    except OSError:
        raise CliError(
            EXIT_USAGE, "write_failed", "Cannot write report at the requested path"
        ) from None
    finally:
        if tmp is not None:
            Path(tmp).unlink(missing_ok=True)
    project_id = (data.get("project") or {}).get("project_id")
    finish(
        ctx,
        render.envelope(
            ok=True,
            status="exported",
            project_id=project_id,
            cycle_id=run_id,
            message=f"Report written to {output}",
            action_url=project_url(ctx, project_id),
            data={"path": str(output)},
        ),
        human=[],
    )


@app.command()
@command
def evaluate(
    ctx: typer.Context,
    manifest_path: Path,
    watch: bool = False,
    deadline: int = typer.Option(DEFAULT_WATCH_DEADLINE, help="Watch deadline in seconds"),
):
    """Submit a frozen campaign manifest for server-side validation."""
    check_deadline(deadline)
    manifest = read_json_file(manifest_path, "Manifest")
    api = client(ctx)
    api.require_route("evaluate", "POST", "/evaluations")
    receipt = api.request("POST", "/evaluations", manifest)
    if not watch:
        finish(
            ctx,
            receipt_result(ctx, receipt, message="Evaluation submitted"),
            human=receipt_lines(receipt),
        )
        return
    operation_id = receipt["operation_id"]
    value = poll(
        ctx,
        lambda: api.request("GET", f"/operations/{operation_id}"),
        lambda op: str(op.get("status")),
        lambda op: op.get("status") in ("succeeded", "failed"),
        deadline,
    )
    if value is KeyboardInterrupt:
        result = receipt_result(ctx, receipt, "detached", "Watcher detached; evaluation continues.")
        finish(ctx, result | {"ok": False, "reason_code": "interrupted"}, EXIT_INTERRUPTED)
    if value is None:
        result = receipt_result(ctx, receipt, "watch_timeout", "Watch deadline expired.")
        finish(ctx, result | {"ok": False, "reason_code": "watch_deadline"}, EXIT_WATCH_DEADLINE)
    result = receipt_result(ctx, value, message=f"Evaluation {value['status']}")
    ok = value["status"] == "succeeded"
    finish(ctx, result | {"ok": ok}, 0 if ok else EXIT_UNSUCCESSFUL)
