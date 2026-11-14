"""Terminal client for the same operator API used by the web action center."""

from __future__ import annotations

import json
import os
import time
import webbrowser
from pathlib import Path
from uuid import uuid4

import httpx
import typer
from rich.console import Console

from colossus.control.config import Settings

app = typer.Typer(
    no_args_is_help=True, help="Recurring repository defence with inspectable evidence."
)
console = Console(stderr=True)


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
        console.no_color = True


def emit(ctx, data):
    if ctx.obj["as_json"]:
        typer.echo(json.dumps(data, ensure_ascii=False))
    else:
        # Never interpret target text as terminal markup or control sequences.
        text = json.dumps(data, indent=2, ensure_ascii=False)
        console.print(text, markup=False, highlight=False)


def request(ctx, method, path, body=None):
    settings = Settings.from_environment()
    token = os.environ.get("COLOSSUS_OPERATOR_TOKEN")
    if not token:
        token_path = settings.data_dir / "operator.token"
        if not token_path.is_file() or token_path.is_symlink():
            console.print("Controller is not initialized; run colossus serve first.", markup=False)
            raise typer.Exit(3)
        token = token_path.read_text().strip()
    headers = {"Authorization": "Bearer " + token}
    if method != "GET":
        headers["Idempotency-Key"] = ctx.obj["idempotency_key"] or str(uuid4())
    try:
        response = httpx.request(
            method,
            ctx.obj["api_url"] + "/api/v1" + path,
            json=body,
            headers=headers,
            timeout=ctx.obj["timeout"],
            follow_redirects=False,
        )
    except httpx.HTTPError:
        console.print("Cannot reach the controller. Check the service or SSH tunnel.", markup=False)
        raise typer.Exit(5) from None
    try:
        data = response.json()
    except ValueError:
        console.print("Controller returned an invalid response.", markup=False)
        raise typer.Exit(5) from None
    if response.is_error:
        emit(ctx, data)
        raise typer.Exit(
            3
            if response.status_code in (401, 403, 409)
            else 2
            if response.status_code == 422
            else 5
        )
    return data


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8787):
    """Start the operator API, credential gateway and isolated worker dispatcher."""
    if host not in {"127.0.0.1", "localhost"}:
        raise typer.BadParameter("Only loopback binding is supported")
    import uvicorn

    from colossus.control.api import create_app

    uvicorn.run(create_app(), host=host, port=port, access_log=False)


@app.command()
def doctor(ctx: typer.Context, profile: str = "standard", check_model: bool = False):
    """Inspect configured local services without printing credentials."""
    import shutil

    settings = Settings.from_environment()
    checks = {
        "python": "ready",
        "docker_cli": "available" if shutil.which("docker") else "missing",
        "docker_context": settings.docker_context,
        "sandbox_runtime": settings.sandbox_runtime,
        "runtime_preflight": "pending",
        "profile": profile,
        "model_capability": "not_checked",
        "pipeline": "under_construction",
    }
    if check_model:
        checks["model_capability"] = "gateway_not_connected"
    emit(ctx, checks)
    raise typer.Exit(3)


@app.command()
def ui(ctx: typer.Context, no_open: bool = False):
    """Create a one-use browser login code; provider keys are never displayed."""
    login = request(ctx, "POST", "/sessions/codes")
    typer.echo("Login code (expires in 60 seconds): " + login["code"])
    typer.echo(ctx.obj["api_url"])
    if not no_open:
        webbrowser.open(ctx.obj["api_url"])


@app.command()
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
    if policy not in ("lab_auto", "review"):
        raise typer.BadParameter("Policy must be lab_auto or review")
    emit(
        ctx,
        request(
            ctx,
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
        ),
    )


@app.command()
def projects(ctx: typer.Context):
    emit(ctx, request(ctx, "GET", "/projects"))


def watch_cycle(ctx, cycle_id):
    deadline = time.monotonic() + ctx.obj["timeout"]
    terminal = {
        "COMPLETE",
        "NO_FINDINGS",
        "NO_CHANGE",
        "REJECTED",
        "CANCELLED",
        "INFRA_FAILED",
        "TIMEOUT",
        "BUDGET_STOP",
    }
    while time.monotonic() < deadline:
        cycle = request(ctx, "GET", f"/cycles/{cycle_id}")
        if cycle["status"] in terminal:
            emit(ctx, cycle)
            if cycle["status"] not in {"COMPLETE", "NO_FINDINGS", "NO_CHANGE"}:
                raise typer.Exit(4)
            return
        time.sleep(2)
    emit(
        ctx,
        {
            "status": "watch_timeout",
            "cycle_id": cycle_id,
            "message": "Operation continues on the server",
        },
    )
    raise typer.Exit(6)


@app.command(name="run")
def run_cycle(ctx: typer.Context, project_id: str, trigger: str = "manual", watch: bool = False):
    receipt = request(ctx, "POST", f"/projects/{project_id}/cycles", {"trigger": trigger})
    if watch:
        watch_cycle(ctx, receipt["resource_ids"]["cycle_id"])
    else:
        emit(ctx, receipt)


@app.command()
def status(ctx: typer.Context, project_id: str, watch: bool = False):
    value = request(ctx, "GET", f"/projects/{project_id}/status")
    if watch and value.get("active_cycle"):
        watch_cycle(ctx, value["active_cycle"]["cycle_id"])
    else:
        emit(ctx, value)


@app.command()
def actions(ctx: typer.Context, project_id: str):
    emit(ctx, request(ctx, "GET", f"/projects/{project_id}/actions"))


@app.command()
def case(ctx: typer.Context, case_id: str):
    emit(ctx, request(ctx, "GET", f"/cases/{case_id}"))


@app.command()
def pause(ctx: typer.Context, project_id: str):
    emit(ctx, request(ctx, "POST", f"/projects/{project_id}/pause"))


@app.command()
def resume(ctx: typer.Context, project_id: str):
    emit(ctx, request(ctx, "POST", f"/projects/{project_id}/resume"))


@app.command()
def retry_setup(ctx: typer.Context, project_id: str):
    emit(ctx, request(ctx, "POST", f"/projects/{project_id}/retry-setup"))


@app.command()
def cancel(ctx: typer.Context, cycle_id: str, yes: bool = False):
    if not yes:
        if not os.isatty(0):
            raise typer.BadParameter("Use --yes for noninteractive cancellation")
        typer.confirm("Cancel this cycle and reconcile any staged changes?", abort=True)
    emit(ctx, request(ctx, "POST", f"/cycles/{cycle_id}/cancel"))


@app.command()
def report(ctx: typer.Context, run_id: str, output: Path, force: bool = False):
    if output.exists() and not force:
        raise typer.BadParameter("Output exists; use --force to replace it")
    data = request(ctx, "GET", f"/reports/{run_id}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2) + "\n")
    emit(ctx, {"status": "exported", "path": str(output)})
