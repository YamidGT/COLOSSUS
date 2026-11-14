"""Authenticated operator API shared by the CLI and repository action center."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import Field

from colossus.contracts.core import Contract, DomainError, content_hash
from colossus.contracts.models import ApprovalRequest, Enrollment, RejectionRequest, RollbackRequest
from colossus.control.artifacts import ArtifactStore
from colossus.control.auth import COOKIE, OperatorAuth
from colossus.control.config import Settings
from colossus.control.lifecycle import InstanceLock
from colossus.control.service import Controller
from colossus.control.services import ServiceSupervisor
from colossus.control.store import Store
from colossus.control.worker import Worker


class RunRequest(Contract):
    trigger: str = "manual"


class LoginRequest(Contract):
    code: str = Field(min_length=1, max_length=100)


def create_app(settings: Settings | None = None, *, execute_tasks: bool = True) -> FastAPI:
    settings = settings or Settings.from_environment()
    token = settings.prepare()
    store = Store(settings.data_dir / "state.sqlite3")
    controller = Controller(store, settings.runtime)
    auth = OperatorAuth(store, token)
    evidence = ArtifactStore(settings.data_dir / "artifacts")

    @asynccontextmanager
    async def lifespan(app):
        if not execute_tasks:
            yield
            return
        instance = InstanceLock(settings.data_dir / "controller.lock")
        instance.acquire()
        services = ServiceSupervisor(settings)
        worker = None
        background = None
        try:
            try:
                await services.start()
                health = await services.clients["launcher"].call("/health")
                if not health.get("ready"):
                    raise DomainError(
                        "sandbox_unavailable", "Configured isolation runtime is unavailable", 503
                    )
                worker = Worker(store, evidence, services, controller, settings.runtime)
                app.state.worker = worker
                app.state.services = services
                background = asyncio.create_task(worker.run(), name="colossus-worker")
                app.state.worker_task = background
            except DomainError as exc:
                app.state.runtime_error = {"code": exc.code, "message": exc.message}
                await services.stop()
            yield
        finally:
            if worker:
                worker.stop_event.set()
            if background:
                try:
                    await asyncio.wait_for(background, timeout=30)
                except (TimeoutError, asyncio.CancelledError, DomainError):
                    background.cancel()
                except Exception:
                    pass
            await services.stop()
            instance.release()
            store.close()

    app = FastAPI(
        title="COLOSSUS operator API",
        version="1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.store = store
    app.state.controller = controller
    app.state.auth = auth
    app.state.evidence = evidence

    @app.exception_handler(DomainError)
    async def domain_error(request, exc):
        return JSONResponse({"error": exc.as_dict()}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        # Pydantic input values may contain credentials or hostile source text.
        errors = [
            {"loc": list(error["loc"]), "type": error["type"], "message": error["msg"]}
            for error in exc.errors()
        ]
        return JSONResponse(
            {
                "error": {
                    "code": "invalid_input",
                    "message": "Request validation failed",
                    "details": errors,
                }
            },
            status_code=422,
        )

    @app.middleware("http")
    async def boundaries(request: Request, call_next):
        try:
            host = urlsplit("//" + request.headers.get("host", "")).hostname
        except ValueError:
            host = None
        if host not in {"127.0.0.1", "localhost", "::1"}:
            return JSONResponse(
                {"error": {"code": "invalid_host", "message": "Loopback host required"}},
                status_code=400,
            )
        write = request.method not in {"GET", "HEAD", "OPTIONS"}
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.headers['host']}":
            return JSONResponse(
                {"error": {"code": "invalid_origin", "message": "Same-origin request required"}},
                status_code=403,
            )
        if write and request.cookies.get(COOKIE) and not origin:
            return JSONResponse(
                {"error": {"code": "origin_required", "message": "Browser writes require Origin"}},
                status_code=403,
            )
        if (
            request.url.path.startswith("/api/v1")
            and request.url.path != "/api/v1/sessions/exchange"
        ):
            try:
                request.state.actor = auth.authenticate(request, write=write)
            except DomainError as exc:
                return JSONResponse({"error": exc.as_dict()}, status_code=exc.status_code)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["Cache-Control"] = (
            "no-store" if request.url.path.startswith("/api/") else "no-cache"
        )
        return response

    def key(request: Request) -> str:
        value = request.headers.get("idempotency-key")
        if not value:
            raise DomainError(
                "missing_idempotency_key", "State changes require Idempotency-Key", 422
            )
        return value

    @app.get("/api/v1/openapi.json")
    def schema():
        return app.openapi()

    @app.get("/api/v1/system/readiness")
    def readiness():
        return {
            "controller": "ready",
            "database": "ready",
            "pipeline": getattr(getattr(app.state, "worker", None), "state", "not_started"),
            "runtime_error": getattr(app.state, "runtime_error", None),
            "worker_alive": bool(
                getattr(app.state, "worker_task", None) and not app.state.worker_task.done()
            ),
            "implemented_runtime_profiles": ["dsvw-python-v1"],
            "remaining_capabilities": [
                "deployment",
                "rollback",
                "formal_adapters",
                "feed_polling",
                "additional_buildpacks",
                "evaluation_campaign",
                "frontend",
            ],
            "docker_context": settings.docker_context,
            "sandbox_runtime": settings.sandbox_runtime,
            "model_credentials": "gateway_only",
            "budget": store.budget(),
        }

    @app.post("/api/v1/sessions/codes")
    def code(request: Request):
        if request.state.actor != "operator:cli":
            raise DomainError("forbidden", "Only host CLI can create login codes", 403)
        return auth.issue()

    @app.post("/api/v1/sessions/exchange")
    def exchange(body: LoginRequest, request: Request, response: Response):
        session_token, csrf = auth.exchange(
            body.code, request.client.host if request.client else "local"
        )
        response.set_cookie(
            COOKIE,
            session_token,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            max_age=28800,
            path="/",
        )
        return {"operator": "local", "csrf_token": csrf}

    @app.get("/api/v1/session")
    def session(request: Request):
        if request.state.actor == "operator:cli":
            return {"operator": "local", "csrf_token": None}
        return {"operator": "local", "csrf_token": auth.session(request.cookies[COOKIE])["csrf"]}

    @app.delete("/api/v1/session")
    def logout(request: Request, response: Response):
        if COOKIE in request.cookies:
            auth.revoke(request.cookies[COOKIE])
        response.delete_cookie(COOKIE)
        return {"status": "logged_out"}

    @app.post("/api/v1/projects", status_code=202)
    def enroll(body: Enrollment, request: Request):
        return controller.enroll(body, key(request), request.state.actor)

    @app.get("/api/v1/projects")
    def projects(limit: int = 25, cursor: str | None = None):
        if not 1 <= limit <= 100:
            raise DomainError("invalid_pagination", "Limit must be 1 through 100", 422)
        try:
            offset = int(cursor or 0)
        except ValueError:
            raise DomainError("invalid_cursor", "Invalid cursor", 422) from None
        rows = store.list("project", limit=limit, offset=offset)
        return {
            "items": [controller.snapshot(p["project_id"]) for p in rows],
            "next_cursor": str(offset + limit) if len(rows) == limit else None,
        }

    @app.get("/api/v1/projects/{project_id}/status")
    def status(project_id: str, request: Request):
        value = controller.snapshot(project_id)
        etag = controller.snapshot_etag(value)
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(value, headers={"ETag": etag})

    @app.get("/api/v1/projects/{project_id}/actions")
    def actions(project_id: str):
        return {"items": controller.actions(project_id)}

    @app.get("/api/v1/projects/{project_id}/cycles")
    def cycles(project_id: str):
        store.get("project", project_id)
        return {"items": store.list("cycle", project_id)}

    @app.get("/api/v1/projects/{project_id}/findings")
    def findings(project_id: str):
        store.get("project", project_id)
        return {"items": store.list("finding", project_id)}

    @app.post("/api/v1/projects/{project_id}/cycles", status_code=202)
    def run(project_id: str, body: RunRequest, request: Request):
        return controller.run(project_id, key(request), request.state.actor, body.trigger)

    @app.post("/api/v1/projects/{project_id}/pause")
    def pause(project_id: str, request: Request):
        return controller.admission(project_id, True, key(request), request.state.actor)

    @app.post("/api/v1/projects/{project_id}/resume")
    def resume(project_id: str, request: Request):
        return controller.admission(project_id, False, key(request), request.state.actor)

    @app.post("/api/v1/projects/{project_id}/retry-setup", status_code=202)
    def retry_setup(project_id: str, request: Request):
        return controller.retry_setup(project_id, key(request), request.state.actor)

    @app.get("/api/v1/cycles/{cycle_id}")
    def cycle(cycle_id: str):
        return store.get("cycle", cycle_id)

    @app.post("/api/v1/cycles/{cycle_id}/cancel", status_code=202)
    def cancel(cycle_id: str, request: Request):
        return controller.cancel(cycle_id, key(request), request.state.actor)

    @app.get("/api/v1/cases/{case_id}")
    def case(case_id: str):
        return store.get("case", case_id)

    @app.get("/api/v1/evidence/{manifest_hash}/review")
    def evidence_review(manifest_hash: str):
        matches = [
            c
            for c in store.list("case", limit=1000)
            if c.get("evidence_manifest_hash") == manifest_hash
        ]
        if len(matches) != 1:
            raise DomainError("not_found", "Evidence has no unique case review", 404)
        return matches[0]

    @app.post("/api/v1/cases/{case_id}/approve", status_code=202)
    def approve(case_id: str, body: ApprovalRequest, request: Request):
        return controller.approve(case_id, body.model_dump(), key(request), request.state.actor)

    @app.post("/api/v1/cases/{case_id}/reject")
    def reject(case_id: str, body: RejectionRequest, request: Request):
        current = store.get("case", case_id)
        if current.get("candidate_id") != body.candidate_id:
            raise DomainError("stale_review", "Candidate changed; refresh the case")
        return controller.reject(
            case_id, body.expected_revision, body.reason, key(request), request.state.actor
        )

    @app.get("/api/v1/deployments/{deployment_id}")
    def deployment(deployment_id: str):
        return store.get("deployment", deployment_id)

    @app.post("/api/v1/deployments/{deployment_id}/rollback", status_code=202)
    def rollback(deployment_id: str, body: RollbackRequest, request: Request):
        value = store.get("deployment", deployment_id)
        return controller.rollback(
            value["project_id"], body.expected_generation, key(request), request.state.actor
        )

    @app.get("/api/v1/operations/{operation_id}")
    def operation(operation_id: str):
        return store.operation(operation_id)

    @app.get("/api/v1/profiles")
    def profiles():
        return {
            "policies": ["lab-auto-v1", "review-v1"],
            "destinations": ["local-web-v1", "local-consumer-v1"],
            "requirements": [],
        }

    @app.get("/api/v1/reports/{run_id}")
    def report(run_id: str):
        return controller.report(run_id)

    @app.get("/api/v1/artifacts/{artifact_id}/download")
    def artifact(artifact_id: str, project_id: str):
        record = store.get(
            "artifact",
            content_hash({"project_id": project_id, "artifact_id": artifact_id}),
            project_id,
        )
        if record.get("visibility") != "operator":
            raise DomainError("forbidden", "Artifact is not available to operator clients", 403)
        return Response(
            evidence.get(artifact_id),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="evidence-{artifact_id[:12]}.txt"'
            },
        )

    @app.get("/{path:path}")
    def frontend(path: str):
        if path.startswith("api/"):
            raise DomainError("not_found", "API route not found", 404)
        root = settings.frontend_dir.resolve()
        candidate = (root / path).resolve()
        if candidate.is_relative_to(root) and candidate.is_file():
            return FileResponse(candidate)
        if (root / "index.html").is_file():
            return FileResponse(root / "index.html")
        return JSONResponse(
            {
                "service": "COLOSSUS",
                "frontend": "not_built",
                "message": "Use the authenticated API; frontend build is pending",
            }
        )

    return app
