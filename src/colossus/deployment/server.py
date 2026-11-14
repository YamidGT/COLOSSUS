"""Private deployment authority; no provider keys or arbitrary source execution."""

import argparse
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from colossus.contracts.core import Contract, DomainError, Hash, Identifier, NonNegative
from colossus.contracts.models import Authorization, EvidenceManifest, GateResult, TargetManifest
from colossus.control.rpc import RPCClient
from colossus.deployment.service import LabDeployer


class Promotion(Contract):
    authorization: Authorization
    certificate: EvidenceManifest
    manifest: TargetManifest
    gates: list[GateResult] = Field(max_length=30)
    source_id: Hash


class ProjectAction(Contract):
    project_id: Identifier


class Rollback(Contract):
    project_id: Identifier
    expected_generation: NonNegative


class RoutedRequest(Contract):
    project_id: Identifier
    path: str = Field(default="/", max_length=8192)
    method: str = "GET"
    body: str | None = Field(default=None, max_length=16384)


def create_deployer(
    token, state_path, launcher_socket, launcher_token, observation_seconds, interval_seconds
):
    launcher = RPCClient(launcher_socket, launcher_token)
    deployer = LabDeployer(state_path, launcher, observation_seconds, interval_seconds)

    @asynccontextmanager
    async def lifespan(app):
        await deployer.reconcile()
        try:
            yield
        finally:
            deployer.close()
            await launcher.close()

    app = FastAPI(docs_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if not secrets.compare_digest(request.headers.get("authorization", ""), "Bearer " + token):
            return JSONResponse(
                {"error": {"code": "unauthorized", "message": "Invalid deployment capability"}},
                status_code=403,
            )
        return await call_next(request)

    @app.exception_handler(DomainError)
    async def domain_error(request, exc):
        return JSONResponse({"error": exc.as_dict()}, status_code=exc.status_code)

    @app.get("/health")
    async def health():
        return {
            "status": "ready",
            "destination_profile": "local-web-v1",
            "observation_seconds": observation_seconds,
        }

    @app.get("/destinations")
    async def destinations():
        return deployer.all_states()

    @app.get("/destinations/{project_id}")
    async def destination(project_id: str):
        return deployer.state(project_id)

    @app.post("/initialize")
    async def initialize(manifest: TargetManifest):
        return await deployer.initialize(manifest)

    @app.post("/promote")
    async def promote(body: Promotion):
        return await deployer.promote(
            body.authorization, body.certificate, body.manifest, body.gates, body.source_id
        )

    @app.post("/abort")
    async def abort(body: ProjectAction):
        return await deployer.abort(body.project_id)

    @app.post("/retire")
    async def retire(body: ProjectAction):
        return await deployer.retire(body.project_id)

    @app.post("/rollback")
    async def rollback(body: Rollback):
        return await deployer.rollback(body.project_id, body.expected_generation)

    @app.post("/request")
    async def routed_request(body: RoutedRequest):
        return await deployer.request(**body.model_dump())

    return app


if __name__ == "__main__":
    from colossus.control.lifecycle import watch_parent

    watch_parent()
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--launcher-socket", type=Path, required=True)
    parser.add_argument("--launcher-token-file", type=Path, required=True)
    parser.add_argument("--state-path", type=Path, required=True)
    parser.add_argument("--observation-seconds", type=int, default=300)
    parser.add_argument("--interval-seconds", type=int, default=15)
    args = parser.parse_args()
    if not 1 <= args.observation_seconds <= 600 or not 1 <= args.interval_seconds <= 60:
        raise SystemExit("Invalid observation bounds")
    uvicorn.run(
        create_deployer(
            args.token_file.read_text().strip(),
            args.state_path,
            args.launcher_socket,
            args.launcher_token_file.read_text().strip(),
            args.observation_seconds,
            args.interval_seconds,
        ),
        uds=str(args.socket),
        access_log=False,
        log_level="warning",
    )
