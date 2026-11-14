"""Runtime authority process with no provider credentials."""

import argparse
import base64
import secrets
from dataclasses import asdict
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from colossus.contracts.core import Contract, DomainError, Identifier
from colossus.sandbox.launcher import SandboxLauncher


class RunJob(Contract):
    project_id: str
    role: str
    files: dict[str, str]
    argv: list[str]
    timeout: int = Field(default=60, ge=1, le=3600)
    network: str = "none"


class PackageJob(Contract):
    files: dict[str, str]
    argv: list[str]


class FormalPolicyJob(Contract):
    project_id: Identifier
    profile_id: str
    expressions: dict[str, str]
    timeout: int = Field(default=90, ge=1, le=480)


class StartTarget(Contract):
    project_id: Identifier
    artifact_digest: str
    ttl_seconds: int = Field(default=7200, ge=60, le=14400)


class TargetRequest(Contract):
    project_id: Identifier
    environment_id: str
    port: int = Field(ge=1, le=65535)
    path: str = "/"
    method: str = "GET"
    body: str | None = None


class TerminateWork(Contract):
    project_id: Identifier
    keep: list[str] = Field(default_factory=list, max_length=4)


class ReapRequest(Contract):
    keep: list[str] = Field(default_factory=list, max_length=5000)


class StopTarget(Contract):
    project_id: Identifier
    environment_id: str
    network_id: str


def decode_files(encoded: dict[str, str]) -> dict[str, bytes]:
    if len(encoded) > 10000 or sum(map(len, encoded.values())) > 140 * 1024 * 1024:
        raise DomainError("source_limit", "Source exceeds transfer budget", 413)
    try:
        files = {path: base64.b64decode(value, validate=True) for path, value in encoded.items()}
    except ValueError:
        raise DomainError("invalid_source", "Invalid encoded source file", 422) from None
    if sum(map(len, files.values())) > 100 * 1024 * 1024:
        raise DomainError("source_limit", "Source exceeds sandbox transfer budget", 413)
    return files


def create_launcher(
    token: str, context: str, deploy_token: str | None = None, formal_toolchain: str | None = None
):
    app = FastAPI(docs_url=None, openapi_url=None)
    launcher = SandboxLauncher(context)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        supplied = request.headers.get("authorization", "")
        is_controller = secrets.compare_digest(supplied, "Bearer " + token)
        is_deployer = bool(
            deploy_token and secrets.compare_digest(supplied, "Bearer " + deploy_token)
        )
        if not is_controller and not is_deployer:
            return JSONResponse(
                {"error": {"code": "unauthorized", "message": "Invalid service capability"}},
                status_code=403,
            )
        if is_deployer and request.url.path not in {
            "/health",
            "/targets",
            "/targets/request",
            "/targets/stop",
        }:
            return JSONResponse(
                {
                    "error": {
                        "code": "forbidden",
                        "message": "Deployment capability cannot build or execute arbitrary jobs",
                    }
                },
                status_code=403,
            )
        return await call_next(request)

    @app.exception_handler(DomainError)
    async def domain_error(request, exc):
        return JSONResponse({"error": exc.as_dict()}, status_code=exc.status_code)

    @app.get("/health")
    def health():
        return launcher.preflight()

    @app.post("/run")
    def run(body: RunJob):
        files = decode_files(body.files)
        return asdict(
            launcher.run(body.project_id, body.role, files, body.argv, body.timeout, body.network)
        )

    @app.post("/package")
    def package(body: PackageJob):
        return launcher.package(decode_files(body.files), body.argv)

    @app.post("/formal/policy")
    def formal_policy(body: FormalPolicyJob):
        from colossus.verification.dafny import POLICY_CALIBRATION, DafnyAdapter

        if not formal_toolchain:
            raise DomainError(
                "formal_unsupported", "No calibrated formal toolchain configured", 422
            )
        if body.profile_id != POLICY_CALIBRATION.profile_id:
            raise DomainError("formal_unsupported", "Policy profile is not registered", 422)
        result = DafnyAdapter(launcher, formal_toolchain).execute(
            body.project_id, POLICY_CALIBRATION, body.expressions, body.timeout
        )
        result["files"] = {
            path: base64.b64encode(data).decode() for path, data in result["files"].items()
        }
        return result

    @app.post("/targets")
    def start_target(body: StartTarget):
        return launcher.start_target(body.project_id, body.artifact_digest, body.ttl_seconds)

    @app.post("/targets/request")
    def target_request(body: TargetRequest):
        return launcher.request(**body.model_dump())

    @app.post("/targets/stop")
    def stop_target(body: StopTarget):
        return launcher.stop_target(body.project_id, body.environment_id, body.network_id)

    @app.post("/terminate-work")
    def terminate_work(body: TerminateWork):
        return launcher.terminate_project_work(body.project_id, body.keep)

    @app.post("/reap")
    def reap(body: ReapRequest):
        return {"removed": launcher.reap(body.keep)}

    return app


if __name__ == "__main__":
    from colossus.control.lifecycle import watch_parent

    watch_parent()
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--deploy-token-file", type=Path)
    parser.add_argument("--formal-toolchain")
    args = parser.parse_args()
    try:  # reconcile orphans left by a previous launcher before serving
        SandboxLauncher(args.context).reap()
    except Exception as error:  # noqa: BLE001
        print("startup reap failed:", type(error).__name__, flush=True)
    uvicorn.run(
        create_launcher(
            args.token_file.read_text().strip(),
            args.context,
            args.deploy_token_file.read_text().strip() if args.deploy_token_file else None,
            args.formal_toolchain,
        ),
        uds=str(args.socket),
        access_log=False,
        log_level="warning",
    )
