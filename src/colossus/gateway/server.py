"""Credential-holding gateway served only on a protected Unix socket."""

import argparse
import asyncio
import base64
import secrets
from dataclasses import asdict
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from colossus.contracts.core import Contract, DomainError
from colossus.contracts.models import Enrollment
from colossus.gateway.model import ModelGateway, load_provider_key
from colossus.gateway.source import GitHubSource


class CompletionRequest(Contract):
    call_id: str
    messages: list[dict]
    max_tokens: int = Field(default=4096, ge=1, le=8192)
    reasoning: str = "low"
    json_output: bool = True


def create_gateway(token: str, env_file: Path):
    app = FastAPI(docs_url=None, openapi_url=None)
    client = httpx.AsyncClient(follow_redirects=False)
    model = ModelGateway(load_provider_key(env_file), client)
    source = GitHubSource(client)
    slots = asyncio.Semaphore(2)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if not secrets.compare_digest(request.headers.get("authorization", ""), "Bearer " + token):
            return JSONResponse(
                {"error": {"code": "unauthorized", "message": "Invalid service capability"}},
                status_code=403,
            )
        return await call_next(request)

    @app.exception_handler(DomainError)
    async def domain_error(request, exc):
        return JSONResponse({"error": exc.as_dict()}, status_code=exc.status_code)

    @app.get("/health")
    def health():
        return {"status": "ready", "model": model.metadata()}

    @app.post("/source")
    async def fetch(body: Enrollment):
        result = await source.fetch(body)
        result["files"] = {
            path: base64.b64encode(data).decode() for path, data in result["files"].items()
        }
        return result

    @app.post("/complete")
    async def complete(body: CompletionRequest):
        async with slots:
            return asdict(
                await model.complete(
                    body.messages, body.max_tokens, body.reasoning, body.json_output
                )
            )

    return app


if __name__ == "__main__":
    from colossus.control.lifecycle import watch_parent

    watch_parent()
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    args = parser.parse_args()
    uvicorn.run(
        create_gateway(args.token_file.read_text().strip(), args.env_file),
        uds=str(args.socket),
        access_log=False,
        log_level="warning",
    )
