"""Service-specific Unix socket clients; target jobs never mount these sockets."""

from pathlib import Path

import httpx

from colossus.contracts.core import DomainError


class RPCClient:
    def __init__(self, socket: Path, token: str):
        self.client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=str(socket)),
            base_url="http://service",
            headers={"Authorization": "Bearer " + token},
            timeout=3600,
        )

    async def call(self, path: str, payload: dict | None = None):
        try:
            response = await self.client.request(
                "GET" if payload is None else "POST", path, json=payload
            )
        except httpx.HTTPError as exc:
            raise DomainError(
                "service_unavailable", "Trusted service is unavailable", 503, retryable=True
            ) from exc
        if response.is_error:
            try:
                error = response.json()["error"]
                raise DomainError(error["code"], error["message"], response.status_code)
            except (ValueError, KeyError):
                raise DomainError("service_error", "Trusted service failed", 503) from None
        return response.json()

    async def close(self):
        await self.client.aclose()
