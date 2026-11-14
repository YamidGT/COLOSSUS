"""HTTP client for the operator API: auth, idempotent retries and exit-code mapping."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from colossus.control.config import Settings

API_PREFIX = "/api/v1"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
TRANSPORT_ATTEMPTS = 3
RETRY_STATUSES = {502, 503, 504}
RETRY_BACKOFF_SECONDS = 0.5

# Exit codes from docs/cli.md.
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BLOCKED = 3
EXIT_UNSUCCESSFUL = 4
EXIT_TRANSPORT = 5
EXIT_WATCH_DEADLINE = 6
EXIT_INTERRUPTED = 130


class CliError(Exception):
    """A failure that ends the command with a documented exit code."""

    def __init__(
        self,
        exit_code: int,
        reason_code: str,
        message: str,
        *,
        http_status: int | None = None,
        data: dict | None = None,
    ):
        super().__init__(message)
        self.exit_code = exit_code
        self.reason_code = reason_code
        self.message = message
        self.http_status = http_status
        self.data = data


def exit_code_for_status(status: int) -> int:
    if status in (401, 403, 409):
        return EXIT_BLOCKED
    if status in (400, 404, 422):
        return EXIT_USAGE
    return EXIT_TRANSPORT


def unavailable(command: str, method: str, route: str) -> CliError:
    return CliError(
        EXIT_BLOCKED,
        "not_available",
        f"`colossus {command}` is not available on this server "
        f"({method} {API_PREFIX}{route} is not implemented).",
    )


def validate_api_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or parts.hostname not in LOOPBACK:
        raise CliError(
            EXIT_USAGE,
            "invalid_api_url",
            "API URL must be a loopback http(s) address (use an SSH tunnel for remote hosts).",
        )
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise CliError(
            EXIT_USAGE, "invalid_api_url", "API URL must not contain a path or credentials."
        )
    return url.rstrip("/")


def read_token() -> str:
    token = os.environ.get("COLOSSUS_OPERATOR_TOKEN")
    if token:
        return token.strip()
    path = Settings.from_environment().data_dir / "operator.token"
    if not path.is_file() or path.is_symlink():
        raise CliError(
            EXIT_BLOCKED,
            "not_initialized",
            "Controller is not initialized; run colossus serve first.",
        )
    return path.read_text().strip()


def make_http_client(api_url: str, timeout: float) -> httpx.Client:
    """Factory seam: tests replace it with a MockTransport or FastAPI TestClient."""
    return httpx.Client(base_url=api_url, timeout=timeout, follow_redirects=False)


def _template(path: str) -> str:
    return re.sub(r"\{[^}]*\}", "{}", path)


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


@dataclass
class ApiClient:
    api_url: str
    timeout: float
    idempotency_key: str | None = None
    _token: str | None = None
    _http: httpx.Client | None = None
    _routes: dict | None = None
    _keys_used: list = field(default_factory=list)

    @property
    def token(self) -> str:
        if self._token is None:
            self._token = read_token()
        return self._token

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = make_http_client(self.api_url, self.timeout)
        return self._http

    def secrets(self) -> list[str]:
        return [self._token] if self._token else []

    def new_key(self) -> str:
        """One idempotency key per mutation; an explicit --idempotency-key wins."""
        key = self.idempotency_key or str(uuid4())
        self._keys_used.append(key)
        return key

    def send(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        key: str | None = None,
        headers: dict | None = None,
        params: dict | None = None,
    ) -> httpx.Response:
        all_headers = {"Authorization": "Bearer " + self.token, **(headers or {})}
        if method not in ("GET", "HEAD"):
            # The same key and identical body are reused for every transport retry.
            all_headers["Idempotency-Key"] = key or self.new_key()
        last: Exception | None = None
        for attempt in range(TRANSPORT_ATTEMPTS):
            try:
                response = self.http.request(
                    method,
                    API_PREFIX + path,
                    json=body,
                    headers=all_headers,
                    params=params,
                )
            except httpx.HTTPError as exc:
                last = exc
            else:
                if response.status_code not in RETRY_STATUSES or attempt == TRANSPORT_ATTEMPTS - 1:
                    return response
            _sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
        raise CliError(
            EXIT_TRANSPORT,
            "transport_error",
            "Cannot reach the controller. Check the service or SSH tunnel.",
        ) from last

    def request(self, method: str, path: str, body: dict | None = None, **kw) -> dict:
        response = self.send(method, path, body, **kw)
        return self.decode(response, method, path)

    def decode(self, response: httpx.Response, method: str, path: str) -> dict:
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.is_error:
            error = data.get("error") if isinstance(data, dict) else None
            if response.status_code == 405 or (
                response.status_code == 404
                and isinstance(error, dict)
                and error.get("message") == "API route not found"
            ):
                raise CliError(
                    EXIT_BLOCKED,
                    "not_available",
                    f"{method} {API_PREFIX}{path} is not available on this server.",
                    http_status=response.status_code,
                )
            if not isinstance(error, dict):
                error = {"code": "http_" + str(response.status_code), "message": "Request failed"}
            raise CliError(
                exit_code_for_status(response.status_code),
                str(error.get("code") or "error"),
                str(error.get("message") or "Request failed"),
                http_status=response.status_code,
                data=error,
            )
        if not isinstance(data, dict):
            raise CliError(
                EXIT_TRANSPORT, "invalid_response", "Controller returned an invalid response."
            )
        return data

    def has_route(self, method: str, route: str) -> bool | None:
        """Check the server's published OpenAPI paths; None when it cannot be determined."""
        if self._routes is None:
            try:
                response = self.send("GET", "/openapi.json")
                schema = response.json() if response.status_code == 200 else None
            except (CliError, ValueError):
                schema = None
            paths = schema.get("paths") if isinstance(schema, dict) else None
            self._routes = paths if isinstance(paths, dict) else {}
            if not isinstance(paths, dict):
                return None
        if not self._routes:
            return None
        wanted = _template(API_PREFIX + route)
        return any(
            _template(path) == wanted and isinstance(entry, dict) and method.lower() in entry
            for path, entry in self._routes.items()
        )

    def require_route(self, command: str, method: str, route: str) -> None:
        # Unknown capability (no schema) falls through to the 404/405 mapping in decode().
        if self.has_route(method, route) is False:
            raise unavailable(command, method, route)

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
