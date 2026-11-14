"""Local operator bearer credentials and short-lived browser sessions."""

import secrets
import time
from collections import defaultdict, deque

from fastapi import Request

from colossus.contracts.core import DomainError, digest

from .store import Store

COOKIE = "colossus_session"


class OperatorAuth:
    def __init__(self, store: Store, operator_token: str):
        self.store = store
        self.operator_token = operator_token
        self.exchange_attempts = defaultdict(deque)

    def authenticate(self, request: Request, write: bool = False) -> str:
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Bearer ") and secrets.compare_digest(
            authorization[7:], self.operator_token
        ):
            return "operator:cli"
        token = request.cookies.get(COOKIE)
        if not token:
            raise DomainError("unauthorized", "Operator authentication required", 401)
        try:
            session = self.store.get("session", digest(token.encode()))
        except DomainError:
            raise DomainError("unauthorized", "Session is invalid", 401) from None
        if session["expires"] < time.time() or session.get("revoked"):
            raise DomainError("unauthorized", "Session expired; log in again", 401)
        if write and not secrets.compare_digest(
            request.headers.get("x-csrf-token", ""), session["csrf"]
        ):
            raise DomainError("csrf_failed", "Refresh the session before submitting an action", 403)
        return "operator:browser"

    def issue(self):
        code = secrets.token_urlsafe(24)
        self.store.put(
            "login_code", digest(code.encode()), {"expires": time.time() + 60, "used": False}
        )
        return {"code": code, "expires_in": 60}

    def exchange(self, code: str, client: str):
        now = time.time()
        attempts = self.exchange_attempts[client]
        while attempts and attempts[0] < now - 60:
            attempts.popleft()
        if len(attempts) >= 5:
            raise DomainError("rate_limited", "Too many login attempts", 429)
        attempts.append(now)
        code_id = digest(code.encode())
        import json

        with self.store.transaction() as db:
            row = db.execute(
                "SELECT data FROM records WHERE kind='login_code' AND id=?", (code_id,)
            ).fetchone()
            value = json.loads(row[0]) if row else None
            if not value or value["used"] or value["expires"] < now:
                raise DomainError("invalid_login_code", "Login code is invalid or expired", 401)
            self.store._put(
                db, "login_code", code_id, value | {"used": True}, None, value["revision"]
            )
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.store._put(
                db,
                "session",
                digest(token.encode()),
                {"csrf": csrf, "expires": now + 28800, "revoked": False},
                None,
            )
        return token, csrf

    def session(self, token: str):
        return self.store.get("session", digest(token.encode()))

    def revoke(self, token: str):
        key = digest(token.encode())
        state = self.store.get("session", key)
        self.store.put(
            "session", key, state | {"revoked": True}, expected_revision=state["revision"]
        )
