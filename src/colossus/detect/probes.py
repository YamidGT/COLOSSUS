"""Closed-profile, harmless dynamic probes. The model may only choose a profile name,
a route and a parameter; it never supplies payloads, hosts, methods or headers."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

MAX_BODY = 1_048_576
MARK = "colossusxss7431"

PROFILES = {
    "sqli_boolean": "boolean-based SQL injection comparison",
    "xss_reflect": "reflected output encoding check",
    "path_traversal": "read of a world-readable canary path",
}


class ProbeRefused(Exception):
    pass


@dataclass
class ProbeResult:
    profile: str
    path: str
    param: str
    confirmed: bool
    detail: str
    requests: list[dict]


class ProbeRunner:
    def __init__(self, base_url: str, max_requests: int = 200, rate_per_sec: float = 2.0):
        u = urlsplit(base_url)
        if u.scheme not in ("http",) or not u.hostname:
            raise ProbeRefused("base URL must be http")
        self.base = base_url.rstrip("/")
        self.host = (u.hostname, u.port)
        self.max_requests = max_requests
        self.interval = 1.0 / rate_per_sec
        self.count = 0
        self._last = 0.0
        self.client = httpx.Client(follow_redirects=False, timeout=15)

    def _get(self, path: str, param: str, value: str) -> tuple[int, str]:
        if not path.startswith("/") or "//" in path or ".." in path or "\n" in path:
            raise ProbeRefused(f"bad path {path!r}")
        if self.count >= self.max_requests:
            raise ProbeRefused("request cap reached")
        wait = self.interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.count += 1
        url = f"{self.base}{path}"
        u = urlsplit(url)
        if (u.hostname, u.port) != self.host:
            raise ProbeRefused("host not allowlisted")
        r = self.client.get(url, params={param: value})
        return r.status_code, r.text[:MAX_BODY]

    def run(self, profile: str, path: str, param: str) -> ProbeResult:
        if profile not in PROFILES:
            raise ProbeRefused(f"unknown profile {profile!r}")
        if not param.isidentifier():
            raise ProbeRefused("bad parameter name")
        reqs: list[dict] = []

        def get(v: str) -> tuple[int, str]:
            code, body = self._get(path, param, v)
            reqs.append({"path": path, "param": param, "value": v, "status": code,
                         "body_len": len(body)})
            return code, body

        try:
            if profile == "xss_reflect":
                _, body = get(f"<{MARK}>")
                ok = f"<{MARK}>" in body
                return ProbeResult(profile, path, param, ok,
                                   "marker reflected unescaped" if ok else "not reflected raw", reqs)
            if profile == "path_traversal":
                _, body = get("../../../../../../etc/passwd")
                ok = "root:x:0:0" in body or "root:*:0:0" in body
                return ProbeResult(profile, path, param, ok,
                                   "canary file content returned" if ok else "no canary", reqs)
            # sqli_boolean: base vs always-true vs always-false must separate
            c0, b0 = get("1")
            c_true, b_true = get("1' OR '1'='1")
            c_false, b_false = get("1' AND '1'='2")
            err = any(s in b_true.lower() or s in b_false.lower()
                      for s in ("sqlite3.operationalerror", "syntax error", "sqlstate", "psycopg"))
            diff = (c_true, len(b_true)) != (c_false, len(b_false))
            ok = diff or err
            return ProbeResult(profile, path, param, ok,
                               "true/false conditions diverge or SQL error leaked"
                               if ok else "responses identical", reqs)
        except httpx.HTTPError as exc:
            return ProbeResult(profile, path, param, False, f"transport error: {exc.__class__.__name__}", reqs)
