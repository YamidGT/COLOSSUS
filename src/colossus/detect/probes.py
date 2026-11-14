"""Closed probes use runtime-owned target identities, never a caller-supplied host."""

import re
from dataclasses import dataclass
from urllib.parse import urlencode

PROFILES = {
    "sqli_boolean": "bounded boolean comparison",
    "xss_reflect": "output-encoding signal",
    "path_traversal": "declared synthetic canary read",
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
    def __init__(
        self, launcher, project_id, environment_id, port, *, max_requests=40, canary_token=None
    ):
        self.launcher, self.project_id, self.environment_id, self.port = (
            launcher,
            project_id,
            environment_id,
            port,
        )
        self.max_requests, self.count, self.canary_token = max_requests, 0, canary_token

    async def run(self, profile, path, param):
        if (
            profile not in PROFILES
            or not re.fullmatch(r"/[A-Za-z0-9_./-]*", path)
            or "//" in path
            or ".." in path
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", param)
        ):
            raise ProbeRefused("Unknown profile or invalid route/parameter")
        if profile == "path_traversal" and not self.canary_token:
            raise ProbeRefused("No synthetic canary was declared for this target")
        values = {
            "sqli_boolean": ["1", "1", "1 AND 1=1", "1 AND 1=2"],
            "xss_reflect": ["<colossus-check>"],
            "path_traversal": ["../../../../tmp/colossus-canary.txt"],
        }[profile]
        if self.count + len(values) > self.max_requests:
            raise ProbeRefused("Request cap reached")
        responses, requests = [], []
        for value in values:
            self.count += 1
            result = await self.launcher.call(
                "/targets/request",
                {
                    "project_id": self.project_id,
                    "environment_id": self.environment_id,
                    "port": self.port,
                    "path": path + "?" + urlencode({param: value}),
                },
            )
            responses.append(result)
            requests.append(
                {
                    "path": path,
                    "param": param,
                    "value": value,
                    "status": result.get("status"),
                    "body_length": len(result.get("body", "")),
                }
            )
        if profile == "path_traversal":
            confirmed = responses[0].get("status") == 200 and self.canary_token in responses[0].get(
                "body", ""
            )
            return ProbeResult(
                profile,
                path,
                param,
                confirmed,
                "Synthetic canary matched" if confirmed else "Canary not observed",
                requests,
            )
        if profile == "xss_reflect":
            signal = "<colossus-check>" in responses[0].get("body", "")
            return ProbeResult(
                profile,
                path,
                param,
                False,
                "Raw reflection requires browser-context review"
                if signal
                else "No raw marker reflection",
                requests,
            )
        bodies = [r.get("body", "") for r in responses]
        stable = (
            all(r.get("status") == 200 and not r.get("truncated") for r in responses)
            and bodies[0] == bodies[1] == bodies[2]
            and bodies[2] != bodies[3]
        )
        # This generic signal is never sufficient to certify SQL injection. The protected
        # repository oracle supplies confirmation separately (e.g. DSVW id-query check).
        return ProbeResult(
            profile,
            path,
            param,
            False,
            "Stable boolean divergence; protected oracle required"
            if stable
            else "No stable boolean signal",
            requests,
        )
