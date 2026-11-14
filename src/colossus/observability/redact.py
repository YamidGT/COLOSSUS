"""Redacted audit events. This is not an OpenTelemetry exporter."""

from __future__ import annotations

import re
from typing import Any

_PRIVATE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_SK = re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b")
_ASSIGN = re.compile(
    r"(?i)\b(api[_-]?key|token|password|secret|authorization)\b(\s*[:=]\s*)([^\s,;]+)"
)
_SENSITIVE = ("secret", "token", "password", "api_key", "apikey", "authorization", "private_key")


def _sensitive(key: str) -> bool:
    folded = key.lower().replace("-", "_")
    return any(part in folded for part in _SENSITIVE)


def redact_text(value: str) -> str:
    value = _PRIVATE.sub("[redacted]", value)
    value = _SK.sub("[redacted]", value)
    return _ASSIGN.sub(r"\1\2[redacted]", value)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: "[redacted]" if _sensitive(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def span(name: str, **ids: str) -> dict:
    return {"name": name, "trace": redact(ids)}
