"""Terminal-safe rendering and the CLI JSON envelope."""

from __future__ import annotations

import json
import re
import sys
import unicodedata

import typer

SCHEMA_VERSION = "1.0"
MAX_TEXT = 4000

# CSI, OSC (BEL or ST terminated), DCS/SOS/PM/APC strings and two-byte escapes.
_ANSI = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
    r"|(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c)"
    r"|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*?(?:\x1b\\|\x9c)"
    r"|\x1b[@-Z\\-_]",
    re.DOTALL,
)


def clean(value: object, limit: int = MAX_TEXT) -> str:
    """Strip ANSI/control/bidi-format characters from server or target text."""
    text = _ANSI.sub("", str(value))
    text = "".join(
        ch
        for ch in text
        if ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co")
    )
    if len(text) > limit:
        text = text[:limit] + "… [truncated]"
    return text


def redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def envelope(
    *,
    ok: bool,
    status: str,
    operation_id: str | None = None,
    project_id: str | None = None,
    cycle_id: str | None = None,
    reason_code: str | None = None,
    message: str | None = None,
    action_url: str | None = None,
    data: object = None,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": ok,
        "operation_id": operation_id,
        "project_id": project_id,
        "cycle_id": cycle_id,
        "status": status,
        "reason_code": reason_code,
        "message": message,
        "action_url": action_url,
        "data": data,
    }


def human_lines(value: object, indent: int = 0) -> list[str]:
    pad = "  " * indent
    if isinstance(value, dict):
        if not value:
            return [pad + "{}"]
        lines = []
        for key, item in value.items():
            if isinstance(item, dict | list) and item:
                lines.append(f"{pad}{clean(key, 200)}:")
                lines.extend(human_lines(item, indent + 1))
            else:
                lines.append(f"{pad}{clean(key, 200)}: {_scalar(item, indent + 1)}")
        return lines
    if isinstance(value, list):
        if not value:
            return [pad + "[]"]
        lines = []
        for item in value:
            if isinstance(item, dict | list) and item:
                lines.append(pad + "-")
                lines.extend(human_lines(item, indent + 1))
            else:
                lines.append(f"{pad}- {_scalar(item, indent + 1)}")
        return lines
    return [pad + _scalar(value, indent)]


def _scalar(value: object, indent: int) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict | list):
        return "{}" if isinstance(value, dict) else "[]"
    return clean(value).replace("\n", "\n" + "  " * indent)


def output(result: dict, *, as_json: bool, secrets: list[str], human: list[str] | None = None):
    """Print one JSON object on stdout, or a sanitized human summary."""
    if as_json:
        # ASCII escaping keeps raw C1/bidi controls out of terminal output in pipe mode too.
        typer.echo(json.dumps(scrub(result, secrets), ensure_ascii=True))
        return
    lines = []
    if result.get("message"):
        lines.append(clean(result["message"]))
    if human is not None:
        lines.extend(human)
    elif result.get("data") is not None:
        lines.extend(human_lines(result["data"]))
    if result.get("action_url"):
        lines.append("Next: " + clean(result["action_url"]))
    stream_ok = result.get("ok", True)
    typer.echo(redact("\n".join(lines), secrets), err=not stream_ok)


def diag(text: str, secrets: list[str] | None = None) -> None:
    """Progress and diagnostics go to stderr so JSON stdout stays one object."""
    typer.echo(redact(clean(text), secrets or []), err=True)


def is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def scrub(value, secrets: list[str]):
    """Redact before encoding so escaped credential characters cannot defeat replacement."""
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, dict):
        return {redact(str(k), secrets): scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, secrets) for v in value]
    return value
