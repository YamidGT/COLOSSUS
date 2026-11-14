"""Trace/span model with COLOSSUS correlation IDs and OTLP-compatible JSON export.

No OpenTelemetry SDK is used. Spans are written as OTLP/JSON ``ExportTraceServiceRequest``
objects, one per line, so a collector ``filelog``/``otlpjson`` receiver can ingest them.

Two outputs are kept apart on purpose:

* telemetry: sampled and bounded. A span that is not sampled, or that does not fit the
  sink's byte budget, is dropped and counted.
* audit: unsampled. A span created with ``audit_kind`` is handed to the audit callable on
  end whatever the sampling decision or sink state. Audit failures propagate; they are
  never swallowed.
"""

from __future__ import annotations

import contextvars
import json
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from colossus.observability.redact import redact

CORRELATION_KEYS = (
    "project_id",
    "cycle_id",
    "case_id",
    "task_id",
    "candidate_id",
    "deployment_id",
)
ATTRIBUTE_PREFIX = "colossus."
SCOPE_NAME = "colossus.observability"
SCOPE_VERSION = "1"
SPAN_KIND_INTERNAL = 1
STATUS_UNSET, STATUS_OK, STATUS_ERROR = 0, 1, 2

AuditCallable = Callable[[str, dict, "str | None", str], None]
"""Signature of ``Store.event(kind, data, project_id, actor)``."""


@dataclass(frozen=True)
class Correlation:
    project_id: str | None = None
    cycle_id: str | None = None
    case_id: str | None = None
    task_id: str | None = None
    candidate_id: str | None = None
    deployment_id: str | None = None

    def merge(self, **ids: str | None) -> Correlation:
        unknown = set(ids) - set(CORRELATION_KEYS)
        if unknown:
            raise ValueError(f"Unknown correlation keys: {sorted(unknown)}")
        current = {k: getattr(self, k) for k in CORRELATION_KEYS}
        for key, value in ids.items():
            if value is None:
                continue
            if current[key] is not None and current[key] != value:
                raise ValueError(f"Correlation {key} cannot change inside a trace branch")
            current[key] = value
        return Correlation(**current)

    def as_dict(self) -> dict[str, str]:
        return {k: v for k in CORRELATION_KEYS if (v := getattr(self, k)) is not None}


class Sampler:
    """Deterministic trace-ID ratio sampler (same idea as OTel TraceIdRatioBased)."""

    def __init__(self, ratio: float = 1.0):
        if not 0.0 <= ratio <= 1.0:
            raise ValueError("Sampling ratio must be within [0, 1]")
        self.ratio = ratio
        self._bound = int(ratio * (1 << 64))

    def sampled(self, trace_id: str) -> bool:
        if self.ratio >= 1.0:
            return True
        return int(trace_id[16:], 16) < self._bound


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    correlation: Correlation
    sampled: bool
    start_unix_nano: int
    start_monotonic_ns: int
    audit_kind: str | None = None
    actor: str = "controller"
    attributes: dict[str, Any] = field(default_factory=dict)
    end_unix_nano: int | None = None
    duration_ns: int | None = None
    status_code: int = STATUS_UNSET
    status_message: str = ""

    def set(self, **attributes: Any) -> None:
        if self.duration_ns is not None:
            raise RuntimeError("Span already ended")
        self.attributes.update(attributes)

    def summary(self) -> dict:
        """Redacted, deterministic dict used for the audit record."""
        return redact(
            {
                "name": self.name,
                "trace_id": self.trace_id,
                "span_id": self.span_id,
                "parent_span_id": self.parent_span_id,
                "correlation": self.correlation.as_dict(),
                "duration_ns": self.duration_ns,
                "status": {STATUS_OK: "ok", STATUS_ERROR: "error"}.get(self.status_code, "unset"),
                "status_message": self.status_message,
                "sampled": self.sampled,
                "attributes": self.attributes,
            }
        )


def _any_value(value: Any) -> dict:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, list | tuple):
        return {"arrayValue": {"values": [_any_value(v) for v in value]}}
    if value is None:
        return {"stringValue": ""}
    if isinstance(value, dict):
        return {"stringValue": json.dumps(value, sort_keys=True, separators=(",", ":"))}
    return {"stringValue": str(value)}


def _attributes(values: dict[str, Any]) -> list[dict]:
    return [{"key": k, "value": _any_value(values[k])} for k in sorted(values)]


def to_otlp(spans: list[Span], resource: dict[str, Any]) -> dict:
    """Build one OTLP/JSON ExportTraceServiceRequest. IDs are lower-case hex as in OTLP/JSON."""
    out = []
    for item in spans:
        attributes = {ATTRIBUTE_PREFIX + k: v for k, v in item.correlation.as_dict().items()}
        attributes |= redact(item.attributes)
        span_json: dict[str, Any] = {
            "traceId": item.trace_id,
            "spanId": item.span_id,
            "name": item.name,
            "kind": SPAN_KIND_INTERNAL,
            "startTimeUnixNano": str(item.start_unix_nano),
            "endTimeUnixNano": str(item.end_unix_nano),
            "attributes": _attributes(attributes),
            "status": {"code": item.status_code},
        }
        if item.parent_span_id:
            span_json["parentSpanId"] = item.parent_span_id
        if item.status_message:
            span_json["status"]["message"] = redact(item.status_message)
        out.append(span_json)
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": _attributes(redact(resource))},
                "scopeSpans": [
                    {"scope": {"name": SCOPE_NAME, "version": SCOPE_VERSION}, "spans": out}
                ],
            }
        ]
    }


class FileSink:
    """Append-only JSON-lines telemetry sink with a byte budget.

    Telemetry may be lost (budget exhausted, I/O error); the loss is counted in
    ``dropped``. This sink must never be used as the audit record.
    """

    def __init__(self, path: Path, max_bytes: int = 64 * 1024 * 1024):
        self.path = path
        self.max_bytes = max_bytes
        self.dropped = 0
        self.written = 0
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def export(self, request: dict) -> bool:
        line = (json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with self._lock:
            size = self.path.stat().st_size if self.path.exists() else 0
            if size + len(line) > self.max_bytes:
                self.dropped += 1
                return False
            try:
                with self.path.open("ab") as handle:
                    handle.write(line)
            except OSError:
                self.dropped += 1
                return False
            self.written += 1
            return True


class MemorySink:
    def __init__(self):
        self.requests: list[dict] = []
        self.dropped = 0

    def export(self, request: dict) -> bool:
        self.requests.append(request)
        return True


_current: contextvars.ContextVar[Span | None] = contextvars.ContextVar(
    "colossus_current_span", default=None
)


class Tracer:
    def __init__(
        self,
        sink: FileSink | MemorySink | None = None,
        *,
        sampler: Sampler | None = None,
        audit: AuditCallable | None = None,
        resource: dict[str, Any] | None = None,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        wall_ns: Callable[[], int] = time.time_ns,
        id_bytes: Callable[[int], str] = secrets.token_hex,
    ):
        self.sink = sink
        self.sampler = sampler or Sampler(1.0)
        self.audit = audit
        self.resource = {"service.name": "colossus-controller"} | (resource or {})
        self._monotonic_ns = monotonic_ns
        self._wall_ns = wall_ns
        self._id = id_bytes
        self.not_sampled = 0

    def start(
        self,
        name: str,
        *,
        audit_kind: str | None = None,
        actor: str = "controller",
        parent: Span | None = None,
        attributes: dict[str, Any] | None = None,
        **ids: str | None,
    ) -> Span:
        parent = parent if parent is not None else _current.get()
        if parent is not None:
            trace_id, parent_id = parent.trace_id, parent.span_id
            correlation, sampled = parent.correlation.merge(**ids), parent.sampled
        else:
            trace_id, parent_id = self._id(16), None
            correlation = Correlation().merge(**ids)
            sampled = self.sampler.sampled(trace_id)
        return Span(
            name=name,
            trace_id=trace_id,
            span_id=self._id(8),
            parent_span_id=parent_id,
            correlation=correlation,
            sampled=sampled,
            start_unix_nano=self._wall_ns(),
            start_monotonic_ns=self._monotonic_ns(),
            audit_kind=audit_kind,
            actor=actor,
            attributes=dict(attributes or {}),
        )

    def end(self, item: Span, *, error: BaseException | str | None = None) -> Span:
        if item.duration_ns is not None:
            raise RuntimeError("Span already ended")
        item.duration_ns = max(0, self._monotonic_ns() - item.start_monotonic_ns)
        # End time is derived from the monotonic duration so wall-clock steps
        # during the span cannot produce negative or inflated durations.
        item.end_unix_nano = item.start_unix_nano + item.duration_ns
        if error is not None:
            item.status_code = STATUS_ERROR
            item.status_message = (
                type(error).__name__ if isinstance(error, BaseException) else str(error)
            )[:200]
        elif item.status_code == STATUS_UNSET:
            item.status_code = STATUS_OK
        # Audit first and unconditionally: sampling and sink state never affect it.
        if item.audit_kind is not None:
            if self.audit is None:
                raise RuntimeError("Span requires an audit record but no audit writer is set")
            self.audit(item.audit_kind, item.summary(), item.correlation.project_id, item.actor)
        if not item.sampled:
            self.not_sampled += 1
        elif self.sink is not None:
            self.sink.export(to_otlp([item], self.resource))
        return item

    @contextmanager
    def span(self, name: str, **kwargs: Any) -> Iterator[Span]:
        item = self.start(name, **kwargs)
        token = _current.set(item)
        try:
            yield item
        except BaseException as exc:
            _current.reset(token)
            self.end(item, error=exc)
            raise
        _current.reset(token)
        self.end(item)


def current_span() -> Span | None:
    return _current.get()
