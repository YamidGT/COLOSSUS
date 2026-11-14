import json

import pytest

from colossus.control.store import Store
from colossus.observability.tracing import (
    STATUS_ERROR,
    FileSink,
    MemorySink,
    Sampler,
    Tracer,
    current_span,
)

SECRET = "sk-TRACESECRETVALUE123"


class Clock:
    def __init__(self, start=1_000):
        self.now = start

    def __call__(self):
        return self.now


def _ids():
    counter = iter(range(1, 10_000))

    def make(n):
        return f"{next(counter):0{2 * n}x}"

    return make


def test_correlation_ids_propagate_to_children_and_otlp_attributes():
    sink = MemorySink()
    tracer = Tracer(sink, id_bytes=_ids())
    with tracer.span("cycle.run", project_id="p1", cycle_id="c1") as root:
        with tracer.span("case.verify", case_id="k1") as child:
            assert current_span() is child
            with tracer.span("candidate.build", task_id="t1", candidate_id="d1") as leaf:
                pass
    assert current_span() is None
    assert child.trace_id == root.trace_id == leaf.trace_id
    assert child.parent_span_id == root.span_id
    assert leaf.parent_span_id == child.span_id
    assert leaf.correlation.as_dict() == {
        "project_id": "p1",
        "cycle_id": "c1",
        "case_id": "k1",
        "task_id": "t1",
        "candidate_id": "d1",
    }
    exported = sink.requests[0]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert exported["name"] == "candidate.build"
    assert exported["parentSpanId"] == child.span_id
    keys = {a["key"]: a["value"]["stringValue"] for a in exported["attributes"]}
    assert keys["colossus.project_id"] == "p1"
    assert keys["colossus.candidate_id"] == "d1"
    assert len(exported["traceId"]) == 32 and len(exported["spanId"]) == 16


def test_correlation_cannot_be_rewritten_inside_a_branch():
    tracer = Tracer(MemorySink())
    with tracer.span("cycle.run", project_id="p1"):
        with pytest.raises(ValueError, match="project_id"):
            tracer.start("case", project_id="p2")
    with pytest.raises(ValueError, match="Unknown"):
        tracer.start("x", tenant="t")


def test_duration_is_monotonic_even_if_wall_clock_steps_back():
    mono, wall = Clock(5_000), Clock(10**18)
    sink = MemorySink()
    tracer = Tracer(sink, monotonic_ns=mono, wall_ns=wall)
    item = tracer.start("stage", project_id="p")
    mono.now += 2_500
    wall.now -= 10**12  # NTP step backwards
    tracer.end(item)
    assert item.duration_ns == 2_500
    span = sink.requests[0]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert int(span["endTimeUnixNano"]) - int(span["startTimeUnixNano"]) == 2_500


def test_unsampled_spans_still_reach_the_audit_record(tmp_path):
    store = Store(tmp_path / "c.sqlite")
    sink = FileSink(tmp_path / "otel" / "spans.jsonl")
    tracer = Tracer(sink, sampler=Sampler(0.0), audit=store.event)
    for n in range(5):
        with tracer.span("task.run", audit_kind="span.task", project_id="p1", task_id=f"t{n}"):
            pass
    with tracer.span("telemetry.only", project_id="p1"):
        pass
    assert not sink.path.exists() or sink.path.read_text() == ""
    assert tracer.not_sampled == 6
    audited = [e for e in store.audit("p1") if e["kind"] == "span.task"]
    assert [e["data"]["correlation"]["task_id"] for e in audited] == [f"t{n}" for n in range(5)]
    assert all(e["data"]["sampled"] is False for e in audited)
    assert store.verify_audit()


def test_full_sink_drops_telemetry_but_not_audit(tmp_path):
    store = Store(tmp_path / "c.sqlite")
    sink = FileSink(tmp_path / "spans.jsonl", max_bytes=1)
    tracer = Tracer(sink, audit=store.event)
    with tracer.span("deploy.swap", audit_kind="span.deploy", project_id="p1"):
        pass
    assert sink.dropped == 1 and sink.written == 0
    assert [e["kind"] for e in store.audit("p1")] == ["span.deploy"]


def test_audit_span_without_writer_fails_loudly():
    tracer = Tracer(MemorySink())
    with pytest.raises(RuntimeError, match="audit"):
        with tracer.span("authority.decide", audit_kind="span.authority"):
            pass


def test_file_sink_writes_otlp_json_lines_and_redacts(tmp_path):
    sink = FileSink(tmp_path / "spans.jsonl")
    tracer = Tracer(sink)
    with pytest.raises(KeyError):
        with tracer.span(
            "model.call", project_id="p1", attributes={"note": f"token={SECRET}"}
        ) as item:
            item.set(api_key=SECRET, latency_ms=12)
            raise KeyError("boom")
    with tracer.span("model.call", project_id="p1"):
        pass
    lines = sink.path.read_text().splitlines()
    assert len(lines) == 2
    assert SECRET not in sink.path.read_text()
    first = json.loads(lines[0])["resourceSpans"][0]
    assert first["resource"]["attributes"][0]["key"] == "service.name"
    span = first["scopeSpans"][0]["spans"][0]
    assert span["status"] == {"code": STATUS_ERROR, "message": "KeyError"}
    values = {a["key"]: a["value"] for a in span["attributes"]}
    assert values["latency_ms"] == {"intValue": "12"}
    assert values["api_key"] == {"stringValue": "[redacted]"}


def test_ratio_sampler_is_deterministic_per_trace():
    sampler = Sampler(0.5)
    low, high = "0" * 16 + "0" * 16, "0" * 16 + "f" * 16
    assert sampler.sampled(low) and not sampler.sampled(high)
    assert sampler.sampled(low) == sampler.sampled(low)
    with pytest.raises(ValueError):
        Sampler(1.5)
