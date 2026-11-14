"""CLI behavior against a scripted httpx MockTransport."""

import json

import httpx
import pytest
from typer.testing import CliRunner

from colossus.cli import client as cli_client
from colossus.cli import main as cli_main
from colossus.cli import render
from colossus.cli.main import app

TOKEN = "operator-token-DO-NOT-PRINT-789"
ENVELOPE = {
    "schema_version",
    "ok",
    "operation_id",
    "project_id",
    "cycle_id",
    "status",
    "reason_code",
    "message",
    "action_url",
    "data",
}


def receipt(**ids):
    return {
        "operation_id": "op-1",
        "idempotency_key": "k",
        "request_hash": "h",
        "kind": "run",
        "resource_ids": ids,
        "status": "accepted",
        "reason_code": None,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "result_ref": None,
    }


class Server:
    """Records requests; `handler(request)` returns an httpx.Response or raises."""

    def __init__(self, handler):
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        return self.handler(request)

    def calls(self, method=None):
        return [r for r in self.requests if method is None or r.method == method]


@pytest.fixture
def serve(monkeypatch):
    monkeypatch.setenv("COLOSSUS_OPERATOR_TOKEN", TOKEN)
    monkeypatch.setattr(cli_client, "_sleep", lambda s: None)
    monkeypatch.setattr(cli_main, "POLL_SECONDS", 0)

    def install(handler):
        server = Server(handler)
        monkeypatch.setattr(
            cli_client,
            "make_http_client",
            lambda url, timeout: httpx.Client(base_url=url, transport=httpx.MockTransport(server)),
        )
        return server

    return install


def invoke(*args, input=None):
    return CliRunner().invoke(app, list(args), input=input)


def test_mutation_retry_reuses_idempotency_key_and_identical_body(serve):
    attempts = []

    def handler(request):
        attempts.append(request)
        if len(attempts) < 3:
            raise httpx.ConnectError("response lost")
        return httpx.Response(202, json=receipt(project_id="p1", cycle_id="c1"))

    server = serve(handler)
    res = invoke("--json", "run", "p1")
    assert res.exit_code == 0, res.output
    posts = server.calls("POST")
    assert len(posts) == 3
    keys = {r.headers["Idempotency-Key"] for r in posts}
    bodies = {r.content for r in posts}
    assert len(keys) == 1 and len(bodies) == 1
    assert json.loads(posts[0].content) == {"trigger": "manual"}
    body = json.loads(res.stdout)
    assert set(body) == ENVELOPE
    assert body["ok"] is True and body["cycle_id"] == "c1" and body["operation_id"] == "op-1"
    assert body["action_url"] == "http://127.0.0.1:8787/projects/p1"


def test_explicit_idempotency_key_is_sent(serve):
    server = serve(lambda r: httpx.Response(200, json=receipt(project_id="p1")))
    assert invoke("--idempotency-key", "my-key", "pause", "p1").exit_code == 0
    assert server.calls("POST")[0].headers["Idempotency-Key"] == "my-key"


def test_transport_failure_exhausts_retries_and_exits_5(serve):
    def handler(request):
        raise httpx.ConnectError("down")

    server = serve(handler)
    res = invoke("--json", "resume", "p1")
    assert res.exit_code == 5
    assert len(server.calls()) == cli_client.TRANSPORT_ATTEMPTS
    assert json.loads(res.stdout)["reason_code"] == "transport_error"


@pytest.mark.parametrize(
    ("status", "code"),
    [(401, 3), (403, 3), (409, 3), (422, 2), (404, 2), (500, 5), (503, 5)],
)
def test_http_status_maps_to_documented_exit_code(serve, status, code):
    serve(
        lambda r: httpx.Response(
            status, json={"error": {"code": f"e{status}", "message": "nope", "retryable": False}}
        )
    )
    res = invoke("--json", "status", "p1")
    assert res.exit_code == code
    body = json.loads(res.stdout)
    assert set(body) == ENVELOPE
    assert body["ok"] is False and body["reason_code"] == f"e{status}"
    assert body["data"]["http_status"] == status


def test_stale_revision_conflict_exits_3(serve):
    serve(
        lambda r: httpx.Response(
            409,
            json={"error": {"code": "stale_revision", "message": "Revision changed"}},
        )
    )
    res = invoke("retry-setup", "p1")
    assert res.exit_code == 3
    assert "Revision changed" in res.stderr and "stale_revision" in res.stderr


def test_non_loopback_api_url_is_refused_before_any_request(serve):
    server = serve(lambda r: httpx.Response(200, json={}))
    res = invoke("--api-url", "http://evil.test:8787", "--json", "projects")
    assert res.exit_code == 2
    assert server.calls() == []


def test_server_text_is_stripped_of_control_sequences_and_token(serve):
    hostile = "evil\x1b[31mRED\x1b[0m\x1b]0;pwned\x07\u202e\x9b2J\rname"
    snapshot = {
        "project_id": "p1",
        "display_name": hostile,
        "setup_state": "READY",
        "admission_state": "active",
        "revision": 3,
        "active_cycle": None,
        "attention_count": 0,
        "reason": "token " + TOKEN,
    }
    serve(lambda r: httpx.Response(200, json=snapshot))
    res = invoke("status", "p1")
    assert res.exit_code == 0
    for bad in ("\x1b", "\x07", "\u202e", "\x9b", "\r", "pwned", TOKEN):
        assert bad not in res.output
    assert "evilREDname" in res.output
    assert "[redacted]" in res.output


def test_error_message_control_chars_stripped(serve):
    serve(
        lambda r: httpx.Response(
            409, json={"error": {"code": "x", "message": "bad\x1b[2Jthing\x00"}}
        )
    )
    res = invoke("pause", "p1")
    assert res.exit_code == 3
    assert "\x1b" not in res.output and "\x00" not in res.output
    assert "badthing" in res.stderr


def test_clean_keeps_text_and_bounds_length():
    assert render.clean("a\tb\nc\x1b[1mD") == "a\tb\ncD"
    assert render.clean("x" * 50, limit=10).startswith("x" * 10)
    assert "truncated" in render.clean("x" * 50, limit=10)


def cycle(status):
    return {"cycle_id": "c1", "project_id": "p1", "status": status, "revision": 1}


def test_run_watch_deadline_expiry_exits_6(serve):
    def handler(request):
        if request.method == "POST":
            return httpx.Response(202, json=receipt(project_id="p1", cycle_id="c1"))
        return httpx.Response(200, json=cycle("RUNNING"))

    serve(handler)
    res = invoke("--json", "run", "p1", "--watch", "--deadline", "0")
    assert res.exit_code == 6
    body = json.loads(res.stdout)
    assert set(body) == ENVELOPE
    assert body["status"] == "watch_timeout" and body["cycle_id"] == "c1"
    assert body["operation_id"] == "op-1"


@pytest.mark.parametrize(("final", "code"), [("COMPLETE", 0), ("CANCELLED", 4), ("BUDGET_STOP", 4)])
def test_run_watch_terminal_outcomes(serve, final, code):
    states = iter(["QUEUED", "RUNNING", final])

    def handler(request):
        if request.method == "POST":
            return httpx.Response(202, json=receipt(project_id="p1", cycle_id="c1"))
        return httpx.Response(200, json=cycle(next(states)))

    serve(handler)
    res = invoke("--json", "run", "p1", "--watch")
    assert res.exit_code == code
    body = json.loads(res.stdout)
    assert body["status"] == final and body["ok"] is (code == 0)
    # Progress goes to stderr; stdout holds exactly one JSON object.
    assert "RUNNING" in res.stderr
    assert res.stdout.count("\n") == 1


def test_watch_ctrl_c_exits_130_without_cancelling(serve, monkeypatch):
    def handler(request):
        if request.method == "POST":
            return httpx.Response(202, json=receipt(project_id="p1", cycle_id="c1"))
        return httpx.Response(200, json=cycle("RUNNING"))

    server = serve(handler)

    def interrupt(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_main.time, "sleep", interrupt)
    res = invoke("--json", "run", "p1", "--watch")
    assert res.exit_code == 130
    assert json.loads(res.stdout)["status"] == "detached"
    assert [r.url.path for r in server.calls("POST")] == ["/api/v1/projects/p1/cycles"]


def test_status_watch_follows_active_cycle(serve):
    snapshot = {"project_id": "p1", "active_cycle": cycle("RUNNING"), "setup_state": "READY"}

    def handler(request):
        if request.url.path.endswith("/status"):
            return httpx.Response(200, json=snapshot)
        return httpx.Response(200, json=cycle("NO_FINDINGS"))

    serve(handler)
    res = invoke("--json", "status", "p1", "--watch")
    assert res.exit_code == 0
    assert json.loads(res.stdout)["status"] == "NO_FINDINGS"


def test_report_refuses_overwrite_without_force(serve, tmp_path):
    out = tmp_path / "report.json"
    out.write_text("keep")
    server = serve(lambda r: httpx.Response(200, json={"project": {"project_id": "p1"}}))
    res = invoke("report", "c1", "--output", str(out))
    assert res.exit_code == 2
    assert out.read_text() == "keep"
    assert server.calls() == []
    res = invoke("--json", "report", "c1", "--output", str(out), "--force")
    assert res.exit_code == 0, res.output
    assert json.loads(out.read_text()) == {"project": {"project_id": "p1"}}
    assert json.loads(res.stdout)["status"] == "exported"
    assert [p.name for p in tmp_path.iterdir()] == ["report.json"]


def test_report_refuses_symlink_output(serve, tmp_path):
    target = tmp_path / "target"
    target.write_text("keep")
    (tmp_path / "link").symlink_to(target)
    serve(lambda r: httpx.Response(200, json={}))
    res = invoke("report", "c1", "--output", str(tmp_path / "link"), "--force")
    assert res.exit_code == 2
    assert target.read_text() == "keep"


def test_cancel_non_tty_without_yes_fails_without_request(serve):
    server = serve(lambda r: httpx.Response(202, json=receipt(cycle_id="c1")))
    res = invoke("--json", "cancel", "c1")
    assert res.exit_code == 2
    assert json.loads(res.stdout)["reason_code"] == "confirmation_required"
    assert server.calls() == []


def test_cancel_yes_reports_cancel_requested(serve):
    server = serve(lambda r: httpx.Response(202, json=receipt(project_id="p1", cycle_id="c1")))
    res = invoke("--json", "cancel", "c1", "--yes")
    assert res.exit_code == 0
    assert json.loads(res.stdout)["status"] == "CANCEL_REQUESTED"
    assert server.calls("POST")[0].url.path == "/api/v1/cycles/c1/cancel"


def test_cancel_tty_asks_once_and_honours_answer(serve, monkeypatch):
    monkeypatch.setattr(render, "is_tty", lambda: True)
    server = serve(lambda r: httpx.Response(202, json=receipt(cycle_id="c1")))
    res = invoke("cancel", "c1", input="n\n")
    assert res.exit_code == 3 and server.calls() == []
    res = invoke("cancel", "c1", input="y\n")
    assert res.exit_code == 0 and len(server.calls("POST")) == 1


def test_missing_route_fallback_without_schema_exits_3(serve):
    def handler(request):
        if request.url.path.endswith("openapi.json"):
            return httpx.Response(404, json={"error": {"code": "not_found", "message": "x"}})
        return httpx.Response(405, json={"detail": "Method Not Allowed"})

    serve(handler)
    res = invoke("--json", "approve", "a" * 64, "--destination", "local-web-v1", "--yes")
    assert res.exit_code == 3
    assert json.loads(res.stdout)["reason_code"] == "not_available"


def test_route_present_in_schema_is_used(serve, tmp_path):
    schema = {"paths": {"/api/v1/evaluations": {"post": {}}}}
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"campaign_id": "x"}))

    def handler(request):
        if request.url.path.endswith("openapi.json"):
            return httpx.Response(200, json=schema)
        if request.method == "POST":
            return httpx.Response(202, json=receipt())
        return httpx.Response(200, json=receipt() | {"status": "failed"})

    server = serve(handler)
    res = invoke("--json", "evaluate", str(manifest), "--watch")
    assert res.exit_code == 4
    assert json.loads(server.calls("POST")[0].content) == {"campaign_id": "x"}


def test_approve_rejects_malformed_hash(serve):
    server = serve(lambda r: httpx.Response(200, json={}))
    assert invoke("approve", "XYZ", "--destination", "d").exit_code == 2
    assert server.calls() == []


def test_configure_rejects_unknown_fields_locally(serve, tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"expected_revision": 1, "command": "rm -rf /"}))
    server = serve(lambda r: httpx.Response(200, json={}))
    res = invoke("--json", "configure", "p1", "--file", str(path))
    assert res.exit_code == 2 and "command" in json.loads(res.stdout)["message"]
    assert server.calls() == []


def test_projects_follows_cursor_pages(serve):
    pages = {
        None: {"items": [{"project_id": "p1"}], "next_cursor": "100"},
        "100": {"items": [{"project_id": "p2"}], "next_cursor": None},
    }
    serve(lambda r: httpx.Response(200, json=pages[r.url.params.get("cursor")]))
    res = invoke("--json", "projects")
    assert res.exit_code == 0
    items = json.loads(res.stdout)["data"]["items"]
    assert [p["project_id"] for p in items] == ["p1", "p2"]


def test_report_does_not_clobber_file_created_during_request(serve, tmp_path):
    output = tmp_path / "report.json"

    def response(request):
        output.write_text("created by another process")
        return httpx.Response(200, json={"report": "downloaded"})

    serve(response)
    res = invoke("--json", "report", "c1", "--output", str(output))
    assert res.exit_code == 2
    assert output.read_text() == "created by another process"
    assert list(tmp_path.iterdir()) == [output]


def test_json_escapes_terminal_controls_and_redacts_encoded_secret(serve, monkeypatch):
    token = 'secret-with-"-quote'
    monkeypatch.setenv("COLOSSUS_OPERATOR_TOKEN", token)
    serve(
        lambda request: httpx.Response(
            200, json={"items": [{"display_name": token + "\x9b2J\u202e"}]}
        )
    )
    res = invoke("--json", "projects")
    assert res.exit_code == 0
    assert "\x9b" not in res.stdout and "\u202e" not in res.stdout
    assert token not in json.loads(res.stdout)["data"]["items"][0]["display_name"]


def test_http_client_ignores_proxy_environment(monkeypatch):
    # Invalid proxy would fail client construction if inherited.
    monkeypatch.setenv("ALL_PROXY", "invalid-scheme://proxy.invalid")
    with cli_client.make_http_client("http://127.0.0.1:8787", 1):
        pass


def test_operator_token_requires_private_regular_file(tmp_path, monkeypatch):
    monkeypatch.delenv("COLOSSUS_OPERATOR_TOKEN", raising=False)
    monkeypatch.setenv("COLOSSUS_DATA_DIR", str(tmp_path))
    path = tmp_path / "operator.token"
    path.write_text("local-test-token")
    path.chmod(0o644)
    with pytest.raises(cli_client.CliError, match="owner-only"):
        cli_client.read_token()
    path.chmod(0o600)
    assert cli_client.read_token() == "local-test-token"


def test_ui_json_is_one_envelope(serve):
    serve(lambda request: httpx.Response(200, json={"code": "one-use-code"}))
    result = invoke("--json", "ui", "--no-open")
    assert result.exit_code == 0
    assert json.loads(result.stdout)["data"]["code"] == "one-use-code"
    assert result.stdout.count("\n") == 1
