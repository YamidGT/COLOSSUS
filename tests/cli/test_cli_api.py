"""CLI against the real operator API (FastAPI TestClient, no worker or sandbox)."""

import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from colossus.cli import client as cli_client
from colossus.cli.main import app
from colossus.control.api import create_app
from colossus.control.config import Settings


@pytest.fixture
def server(tmp_path, monkeypatch):
    api = create_app(Settings(data_dir=tmp_path / "state"), execute_tasks=False)
    token = (tmp_path / "state/operator.token").read_text().strip()
    monkeypatch.setenv("COLOSSUS_OPERATOR_TOKEN", token)
    monkeypatch.setattr(
        cli_client, "make_http_client", lambda url, timeout: TestClient(api, base_url=url)
    )
    yield api, token
    api.state.store.close()


def invoke(*args, input=None):
    return CliRunner().invoke(app, list(args), input=input)


def enroll(url="https://github.com/stamparm/DSVW", key=None):
    args = ["--json"] + (["--idempotency-key", key] if key else []) + ["enroll", url]
    return invoke(*args)


def test_enroll_status_projects_actions_roundtrip(server):
    api, token = server
    res = enroll()
    assert res.exit_code == 0, res.output
    body = json.loads(res.stdout)
    project_id = body["project_id"]
    assert body["ok"] is True and body["operation_id"]
    assert token not in res.output

    status = json.loads(invoke("--json", "status", project_id).stdout)
    assert status["status"] == "NEW" and status["data"]["project_id"] == project_id

    listed = json.loads(invoke("--json", "projects").stdout)
    assert [p["project_id"] for p in listed["data"]["items"]] == [project_id]

    actions = invoke("--json", "actions", project_id)
    assert actions.exit_code == 0
    assert isinstance(json.loads(actions.stdout)["data"]["items"], list)

    human = invoke("status", project_id)
    assert human.exit_code == 0 and "Setup: NEW" in human.stdout


def test_same_key_same_body_returns_same_receipt_and_changed_body_exits_3(server):
    a = json.loads(enroll(key="k1").stdout)
    b = json.loads(enroll(key="k1").stdout)
    assert a["operation_id"] == b["operation_id"]
    conflict = enroll("https://github.com/erev0s/VAmPI", key="k1")
    assert conflict.exit_code == 3
    assert json.loads(conflict.stdout)["reason_code"] == "idempotency_conflict"


def test_ineligible_run_conflict_exits_3(server):
    project_id = json.loads(enroll().stdout)["project_id"]
    res = invoke("--json", "run", project_id)
    assert res.exit_code == 3
    assert json.loads(res.stdout)["ok"] is False


def test_pause_resume_and_unknown_resources(server):
    project_id = json.loads(enroll().stdout)["project_id"]
    assert invoke("pause", project_id).exit_code == 0
    assert (
        json.loads(invoke("--json", "status", project_id).stdout)["data"]["admission_state"]
        == "paused"
    )
    assert invoke("resume", project_id).exit_code == 0
    assert invoke("--json", "status", "missing").exit_code == 2
    assert invoke("--json", "cancel", "missing", "--yes").exit_code == 2


def test_bad_token_exits_3(server, monkeypatch):
    monkeypatch.setenv("COLOSSUS_OPERATOR_TOKEN", "wrong-token-value")
    res = invoke("--json", "projects")
    assert res.exit_code == 3
    assert "wrong-token-value" not in res.output


def test_missing_case_diff_uses_real_route(server):
    res = invoke("--json", "case", "missing", "--diff")
    assert res.exit_code == 2
    assert json.loads(res.stdout)["reason_code"] == "not_found"


@pytest.mark.parametrize(
    "args",
    [["reject", "c1", "--candidate", "x", "--reason", "unsafe"], ["rollback", "d1", "--yes"]],
)
def test_reject_and_rollback_unknown_ids_reach_server(server, args):
    res = invoke("--json", *args)
    assert res.exit_code == 2, res.output
    assert json.loads(res.stdout)["reason_code"] == "not_found"


def test_approve_unknown_manifest_reaches_server_and_fails(server):
    res = invoke("--json", "approve", "a" * 64, "--destination", "local-web-v1", "--yes")
    assert res.exit_code == 2, res.output
    assert json.loads(res.stdout)["reason_code"] == "not_found"


def test_approve_without_yes_in_non_tty_needs_confirmation(server):
    res = invoke("--json", "approve", "a" * 64, "--destination", "local-web-v1")
    assert res.exit_code == 2, res.output
    assert json.loads(res.stdout)["reason_code"] == "confirmation_required"


def test_configure_and_evaluate_reach_server_validation(server, tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"expected_revision": 1, "subdir": "app"}))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"campaign_id": "x"}))
    res = invoke("--json", "configure", "p1", "--file", str(config))
    assert res.exit_code == 2  # incomplete amendment rejected by the API schema
    assert json.loads(res.stdout)["reason_code"] != "not_available"
    res = invoke("--json", "evaluate", str(manifest))
    assert res.exit_code == 3
    assert json.loads(res.stdout)["reason_code"] == "not_available"


def test_case_read_and_missing_case(server):
    res = invoke("--json", "case", "missing")
    assert res.exit_code == 2
    assert json.loads(res.stdout)["reason_code"] == "not_found"


def test_lost_mutation_response_commits_once_against_real_controller(server, monkeypatch):
    import httpx

    api, _ = server
    calls = []
    transport = TestClient(api, base_url="http://127.0.0.1:8787")

    class LostResponse:
        def request(self, method, path, **kwargs):
            response = transport.request(method, path, **kwargs)
            calls.append(kwargs)
            if len(calls) == 1:
                raise httpx.ReadError("response lost after server committed")
            return response

        def close(self):
            transport.close()

    monkeypatch.setattr(cli_client, "make_http_client", lambda *args: LostResponse())
    monkeypatch.setattr(cli_client, "_sleep", lambda seconds: None)
    result = enroll(key="retry-one-enrollment")
    assert result.exit_code == 0
    assert len(calls) == 2
    assert calls[0]["json"] == calls[1]["json"]
    assert calls[0]["headers"]["Idempotency-Key"] == calls[1]["headers"]["Idempotency-Key"]
    assert len(api.state.store.list("project")) == 1
    with api.state.store.lock:
        assert api.state.store.connection.execute("SELECT count(*) FROM tasks").fetchone()[0] == 1
    assert api.state.store.verify_audit()


def test_configuration_recovers_failed_setup_once_with_history(server, tmp_path):
    api, _ = server
    project_id = json.loads(enroll().stdout)["project_id"]
    store = api.state.store
    project = store.get("project", project_id)
    with store.transaction() as db:
        db.execute("UPDATE tasks SET state='failed' WHERE project_id=?", (project_id,))
    store.put(
        "project",
        project_id,
        project
        | {"setup_state": "NEEDS_CONFIGURATION", "source": {"failure_evidence": "retained"}},
        project_id,
    )
    body = api.state.controller.configuration(project_id)
    body["subdir"] = "api"
    config = tmp_path / "amendment.json"
    config.write_text(json.dumps(body))
    args = [
        "--json",
        "--idempotency-key",
        "configure-once",
        "configure",
        project_id,
        "--file",
        str(config),
    ]
    a, b = invoke(*args), invoke(*args)
    assert a.exit_code == b.exit_code == 0, a.output
    assert json.loads(a.stdout)["operation_id"] == json.loads(b.stdout)["operation_id"]
    changed = store.get("project", project_id)
    assert (
        changed["subdir"] == "api" and changed["setup_state"] == "NEW" and changed["source"] == {}
    )
    history = store.list("configuration_change", project_id)
    assert len(history) == 1 and history[0]["previous_source"] == {"failure_evidence": "retained"}
    stale = invoke("--json", "configure", project_id, "--file", str(config))
    assert stale.exit_code == 3 and json.loads(stale.stdout)["reason_code"] == "stale_revision"
    assert store.verify_audit()


@pytest.mark.parametrize(
    "changes",
    [
        {"subdir": "../outside"},
        {"requested_ref": "-unsafe"},
        {"assurance_profile": "formal_required"},
        {"expected_revision": True},
    ],
)
def test_configuration_rejects_invalid_fields(server, tmp_path, changes):
    api, _ = server
    project_id = json.loads(enroll().stdout)["project_id"]
    body = api.state.controller.configuration(project_id) | changes
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body))
    result = invoke("--json", "configure", project_id, "--file", str(path))
    assert result.exit_code == 2
    assert not api.state.store.list("configuration_change", project_id)
