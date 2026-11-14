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
    assert json.loads(invoke("--json", "status", project_id).stdout)["data"][
        "admission_state"
    ] == "paused"
    assert invoke("resume", project_id).exit_code == 0
    assert invoke("--json", "status", "missing").exit_code == 2
    assert invoke("--json", "cancel", "missing", "--yes").exit_code == 2


def test_bad_token_exits_3(server, monkeypatch):
    monkeypatch.setenv("COLOSSUS_OPERATOR_TOKEN", "wrong-token-value")
    res = invoke("--json", "projects")
    assert res.exit_code == 3
    assert "wrong-token-value" not in res.output


@pytest.mark.parametrize("args", [["case", "c1", "--diff"]])
def test_commands_without_server_routes_exit_3(server, args):
    res = invoke("--json", *args)
    assert res.exit_code == 3, res.output
    body = json.loads(res.stdout)
    assert body["reason_code"] == "not_available"
    assert "not available on this server" in body["message"]


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
    for args in (["configure", "p1", "--file", str(config)], ["evaluate", str(manifest)]):
        res = invoke("--json", *args)
        assert res.exit_code == 2, res.output  # incomplete body -> 422 from the real route
        assert json.loads(res.stdout)["reason_code"] != "not_available"


def test_case_read_and_missing_case(server):
    res = invoke("--json", "case", "missing")
    assert res.exit_code == 2
    assert json.loads(res.stdout)["reason_code"] == "not_found"
