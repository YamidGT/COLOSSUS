import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from colossus.cli.main import app as cli
from colossus.contracts.core import DomainError, new_id, utcnow
from colossus.contracts.models import GateResult
from colossus.control.api import create_app
from colossus.control.config import Settings
from colossus.control.decisions import read_configuration
from colossus.verification.policy import REQUIRED_CHECKS

EVIDENCE = "c" * 64
CANDIDATE = "a" * 64


@pytest.fixture
def api(tmp_path):
    app = create_app(Settings(data_dir=tmp_path / "state"), execute_tasks=False)
    token = (tmp_path / "state/operator.token").read_text()
    with TestClient(app, base_url="http://127.0.0.1:8787") as client:
        yield app, client, {"Authorization": f"Bearer {token}"}
    app.state.store.close()


def gates(status="pass"):
    case_id, candidate_id = new_id(), new_id()
    rows = []
    for profile in REQUIRED_CHECKS:
        rows.append(
            GateResult(
                gate_id=new_id(),
                case_id=case_id,
                candidate_id=candidate_id,
                candidate_hash=CANDIDATE,
                check_profile_id=profile,
                category="policy",
                status=status,
                scope=["test"],
                tool_version="1",
                command_profile_hash="b" * 64,
                started_at=utcnow(),
                finished_at=utcnow(),
                evidence_ids=[],
            ).model_dump(mode="json")
        )
    rows.append(
        GateResult(
            gate_id=new_id(),
            case_id=case_id,
            candidate_id=candidate_id,
            candidate_hash=CANDIDATE,
            check_profile_id="formal-v1",
            category="formal",
            status="not_applicable",
            proof_outcome="UNSUPPORTED",
            scope=["test"],
            tool_version="not-invoked",
            command_profile_hash="b" * 64,
            started_at=utcnow(),
            finished_at=utcnow(),
            evidence_ids=[],
        ).model_dump(mode="json")
    )
    return case_id, rows


def enroll(client, headers):
    response = client.post(
        "/api/v1/projects",
        json={"repo_url": "https://github.com/stamparm/DSVW"},
        headers=headers | {"Idempotency-Key": "enroll"},
    )
    assert response.status_code == 202
    return response.json()["resource_ids"]["project_id"]


def test_configure_changes_policy_and_refuses_secrets(api, tmp_path):
    app, client, headers = api
    project_id = enroll(client, headers)
    revision = client.get(f"/api/v1/projects/{project_id}/status", headers=headers).json()[
        "revision"
    ]
    updated = client.post(
        f"/api/v1/projects/{project_id}/configuration",
        json={
            "expected_revision": revision,
            "owner_policy_id": "review-v1",
            "deployment_profile_id": "local-web-v1",
            "assurance_profile": "tested",
        },
        headers=headers | {"Idempotency-Key": "configure"},
    )
    assert updated.status_code == 200
    status = client.get(f"/api/v1/projects/{project_id}/status", headers=headers).json()
    assert status["owner_policy_id"] == "review-v1"
    secret = client.post(
        f"/api/v1/projects/{project_id}/configuration",
        json={
            "expected_revision": status["revision"],
            "requested_ref": "token=abc",
            "owner_policy_id": "review-v1",
            "deployment_profile_id": "local-web-v1",
            "assurance_profile": "tested",
        },
        headers=headers | {"Idempotency-Key": "secret"},
    )
    assert secret.status_code == 422
    path = tmp_path / "config.json"
    path.write_text('{"requested_ref": "token=abc"}')
    with pytest.raises(DomainError, match="credentials"):
        read_configuration(path.read_text())


def test_approve_records_authorization_without_promotion_and_failed_gates_do_not(api):
    app, client, headers = api
    project_id = enroll(client, headers)
    case_id, rows = gates()
    app.state.store.put(
        "case",
        case_id,
        {
            "case_id": case_id,
            "project_id": project_id,
            "status": "REVIEW_READY",
            "candidate_hash": CANDIDATE,
            "assurance_profile": "tested",
            "evidence_manifest_hash": EVIDENCE,
            "destination_id": "local-web-v1",
            "expected_deployment_generation": 0,
            "gate_results": rows,
            "created_at": utcnow(),
            "title": "review",
            "reason": "test",
        },
        project_id,
    )
    body = {"evidence_manifest_hash": EVIDENCE, "destination_id": "local-web-v1"}
    approved = client.post(
        "/api/v1/authorizations", json=body, headers=headers | {"Idempotency-Key": "approve"}
    )
    assert approved.status_code == 202
    assert approved.json()["promotion"] == "not_executed"
    assert approved.json()["resource_ids"]["promotion"] == "not_executed"
    assert app.state.store.get("case", case_id)["status"] == "AUTHORIZED"

    bad_id, bad_rows = gates(status="fail")
    app.state.store.put(
        "case",
        bad_id,
        {
            "case_id": bad_id,
            "project_id": project_id,
            "status": "REVIEW_READY",
            "candidate_hash": CANDIDATE,
            "assurance_profile": "tested",
            "evidence_manifest_hash": "d" * 64,
            "destination_id": "local-web-v1",
            "expected_deployment_generation": 0,
            "gate_results": bad_rows,
            "created_at": utcnow(),
            "title": "bad",
            "reason": "test",
        },
        project_id,
    )
    refused = client.post(
        "/api/v1/authorizations",
        json={"evidence_manifest_hash": "d" * 64, "destination_id": "local-web-v1"},
        headers=headers | {"Idempotency-Key": "bad-approve"},
    )
    assert refused.status_code == 409
    assert app.state.store.list("authorization")
    assert all(
        item["evidence_manifest_hash"] != "d" * 64
        for item in app.state.store.list("authorization")
    )


def test_rollback_without_a_prior_artifact_does_not_claim_recovery(api):
    app, client, headers = api
    project_id = enroll(client, headers)
    deployment_id = new_id()
    app.state.store.put(
        "deployment",
        deployment_id,
        {
            "deployment_id": deployment_id,
            "project_id": project_id,
            "generation": 1,
            "digest": "sha256:" + "a" * 64,
            "previous_digest": None,
            "status": "PROMOTED",
        },
        project_id,
    )
    response = client.post(
        f"/api/v1/deployments/{deployment_id}/rollback",
        json={"expected_generation": 1},
        headers=headers | {"Idempotency-Key": "rollback"},
    )
    assert response.status_code == 202
    saved = app.state.store.get("deployment", deployment_id)
    assert saved["status"] == "UNAVAILABLE"
    assert saved["actuator"] == "record_only"
    assert response.json()["resource_ids"]["claimed_rollback"] == "false"


def test_candidate_roster_is_not_executed(api):
    _, client, headers = api
    manifest = json.loads(
        (Path(__file__).parents[2] / "evaluation" / "repository-candidates.json").read_text()
    )
    response = client.post(
        "/api/v1/evaluations",
        json=manifest,
        headers=headers | {"Idempotency-Key": "evaluate"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "candidate_only"


def test_confirmation_is_required_when_there_is_no_terminal():
    result = CliRunner().invoke(cli, ["approve", "a" * 64, "--destination", "local-web-v1"])
    assert result.exit_code != 0
    assert "--yes" in result.output
