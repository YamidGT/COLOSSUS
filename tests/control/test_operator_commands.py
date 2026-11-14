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


# Approve and rollback now use Daniel's routes (/cases/{id}/approve, /deployments/{id}/rollback
# with deployment authority). Their behaviour is covered by tests/deployment/test_authority.py;
# the two tests for the removed /authorizations duplicate were dropped in the merge.


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
