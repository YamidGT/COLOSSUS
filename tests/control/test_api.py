import pytest
from fastapi.testclient import TestClient

from colossus.contracts.models import ProjectSnapshot
from colossus.control.api import create_app
from colossus.control.config import Settings


@pytest.fixture
def api(tmp_path):
    app = create_app(Settings(data_dir=tmp_path / "state"), execute_tasks=False)
    token = (tmp_path / "state/operator.token").read_text()
    with TestClient(app, base_url="http://127.0.0.1:8787") as client:
        yield app, client, {"Authorization": f"Bearer {token}"}
    app.state.store.close()


def test_api_rejects_host_origin_and_unauthenticated_reads(api):
    _, client, headers = api
    assert client.get("/api/v1/projects").status_code == 401
    assert (
        client.get("/api/v1/projects", headers=headers | {"Host": "evil.test"}).status_code == 400
    )
    assert (
        client.post(
            "/api/v1/projects", headers=headers | {"Origin": "https://evil.test"}, json={}
        ).status_code
        == 403
    )


def test_duplicate_enrollment_survives_response_loss(api):
    app, client, headers = api
    headers |= {"Idempotency-Key": "enroll"}
    request = {"repo_url": "https://github.com/stamparm/DSVW"}
    a = client.post("/api/v1/projects", json=request, headers=headers)
    b = client.post("/api/v1/projects", json=request, headers=headers)
    assert a.status_code == 202 and a.json() == b.json()
    assert len(app.state.store.list("project")) == 1
    assert (
        client.post(
            "/api/v1/projects",
            json={"repo_url": "https://github.com/erev0s/VAmPI"},
            headers=headers,
        ).status_code
        == 409
    )
    project_id = a.json()["resource_ids"]["project_id"]
    status = client.get(f"/api/v1/projects/{project_id}/status", headers=headers)
    assert status.json()["setup_state"] == "NEW"
    ProjectSnapshot.model_validate(status.json())
    assert (
        client.post(
            f"/api/v1/projects/{project_id}/cycles",
            json={},
            headers=headers | {"Idempotency-Key": "run"},
        ).status_code
        == 409
    )


def test_browser_login_is_one_use_and_mutations_require_csrf(api):
    _, client, headers = api
    code = client.post("/api/v1/sessions/codes", headers=headers).json()["code"]
    login = client.post(
        "/api/v1/sessions/exchange",
        json={"code": code},
        headers={"Origin": "http://127.0.0.1:8787"},
    )
    assert login.status_code == 200
    assert "HttpOnly" in login.headers["set-cookie"]
    assert client.get("/api/v1/projects").status_code == 200
    browser_headers = {"Origin": "http://127.0.0.1:8787", "Idempotency-Key": "browser"}
    request = {"repo_url": "https://github.com/stamparm/DSVW"}
    assert client.post("/api/v1/projects", json=request, headers=browser_headers).status_code == 403
    browser_headers["X-CSRF-Token"] = login.json()["csrf_token"]
    assert client.post("/api/v1/projects", json=request, headers=browser_headers).status_code == 202
    assert (
        client.post(
            "/api/v1/sessions/exchange",
            json={"code": code},
            headers={"Origin": "http://127.0.0.1:8787"},
        ).status_code
        == 401
    )
    assert client.delete("/api/v1/session", headers=browser_headers).status_code == 200
    assert client.get("/api/v1/projects").status_code == 401


def test_validation_does_not_echo_credential_shaped_input(api):
    _, client, headers = api
    secret = "a-private-value-that-must-not-be-reflected"
    response = client.post(
        "/api/v1/projects", json={"repo_url": secret}, headers=headers | {"Idempotency-Key": "bad"}
    )
    assert response.status_code == 422
    assert secret not in response.text


def test_evidence_download_requires_project_binding_and_explicit_visibility(api):
    from colossus.onboarding.service import Onboarding

    app, client, headers = api
    artifacts = app.state.evidence
    writer = Onboarding(app.state.store, artifacts, None, None)
    public = writer.evidence("project-a", {"check": "passed"}, visibility="operator")
    private = writer.evidence("project-a", {"files": {"source.py": "private"}})
    endpoint = f"/api/v1/artifacts/{public}/download"
    assert client.get(endpoint + "?project_id=project-a", headers=headers).json() == {
        "check": "passed"
    }
    assert client.get(endpoint + "?project_id=project-b", headers=headers).status_code == 404
    assert (
        client.get(
            f"/api/v1/artifacts/{private}/download?project_id=project-a", headers=headers
        ).status_code
        == 403
    )
