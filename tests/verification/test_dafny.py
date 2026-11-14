import pytest
from fastapi.testclient import TestClient

from colossus.contracts.core import DomainError
from colossus.sandbox.launcher import ProcessResult
from colossus.sandbox.server import create_launcher
from colossus.verification.dafny import CORRECT_POLICY, POLICY_CALIBRATION, proof_passed


@pytest.mark.parametrize(
    "payload",
    [
        "true; assume false",
        "true } method Escape() {}",
        "{:verify false}",
        "actor == target //",
        'true\ninclude "evil.dfy"',
        "unknown",
        "Public(actor)",
        "(true",
        "true false",
        "true /* bypass */",
        "",
        "!" * 1500 + "true",
    ],
)
def test_policy_rejects_non_expression_edits(payload):
    with pytest.raises(DomainError):
        POLICY_CALIBRATION.render(CORRECT_POLICY | {"password": payload})


def test_candidate_changes_cannot_modify_contracts():
    original = POLICY_CALIBRATION.render(CORRECT_POLICY)
    wrong = POLICY_CALIBRATION.render(CORRECT_POLICY | {"password": "true"})
    assert (
        original.replace(
            b"allowed := authenticated && resourceExists && actor == target", b"allowed := true"
        )
        == wrong
    )
    with pytest.raises(DomainError):
        POLICY_CALIBRATION.render(CORRECT_POLICY | {"ensures": "true"})


def test_empty_partial_or_failed_proof_never_passes():
    expected = POLICY_CALIBRATION.expected_symbols
    csv = "TestResult.DisplayName,TestResult.Outcome\n" + "".join(
        f"{symbol} (correctness),Passed\n" for symbol in sorted(expected)
    )
    success = ProcessResult(
        0, "Dafny program verifier finished with 4 verified, 0 errors", "", False, 1
    )
    assert proof_passed(success, csv.encode(), expected)
    assert not proof_passed(success, b"", expected)
    assert not proof_passed(success, csv.replace("Passed", "Failed", 1).encode(), expected)
    assert not proof_passed(success, csv.encode(), expected | {"Policy.Missing"})
    assert not proof_passed(
        ProcessResult(0, "Dafny program verifier finished with 0 verified, 0 errors", "", False, 1),
        csv.encode(),
        expected,
    )
    assert not proof_passed(
        ProcessResult(1, success.stdout, "failure", False, 1), csv.encode(), expected
    )
    assert not proof_passed(ProcessResult(0, success.stdout, "", True, 1), csv.encode(), expected)
    assert not proof_passed(
        ProcessResult(0, success.stdout, "", False, 1, True), csv.encode(), expected
    )


def test_formal_endpoint_requires_controller_and_configured_toolchain():
    with TestClient(create_launcher("controller", "unavailable", "deployer")) as client:
        body = {
            "project_id": "00000000-0000-4000-8000-000000000001",
            "profile_id": POLICY_CALIBRATION.profile_id,
            "expressions": CORRECT_POLICY,
        }
        assert client.post("/formal/policy", json=body).status_code == 403
        assert (
            client.post(
                "/formal/policy", json=body, headers={"Authorization": "Bearer deployer"}
            ).status_code
            == 403
        )
        response = client.post(
            "/formal/policy", json=body, headers={"Authorization": "Bearer controller"}
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "formal_unsupported"
