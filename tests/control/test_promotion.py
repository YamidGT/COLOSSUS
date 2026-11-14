import pytest

from colossus.contracts.core import DomainError
from colossus.control.promotion import (
    assert_runnable,
    fixed_mirror_did_not_reproduce,
    publication,
    rollback_plan,
)

DIGEST = "sha256:" + "a" * 64
NOW = "2026-11-14T15:10:00Z"


def project():
    return {
        "project_id": "11111111-1111-1111-1111-111111111111",
        "owner_policy_id": "lab-auto-v1",
        "source": {"source_id": "old-source", "commit": "abc"},
        "mirror": {"state": "READY"},
        "deployment": {},
    }


def case():
    return {
        "candidate_digest": DIGEST,
        "evidence_manifest_hash": "c" * 64,
        "source_candidate_id": "patched-source",
        "candidate_hash": "d" * 64,
        "destination_id": "local-web-v1",
    }


def test_lab_publication_records_the_verified_artifact_and_switches_source():
    published = publication(project(), case(), NOW)
    deployment = published["deployment"]
    assert deployment["status"] == "READY"
    assert deployment["generation"] == 1
    assert deployment["digest"] == DIGEST
    assert deployment["actuator"] == "verified_artifact"
    changes = published["project_changes"]
    assert changes["source"]["source_id"] == "patched-source"
    assert changes["source"]["previous_source_id"] == "old-source"
    assert changes["mirror"]["state"] == "current"
    assert changes["active_cycle_id"] is None
    again = publication(project() | {"deployment": deployment}, case(), NOW)
    assert again["authorization"] is None
    assert again["deployment"]["generation"] == 1


def test_rollback_restores_the_previous_source_and_first_deploy_does_not_claim_it():
    published = publication(project(), case(), NOW)
    restored = rollback_plan(project(), published["deployment"], 1)
    assert restored["claimed_rollback"] is False
    assert restored["deployment"]["status"] == "UNAVAILABLE"
    second = publication(
        project() | {"deployment": published["deployment"], "source": published["project_changes"]["source"]},
        case() | {"candidate_digest": "sha256:" + "b" * 64, "evidence_manifest_hash": "f" * 64},
        NOW,
    )
    back = rollback_plan(
        project() | {"source": second["project_changes"]["source"]},
        second["deployment"],
        second["deployment"]["generation"],
    )
    assert back["claimed_rollback"] is True
    assert back["deployment"]["digest"] == DIGEST
    assert back["project_changes"]["source"]["source_id"] == "patched-source"


def test_stale_mirror_blocks_the_next_cycle_and_a_fixed_mirror_is_not_a_failure():
    with pytest.raises(DomainError, match="stale"):
        assert_runnable({"deployment": {"mirror_state": "stale"}})
    assert fixed_mirror_did_not_reproduce({"deployment": {"mirror_state": "current"}}, False)
    assert not fixed_mirror_did_not_reproduce({"deployment": {}}, False)
