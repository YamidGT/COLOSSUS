import pytest

from colossus.contracts.core import DomainError, new_id
from colossus.contracts.models import Authorization
from colossus.deploy.policy import (
    empty_destination,
    observe_refresh,
    promote,
    recover,
    recurrence_decision,
)

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
EVIDENCE = "c" * 64


def auth(generation=0, expires="2026-11-14T16:00:00Z"):
    return Authorization(
        authorization_id=new_id(),
        project_id=new_id(),
        evidence_manifest_hash=EVIDENCE,
        destination_id="local-web-v1",
        expected_deployment_generation=generation,
        mode="owner_approval",
        actor_or_policy_id="operator:test",
        issued_at="2026-11-14T15:00:00Z",
        expires_at=expires,
    )


def test_promotion_is_digest_bound_and_idempotent():
    granted = auth()
    slot = promote(
        empty_destination(), granted, EVIDENCE, DIGEST, "2026-11-14T15:10:00Z", gates_ok=True
    )
    assert slot.status == "PROMOTED"
    assert slot.generation == 1
    assert slot.digest == DIGEST
    assert slot.mirror_state == "stale"
    again = promote(slot, granted, EVIDENCE, DIGEST, "2026-11-14T15:10:00Z", gates_ok=True)
    assert again == slot


def test_promotion_rejects_stale_expired_and_unbound_evidence():
    slot = empty_destination()
    now = "2026-11-14T15:10:00Z"
    with pytest.raises(DomainError, match="gates"):
        promote(slot, auth(), EVIDENCE, DIGEST, now, gates_ok=False)
    with pytest.raises(DomainError, match="not bound"):
        promote(slot, auth(), "d" * 64, DIGEST, now, gates_ok=True)
    with pytest.raises(DomainError, match="expired"):
        promote(slot, auth(expires="2026-11-14T15:00:00Z"), EVIDENCE, DIGEST, now, gates_ok=True)
    moved = promote(slot, auth(), EVIDENCE, DIGEST, now, gates_ok=True)
    with pytest.raises(DomainError, match="generation"):
        promote(moved, auth(generation=0), EVIDENCE, OTHER, now, gates_ok=True)


def test_first_failure_does_not_claim_a_rollback():
    failed = recover(empty_destination(), 0)
    assert failed.status == "UNAVAILABLE"
    assert failed.digest is None


def test_rollback_restores_the_previous_digest():
    now = "2026-11-14T15:10:00Z"
    first = promote(empty_destination(), auth(), EVIDENCE, DIGEST, now, gates_ok=True)
    assert recover(first, first.generation).status == "UNAVAILABLE"
    second = promote(first, auth(generation=1), EVIDENCE, OTHER, now, gates_ok=True)
    restored = recover(second, second.generation)
    assert restored.status == "ROLLED_BACK"
    assert restored.digest == DIGEST
    assert restored.previous_digest == OTHER
    with pytest.raises(DomainError, match="generation"):
        recover(restored, second.generation)


def test_failed_refresh_keeps_the_deployment_and_marks_the_mirror_stale():
    slot = promote(
        empty_destination(), auth(), EVIDENCE, DIGEST, "2026-11-14T15:10:00Z", gates_ok=True
    )
    stale = observe_refresh(slot, ok=False, manifest_hash=None)
    assert stale.status == "MIRROR_STALE"
    assert stale.digest == DIGEST
    assert stale.generation == slot.generation
    ready = observe_refresh(stale, ok=True, manifest_hash="e" * 64)
    assert ready.mirror_state == "current"
    assert ready.status == "READY"


def test_recurrence_waits_for_a_current_mirror_and_does_not_execute():
    blocked = recurrence_decision(
        mirror_state="stale", previous_fingerprints=["f"], observed_fingerprints=[]
    )
    assert blocked == {"executed": False, "cycle": "blocked", "reason": "mirror_not_current"}
    compared = recurrence_decision(
        mirror_state="current",
        previous_fingerprints=["old"],
        observed_fingerprints=["old", "new"],
    )
    assert compared["executed"] is False
    assert compared["reopened_fingerprints"] == ["old"]
    assert compared["new_fingerprints"] == ["new"]
