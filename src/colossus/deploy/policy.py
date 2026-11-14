"""Lab promotion decisions. This module does not start containers or claim a canary ran."""

from __future__ import annotations

import re
from dataclasses import dataclass

from colossus.contracts.core import DomainError
from colossus.contracts.models import Authorization

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


@dataclass(frozen=True)
class Destination:
    generation: int
    digest: str | None
    previous_digest: str | None
    mirror_hash: str | None
    mirror_state: str
    last_authorization_id: str | None
    status: str


def empty_destination() -> Destination:
    return Destination(0, None, None, None, "absent", None, "EMPTY")


def _digest(value: str) -> str:
    if not _DIGEST.fullmatch(value):
        raise DomainError("artifact_digest", "Promotion requires a sha256 digest", 422)
    return value


def promote(
    slot: Destination,
    authorization: Authorization,
    evidence_hash: str,
    candidate_digest: str,
    now: str,
    *,
    gates_ok: bool,
) -> Destination:
    candidate_digest = _digest(candidate_digest)
    if (
        slot.last_authorization_id == authorization.authorization_id
        and slot.digest == candidate_digest
    ):
        return slot
    if not gates_ok:
        raise DomainError("failed_gates", "Promotion requires the recorded gates to pass", 409)
    if authorization.evidence_manifest_hash != evidence_hash:
        raise DomainError("evidence_mismatch", "Authorization is not bound to this evidence", 409)
    if authorization.expires_at <= now:
        raise DomainError("authorization_expired", "Authorization has expired", 409)
    if authorization.expected_deployment_generation != slot.generation:
        raise DomainError("stale_generation", "Deployment generation changed", 409)
    return Destination(
        generation=slot.generation + 1,
        digest=candidate_digest,
        previous_digest=slot.digest,
        mirror_hash=slot.mirror_hash,
        mirror_state="stale",
        last_authorization_id=authorization.authorization_id,
        status="PROMOTED",
    )


def recover(slot: Destination, expected_generation: int) -> Destination:
    if slot.generation != expected_generation:
        raise DomainError("stale_generation", "Deployment generation changed", 409)
    if slot.previous_digest is None:
        return Destination(
            generation=slot.generation + 1,
            digest=None,
            previous_digest=None,
            mirror_hash=None,
            mirror_state="absent",
            last_authorization_id=None,
            status="UNAVAILABLE",
        )
    return Destination(
        generation=slot.generation + 1,
        digest=slot.previous_digest,
        previous_digest=slot.digest,
        mirror_hash=slot.mirror_hash,
        mirror_state="stale",
        last_authorization_id=None,
        status="ROLLED_BACK",
    )


def observe_refresh(
    slot: Destination, *, ok: bool, manifest_hash: str | None
) -> Destination:
    if slot.status not in {"PROMOTED", "ROLLED_BACK", "MIRROR_STALE", "READY"}:
        raise DomainError("not_promoted", "Mirror refresh needs an observed deployment", 409)
    if not ok or not manifest_hash:
        return Destination(
            slot.generation,
            slot.digest,
            slot.previous_digest,
            slot.mirror_hash,
            "stale",
            slot.last_authorization_id,
            "MIRROR_STALE",
        )
    return Destination(
        slot.generation,
        slot.digest,
        slot.previous_digest,
        manifest_hash,
        "current",
        slot.last_authorization_id,
        "READY",
    )


def recurrence_decision(
    *,
    mirror_state: str,
    previous_fingerprints: list[str],
    observed_fingerprints: list[str],
) -> dict:
    """Classify supplied observations. This does not start a second cycle."""
    if mirror_state != "current":
        return {"executed": False, "cycle": "blocked", "reason": "mirror_not_current"}
    previous, observed = set(previous_fingerprints), set(observed_fingerprints)
    return {
        "executed": False,
        "cycle": "comparable",
        "reopened_fingerprints": sorted(previous & observed),
        "new_fingerprints": sorted(observed - previous),
    }
