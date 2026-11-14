"""Record a verified artifact as the lab deployment. This does not start a new container."""

from __future__ import annotations

from datetime import datetime, timedelta

from colossus.contracts.core import DomainError, new_id, utcnow
from colossus.contracts.models import Authorization
from colossus.deploy.policy import (
    Destination,
    empty_destination,
    observe_refresh,
    promote,
    recover,
)


def slot_from(deployment: dict | None) -> Destination:
    raw = deployment or {}
    if not raw.get("status"):
        return empty_destination()
    return Destination(
        generation=int(raw.get("generation") or 0),
        digest=raw.get("digest"),
        previous_digest=raw.get("previous_digest"),
        mirror_hash=raw.get("mirror_hash"),
        mirror_state=raw.get("mirror_state") or "absent",
        last_authorization_id=raw.get("authorization_id"),
        status=raw["status"],
    )


def assert_runnable(project: dict) -> None:
    if (project.get("deployment") or {}).get("mirror_state") == "stale":
        raise DomainError(
            "mirror_stale",
            "Deployed mirror is stale; refresh it before another cycle",
            409,
        )


def fixed_mirror_did_not_reproduce(project: dict, vulnerability_confirmed: bool) -> bool:
    deployment = project.get("deployment") or {}
    return (not vulnerability_confirmed) and deployment.get("mirror_state") == "current"


def publication(project: dict, case: dict, now: str | None = None) -> dict:
    now = now or utcnow()
    current = project.get("deployment") or {}
    digest = case.get("candidate_digest")
    if current.get("status") == "READY" and current.get("digest") == digest:
        return {"authorization": None, "deployment": current, "project_changes": {"active_cycle_id": None}}
    if not isinstance(digest, str):
        raise DomainError("artifact_digest", "Case has no verified artifact", 409)
    evidence = case.get("evidence_manifest_hash")
    if not isinstance(evidence, str):
        raise DomainError("evidence_mismatch", "Case has no evidence manifest", 409)
    slot = slot_from(current)
    expires = (
        datetime.fromisoformat(now.replace("Z", "+00:00")) + timedelta(minutes=15)
    ).isoformat().replace("+00:00", "Z")
    granted = Authorization(
        authorization_id=new_id(),
        project_id=project["project_id"],
        evidence_manifest_hash=evidence,
        destination_id=case.get("destination_id") or "local-web-v1",
        expected_deployment_generation=slot.generation,
        mode="preauthorized_policy" if project.get("owner_policy_id") == "lab-auto-v1" else "owner_approval",
        actor_or_policy_id=project.get("owner_policy_id") or "review-v1",
        issued_at=now,
        expires_at=expires,
    )
    ready = observe_refresh(
        promote(slot, granted, evidence, digest, now, gates_ok=True),
        ok=True,
        manifest_hash=(project.get("source") or {}).get("manifest_hash") or evidence,
    )
    previous_source = (project.get("source") or {}).get("source_id")
    deployment = {
        "deployment_id": current.get("deployment_id") or new_id(),
        "project_id": project["project_id"],
        "generation": ready.generation,
        "digest": ready.digest,
        "previous_digest": ready.previous_digest,
        "mirror_hash": ready.mirror_hash,
        "mirror_state": ready.mirror_state,
        "authorization_id": granted.authorization_id,
        "status": ready.status,
        "actuator": "verified_artifact",
        "source_id": case.get("source_candidate_id") or previous_source,
        "previous_source_id": previous_source,
    }
    source = dict(project.get("source") or {})
    source["previous_source_id"] = previous_source
    if case.get("source_candidate_id"):
        source["source_id"] = case["source_candidate_id"]
    if case.get("candidate_hash"):
        source["tree_sha256"] = case["candidate_hash"]
    mirror = dict(project.get("mirror") or {})
    mirror["state"] = "current"
    mirror["deployed_digest"] = ready.digest
    return {
        "authorization": granted,
        "deployment": deployment,
        "project_changes": {
            "deployment": deployment,
            "source": source,
            "mirror": mirror,
            "active_cycle_id": None,
        },
    }


def rollback_plan(project: dict, deployment: dict, expected_generation: int) -> dict:
    restored = recover(slot_from(deployment), expected_generation)
    updated = dict(deployment)
    updated.update(
        {
            "generation": restored.generation,
            "digest": restored.digest,
            "previous_digest": restored.previous_digest,
            "status": restored.status,
            "mirror_state": "current" if restored.status == "ROLLED_BACK" else "absent",
            "actuator": "verified_artifact",
        }
    )
    source = dict(project.get("source") or {})
    mirror = dict(project.get("mirror") or {})
    if restored.status == "ROLLED_BACK" and deployment.get("previous_source_id"):
        updated["source_id"] = deployment["previous_source_id"]
        source["source_id"] = deployment["previous_source_id"]
        mirror["state"] = "current"
        mirror["deployed_digest"] = restored.digest
    else:
        mirror["state"] = "absent"
        mirror.pop("deployed_digest", None)
    return {
        "deployment": updated,
        "claimed_rollback": restored.status == "ROLLED_BACK",
        "project_changes": {"deployment": updated, "source": source, "mirror": mirror},
    }
