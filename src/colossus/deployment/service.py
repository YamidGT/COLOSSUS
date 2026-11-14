"""Synthetic lab front door with durable routing and separate deployment authority."""

import asyncio
import json
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

from colossus.contracts.core import DomainError, canonical_json, content_hash, new_id, utcnow
from colossus.contracts.models import Authorization, EvidenceManifest, GateResult, TargetManifest
from colossus.detection.service import dsvw_checks
from colossus.verification.policy import REQUIRED_CHECKS, validate_gates, validate_manifest_hash


def validate_authority(authorization, certificate, manifest, gates, generation):
    validate_manifest_hash(certificate)
    if authorization.project_id != manifest.project_id:
        raise DomainError("authorization_scope", "Authorization targets another project", 409)
    if (
        authorization.destination_id != "local-web-v1"
        or manifest.deployment_profile_id != "local-web-v1"
    ):
        raise DomainError(
            "unsupported_destination", "Only the isolated local web destination is installed", 422
        )
    if authorization.evidence_manifest_hash != content_hash(certificate.model_dump()):
        raise DomainError(
            "authorization_binding", "Authorization is bound to different evidence", 409
        )
    if (
        certificate.target_manifest_hash != content_hash(manifest.model_dump())
        or certificate.policy_hash != manifest.policy_hash
    ):
        raise DomainError(
            "stale_manifest", "Source or policy differs from the verified manifest", 409
        )
    if certificate.baseline_hash != manifest.tree_sha256:
        raise DomainError("stale_source", "Candidate was verified against another baseline", 409)
    if authorization.expected_deployment_generation != generation:
        raise DomainError("stale_generation", "Deployment changed; obtain fresh authorization", 409)
    try:
        expiry = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
        issued = datetime.fromisoformat(authorization.issued_at.replace("Z", "+00:00"))
        now = datetime.now(UTC)
        if (
            expiry.tzinfo is None
            or issued.tzinfo is None
            or not issued <= now < expiry
            or (expiry - issued).total_seconds() > 3600
        ):
            raise ValueError()
    except (ValueError, TypeError):
        raise DomainError(
            "expired_authorization", "Authorization is expired or has invalid time bounds", 409
        ) from None
    validate_gates(gates, certificate.candidate_hash, certificate.assurance_profile)
    if any(g.case_id != certificate.case_id for g in gates) or set(certificate.gate_result_ids) != {
        g.gate_id for g in gates
    }:
        raise DomainError(
            "gate_inventory", "Evidence does not enumerate these exact case gates", 409
        )
    if set(certificate.required_gate_ids) != {
        g.gate_id for g in gates if g.check_profile_id in REQUIRED_CHECKS
    }:
        raise DomainError("gate_inventory", "Required gate inventory was changed", 409)
    if manifest.recipe_id != "dsvw-python-v1":
        raise DomainError(
            "unsupported_deployment_profile",
            "Synthetic workflow adapter is not installed for this recipe",
            422,
        )


class LabDeployer:
    def __init__(self, path: Path, launcher, observation_seconds=300, interval_seconds=15):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS destinations(project_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, data TEXT NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS decisions(authorization_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, result TEXT NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT, created_at TEXT, data TEXT)"
        )
        self.launcher = launcher
        self.observation_seconds, self.interval_seconds = observation_seconds, interval_seconds
        self.locks = {}

    def close(self):
        self.db.close()

    def state(self, project_id):
        row = self.db.execute(
            "SELECT data FROM destinations WHERE project_id=?", (project_id,)
        ).fetchone()
        return (
            json.loads(row[0])
            if row
            else {
                "project_id": project_id,
                "generation": 0,
                "current": None,
                "previous": None,
                "intent": None,
                "status": "UNAVAILABLE",
            }
        )

    def all_states(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT data FROM destinations")]

    def save(self, value, expected_generation):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self.db.execute(
                "SELECT generation FROM destinations WHERE project_id=?", (value["project_id"],)
            ).fetchone()
            if (old[0] if old else 0) != expected_generation:
                raise DomainError("stale_generation", "Destination routing changed", 409)
            self.db.execute(
                "INSERT INTO destinations VALUES(?,?,?) ON CONFLICT(project_id) DO UPDATE SET generation=excluded.generation,data=excluded.data",
                (value["project_id"], value["generation"], canonical_json(value).decode()),
            )
            self.db.execute(
                "INSERT INTO events(project_id,created_at,data) VALUES(?,?,?)",
                (
                    value["project_id"],
                    utcnow(),
                    canonical_json(
                        {
                            "status": value["status"],
                            "generation": value["generation"],
                            "state_hash": content_hash(value),
                        }
                    ).decode(),
                ),
            )
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    async def stop(self, slot):
        if slot:
            await self.launcher.call(
                "/targets/stop",
                {k: slot[k] for k in ("project_id", "environment_id", "network_id")},
            )

    async def checks(self, project_id, slot):
        return await dsvw_checks(self.launcher, project_id, slot["environment_id"], slot["port"])

    async def request(self, project_id, path="/", method="GET", body=None):
        state = self.state(project_id)
        slot = state["current"]
        if not slot or state["status"] in {
            "RECOVERY_FAILED",
            "RETIRING",
            "RETIRE_FAILED",
            "RETIRED",
        }:
            raise DomainError("destination_unavailable", "No healthy lab route is active", 503)
        response = await self.launcher.call(
            "/targets/request",
            {
                "project_id": project_id,
                "environment_id": slot["environment_id"],
                "port": slot["port"],
                "path": path,
                "method": method,
                "body": body,
            },
        )
        return {
            "generation": state["generation"],
            "artifact_digest": slot["artifact_digest"],
            "response": response,
        }

    async def initialize(self, manifest: TargetManifest):
        project_id = manifest.project_id
        async with self.locks.setdefault(project_id, asyncio.Lock()):
            state = self.state(project_id)
            if state["current"]:
                return state
            if state["intent"] or manifest.recipe_id != "dsvw-python-v1":
                raise DomainError(
                    "initialization_blocked",
                    "Destination requires reconciliation or an installed workflow adapter",
                    409,
                )
            slot = await self.launcher.call(
                "/targets", {"project_id": project_id, "artifact_digest": manifest.artifact_digest}
            )
            slot |= {
                "port": manifest.services[0].internal_ports[0],
                "manifest": manifest.model_dump(),
                "source_id": manifest.setup_provenance[0]["source_id"],
                "known_vulnerable_baseline": True,
            }
            try:
                check = await self.checks(project_id, slot)
                if not check["functional_pass"]:
                    raise DomainError(
                        "baseline_unhealthy",
                        "Initial lab destination failed positive workflows",
                        503,
                    )
                state |= {
                    "current": slot,
                    "status": "BASELINE",
                    "deployment_id": new_id(),
                    "baseline_evidence": check,
                }
                self.save(state, 0)
                return state
            except BaseException:
                await self.stop(slot)
                raise

    async def promote(
        self,
        authorization: Authorization,
        certificate: EvidenceManifest,
        manifest: TargetManifest,
        gates: list[GateResult],
        source_id: str,
    ):
        project_id = authorization.project_id
        request_hash = content_hash(
            {
                "authorization": authorization.model_dump(),
                "certificate": certificate.model_dump(),
                "manifest": manifest.model_dump(),
                "gates": [g.model_dump() for g in gates],
                "source_id": source_id,
            }
        )
        async with self.locks.setdefault(project_id, asyncio.Lock()):
            prior = self.db.execute(
                "SELECT request_hash,result FROM decisions WHERE authorization_id=?",
                (authorization.authorization_id,),
            ).fetchone()
            if prior:
                if prior[0] != request_hash:
                    raise DomainError(
                        "authorization_reuse", "Authorization was reused with different inputs", 409
                    )
                return json.loads(prior[1])
            state = self.state(project_id)
            if state["intent"] or state["status"] == "RECOVERY_FAILED":
                raise DomainError(
                    "promotion_blocked", "Destination has unfinished work or failed recovery", 409
                )
            validate_authority(authorization, certificate, manifest, gates, state["generation"])
            original = dict(state)
            state |= {
                "status": "STAGING",
                "intent": {
                    "authorization_id": authorization.authorization_id,
                    "request_hash": request_hash,
                    "target": None,
                    "started_at": utcnow(),
                },
            }
            self.save(state, original["generation"])
            slot = None
            observations = []
            try:
                slot = await self.launcher.call(
                    "/targets",
                    {"project_id": project_id, "artifact_digest": certificate.artifact_digest},
                )
                slot |= {
                    "port": manifest.services[0].internal_ports[0],
                    "source_id": source_id,
                    "known_vulnerable_baseline": False,
                    "evidence_manifest_hash": authorization.evidence_manifest_hash,
                    "base_manifest": manifest.model_dump(),
                    "candidate_tree_hash": certificate.candidate_hash,
                }
                state["intent"]["target"] = slot
                state["status"] = "OBSERVING"
                self.save(state, original["generation"])
                deadline = time.monotonic() + self.observation_seconds
                while True:
                    if self.state(project_id).get("intent", {}).get("cancel_requested"):
                        raise DomainError(
                            "cancelled", "Promotion cancelled before route switch", 409
                        )
                    check = await self.checks(project_id, slot)
                    observations.append(
                        {
                            "observed_at": utcnow(),
                            "functional_pass": check["functional_pass"],
                            "security_pass": check["security_pass"],
                            "evidence": check,
                        }
                    )
                    if not check["functional_pass"] or not check["security_pass"]:
                        raise DomainError(
                            "canary_failed",
                            "Candidate failed a synthetic functional or security workflow",
                            409,
                        )
                    if time.monotonic() >= deadline:
                        break
                    await asyncio.sleep(
                        min(self.interval_seconds, max(0, deadline - time.monotonic()))
                    )
                if self.state(project_id).get("intent", {}).get("cancel_requested"):
                    raise DomainError("cancelled", "Promotion cancelled before route switch", 409)
                validate_authority(
                    authorization,
                    certificate,
                    manifest,
                    gates,
                    self.state(project_id)["generation"],
                )
                # The immutable route changes only after the complete observation window.
                promoted = {
                    "project_id": project_id,
                    "generation": original["generation"] + 1,
                    "current": slot,
                    "previous": original["current"],
                    "intent": None,
                    "status": "PROMOTED",
                    "deployment_id": new_id(),
                    "authorization_id": authorization.authorization_id,
                    "observations": observations,
                    "promoted_at": utcnow(),
                }
                result = {
                    "status": "PROMOTED",
                    "project_id": project_id,
                    "generation": promoted["generation"],
                    "deployment_id": promoted["deployment_id"],
                    "candidate_digest": certificate.artifact_digest,
                    "previous_digest": original["current"]["artifact_digest"]
                    if original["current"]
                    else None,
                    "observations": observations,
                    "authorization_id": authorization.authorization_id,
                    "current": slot,
                    "previous": original["current"],
                }
                # Route and idempotency decision commit together: response loss cannot redeploy.
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    row = self.db.execute(
                        "SELECT generation FROM destinations WHERE project_id=?", (project_id,)
                    ).fetchone()
                    if row[0] != original["generation"]:
                        raise DomainError("stale_generation", "Routing changed during canary", 409)
                    self.db.execute(
                        "UPDATE destinations SET generation=?,data=? WHERE project_id=?",
                        (promoted["generation"], canonical_json(promoted).decode(), project_id),
                    )
                    self.db.execute(
                        "INSERT INTO decisions VALUES(?,?,?)",
                        (
                            authorization.authorization_id,
                            request_hash,
                            canonical_json(result).decode(),
                        ),
                    )
                    self.db.execute(
                        "INSERT INTO events(project_id,created_at,data) VALUES(?,?,?)",
                        (
                            project_id,
                            utcnow(),
                            canonical_json(
                                {
                                    "status": "PROMOTED",
                                    "generation": promoted["generation"],
                                    "authorization_id": authorization.authorization_id,
                                }
                            ).decode(),
                        ),
                    )
                    self.db.execute("COMMIT")
                except BaseException:
                    self.db.execute("ROLLBACK")
                    raise
                return result
            except BaseException:
                # Before a committed route switch, restoration means validating the original route.
                if self.state(project_id)["generation"] == original["generation"]:
                    await self.stop(slot)
                    recovery = (
                        await self.checks(project_id, original["current"])
                        if original["current"]
                        else None
                    )
                    restored = bool(recovery and recovery["functional_pass"])
                    original |= {
                        "status": "ROLLED_BACK"
                        if restored
                        else "RECOVERY_FAILED"
                        if original["current"]
                        else "UNAVAILABLE",
                        "intent": None,
                        "recovery": recovery,
                        "failed_observations": observations,
                    }
                    self.save(original, original["generation"])
                raise

    async def abort(self, project_id):
        state = self.state(project_id)
        if state["intent"]:
            state["intent"]["cancel_requested"] = True
            self.save(state, state["generation"])
            deadline = time.monotonic() + 60
            while self.state(project_id)["intent"]:
                if time.monotonic() >= deadline:
                    raise DomainError(
                        "termination_unconfirmed",
                        "Promotion has not acknowledged cancellation",
                        503,
                    )
                await asyncio.sleep(0.2)
        return self.state(project_id)

    async def retire(self, project_id):
        """Withdraw routing before removing the owned lab instances."""
        await self.abort(project_id)
        async with self.locks.setdefault(project_id, asyncio.Lock()):
            state = self.state(project_id)
            if state["status"] == "RETIRED":
                return state
            state["status"] = "RETIRING"
            self.save(state, state["generation"])
            try:
                await self.stop(state["current"])
                await self.stop(state["previous"])
            except BaseException:
                state["status"] = "RETIRE_FAILED"
                self.save(state, state["generation"])
                raise
            retired = state | {
                "current": None,
                "previous": None,
                "intent": None,
                "status": "RETIRED",
                "generation": state["generation"] + 1,
                "retired_at": utcnow(),
            }
            self.save(retired, state["generation"])
            return retired

    async def rollback(self, project_id, expected_generation):
        async with self.locks.setdefault(project_id, asyncio.Lock()):
            state = self.state(project_id)
            if state["generation"] != expected_generation or state["intent"]:
                raise DomainError(
                    "stale_generation", "Destination changed or is currently promoting", 409
                )
            previous = state["previous"]
            if not previous:
                raise DomainError(
                    "no_previous_artifact", "No prior destination exists to restore", 409
                )
            check = await self.checks(project_id, previous)
            if not check["functional_pass"]:
                state |= {"status": "RECOVERY_FAILED", "recovery": check}
                self.save(state, expected_generation)
                raise DomainError(
                    "recovery_failed", "Previous artifact failed recovery workflows", 503
                )
            restored = state | {
                "generation": expected_generation + 1,
                "current": previous,
                "previous": state["current"],
                "status": "ROLLED_BACK",
                "recovery": check,
                "rolled_back_at": utcnow(),
                "deployment_id": new_id(),
            }
            self.save(restored, expected_generation)
            return restored

    async def reconcile(self):
        for state in self.all_states():
            if state["status"] in {"RETIRING", "RETIRE_FAILED"}:
                await self.retire(state["project_id"])
                continue
            if state["intent"]:
                target = state["intent"].get("target")
                await self.stop(target)
                check = (
                    await self.checks(state["project_id"], state["current"])
                    if state["current"]
                    else None
                )
                status = (
                    "ROLLED_BACK"
                    if check and check["functional_pass"]
                    else "RECOVERY_FAILED"
                    if state["current"]
                    else "UNAVAILABLE"
                )
                self.save(
                    state | {"status": status, "intent": None, "recovery": check},
                    state["generation"],
                )
        return self.all_states()
