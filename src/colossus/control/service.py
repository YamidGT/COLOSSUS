"""Operator intentions and read models over durable controller state."""

from __future__ import annotations

import json
import time

from colossus.contracts.core import DomainError, content_hash, new_id, utcnow
from colossus.contracts.models import Enrollment, GateResult, ProjectConfigAmendment
from colossus.contracts.runtime import RuntimeConfig
from colossus.verification.policy import validate_gates

from .decisions import assess_campaign, reject_secrets
from .promotion import publication, rollback_plan
from .store import Store

TERMINAL_CYCLES = {
    "COMPLETE",
    "NO_FINDINGS",
    "NO_CHANGE",
    "REJECTED",
    "CANCELLED",
    "INFRA_FAILED",
    "TIMEOUT",
    "BUDGET_STOP",
}


class Controller:
    def __init__(self, store: Store, runtime: RuntimeConfig):
        self.store = store
        self.runtime = runtime

    def enroll(self, enrollment: Enrollment, key: str, actor: str):
        if enrollment.requirement_ids:
            raise DomainError(
                "unapproved_requirement", "No approved requirement profile is installed yet", 422
            )

        def action(db, operation_id):
            project_id = new_id()
            project = enrollment.model_dump() | {
                "project_id": project_id,
                "display_name": enrollment.repo_url.removeprefix("https://github.com/"),
                "setup_state": "NEW",
                "admission_state": "active",
                "created_at": utcnow(),
                "source": {},
                "mirror": {},
                "deployment": {},
                "active_cycle_id": None,
                "reason_code": None,
                "reason": None,
                "operation_id": operation_id,
            }
            self.store._put(db, "project", project_id, project, project_id)
            task_id = self.store.enqueue(
                db,
                project_id,
                "onboard",
                {"operation_id": operation_id},
                time.time() + self.runtime.onboarding_seconds,
            )
            return {"project_id": project_id, "task_id": task_id}

        return self.store.mutate(actor, key, "enroll", enrollment.model_dump(), action)

    def _project(self, db, project_id):
        row = db.execute(
            "SELECT data FROM records WHERE id=? AND kind='project'", (project_id,)
        ).fetchone()
        if not row:
            raise DomainError("not_found", "Project not found", 404)
        return json.loads(row[0])

    def run(self, project_id: str, key: str, actor: str, trigger: str = "manual"):
        if trigger not in {"manual", "schedule", "source", "advisory", "post_promotion"}:
            raise DomainError("invalid_trigger", "Unknown cycle trigger", 422)

        def action(db, operation_id):
            project = self._project(db, project_id)
            if project["admission_state"] != "active":
                raise DomainError("project_paused", "Resume the project before starting work")
            if project["setup_state"] != "READY":
                raise DomainError("project_not_ready", "Repository setup has not completed")
            if project.get("active_cycle_id"):
                return {"project_id": project_id, "cycle_id": project["active_cycle_id"]}
            cycle_id = new_id()
            deadline = time.time() + self.runtime.cycle_seconds
            cycle = dict(
                cycle_id=cycle_id,
                project_id=project_id,
                status="QUEUED",
                trigger=trigger,
                created_at=utcnow(),
                started_at=None,
                finished_at=None,
                deadline=deadline,
                manifest_hash=project["source"].get("manifest_hash"),
                case_ids=[],
                cancel_requested=False,
                operation_id=operation_id,
                reason=None,
            )
            self.store._put(db, "cycle", cycle_id, cycle, project_id)
            self.store._put(
                db,
                "project",
                project_id,
                project | {"active_cycle_id": cycle_id},
                project_id,
                project["revision"],
            )
            task_id = self.store.enqueue(
                db,
                project_id,
                "cycle",
                {"cycle_id": cycle_id, "operation_id": operation_id},
                deadline,
            )
            return {"project_id": project_id, "cycle_id": cycle_id, "task_id": task_id}

        return self.store.mutate(
            actor, key, "run", {"project_id": project_id, "trigger": trigger}, action
        )

    def admission(self, project_id: str, paused: bool, key: str, actor: str):
        def action(db, operation_id):
            project = self._project(db, project_id)
            self.store._put(
                db,
                "project",
                project_id,
                project | {"admission_state": "paused" if paused else "active"},
                project_id,
                project["revision"],
            )
            return {"project_id": project_id}

        receipt = self.store.mutate(
            actor, key, "pause" if paused else "resume", {"project_id": project_id}, action
        )
        self.store.finish_operation(receipt["operation_id"], "succeeded")
        return self.store.operation(receipt["operation_id"])

    def cancel(self, cycle_id: str, key: str, actor: str):
        def action(db, operation_id):
            row = db.execute(
                "SELECT data FROM records WHERE kind='cycle' AND id=?", (cycle_id,)
            ).fetchone()
            if not row:
                raise DomainError("not_found", "Cycle not found", 404)
            cycle = json.loads(row[0])
            if cycle["status"] in TERMINAL_CYCLES:
                raise DomainError("cycle_finished", "Cycle has already finished")
            self.store._put(
                db,
                "cycle",
                cycle_id,
                cycle | {"cancel_requested": True},
                cycle["project_id"],
                cycle["revision"],
            )
            return {"project_id": cycle["project_id"], "cycle_id": cycle_id}

        return self.store.mutate(actor, key, "cancel", {"cycle_id": cycle_id}, action)

    def retry_setup(self, project_id, key, actor):
        def action(db, operation_id):
            project = self._project(db, project_id)
            if project["setup_state"] not in {"SETUP_FAILED", "UNSUPPORTED", "NEEDS_CONFIGURATION"}:
                raise DomainError("setup_not_retryable", "Setup is not in a retryable state")
            if project["admission_state"] == "paused":
                raise DomainError("project_paused", "Resume project before retrying")
            self.store._put(
                db,
                "project",
                project_id,
                project | {"setup_state": "NEW", "reason": None, "reason_code": None},
                project_id,
                project["revision"],
            )
            task_id = self.store.enqueue(
                db,
                project_id,
                "onboard",
                {"operation_id": operation_id},
                time.time() + self.runtime.onboarding_seconds,
            )
            return {"project_id": project_id, "task_id": task_id}

        return self.store.mutate(actor, key, "retry_setup", {"project_id": project_id}, action)

    def snapshot(self, project_id: str) -> dict:
        p = self.store.get("project", project_id)
        active = self.store.get("cycle", p["active_cycle_id"]) if p.get("active_cycle_id") else None
        actions = self.actions(project_id)
        budget = self.store.budget()
        return dict(
            project_id=project_id,
            display_name=p["display_name"],
            repo_url=p["repo_url"],
            revision=p["revision"],
            observed_at=utcnow(),
            setup_state=p["setup_state"],
            admission_state=p["admission_state"],
            source_summary=p["source"],
            mirror_summary=p["mirror"],
            deployment_summary=p["deployment"],
            active_cycle=active,
            attention_count=len(actions),
            cost_summary=budget
            | {
                "unit": "micro_usd",
                "scope": "platform",
                "ceiling": self.runtime.automatic_ceiling_micro_usd,
            },
            feed_freshness=self.store.list("feed", limit=20),
            allowed_actions=self._project_actions(p),
            owner_policy_id=p["owner_policy_id"],
            assurance_profile=p["assurance_profile"],
            reason=p.get("reason"),
        )

    def _project_actions(self, p):
        ready = (
            p["setup_state"] == "READY"
            and p["admission_state"] == "active"
            and not p.get("active_cycle_id")
        )
        return [
            dict(
                action="run",
                resource_id=p["project_id"],
                expected_revision=p["revision"],
                eligible=ready,
                disabled_reason=None
                if ready
                else "Project is paused, not ready or already running",
                required_confirmation=False,
            ),
            dict(
                action="pause" if p["admission_state"] == "active" else "resume",
                resource_id=p["project_id"],
                expected_revision=p["revision"],
                eligible=True,
                disabled_reason=None,
                required_confirmation=False,
            ),
        ]

    def actions(self, project_id):
        p = self.store.get("project", project_id)
        result = []
        if p["setup_state"] in {"SETUP_FAILED", "UNSUPPORTED", "NEEDS_CONFIGURATION"}:
            result.append(
                dict(
                    action_id=f"{project_id}:setup",
                    project_id=project_id,
                    case_id=None,
                    kind="setup",
                    priority=1,
                    title="Repository setup needs attention",
                    reason_code=p.get("reason_code") or p["setup_state"],
                    reason=p.get("reason") or "Review setup evidence",
                    created_at=p["created_at"],
                    updated_at=utcnow(),
                    evidence_refs=[],
                    allowed_actions=[
                        dict(
                            action="retry_setup",
                            resource_id=project_id,
                            expected_revision=p["revision"],
                            eligible=p["admission_state"] == "active",
                            disabled_reason=None,
                            required_confirmation=False,
                        )
                    ],
                    disabled_reasons={},
                )
            )
        for case in self.store.list("case", project_id):
            if case["status"] in {"REVIEW_READY", "NEEDS_REVIEW", "RECOVERY_FAILED"}:
                result.append(
                    dict(
                        action_id=f"{case['case_id']}:review",
                        project_id=project_id,
                        case_id=case["case_id"],
                        kind="review",
                        priority=0 if case["status"] == "RECOVERY_FAILED" else 2,
                        title=case.get("title", "Review case"),
                        reason_code=case["status"],
                        reason=case.get("reason", "Review candidate evidence"),
                        created_at=case["created_at"],
                        updated_at=case.get("updated_at", case["created_at"]),
                        evidence_refs=[],
                        allowed_actions=[],
                        disabled_reasons={},
                    )
                )
        return sorted(
            result, key=lambda item: (item["priority"], item["created_at"], item["action_id"])
        )

    def report(self, run_id):
        cycle = self.store.get("cycle", run_id)
        project_id = cycle["project_id"]
        return dict(
            schema_version="1.0",
            project=self.snapshot(project_id),
            cycle=cycle,
            cases=[
                case
                for case in self.store.list("case", project_id)
                if case.get("cycle_id") == run_id
            ],
            findings=[
                f for f in self.store.list("finding", project_id) if f.get("cycle_id") == run_id
            ],
            audit=[
                e
                for e in self.store.audit(project_id)
                if e["data"].get("cycle_id", run_id) == run_id
            ],
            limitations=[
                "No findings is not proof of security",
                "Formal claims are limited to declared properties and assumptions",
            ],
        )

    def _done(self, receipt):
        self.store.finish_operation(receipt["operation_id"], "succeeded")
        return self.store.operation(receipt["operation_id"])

    def configure(self, project_id: str, amendment: ProjectConfigAmendment, key: str, actor: str):
        reject_secrets(amendment.model_dump())
        if amendment.requirement_ids:
            raise DomainError(
                "unapproved_requirement", "No approved requirement profile is installed yet", 422
            )

        def action(db, operation_id):
            del operation_id
            project = self._project(db, project_id)
            if project["revision"] != amendment.expected_revision:
                raise DomainError("stale_revision", "Project revision changed", 409)
            updated = project | {
                "requested_ref": amendment.requested_ref,
                "subdir": amendment.subdir,
                "owner_policy_id": amendment.owner_policy_id,
                "deployment_profile_id": amendment.deployment_profile_id,
                "assurance_profile": amendment.assurance_profile,
                "requirement_ids": [],
            }
            self.store._put(db, "project", project_id, updated, project_id, project["revision"])
            return {"project_id": project_id}

        return self._done(
            self.store.mutate(actor, key, "configure", amendment.model_dump(), action)
        )

    def approve(self, manifest_hash: str, destination_id: str, key: str, actor: str):
        def action(db, operation_id):
            del operation_id
            rows = db.execute("SELECT data FROM records WHERE kind='case'").fetchall()
            matches = [
                json.loads(row[0])
                for row in rows
                if json.loads(row[0]).get("evidence_manifest_hash") == manifest_hash
            ]
            if not matches:
                raise DomainError("not_found", "No case is bound to that evidence manifest", 404)
            if len(matches) != 1:
                raise DomainError(
                    "ambiguous_manifest", "Evidence manifest matches more than one case", 409
                )
            case = matches[0]
            if case.get("destination_id") != destination_id:
                raise DomainError("destination_mismatch", "Destination does not match the case", 409)
            if case.get("status") not in {"REVIEW_READY", "NEEDS_REVIEW"}:
                raise DomainError("not_reviewable", "Case is not waiting for a decision", 409)
            gates = [GateResult.model_validate(item) for item in case.get("gate_results", [])]
            validate_gates(gates, case["candidate_hash"], case.get("assurance_profile", "tested"))
            project = self._project(db, case["project_id"])
            published = publication(project, case | {"destination_id": destination_id})
            granted = published["authorization"]
            deployed = published["deployment"]
            if granted is not None:
                self.store._put(
                    db,
                    "authorization",
                    granted.authorization_id,
                    granted.model_dump(),
                    case["project_id"],
                )
                self.store._put(
                    db, "deployment", deployed["deployment_id"], deployed, case["project_id"]
                )
            self.store._put(
                db,
                "project",
                case["project_id"],
                project | published["project_changes"],
                case["project_id"],
                project["revision"],
            )
            self.store._put(
                db,
                "case",
                case["case_id"],
                case
                | {
                    "status": "DEPLOYED",
                    "destination_id": destination_id,
                    "deployment_id": deployed["deployment_id"],
                    "authorization_id": None if granted is None else granted.authorization_id,
                },
                case["project_id"],
                case["revision"],
            )
            return {
                "project_id": case["project_id"],
                "authorization_id": deployed.get("authorization_id") or "",
                "deployment_id": deployed["deployment_id"],
                "promotion": "recorded",
            }

        receipt = self._done(
            self.store.mutate(
                actor,
                key,
                "approve",
                {"evidence_manifest_hash": manifest_hash, "destination_id": destination_id},
                action,
            )
        )
        return receipt | {"promotion": "recorded"}

    def rollback(self, deployment_id: str, expected_generation: int, key: str, actor: str):
        def action(db, operation_id):
            del operation_id
            row = db.execute(
                "SELECT data FROM records WHERE kind='deployment' AND id=?", (deployment_id,)
            ).fetchone()
            if row is None:
                raise DomainError("not_found", "Deployment not found", 404)
            deployment = json.loads(row[0])
            project = self._project(db, deployment["project_id"])
            planned = rollback_plan(project, deployment, expected_generation)
            updated = planned["deployment"]
            self.store._put(
                db,
                "deployment",
                deployment_id,
                updated,
                deployment["project_id"],
                deployment["revision"],
            )
            self.store._put(
                db,
                "project",
                deployment["project_id"],
                project | planned["project_changes"],
                deployment["project_id"],
                project["revision"],
            )
            return {
                "project_id": deployment["project_id"],
                "deployment_id": deployment_id,
                "status": updated["status"],
                "claimed_rollback": "true" if planned["claimed_rollback"] else "false",
            }

        return self._done(
            self.store.mutate(
                actor,
                key,
                "rollback",
                {"deployment_id": deployment_id, "expected_generation": expected_generation},
                action,
            )
        )

    def evaluate(self, manifest: dict, key: str, actor: str):
        report = assess_campaign(manifest)

        def action(db, operation_id):
            del operation_id
            evaluation_id = new_id()
            self.store._put(
                db,
                "evaluation",
                evaluation_id,
                report | {"evaluation_id": evaluation_id},
                None,
            )
            return {"evaluation_id": evaluation_id, "executed": "false"}

        receipt = self._done(self.store.mutate(actor, key, "evaluate", manifest, action))
        return receipt | {"report": report}

    def snapshot_etag(self, snapshot):
        body = {key: value for key, value in snapshot.items() if key != "observed_at"}
        return '"' + content_hash(body) + '"'
