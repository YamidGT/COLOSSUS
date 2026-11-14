"""Operator intentions and read models over durable controller state."""

from __future__ import annotations

import json
import time

from colossus.contracts.core import DomainError, content_hash, new_id, utcnow
from colossus.contracts.models import Enrollment
from colossus.contracts.runtime import RuntimeConfig

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
            if project.get("maintenance_operation_id"):
                raise DomainError(
                    "project_maintenance", "Wait for the destination operation to finish"
                )
            if (
                project["setup_state"] != "READY"
                or project.get("mirror", {}).get("state") != "READY"
            ):
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

    def approve(self, case_id, decision, key, actor):
        def action(db, operation_id):
            row = db.execute(
                "SELECT data FROM records WHERE kind='case' AND id=?", (case_id,)
            ).fetchone()
            if not row:
                raise DomainError("not_found", "Case not found", 404)
            case = json.loads(row[0])
            if (
                case["status"] != "REVIEW_READY"
                or case["revision"] != decision["expected_revision"]
            ):
                raise DomainError(
                    "stale_review", "Case changed; refresh its evidence before approving"
                )
            for field in (
                "candidate_id",
                "evidence_manifest_hash",
                "expected_deployment_generation",
            ):
                if case[field] != decision[field]:
                    raise DomainError(
                        "approval_binding",
                        "Approval does not match the current candidate or destination",
                    )
            project = self._project(db, case["project_id"])
            if project["admission_state"] != "active" or project["mirror"].get("state") != "READY":
                raise DomainError(
                    "project_not_ready", "Resume/reconcile the project before approving"
                )
            self.store._put(
                db,
                "case",
                case_id,
                case | {"status": "PROMOTION_QUEUED"},
                case["project_id"],
                case["revision"],
            )
            task_id = self.store.enqueue(
                db,
                case["project_id"],
                "promote",
                {
                    "case_id": case_id,
                    "cycle_id": case["cycle_id"],
                    "operation_id": operation_id,
                    "actor": actor,
                },
                time.time()
                + self.runtime.observation_seconds
                + self.runtime.refresh_seconds
                + self.runtime.recovery_seconds
                + 60,
            )
            cycle = json.loads(
                db.execute(
                    "SELECT data FROM records WHERE kind='cycle' AND id=?", (case["cycle_id"],)
                ).fetchone()[0]
            )
            self.store._put(
                db,
                "cycle",
                cycle["cycle_id"],
                cycle
                | {
                    "status": "PROMOTION_QUEUED",
                    "deadline": time.time()
                    + self.runtime.observation_seconds
                    + self.runtime.refresh_seconds
                    + self.runtime.recovery_seconds
                    + 60,
                },
                case["project_id"],
                cycle["revision"],
            )
            return {"project_id": case["project_id"], "case_id": case_id, "task_id": task_id}

        return self.store.mutate(actor, key, "approve", {"case_id": case_id, **decision}, action)

    def reject(self, case_id, expected_revision, reason, key, actor):
        def action(db, operation_id):
            row = db.execute(
                "SELECT data FROM records WHERE kind='case' AND id=?", (case_id,)
            ).fetchone()
            if not row:
                raise DomainError("not_found", "Case not found", 404)
            case = json.loads(row[0])
            if case["status"] != "REVIEW_READY" or case["revision"] != expected_revision:
                raise DomainError("stale_review", "Case changed or is not waiting for review")
            project = self._project(db, case["project_id"])
            self.store._put(
                db,
                "case",
                case_id,
                case | {"status": "REJECTED", "reason": reason},
                case["project_id"],
                expected_revision,
            )
            cycle = json.loads(
                db.execute(
                    "SELECT data FROM records WHERE kind='cycle' AND id=?", (case["cycle_id"],)
                ).fetchone()[0]
            )
            self.store._put(
                db,
                "cycle",
                cycle["cycle_id"],
                cycle | {"status": "REJECTED", "reason": reason, "finished_at": utcnow()},
                case["project_id"],
            )
            self.store._put(
                db,
                "project",
                project["project_id"],
                project | {"active_cycle_id": None},
                project["project_id"],
            )
            return {"project_id": project["project_id"], "case_id": case_id}

        receipt = self.store.mutate(
            actor,
            key,
            "reject",
            {"case_id": case_id, "expected_revision": expected_revision, "reason": reason},
            action,
        )
        self.store.finish_operation(receipt["operation_id"], "succeeded")
        return self.store.operation(receipt["operation_id"])

    def rollback(self, project_id, expected_generation, key, actor):
        def action(db, operation_id):
            project = self._project(db, project_id)
            if project.get("active_cycle_id") or project.get("maintenance_operation_id"):
                raise DomainError("project_busy", "Finish active work before requesting rollback")
            if project.get("deployment", {}).get("generation") != expected_generation:
                raise DomainError(
                    "stale_generation", "Refresh the destination before requesting rollback"
                )
            self.store._put(
                db,
                "project",
                project_id,
                project | {"maintenance_operation_id": operation_id},
                project_id,
                project["revision"],
            )
            task_id = self.store.enqueue(
                db,
                project_id,
                "rollback",
                {"operation_id": operation_id, "expected_generation": expected_generation},
                time.time() + self.runtime.recovery_seconds + self.runtime.refresh_seconds,
            )
            return {"project_id": project_id, "task_id": task_id}

        return self.store.mutate(
            actor,
            key,
            "rollback",
            {"project_id": project_id, "expected_generation": expected_generation},
            action,
        )

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
            and not p.get("maintenance_operation_id")
            and p.get("mirror", {}).get("state") == "READY"
        )
        deployment = p.get("deployment", {})
        recovery_ready = bool(deployment.get("previous_digest")) and not (
            p.get("active_cycle_id") or p.get("maintenance_operation_id")
        )
        return [
            dict(
                action="run",
                resource_id=p["project_id"],
                expected_revision=p["revision"],
                eligible=ready,
                disabled_reason=None
                if ready
                else "Project is paused, busy, or its mirror is not ready",
                required_confirmation=False,
            ),
            dict(
                action="rollback",
                resource_id=deployment.get("deployment_id") or p["project_id"],
                expected_revision=p["revision"],
                eligible=recovery_ready,
                disabled_reason=None
                if recovery_ready
                else "No retained artifact or project is busy",
                required_confirmation=True,
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
                        allowed_actions=self.case_review(case["case_id"])["allowed_actions"],
                        disabled_reasons={},
                    )
                )
        return sorted(
            result, key=lambda item: (item["priority"], item["created_at"], item["action_id"])
        )

    def case_review(self, case_id):
        from colossus.contracts.models import CaseReview

        case = self.store.get("case", case_id)
        project = self.store.get("project", case["project_id"])
        fresh = (
            project["admission_state"] == "active"
            and project.get("mirror", {}).get("state") == "READY"
        )
        eligible = fresh and case["status"] == "REVIEW_READY"
        case["allowed_actions"] = [
            dict(
                action=action,
                resource_id=case_id,
                expected_revision=case["revision"],
                eligible=eligible,
                disabled_reason=None if eligible else "Case is not ready for a fresh decision",
                required_confirmation=action == "approve",
            )
            for action in ("approve", "reject")
        ]
        return CaseReview.model_validate(
            {k: v for k, v in case.items() if k in CaseReview.model_fields}
        ).model_dump()

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

    def snapshot_etag(self, snapshot):
        body = {key: value for key, value in snapshot.items() if key != "observed_at"}
        return '"' + content_hash(body) + '"'
