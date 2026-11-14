"""Operator read models and mutations (docs/contracts.md).

ProjectSnapshot and CaseReview are not defined yet: their summary sub-objects
are not specified field-by-field, so they wait for an A/D decision instead of
being invented here.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import Field, model_validator

from .common import BoundedList, ProfileId, RelPath, Sha256, ShortText, StrictModel, UtcTimestamp, Uuid
from .payloads import AssuranceProfile, GitRef


class ActionKind(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    ROLLBACK = "rollback"
    PAUSE = "pause"
    RESUME = "resume"
    CANCEL = "cancel"
    RETRY_SETUP = "retry_setup"
    CONFIGURE = "configure"
    RUN = "run"


class AllowedAction(StrictModel):
    """UI hint only; the server rechecks every action."""

    action: ActionKind
    resource_id: Uuid
    expected_revision: Annotated[int, Field(ge=0)]
    eligible: bool
    disabled_reason: ShortText | None
    required_confirmation: bool

    @model_validator(mode="after")
    def _reason_when_disabled(self) -> "AllowedAction":
        if not self.eligible and self.disabled_reason is None:
            raise ValueError("an ineligible action needs disabled_reason")
        if self.eligible and self.disabled_reason is not None:
            raise ValueError("an eligible action has no disabled_reason")
        return self


class ActionItem(StrictModel):
    action_id: ShortText
    project_id: Uuid
    case_id: Uuid | None
    kind: ProfileId
    priority: Annotated[int, Field(ge=0, le=100)]
    title: ShortText
    reason_code: ProfileId
    reason: ShortText
    created_at: UtcTimestamp
    updated_at: UtcTimestamp
    evidence_refs: BoundedList(Uuid, 64)
    allowed_actions: BoundedList(AllowedAction, 16)
    disabled_reasons: dict[ProfileId, ShortText] = {}


class OperationStatus(StrEnum):
    ACCEPTED = "accepted"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class OperationReceipt(StrictModel):
    operation_id: Uuid
    idempotency_key: Annotated[str, Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]
    request_hash: Sha256
    kind: ActionKind
    resource_ids: dict[ProfileId, Uuid]
    status: OperationStatus
    reason_code: ProfileId | None
    created_at: UtcTimestamp
    updated_at: UtcTimestamp
    result_ref: Uuid | None


class ProjectConfigAmendment(StrictModel):
    expected_revision: Annotated[int, Field(ge=1)]
    requested_ref: GitRef | None
    subdir: RelPath | None
    owner_policy_id: ProfileId
    deployment_profile_id: ProfileId
    assurance_profile: AssuranceProfile
    requirement_ids: BoundedList(ProfileId, 64)


class ReviewDecision(StrictModel):
    case_id: Uuid
    candidate_id: Uuid
    expected_revision: Annotated[int, Field(ge=1)]
    decision: Annotated[str, Field(pattern=r"^reject$")]
    reason: ShortText


OPERATOR_TYPES = {
    cls.__name__: cls
    for cls in (AllowedAction, ActionItem, OperationReceipt, ProjectConfigAmendment, ReviewDecision)
}
