"""Typed error object: {code, message, retryable, evidence_ids}. No secrets in messages."""

from __future__ import annotations

from enum import StrEnum

from .common import BoundedList, ShortText, StrictModel, Uuid


class ErrorCode(StrEnum):
    INVALID_INPUT = "invalid_input"
    SCHEMA_VERSION_MISMATCH = "schema_version_mismatch"
    PAYLOAD_HASH_MISMATCH = "payload_hash_mismatch"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    CONFLICT = "conflict"
    STALE_REVISION = "stale_revision"
    STALE_GENERATION = "stale_generation"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    BUDGET_STOP = "budget_stop"
    UNSUPPORTED = "unsupported"
    NEEDS_CONFIGURATION = "needs_configuration"
    POLICY_DENIED = "policy_denied"
    ISOLATION_UNAVAILABLE = "isolation_unavailable"
    INFRA_FAILED = "infra_failed"
    INTERNAL = "internal"


RETRYABLE_BY_DEFAULT = frozenset({ErrorCode.TIMEOUT, ErrorCode.INFRA_FAILED})


class ColossusError(StrictModel):
    code: ErrorCode
    message: ShortText
    retryable: bool
    evidence_ids: BoundedList(Uuid, 64) = []

    @classmethod
    def of(cls, code: ErrorCode, message: str, evidence_ids: list[str] | None = None) -> "ColossusError":
        return cls(
            code=code,
            message=message[:256],
            retryable=code in RETRYABLE_BY_DEFAULT,
            evidence_ids=evidence_ids or [],
        )


class ContractError(Exception):
    """Raised by controller-side validators; carries a typed ColossusError."""

    def __init__(self, error: ColossusError):
        super().__init__(f"{error.code}: {error.message}")
        self.error = error
