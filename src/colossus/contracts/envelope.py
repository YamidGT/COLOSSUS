"""Message envelope. The producer string is a label, not authentication."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import model_validator

from .common import SCHEMA_VERSION, ProfileId, Sha256, StrictModel, UtcTimestamp, Uuid, content_hash
from .errors import ColossusError, ContractError, ErrorCode
from .operator import OPERATOR_TYPES
from .payloads import PAYLOAD_TYPES

ALL_TYPES = {**PAYLOAD_TYPES, **OPERATOR_TYPES}


class Envelope(StrictModel):
    schema_version: Literal["1.0"]
    message_id: Uuid
    project_id: Uuid
    cycle_id: Uuid | None
    case_id: Uuid | None
    task_id: Uuid | None
    parent_message_id: Uuid | None
    kind: ProfileId
    producer: ProfileId
    created_at: UtcTimestamp
    payload: dict[str, Any]
    payload_sha256: Sha256

    @model_validator(mode="after")
    def _kind_known(self) -> "Envelope":
        if self.kind not in ALL_TYPES:
            raise ValueError(f"unknown payload kind {self.kind!r}")
        return self

    def verify(self) -> Any:
        """Check payload hash, then return the strictly validated typed payload."""
        if content_hash(self.payload) != self.payload_sha256:
            raise ContractError(ColossusError.of(ErrorCode.PAYLOAD_HASH_MISMATCH, "payload hash does not match"))
        model = ALL_TYPES[self.kind]
        return model.model_validate_json(json.dumps(self.payload))


def wrap(payload: Any, *, message_id: str, project_id: str, producer: str, created_at: str, **ids: Any) -> Envelope:
    """Build an envelope; created_at is an RFC3339 UTC string."""
    data = payload.model_dump(mode="json")
    return Envelope.model_validate_json(
        json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "message_id": message_id,
            "project_id": project_id,
            "cycle_id": ids.get("cycle_id"),
            "case_id": ids.get("case_id"),
            "task_id": ids.get("task_id"),
            "parent_message_id": ids.get("parent_message_id"),
            "kind": type(payload).__name__,
            "producer": producer,
            "created_at": created_at,
            "payload": data,
            "payload_sha256": content_hash(data),
        }
        )
    )
