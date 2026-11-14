"""Shared identifiers, validation and deterministic content hashes."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Annotated, Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Hash = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"),
]
NonNegative = Annotated[int, Field(ge=0, strict=True)]
Text = Annotated[str, StringConstraints(max_length=8192)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_assignment=True)


def new_id() -> str:
    return str(uuid4())


def utcnow() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def content_hash(value: Any) -> str:
    return digest(canonical_json(value))


def safe_relative_path(value: str) -> str:
    p = PurePosixPath(value)
    if not value or "\x00" in value or "\\" in value or p.is_absolute():
        raise ValueError("Path must be a nonempty relative POSIX path")
    if any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("Path cannot contain empty, dot or parent segments")
    return value


class DomainError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 409, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.retryable = retryable

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "evidence_ids": [],
        }
