"""Shared conventions from docs/contracts.md "Common conventions"."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timedelta
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

SCHEMA_VERSION = "1.0"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_OCI_DIGEST = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$")
_PLATFORM = re.compile(r"^(linux)/(amd64|arm64)(/v[0-9]+)?$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class StrictModel(BaseModel):
    """Base for every contract object: no unknown fields, strict scalars, immutable."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _check_sha256(value: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError("must be 64 lowercase hexadecimal characters")
    return value


def _check_uuid(value: str) -> str:
    if not _UUID.fullmatch(value):
        raise ValueError("must be a lowercase UUID string")
    return value


def _check_profile_id(value: str) -> str:
    if not _ID.fullmatch(value):
        raise ValueError("must be a short identifier [A-Za-z0-9._:-]")
    return value


def _check_rel_path(value: str) -> str:
    if not value or len(value) > 1024:
        raise ValueError("path must be 1..1024 characters")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        raise ValueError("path must be relative POSIX without NUL or backslash")
    parts = value.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError("path must not contain empty, '.' or '..' segments")
    return value


def _check_image_digest(value: str) -> str:
    if not _OCI_DIGEST.fullmatch(value):
        raise ValueError("image must be pinned as name@sha256:<64 hex>")
    return value


def _check_platform(value: str) -> str:
    if not _PLATFORM.fullmatch(value):
        raise ValueError("platform must look like linux/amd64 or linux/arm64")
    return value


def _check_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be timezone-aware UTC")
    return value


Sha256 = Annotated[str, AfterValidator(_check_sha256)]
Uuid = Annotated[str, AfterValidator(_check_uuid)]
ProfileId = Annotated[str, AfterValidator(_check_profile_id)]
RelPath = Annotated[str, AfterValidator(_check_rel_path)]
ImageDigest = Annotated[str, AfterValidator(_check_image_digest)]
Platform = Annotated[str, AfterValidator(_check_platform)]
UtcTimestamp = Annotated[datetime, AfterValidator(_check_utc)]

ShortText = Annotated[str, StringConstraints(min_length=1, max_length=256)]
LongText = Annotated[str, StringConstraints(max_length=8192)]
MicroUsd = Annotated[int, Field(ge=0)]
TokenCount = Annotated[int, Field(ge=0)]
Seconds = Annotated[int, Field(ge=1, le=7 * 24 * 3600)]

MAX_LIST = 512


def BoundedList(item: Any, max_length: int = MAX_LIST) -> Any:  # noqa: N802 - type factory
    return Annotated[list[item], Field(max_length=max_length)]


def canonical_json(value: Any) -> bytes:
    """UTF-8, sorted keys, compact separators, no NaN/Infinity."""

    def reject_floats(obj: Any) -> None:
        if isinstance(obj, float) and not math.isfinite(obj):
            raise ValueError("NaN/Infinity are not allowed in canonical JSON")
        if isinstance(obj, dict):
            for v in obj.values():
                reject_floats(v)
        elif isinstance(obj, list):
            for v in obj:
                reject_floats(v)

    reject_floats(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(model_or_value: Any) -> str:
    """Canonical SHA-256 of a contract object or plain JSON value."""
    if isinstance(model_or_value, BaseModel):
        model_or_value = model_or_value.model_dump(mode="json")
    return sha256_hex(canonical_json(model_or_value))
