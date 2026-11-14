"""Strict parsers for OSV vulnerability JSON and the CISA KEV catalog.

Feed bytes are untrusted. Every document is size-limited, rejects duplicate keys, NaN and
excessive nesting, and is rejected as a whole on any schema error so a malformed record can
never be read as "no vulnerabilities".
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from colossus.contracts.core import DomainError

from .models import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    KevCatalog,
    KevEntry,
    Provenance,
    RangeEvent,
)

MAX_OSV_BYTES = 8 * 1024 * 1024
MAX_KEV_BYTES = 16 * 1024 * 1024
MAX_OSV_RECORDS = 10_000
MAX_KEV_RECORDS = 50_000
MAX_DEPTH = 32
_SEVERITY_PREFERENCE = ("CVSS_V4", "CVSS_V3", "CVSS_V2")
_EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")


def _invalid(message: str) -> DomainError:
    return DomainError("invalid_feed", message, 422)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _invalid(f"Duplicate JSON key {key[:64]!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise _invalid(f"Non-finite JSON number {name}")


def _depth(value: Any, limit: int) -> None:
    stack = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if level > limit:
            raise _invalid("JSON nesting exceeds limit")
        if isinstance(item, dict):
            stack.extend((v, level + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, level + 1) for v in item)


def load_json(raw: bytes, limit: int) -> Any:
    if not isinstance(raw, bytes | bytearray):
        raise _invalid("Feed content must be bytes")
    if len(raw) > limit:
        raise DomainError("feed_limit", "Feed document exceeds size limit", 413)
    try:
        value = json.loads(
            bytes(raw).decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
        )
    except DomainError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _invalid("Feed document is not valid UTF-8 JSON") from exc
    _depth(value, MAX_DEPTH)
    return value


def _get(obj: dict, key: str, kind: type | tuple, *, required: bool = False, default=None):
    if key not in obj or obj[key] is None:
        if required:
            raise _invalid(f"Missing field {key!r}")
        return default
    value = obj[key]
    if isinstance(value, bool) and kind is not bool:
        raise _invalid(f"Field {key!r} has wrong type")
    if not isinstance(value, kind):
        raise _invalid(f"Field {key!r} has wrong type")
    return value


def _timestamp(obj: dict, key: str) -> str | None:
    value = _get(obj, key, str)
    if value is None:
        return None
    if len(value) > 64:
        raise _invalid(f"Field {key!r} is not a timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _invalid(f"Field {key!r} is not a timestamp") from exc
    return value


def _str_list(obj: dict, key: str) -> list[str]:
    values = _get(obj, key, list, default=[])
    if not all(isinstance(v, str) for v in values):
        raise _invalid(f"Field {key!r} must be a list of strings")
    return list(values)


def _severity(entries: list) -> tuple[str | None, str | None]:
    found: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise _invalid("Severity entry must be an object")
        kind = _get(entry, "type", str, required=True)
        score = _get(entry, "score", str, required=True)
        found.setdefault(kind, score)
    for kind in _SEVERITY_PREFERENCE:
        if kind in found:
            return found[kind], kind
    return None, None


def _affected(entry: Any) -> tuple[AffectedPackage, list]:
    if not isinstance(entry, dict):
        raise _invalid("Affected entry must be an object")
    package = _get(entry, "package", dict, required=True)
    ranges = []
    for rng in _get(entry, "ranges", list, default=[]):
        if not isinstance(rng, dict):
            raise _invalid("Range must be an object")
        events = []
        for event in _get(rng, "events", list, required=True):
            if not isinstance(event, dict) or len(event) != 1:
                raise _invalid("Range event must be an object with one key")
            ((kind, version),) = event.items()
            if kind not in _EVENT_KINDS or not isinstance(version, str):
                raise _invalid("Unsupported range event")
            events.append(RangeEvent(kind=kind, version=version))
        ranges.append(AffectedRange(type=_get(rng, "type", str, required=True), events=events))
    affected = AffectedPackage(
        ecosystem=_get(package, "ecosystem", str, required=True),
        package=_get(package, "name", str, required=True),
        ranges=ranges,
        versions=_str_list(entry, "versions"),
    )
    return affected, _get(entry, "severity", list, default=[])


def parse_osv_record(record: Any, provenance: Provenance) -> Advisory:
    if not isinstance(record, dict):
        raise _invalid("OSV record must be an object")
    try:
        affected = []
        package_severity: list = []
        for entry in _get(record, "affected", list, default=[]):
            item, sev = _affected(entry)
            affected.append(item)
            package_severity.extend(sev)
        vector, kind = _severity(_get(record, "severity", list, default=[]))
        if vector is None:
            vector, kind = _severity(package_severity)
        return Advisory(
            advisory_id=_get(record, "id", str, required=True),
            aliases=_str_list(record, "aliases"),
            published_at=_timestamp(record, "published"),
            modified_at=_timestamp(record, "modified"),
            withdrawn_at=_timestamp(record, "withdrawn"),
            summary=_get(record, "summary", str, default="")[:8192],
            affected=affected,
            severity_vector=vector,
            severity_source=f"osv:{kind}" if kind else "unavailable",
            provenance=provenance,
        )
    except ValidationError as exc:
        raise _invalid("OSV record failed schema validation") from exc


def parse_osv(raw: bytes, provenance: Provenance) -> list[Advisory]:
    """Accept one OSV record, a list of records, or an OSV ``{"vulns": [...]}`` response."""
    document = load_json(raw, MAX_OSV_BYTES)
    if isinstance(document, dict) and "id" in document:
        records = [document]
    elif isinstance(document, dict) and set(document) <= {"vulns", "next_page_token"}:
        records = _get(document, "vulns", list, default=[])
    elif isinstance(document, list):
        records = document
    else:
        raise _invalid("Unrecognized OSV document shape")
    if len(records) > MAX_OSV_RECORDS:
        raise DomainError("feed_limit", "OSV document has too many records", 413)
    advisories = [parse_osv_record(r, provenance) for r in records]
    ids = [a.advisory_id for a in advisories]
    if len(ids) != len(set(ids)):
        raise _invalid("OSV document repeats an advisory id")
    return advisories


def parse_kev(raw: bytes, provenance: Provenance) -> KevCatalog:
    document = load_json(raw, MAX_KEV_BYTES)
    if not isinstance(document, dict):
        raise _invalid("KEV catalog must be an object")
    rows = _get(document, "vulnerabilities", list, required=True)
    if len(rows) > MAX_KEV_RECORDS:
        raise DomainError("feed_limit", "KEV catalog has too many records", 413)
    entries: dict[str, KevEntry] = {}
    try:
        for row in rows:
            if not isinstance(row, dict):
                raise _invalid("KEV entry must be an object")
            cve = _get(row, "cveID", str, required=True)
            if cve in entries:
                raise _invalid("KEV catalog repeats a CVE id")
            entries[cve] = KevEntry(
                cve_id=cve,
                vendor=_get(row, "vendorProject", str, default=""),
                product=_get(row, "product", str, default=""),
                date_added=_get(row, "dateAdded", str),
                known_ransomware_use=_get(row, "knownRansomwareCampaignUse", str),
            )
        count = _get(document, "count", int)
        if count is not None and count != len(entries):
            raise _invalid("KEV count does not match its entries")
        return KevCatalog(
            catalog_version=_get(document, "catalogVersion", str),
            date_released=_timestamp(document, "dateReleased"),
            entries=entries,
            provenance=provenance,
        )
    except ValidationError as exc:
        raise _invalid("KEV catalog failed schema validation") from exc
