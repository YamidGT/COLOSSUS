"""Lane-local intel models.

``IntelEvent`` (shared contract) is per dependency match: it carries package, version and
affected_status. Feed records are parsed into these strict local models first and become
``IntelEvent`` only when joined with a dependency inventory entry.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from colossus.contracts.core import Contract, Hash, Text
from colossus.contracts.models import IntelEvent

AffectedStatus = Literal["affected", "not_affected", "unknown"]
FeedKind = Literal["osv", "kev"]


class RangeEvent(Contract):
    kind: Literal["introduced", "fixed", "last_affected", "limit"]
    version: str = Field(min_length=1, max_length=256)


class AffectedRange(Contract):
    type: str = Field(min_length=1, max_length=32)
    events: list[RangeEvent] = Field(max_length=512)


class AffectedPackage(Contract):
    ecosystem: str = Field(min_length=1, max_length=64)
    package: str = Field(min_length=1, max_length=256)
    ranges: list[AffectedRange] = Field(default_factory=list, max_length=64)
    versions: list[str] = Field(default_factory=list, max_length=5000)


class Provenance(Contract):
    feed_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=64)
    source_url: str = Field(max_length=2048)
    raw_content_id: Hash
    raw_content_hash: Hash
    fetched_at: str
    replay: bool


class Advisory(Contract):
    """One validated OSV record."""

    advisory_id: str = Field(min_length=1, max_length=128)
    aliases: list[str] = Field(default_factory=list, max_length=256)
    published_at: str | None = None
    modified_at: str | None = None
    summary: Text = ""
    affected: list[AffectedPackage] = Field(max_length=512)
    severity_vector: str | None = Field(default=None, max_length=512)
    severity_source: str = Field(max_length=64)
    withdrawn_at: str | None = None
    provenance: Provenance


class KevEntry(Contract):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    vendor: str = Field(default="", max_length=256)
    product: str = Field(default="", max_length=256)
    date_added: str | None = None
    known_ransomware_use: str | None = Field(default=None, max_length=64)


class KevCatalog(Contract):
    catalog_version: str | None = Field(default=None, max_length=64)
    date_released: str | None = None
    entries: dict[str, KevEntry]
    provenance: Provenance


class FetchAttempt(Contract):
    at: str
    ok: bool
    raw_content_hash: Hash | None = None
    failure_reason: str | None = Field(default=None, max_length=500)


class FeedFreshness(Contract):
    feed_id: str
    kind: FeedKind
    mode: Literal["live", "replay"]
    state: Literal["fresh", "stale", "never_fetched"]
    has_data: bool
    last_success_at: str | None = None
    age_seconds: int | None = None
    stale_reason: str | None = None
    last_failure_at: str | None = None
    last_failure_reason: str | None = None


class DependencyEntry(Contract):
    package: str = Field(min_length=1, max_length=256)
    ecosystem: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=256)
    manifest_path: str | None = Field(default=None, max_length=1024)


class IntelMatch(Contract):
    """Join of one dependency with one deduplicated advisory, ready for Finding creation."""

    dependency: DependencyEntry
    event: IntelEvent
    advisory_ids: list[str]
    reason: str = Field(max_length=500)
    conflicts: list[str] = Field(default_factory=list)
    feed_stale: bool
    stale_reasons: list[str] = Field(default_factory=list)
    severity_origin: Literal["official", "heuristic"]
    kev: KevEntry | None = None
