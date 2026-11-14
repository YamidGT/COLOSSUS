"""OSV affected-version evaluation and dependency inventory joins.

Rules: ecosystem ordering only (never lexical); anything that cannot be ordered yields
``unknown``; ``not_affected`` is reported only when every applicable range was evaluated.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from colossus.contracts.core import DomainError
from colossus.contracts.models import IntelEvent

from .models import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    AffectedStatus,
    DependencyEntry,
    FeedFreshness,
    IntelMatch,
    KevCatalog,
)
from .versions import normalize_pypi_name, pep440_key, semver_key

_RANK = {"not_affected": 0, "unknown": 1, "affected": 2}


def _ecosystem(value: str) -> str:
    return value.strip().lower()


def _package(ecosystem: str, name: str) -> str:
    return normalize_pypi_name(name) if _ecosystem(ecosystem) == "pypi" else name


def _key_function(range_type: str, ecosystem: str) -> Callable[[str], tuple | None] | None:
    if range_type == "SEMVER":
        return semver_key
    if range_type == "ECOSYSTEM" and _ecosystem(ecosystem) == "pypi":
        return pep440_key
    return None  # GIT ranges and unsupported ecosystems cannot be evaluated here


def evaluate_range(rng: AffectedRange, ecosystem: str, version: str) -> tuple[AffectedStatus, str]:
    key = _key_function(rng.type, ecosystem)
    if key is None:
        return "unknown", f"{rng.type} range for {ecosystem} is not evaluable"
    target = key(version)
    if target is None:
        return "unknown", f"version {version[:64]!r} is not orderable as {rng.type}"
    ordered = []
    for event in rng.events:
        if event.kind == "limit":
            continue  # limit only bounds commit walks; it never marks a version safe
        if event.kind == "introduced" and event.version == "0":
            ordered.append(((), 0, event.kind))
            continue
        event_key = key(event.version)
        if event_key is None:
            return "unknown", f"range event {event.version[:64]!r} is not orderable"
        ordered.append(((1, event_key), 1, event.kind))
    if not any(kind == "introduced" for _, _, kind in ordered):
        return "unknown", "range has no introduced event"
    affected = False
    reason = "before first introduced version"
    for sort_key, _, kind in sorted(ordered, key=lambda o: (o[0], o[1])):
        bound = sort_key[1] if sort_key else None
        if kind == "introduced":
            if bound is None or bound <= target:
                affected, reason = True, "at or after introduced version"
        elif kind == "fixed":
            if bound <= target:
                affected, reason = False, "at or after fixed version"
        elif kind == "last_affected":
            if bound < target:
                affected, reason = False, "after last_affected version"
    return ("affected" if affected else "not_affected"), reason


def evaluate_package(affected: AffectedPackage, version: str) -> tuple[AffectedStatus, str]:
    if version in affected.versions:
        return "affected", "version listed explicitly"
    if not affected.ranges:
        if affected.versions:
            # An enumerated list without ranges is exhaustive only for exact strings.
            key = pep440_key if _ecosystem(affected.ecosystem) == "pypi" else None
            target = key(version) if key else None
            if target is not None and all(key(v) is not None for v in affected.versions):
                if any(key(v) == target for v in affected.versions):
                    return "affected", "version listed explicitly (normalized)"
                return "not_affected", "version not in enumerated affected list"
        return "unknown", "advisory has no evaluable ranges"
    # GIT ranges describe commits; they apply to a released version only when no
    # version-ordered range exists for the package.
    evaluable = [r for r in affected.ranges if _key_function(r.type, affected.ecosystem)]
    if not evaluable:
        return "unknown", "no version-ordered range for this ecosystem"
    results = [evaluate_range(r, affected.ecosystem, version) for r in evaluable]
    return max(results, key=lambda r: _RANK[r[0]])


def advisory_status(advisory: Advisory, dep: DependencyEntry) -> tuple[AffectedStatus, str] | None:
    """None when the advisory does not name this package in this ecosystem."""
    eco = _ecosystem(dep.ecosystem)
    name = _package(dep.ecosystem, dep.package)
    results = [
        evaluate_package(a, dep.version)
        for a in advisory.affected
        if _ecosystem(a.ecosystem) == eco and _package(a.ecosystem, a.package) == name
    ]
    if not results:
        return None
    return max(results, key=lambda r: _RANK[r[0]])


def fixed_versions(advisory: Advisory, dep: DependencyEntry) -> list[str]:
    eco = _ecosystem(dep.ecosystem)
    name = _package(dep.ecosystem, dep.package)
    out: list[str] = []
    for a in advisory.affected:
        if _ecosystem(a.ecosystem) == eco and _package(a.ecosystem, a.package) == name:
            for rng in a.ranges:
                if _key_function(rng.type, a.ecosystem) is None:
                    continue  # GIT commits are not installable versions
                out.extend(e.version for e in rng.events if e.kind == "fixed")
    return sorted(set(out))


def _group_duplicates(advisories: list[Advisory]) -> list[list[Advisory]]:
    """Union advisories that share an id or alias (applied per package by the caller)."""
    groups: list[tuple[set[str], list[Advisory]]] = []
    for advisory in advisories:
        names = {advisory.advisory_id, *advisory.aliases}
        merged = [g for g in groups if g[0] & names]
        ids, members = set(names), [advisory]
        for g in merged:
            ids |= g[0]
            members = g[1] + members
            groups.remove(g)
        groups.append((ids, members))
    return [sorted(m, key=lambda a: a.advisory_id) for _, m in groups]


def match_inventory(
    inventory: Iterable[DependencyEntry],
    advisories: Iterable[Advisory],
    kev: KevCatalog | None = None,
    freshness: Iterable[FeedFreshness] = (),
) -> list[IntelMatch]:
    """Join dependencies with advisories; returns every named-package match with its status.

    Replay and live advisories cannot be joined in one call. Stale or failed feeds are
    propagated to every match; KEV absence becomes ``kev_status=False`` only when the KEV
    feed is fresh, otherwise ``None``.
    """
    advisories = [a for a in advisories if a.withdrawn_at is None]
    modes = {a.provenance.replay for a in advisories}
    if kev is not None:
        modes.add(kev.provenance.replay)
    if len(modes) > 1:
        raise DomainError("mixed_intel_modes", "Replay and live intel cannot be joined", 409)
    freshness = list(freshness)
    stale = {f.feed_id: f for f in freshness if f.state != "fresh"}
    stale_reasons = sorted(f"{f.feed_id}: {f.stale_reason}" for f in stale.values())
    kev_fresh = kev is not None and kev.provenance.feed_id not in stale
    matches: list[IntelMatch] = []
    for dep in inventory:
        hits = [(a, advisory_status(a, dep)) for a in advisories]
        named = [a for a, status in hits if status is not None]
        for group in _group_duplicates(named):
            statuses = {a.advisory_id: advisory_status(a, dep) for a in group}
            primary = group[0]
            status, reason = max(statuses.values(), key=lambda r: _RANK[r[0]])
            conflicts = []
            if len({s for s, _ in statuses.values()}) > 1:
                conflicts = [f"{aid}: {s} ({r})" for aid, (s, r) in sorted(statuses.items())]
            aliases = sorted({n for a in group for n in (a.advisory_id, *a.aliases)})
            kev_entry = None
            if kev is not None:
                kev_entry = next((kev.entries[n] for n in aliases if n in kev.entries), None)
            kev_status = True if kev_entry else (False if kev_fresh else None)
            with_vector = next((a for a in group if a.severity_vector), None)
            source_stale = sorted(
                {a.provenance.feed_id for a in group} | ({kev.provenance.feed_id} if kev else set())
            )
            event = IntelEvent(
                source=primary.provenance.source,
                source_url=primary.provenance.source_url,
                raw_content_id=primary.provenance.raw_content_id,
                raw_content_hash=primary.provenance.raw_content_hash,
                fetched_at=primary.provenance.fetched_at,
                published_at=primary.published_at,
                modified_at=primary.modified_at,
                advisory_id=primary.advisory_id,
                aliases=[n for n in aliases if n != primary.advisory_id],
                package=dep.package,
                ecosystem=dep.ecosystem,
                version=dep.version,
                affected_status=status,
                fixed_versions=sorted({v for a in group for v in fixed_versions(a, dep)}),
                severity_vector=with_vector.severity_vector if with_vector else None,
                severity_source=with_vector.severity_source if with_vector else "unavailable",
                kev_status=kev_status,
                replay=primary.provenance.replay,
            )
            matches.append(
                IntelMatch(
                    dependency=dep,
                    event=event,
                    advisory_ids=[a.advisory_id for a in group],
                    reason=reason,
                    conflicts=conflicts,
                    feed_stale=any(fid in stale for fid in source_stale),
                    stale_reasons=[r for r in stale_reasons if r.split(":", 1)[0] in source_stale],
                    severity_origin="official" if with_vector else "heuristic",
                    kev=kev_entry,
                )
            )
    return matches
