"""Feed cache with provenance, staleness and frozen replay snapshots.

A failed fetch never clears data: the previous content is kept and the feed is reported stale
with the failure reason. Content is validated before it replaces the cached copy, so a
malformed upstream document is a recorded failure, not an empty feed.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from colossus.contracts.core import DomainError, content_hash, digest

from .fetcher import FeedFetcher
from .models import Advisory, FeedFreshness, FeedKind, FetchAttempt, KevCatalog, Provenance
from .parsers import MAX_KEV_BYTES, parse_kev, parse_osv

DEFAULT_POLL_SECONDS = 15 * 60
SNAPSHOT_FORMAT = "colossus-intel-snapshot-v1"
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_REASON = 500


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return parsed


@dataclass
class _Feed:
    kind: FeedKind
    source_url: str
    content: bytes | None = None
    provenance: Provenance | None = None
    attempts: list[FetchAttempt] = field(default_factory=list)


class FeedCache:
    def __init__(
        self,
        poll_seconds: int = DEFAULT_POLL_SECONDS,
        mode: Literal["live", "replay"] = "live",
        history_limit: int = 50,
    ):
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        self.poll_seconds = poll_seconds
        self.mode = mode
        self.history_limit = history_limit
        self._feeds: dict[str, _Feed] = {}

    @property
    def stale_after_seconds(self) -> int:
        return 2 * self.poll_seconds

    def register(self, feed_id: str, kind: FeedKind, source_url: str) -> None:
        existing = self._feeds.get(feed_id)
        if existing and existing.kind != kind:
            raise DomainError("feed_kind_conflict", "Feed is registered with another kind", 409)
        self._feeds.setdefault(feed_id, _Feed(kind=kind, source_url=source_url))

    def _feed(self, feed_id: str) -> _Feed:
        try:
            return self._feeds[feed_id]
        except KeyError:
            raise DomainError("unknown_feed", "Feed is not registered", 404) from None

    def _append(self, feed: _Feed, attempt: FetchAttempt) -> None:
        feed.attempts.append(attempt)
        del feed.attempts[: -self.history_limit]

    def _provenance(self, feed_id: str, feed: _Feed, content: bytes, fetched_at: str, url: str):
        raw_hash = digest(content)
        return Provenance(
            feed_id=feed_id,
            source=feed.kind,
            source_url=url,
            raw_content_id=content_hash(
                {
                    "feed_id": feed_id,
                    "source_url": url,
                    "fetched_at": fetched_at,
                    "sha256": raw_hash,
                }
            ),
            raw_content_hash=raw_hash,
            fetched_at=fetched_at,
            replay=self.mode == "replay",
        )

    def _parse(self, feed: _Feed, content: bytes, provenance: Provenance):
        if feed.kind == "osv":
            return parse_osv(content, provenance)
        return parse_kev(content, provenance)

    def record_success(
        self, feed_id: str, content: bytes, fetched_at: str, source_url: str | None = None
    ) -> Provenance:
        if self.mode == "replay":
            raise DomainError("replay_read_only", "Replay caches cannot record live fetches", 409)
        feed = self._feed(feed_id)
        _parse_time(fetched_at)
        url = source_url or feed.source_url
        provenance = self._provenance(feed_id, feed, content, fetched_at, url)
        try:
            self._parse(feed, content, provenance)
        except DomainError as exc:
            self.record_failure(feed_id, f"{exc.code}: {exc.message}", fetched_at)
            raise
        feed.content, feed.provenance, feed.source_url = bytes(content), provenance, url
        self._append(
            feed, FetchAttempt(at=fetched_at, ok=True, raw_content_hash=provenance.raw_content_hash)
        )
        return provenance

    def record_failure(self, feed_id: str, reason: str, at: str) -> None:
        if self.mode == "replay":
            raise DomainError("replay_read_only", "Replay caches cannot record live fetches", 409)
        _parse_time(at)
        feed = self._feed(feed_id)
        self._append(feed, FetchAttempt(at=at, ok=False, failure_reason=reason[:MAX_REASON]))

    def attempts(self, feed_id: str) -> list[FetchAttempt]:
        return list(self._feed(feed_id).attempts)

    def freshness(self, feed_id: str, now: datetime) -> FeedFreshness:
        feed = self._feed(feed_id)
        failure = next((a for a in reversed(feed.attempts) if not a.ok), None)
        base = {
            "feed_id": feed_id,
            "kind": feed.kind,
            "mode": self.mode,
            "has_data": feed.content is not None,
            "last_failure_at": failure.at if failure else None,
            "last_failure_reason": failure.failure_reason if failure else None,
        }
        if feed.provenance is None:
            reason = "no successful fetch"
            if failure:
                reason += f"; last attempt failed: {failure.failure_reason}"
            return FeedFreshness(**base, state="never_fetched", stale_reason=reason[:MAX_REASON])
        fetched = _parse_time(feed.provenance.fetched_at)
        age = max(0, int((now - fetched).total_seconds()))
        reasons = []
        if failure and _parse_time(failure.at) >= fetched:
            reasons.append(f"last fetch failed at {failure.at}: {failure.failure_reason}")
        if age > self.stale_after_seconds:
            reasons.append(f"age {age}s exceeds 2x poll period ({self.stale_after_seconds}s)")
        return FeedFreshness(
            **base,
            state="stale" if reasons else "fresh",
            last_success_at=feed.provenance.fetched_at,
            age_seconds=age,
            stale_reason="; ".join(reasons)[:MAX_REASON] if reasons else None,
        )

    def all_freshness(self, now: datetime) -> list[FeedFreshness]:
        return [self.freshness(fid, now) for fid in sorted(self._feeds)]

    def advisories(self, feed_id: str) -> list[Advisory]:
        feed = self._feed(feed_id)
        if feed.kind != "osv":
            raise DomainError("feed_kind_conflict", "Feed is not an OSV feed", 409)
        if feed.content is None or feed.provenance is None:
            return []
        return parse_osv(feed.content, feed.provenance)

    def kev(self, feed_id: str) -> KevCatalog | None:
        feed = self._feed(feed_id)
        if feed.kind != "kev":
            raise DomainError("feed_kind_conflict", "Feed is not a KEV feed", 409)
        if feed.content is None or feed.provenance is None:
            return None
        return parse_kev(feed.content, feed.provenance)

    def export_snapshot(self) -> bytes:
        """Frozen copy of the latest successful content of every feed, for replay."""
        feeds = []
        for feed_id, feed in sorted(self._feeds.items()):
            if feed.content is None or feed.provenance is None:
                continue
            feeds.append(
                {
                    "feed_id": feed_id,
                    "kind": feed.kind,
                    "source_url": feed.provenance.source_url,
                    "fetched_at": feed.provenance.fetched_at,
                    "raw_content_hash": feed.provenance.raw_content_hash,
                    "content_b64": base64.b64encode(feed.content).decode(),
                }
            )
        return json.dumps({"format": SNAPSHOT_FORMAT, "feeds": feeds}, sort_keys=True).encode()

    @classmethod
    def from_snapshot(cls, raw: bytes, poll_seconds: int = DEFAULT_POLL_SECONDS) -> FeedCache:
        """Load a frozen snapshot. Everything derived from it carries ``replay=True``."""
        if len(raw) > MAX_SNAPSHOT_BYTES:
            raise DomainError("feed_limit", "Replay snapshot exceeds size limit", 413)
        try:
            document = json.loads(raw)
            if document.get("format") != SNAPSHOT_FORMAT or not isinstance(
                document.get("feeds"), list
            ):
                raise ValueError("format")
            cache = cls(poll_seconds=poll_seconds, mode="replay")
            for item in document["feeds"]:
                content = base64.b64decode(item["content_b64"], validate=True)
                if len(content) > MAX_KEV_BYTES or digest(content) != item["raw_content_hash"]:
                    raise ValueError("content")
                _parse_time(item["fetched_at"])
                if item["kind"] not in ("osv", "kev") or item["feed_id"] in cache._feeds:
                    raise ValueError("feed")
                cache.register(item["feed_id"], item["kind"], item["source_url"])
                feed = cache._feeds[item["feed_id"]]
                provenance = cache._provenance(
                    item["feed_id"], feed, content, item["fetched_at"], item["source_url"]
                )
                cache._parse(feed, content, provenance)
                feed.content, feed.provenance = content, provenance
        except DomainError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            raise DomainError("invalid_snapshot", "Replay snapshot is invalid", 422) from exc
        return cache

    @classmethod
    def load_replay(cls, path: Path, poll_seconds: int = DEFAULT_POLL_SECONDS) -> FeedCache:
        return cls.from_snapshot(Path(path).read_bytes(), poll_seconds)


async def refresh(
    cache: FeedCache, fetcher: FeedFetcher, feed_id: str, at: str, cursor: str | None = None
) -> bool:
    """Fetch through the injected fetcher. Any failure is recorded; cached data is kept."""
    try:
        payload = await fetcher.fetch_feed(feed_id, cursor)
        if payload.feed_id != feed_id:
            raise DomainError("feed_mismatch", "Fetcher returned another feed", 502)
    except DomainError as exc:
        cache.record_failure(feed_id, f"{exc.code}: {exc.message}", at)
        return False
    except Exception as exc:  # adapter failures must never surface as "no exposure"
        cache.record_failure(feed_id, f"fetch_error: {type(exc).__name__}", at)
        return False
    try:
        cache.record_success(feed_id, payload.content, payload.fetched_at, payload.source_url)
    except DomainError:
        return False  # record_success already logged the validation failure
    except ValueError:
        cache.record_failure(feed_id, "invalid_feed: fetched_at is not a timestamp", at)
        return False
    return True
