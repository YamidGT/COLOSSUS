"""Injected feed fetcher interface. The gateway owns network access; this lane never fetches."""

from __future__ import annotations

from typing import Protocol

from pydantic import Field

from colossus.contracts.core import Contract, DomainError


class FeedPayload(Contract):
    feed_id: str = Field(min_length=1, max_length=128)
    source_url: str = Field(max_length=2048)
    content: bytes
    fetched_at: str


class FeedFetcher(Protocol):
    async def fetch_feed(self, feed_id: str, cursor: str | None) -> FeedPayload: ...


class GatewayFeedFetcher:
    """NOT WIRED. Placeholder for the contract's ``fetch_feed(feed_id, cursor)`` gateway call.

    ``colossus.gateway.server`` exposes only ``/health``, ``/source`` and ``/complete`` today.
    Until the gateway owner adds a feed route, every call fails with ``feed_not_wired`` so the
    cache records a failure and keeps any previous data marked stale. It never reports
    "no exposure" and never opens a network connection.
    """

    wired = False

    def __init__(self, client: object | None = None):
        self.client = client

    async def fetch_feed(self, feed_id: str, cursor: str | None) -> FeedPayload:
        raise DomainError(
            "feed_not_wired", "Gateway has no feed route; intel fetch is not wired", 503
        )
