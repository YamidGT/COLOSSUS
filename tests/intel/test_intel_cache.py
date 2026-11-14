import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from colossus.contracts.core import DomainError
from colossus.intel import (
    DependencyEntry,
    FeedCache,
    FeedPayload,
    GatewayFeedFetcher,
    match_inventory,
    refresh,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "intel"
OSV = (FIXTURES / "osv-synthetic-pypi.json").read_bytes()
KEV = (FIXTURES / "kev-synthetic.json").read_bytes()
T0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("intel tests must not open sockets")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


class FakeFetcher:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    async def fetch_feed(self, feed_id, cursor):
        self.calls.append((feed_id, cursor))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def osv_cache() -> FeedCache:
    cache = FeedCache(poll_seconds=900)
    cache.register("osv-pypi", "osv", "https://osv.example.invalid/pypi")
    return cache


def test_stale_after_twice_poll_period():
    cache = osv_cache()
    cache.record_success("osv-pypi", OSV, iso(T0))
    assert cache.freshness("osv-pypi", T0 + timedelta(seconds=1800)).state == "fresh"
    late = cache.freshness("osv-pypi", T0 + timedelta(seconds=1801))
    assert late.state == "stale" and late.has_data
    assert "exceeds 2x poll period (1800s)" in late.stale_reason


def test_never_fetched_is_not_no_exposure():
    cache = osv_cache()
    fresh = cache.freshness("osv-pypi", T0)
    assert fresh.state == "never_fetched" and not fresh.has_data
    assert cache.advisories("osv-pypi") == []


async def test_failure_keeps_previous_data_stale_with_reason():
    cache = osv_cache()
    ok = FeedPayload(
        feed_id="osv-pypi",
        source_url="https://osv.example.invalid/pypi",
        content=OSV,
        fetched_at=iso(T0),
    )
    fetcher = FakeFetcher([ok, DomainError("upstream_timeout", "OSV timed out", 504)])
    assert await refresh(cache, fetcher, "osv-pypi", iso(T0)) is True
    before = cache.advisories("osv-pypi")
    later = T0 + timedelta(minutes=15)
    assert await refresh(cache, fetcher, "osv-pypi", iso(later)) is False
    state = cache.freshness("osv-pypi", later)
    assert state.state == "stale" and state.has_data
    assert "upstream_timeout: OSV timed out" in state.stale_reason
    assert state.last_success_at == iso(T0)
    assert cache.advisories("osv-pypi") == before
    assert [a.ok for a in cache.attempts("osv-pypi")] == [True, False]
    dep = DependencyEntry(package="example-pkg", ecosystem="PyPI", version="1.0")
    m = match_inventory([dep], before, None, cache.all_freshness(later))[0]
    assert m.event.affected_status == "affected" and m.feed_stale
    assert "upstream_timeout" in m.stale_reasons[0]


async def test_malformed_upstream_document_is_failure_not_empty_feed():
    cache = osv_cache()
    cache.record_success("osv-pypi", OSV, iso(T0))
    bad = FeedPayload(
        feed_id="osv-pypi",
        source_url="https://osv.example.invalid/pypi",
        content=b'{"vulns": [{"id": 7}]}',
        fetched_at=iso(T0 + timedelta(minutes=15)),
    )
    assert await refresh(cache, FakeFetcher([bad]), "osv-pypi", iso(T0)) is False
    assert len(cache.advisories("osv-pypi")) == 5
    assert cache.freshness("osv-pypi", T0 + timedelta(minutes=16)).state == "stale"


async def test_unexpected_adapter_error_and_wrong_feed_are_recorded():
    cache = osv_cache()
    wrong = FeedPayload(feed_id="other", source_url="u", content=OSV, fetched_at=iso(T0))
    assert not await refresh(cache, FakeFetcher([RuntimeError("boom")]), "osv-pypi", iso(T0))
    assert not await refresh(cache, FakeFetcher([wrong]), "osv-pypi", iso(T0))
    reasons = [a.failure_reason for a in cache.attempts("osv-pypi")]
    assert reasons == ["fetch_error: RuntimeError", "feed_mismatch: Fetcher returned another feed"]
    assert cache.freshness("osv-pypi", T0).state == "never_fetched"


async def test_gateway_fetcher_is_explicitly_not_wired():
    cache = osv_cache()
    fetcher = GatewayFeedFetcher()
    assert fetcher.wired is False
    assert await refresh(cache, fetcher, "osv-pypi", iso(T0)) is False
    state = cache.freshness("osv-pypi", T0)
    assert state.state == "never_fetched" and "feed_not_wired" in state.stale_reason


def test_replay_snapshot_labels_everything_and_is_read_only(tmp_path):
    live = osv_cache()
    live.register("kev", "kev", "https://kev.example.invalid/catalog")
    live.record_success("osv-pypi", OSV, iso(T0))
    live.record_success("kev", KEV, iso(T0))
    path = tmp_path / "frozen.json"
    path.write_bytes(live.export_snapshot())
    replay = FeedCache.load_replay(path)
    assert replay.mode == "replay"
    advisories = replay.advisories("osv-pypi")
    assert advisories and all(a.provenance.replay for a in advisories)
    assert replay.kev("kev").provenance.replay is True
    assert all(not a.provenance.replay for a in live.advisories("osv-pypi"))
    assert (
        advisories[0].provenance.raw_content_hash
        == live.advisories("osv-pypi")[0].provenance.raw_content_hash
    )
    dep = DependencyEntry(package="example-pkg", ecosystem="PyPI", version="1.0")
    events = match_inventory([dep], advisories, replay.kev("kev"))
    assert events[0].event.replay is True
    assert replay.freshness("osv-pypi", T0).mode == "replay"
    with pytest.raises(DomainError) as exc:
        replay.record_success("osv-pypi", OSV, iso(T0))
    assert exc.value.code == "replay_read_only"
    with pytest.raises(DomainError):
        replay.record_failure("osv-pypi", "x", iso(T0))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(format="other"),
        lambda d: d["feeds"][0].update(raw_content_hash="0" * 64),
        lambda d: d["feeds"][0].update(content_b64="!!!"),
        lambda d: d["feeds"][0].update(kind="news"),
        lambda d: d["feeds"].append(dict(d["feeds"][0])),
        lambda d: d["feeds"][0].pop("fetched_at"),
    ],
)
def test_tampered_snapshot_rejected(mutate):
    live = osv_cache()
    live.record_success("osv-pypi", OSV, iso(T0))
    document = json.loads(live.export_snapshot())
    mutate(document)
    with pytest.raises(DomainError) as exc:
        FeedCache.from_snapshot(json.dumps(document).encode())
    assert exc.value.code == "invalid_snapshot"


def test_registration_and_kind_checks():
    cache = osv_cache()
    with pytest.raises(DomainError):
        cache.register("osv-pypi", "kev", "x")
    with pytest.raises(DomainError):
        cache.kev("osv-pypi")
    with pytest.raises(DomainError):
        cache.freshness("missing", T0)
    with pytest.raises(ValueError):
        FeedCache(poll_seconds=0)
