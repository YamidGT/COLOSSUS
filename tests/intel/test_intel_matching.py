from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from colossus.contracts.core import DomainError
from colossus.intel import DependencyEntry, FeedCache, match_inventory
from colossus.intel.matching import evaluate_range
from colossus.intel.models import AffectedRange, RangeEvent
from colossus.intel.versions import pep440_key, semver_key

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "intel"
T0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def loaded_cache() -> FeedCache:
    cache = FeedCache()
    cache.register("osv-pypi", "osv", "https://osv.example.invalid/pypi")
    cache.register("kev", "kev", "https://kev.example.invalid/catalog")
    cache.record_success("osv-pypi", (FIXTURES / "osv-synthetic-pypi.json").read_bytes(), iso(T0))
    cache.record_success("kev", (FIXTURES / "kev-synthetic.json").read_bytes(), iso(T0))
    return cache


def match(package, version, cache=None, now=T0):
    cache = cache or loaded_cache()
    dep = DependencyEntry(package=package, ecosystem="PyPI", version=version)
    return match_inventory(
        [dep], cache.advisories("osv-pypi"), cache.kev("kev"), cache.all_freshness(now)
    )


def status(package, version):
    results = match(package, version)
    assert len(results) == 1
    return results[0].event.affected_status


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.9.9", "affected"),
        ("2.0.0", "not_affected"),  # fixed version itself is not affected
        ("2.0", "not_affected"),  # PEP 440 equality, not string equality
        ("2.5", "not_affected"),
        ("3.0", "affected"),
        ("3.2", "affected"),  # last_affected boundary is inclusive
        ("3.2rc1", "affected"),
        ("3.2.1", "not_affected"),
        ("3.2.post1", "not_affected"),
        ("v3.1", "affected"),
    ],
)
def test_example_pkg_ranges(version, expected):
    assert status("example-pkg", version) == expected


def test_introduced_before_is_not_affected():
    assert status("otherpkg", "1.4") == "not_affected"
    assert status("otherpkg", "1.5") == "affected"
    assert status("otherpkg", "1.7") == "not_affected"
    assert status("otherpkg", "1.10") == "not_affected"  # not lexical: 1.10 > 1.7


@pytest.mark.parametrize("version", ["latest", "1.0-DIRTY!", "x" * 300, "1.0.0+"])
def test_unparseable_dependency_version_stays_unknown(version):
    if len(version) > 256:
        with pytest.raises(ValueError):
            DependencyEntry(package="example-pkg", ecosystem="PyPI", version=version)
        return
    assert status("example-pkg", version) == "unknown"


def test_unorderable_advisory_event_and_git_only_ranges_stay_unknown():
    assert status("weirdpkg", "1.0") == "unknown"
    assert status("gitonly", "1.0") == "unknown"


def test_unsupported_ecosystem_is_unknown():
    rng = AffectedRange(
        type="ECOSYSTEM",
        events=[RangeEvent(kind="introduced", version="0"), RangeEvent(kind="fixed", version="2")],
    )
    assert evaluate_range(rng, "Debian", "1")[0] == "unknown"
    assert evaluate_range(rng, "PyPI", "1")[0] == "affected"


def test_semver_range_ordering():
    rng = AffectedRange(
        type="SEMVER",
        events=[
            RangeEvent(kind="introduced", version="1.2.0-beta.2"),
            RangeEvent(kind="fixed", version="1.10.0"),
        ],
    )
    assert evaluate_range(rng, "npm", "1.2.0-beta.1")[0] == "not_affected"
    assert evaluate_range(rng, "npm", "1.2.0-beta.11")[0] == "affected"
    assert evaluate_range(rng, "npm", "1.9.0")[0] == "affected"
    assert evaluate_range(rng, "npm", "1.10.0")[0] == "not_affected"
    assert evaluate_range(rng, "npm", "1.9")[0] == "unknown"
    assert semver_key("01.0.0") is None


def test_pep440_ordering_samples():
    ordered = ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0+local", "1.0.post1", "1.1"]
    keys = [pep440_key(v) for v in ordered]
    assert keys == sorted(keys)
    assert pep440_key("1!0.1") > pep440_key("9.9")
    assert pep440_key("1.0") == pep440_key("1.0.0")
    assert pep440_key("not-a-version") is None


def test_alias_duplicates_collapse_and_preserve_conflict():
    results = match("Example.Pkg", "0.5")
    assert len(results) == 1
    m = results[0]
    assert m.advisory_ids == ["OSV-SYNTH-0001", "PYSEC-SYNTH-0001"]
    assert m.event.affected_status == "affected"
    assert m.conflicts and any("not_affected" in c for c in m.conflicts)
    assert "CVE-2099-0001" in m.event.aliases
    assert m.event.kev_status is True and m.kev.cve_id == "CVE-2099-0001"
    assert m.event.fixed_versions == ["2.0.0"]
    assert m.event.severity_vector.startswith("CVSS:3.1/")
    assert m.event.severity_source == "osv:CVSS_V3"
    assert m.severity_origin == "official"
    assert m.event.raw_content_hash and m.event.fetched_at == iso(T0)
    assert m.event.replay is False and m.feed_stale is False


def test_unrelated_package_yields_no_match_and_kev_absence_semantics():
    assert match("unrelated", "1.0") == []
    fresh = match("otherpkg", "1.6")[0]
    assert fresh.event.kev_status is False
    assert fresh.severity_origin == "heuristic"
    assert fresh.event.severity_source == "unavailable"
    stale = match("otherpkg", "1.6", now=T0 + timedelta(hours=1))[0]
    assert stale.event.kev_status is None  # stale KEV absence is not "not exploited"
    assert stale.feed_stale is True and stale.stale_reasons


def test_replay_and_live_cannot_be_joined():
    live = loaded_cache()
    replay = FeedCache.from_snapshot(live.export_snapshot())
    dep = DependencyEntry(package="example-pkg", ecosystem="PyPI", version="1.0")
    with pytest.raises(DomainError) as exc:
        match_inventory([dep], live.advisories("osv-pypi") + replay.advisories("osv-pypi"))
    assert exc.value.code == "mixed_intel_modes"
    with pytest.raises(DomainError):
        match_inventory([dep], live.advisories("osv-pypi"), replay.kev("kev"))
