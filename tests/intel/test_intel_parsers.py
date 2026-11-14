import json
from pathlib import Path

import pytest

from colossus.contracts.core import DomainError, digest
from colossus.intel import parse_kev, parse_osv
from colossus.intel.models import Provenance
from colossus.intel.parsers import MAX_OSV_BYTES

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "intel"


def prov(content: bytes, kind="osv") -> Provenance:
    return Provenance(
        feed_id="f",
        source=kind,
        source_url="https://feed.example.invalid",
        raw_content_id=digest(b"id" + content),
        raw_content_hash=digest(content),
        fetched_at="2026-11-14T12:00:00Z",
        replay=False,
    )


def osv(document) -> list:
    raw = json.dumps(document).encode() if not isinstance(document, bytes) else document
    return parse_osv(raw, prov(raw))


def record(**overrides):
    base = {
        "id": "OSV-SYNTH-9",
        "modified": "2026-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "p"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    base.update(overrides)
    return base


def test_fixture_documents_parse():
    raw = (FIXTURES / "osv-synthetic-pypi.json").read_bytes()
    advisories = parse_osv(raw, prov(raw))
    assert [a.advisory_id for a in advisories][:2] == ["OSV-SYNTH-0001", "PYSEC-SYNTH-0001"]
    first = advisories[0]
    assert first.aliases == ["CVE-2099-0001"]
    assert first.severity_source == "osv:CVSS_V3"
    assert first.provenance.raw_content_hash == digest(raw)
    assert [e.kind for e in first.affected[0].ranges[1].events] == ["introduced", "last_affected"]
    kev_raw = (FIXTURES / "kev-synthetic.json").read_bytes()
    kev = parse_kev(kev_raw, prov(kev_raw, "kev"))
    assert set(kev.entries) == {"CVE-2099-0001", "CVE-2099-0099"}
    assert kev.catalog_version == "2099.01.01"


def test_single_record_and_list_shapes():
    assert len(osv(record())) == 1
    assert len(osv([record(), record(id="OSV-SYNTH-10")])) == 2


def test_severity_prefers_newest_cvss_and_falls_back_to_package():
    sev = [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"},
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"},
    ]
    assert osv(record(severity=sev))[0].severity_source == "osv:CVSS_V4"
    rec = record()
    rec["affected"][0]["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L"}]
    assert osv(rec)[0].severity_vector == "CVSS:3.1/AV:L"


@pytest.mark.parametrize(
    "document",
    [
        record(id=5),
        record(aliases="CVE-2099-1"),
        record(aliases=[1, 2]),
        record(affected={"package": "p"}),
        record(affected=[{"package": {"ecosystem": "PyPI"}}]),
        record(
            affected=[
                {
                    "package": {"ecosystem": "PyPI", "name": "p"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": 1}]}],
                }
            ]
        ),
        record(
            affected=[
                {
                    "package": {"ecosystem": "PyPI", "name": "p"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0", "fixed": "1"}]}
                    ],
                }
            ]
        ),
        record(
            affected=[
                {
                    "package": {"ecosystem": "PyPI", "name": "p"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"patched": "1"}]}],
                }
            ]
        ),
        record(modified="yesterday"),
        record(severity=[{"type": "CVSS_V3", "score": 9.8}]),
        record(withdrawn=True),
        {"vulns": "none"},
        {"vulns": [], "extra": 1},
        {"unrelated": True},
        "just a string",
        [record(), record()],
        b"\xff\xfe not utf8",
        b'{"id": "A", "id": "B"}',
        b'{"id": "A", "x": NaN}',
        b"[" * 100_000 + b"]" * 100_000,
        b"[" * 40 + b"]" * 40,
        b"{not json",
    ],
)
def test_hostile_osv_rejected_cleanly(document):
    with pytest.raises(DomainError) as exc:
        osv(document)
    assert exc.value.code in {"invalid_feed", "feed_limit"}


def test_oversized_documents_rejected_before_parsing():
    huge = b'{"vulns": [' + b" " * (MAX_OSV_BYTES + 1) + b"]}"
    with pytest.raises(DomainError) as exc:
        osv(huge)
    assert exc.value.code == "feed_limit"
    many = json.dumps({"vulns": [{}] * 10_001}).encode()
    with pytest.raises(DomainError) as exc:
        osv(many)
    assert exc.value.code == "feed_limit"
    long_range = record()
    long_range["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}] * 600
    with pytest.raises(DomainError):
        osv(long_range)


@pytest.mark.parametrize(
    "document",
    [
        {"vulnerabilities": "x"},
        {"vulnerabilities": [{"cveID": "not-a-cve"}]},
        {"vulnerabilities": [{"cveID": 12}]},
        {"vulnerabilities": [{"cveID": "CVE-2099-0001"}, {"cveID": "CVE-2099-0001"}]},
        {"vulnerabilities": [{"cveID": "CVE-2099-0001"}], "count": 3},
        {"vulnerabilities": [{"cveID": "CVE-2099-0001"}], "count": "1"},
        {"vulnerabilities": [{"cveID": "CVE-2099-0001", "vendorProject": ["x"]}]},
        {"count": 0},
        [],
    ],
)
def test_hostile_kev_rejected_cleanly(document):
    raw = json.dumps(document).encode()
    with pytest.raises(DomainError) as exc:
        parse_kev(raw, prov(raw, "kev"))
    assert exc.value.code == "invalid_feed"
