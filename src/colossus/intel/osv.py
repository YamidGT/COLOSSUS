"""Dependency intelligence: OSV batch matching + CISA KEV enrichment (stdlib parsing, httpx)."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)")


def parse_requirements(path: Path) -> list[tuple[str, str]]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = PIN.match(line.split("#")[0])
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def fetch_kev() -> set[str]:
    try:
        r = httpx.get(KEV_URL, timeout=30)
        r.raise_for_status()
        return {v["cveID"] for v in r.json().get("vulnerabilities", [])}
    except (httpx.HTTPError, ValueError, KeyError):
        return set()  # stale/unavailable: caller must report, never "no vulns"


def match_dependencies(pins: list[tuple[str, str]], kev: set[str] | None = None,
                       max_details: int = 60) -> list[dict]:
    """Exact pinned name/version -> OSV advisories. Reachability is NOT established here."""
    if not pins:
        return []
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in pins]
    r = httpx.post(OSV_BATCH, json={"queries": queries}, timeout=60)
    r.raise_for_status()
    kev = kev or set()
    hits = [(name, ver, v["id"])
            for (name, ver), res in zip(pins, r.json().get("results", []), strict=False)
            for v in res.get("vulns", [])]

    def fetch(h: tuple[str, str, str]) -> dict:
        name, ver, vid = h
        try:
            full = httpx.get(OSV_VULN.format(id=vid), timeout=20).json()
        except (httpx.HTTPError, ValueError):
            full = {}  # keep the match visible even if the detail fetch failed
        aliases = full.get("aliases", [])
        return {
            "advisory_id": vid, "aliases": aliases, "package": name, "version": ver,
            "summary": full.get("summary", "")[:300],
            "cwe_ids": full.get("database_specific", {}).get("cwe_ids", []),
            "kev": any(a in kev for a in aliases), "affected_status": "affected",
            "source": "osv", "detail_fetched": bool(full),
        }

    # Cap detail fetches (a pinned-old stack can have hundreds of advisories); the rest are
    # reported as matches without detail, never silently dropped.
    head, tail = hits[:max_details], hits[max_details:]
    with ThreadPoolExecutor(max_workers=8) as pool:
        events = list(pool.map(fetch, head))
    events += [{"advisory_id": vid, "aliases": [], "package": n, "version": v, "summary": "",
                "cwe_ids": [], "kev": False, "affected_status": "affected", "source": "osv",
                "detail_fetched": False} for n, v, vid in tail]
    return events
