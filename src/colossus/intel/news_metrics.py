"""News-driven metrics: of the advisories a feed delivers, how many affect THIS project?

    python -m colossus.intel.news_metrics DSVW VAmPI

Uses the integrated `ThreatFeeds` (OSV + CISA KEV). Counts are over *declared pins* in the
target's requirements files, not an installed inventory, and an OSV match is not reachability.
Fix metrics are about the *upstream route* only: is a fixed version published? No patch is
generated or deployed here, so nothing in this report claims a vulnerability was remediated.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

from colossus.intel.osv import ThreatFeeds, parse_requirements

ROOT = Path(__file__).resolve().parents[3]


async def measure(target: str) -> dict:
    pins, unresolved = [], []
    for req in sorted((ROOT / "tmp/targets" / target).rglob("requirements*.txt")):
        parsed = parse_requirements(req.read_text(encoding="utf-8", errors="replace"))
        pins += parsed["pins"]
        unresolved += parsed["unresolved"]
    async with httpx.AsyncClient() as client:
        feeds = ThreatFeeds(client)
        result = await feeds.match(pins[:100])
        kev = await feeds.kev()
    # Broad news stream: every CISA KEV entry is "news". Name overlap with a declared package is
    # a weak, string-level signal (KEV has no PyPI mapping) and is reported as such.
    catalog = (kev.data or {}).get("vulnerabilities", [])
    names = {p[0].lower().replace("_", "-") for p in pins}
    overlap = [v.get("cveID") for v in catalog if any(
        n in (str(v.get("product", "")) + " " + str(v.get("vendorProject", ""))).lower()
        for n in names)]
    events = result["events"]
    by_status: dict[str, int] = {}
    for e in events:
        by_status[e["affected_status"]] = by_status.get(e["affected_status"], 0) + 1
    affected = [e for e in events if e["affected_status"] == "affected"]
    kev_known = [e for e in events if e.get("kev_status")]
    fixable = [e for e in affected if e.get("fixed_versions")]
    return {
        "target": target,
        "declared_pins": len(pins),
        "unresolved_requirements": len(unresolved),
        "news_stream_kev_total": len(catalog),
        "news_stream_kev_name_overlap": len(overlap),
        "news_stream_kev_overlap_ids": overlap[:10],
        "advisories_received": len(events),
        "affecting_project": len(affected),
        "affect_rate": round(len(affected) / len(events), 3) if events else None,
        "by_status": by_status,
        "packages_affected": len({e["package"] for e in affected}),
        "packages_total": len(pins),
        "actively_exploited_kev": len(kev_known),
        "kev_feed_status": next((f["status"] for f in result["feeds"] if f["source"] == "cisa-kev"), None),
        "upstream_fix_published": len(fixable),
        "upstream_fix_rate": round(len(fixable) / len(affected), 3) if affected else None,
        "no_fixed_version": len(affected) - len(fixable),
        "incomplete": result["incomplete"],
        "scope": "declared pins only; match is not reachability; no patch generated or deployed",
    }


if __name__ == "__main__":
    out = ROOT / "tmp/news_metrics"
    out.mkdir(parents=True, exist_ok=True)
    for t in sys.argv[1:] or ["DSVW", "VAmPI"]:
        r = asyncio.run(measure(t))
        (out / f"{t}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(json.dumps(r), flush=True)
