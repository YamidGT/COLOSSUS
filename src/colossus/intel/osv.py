"""Fixed-origin vulnerability fetcher. Construct only inside the credential gateway."""

import json
import re
from dataclasses import asdict, dataclass

import httpx

from colossus.contracts.core import DomainError, digest, utcnow

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PIN = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+!-]+)\s*(?:;.*)?$")


def parse_requirements(text: str):
    pins, unresolved = [], []
    for line in text.splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean:
            continue
        match = PIN.fullmatch(clean)
        if match:
            pins.append((match[1], match[2]))
        else:
            unresolved.append(clean[:200])
    return {
        "pins": pins,
        "unresolved": unresolved,
        "scope": "declared pins, not an installed dependency inventory",
    }


@dataclass
class FeedResult:
    source: str
    source_url: str
    fetched_at: str
    status: str
    raw_content_hash: str | None
    data: dict | None
    error: str | None = None


class ThreatFeeds:
    def __init__(self, client):
        self.client = client

    async def read(self, source, url, payload=None):
        try:
            async with self.client.stream(
                "GET" if payload is None else "POST",
                url,
                json=payload,
                timeout=30,
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    raise DomainError(
                        "feed_http_error", "Feed returned HTTP " + str(response.status_code), 502
                    )
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 8 * 1024 * 1024:
                        raise DomainError("feed_limit", "Feed exceeded bounded response size", 413)
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError()
            return FeedResult(source, url, utcnow(), "fresh", digest(bytes(raw)), data)
        except (httpx.HTTPError, DomainError, ValueError) as exc:
            return FeedResult(
                source,
                url,
                utcnow(),
                "unavailable",
                None,
                None,
                exc.code if isinstance(exc, DomainError) else type(exc).__name__,
            )

    async def kev(self):
        result = await self.read("cisa-kev", KEV_URL)
        if result.data is not None and not isinstance(result.data.get("vulnerabilities"), list):
            result.status, result.error, result.data = "unavailable", "invalid_feed_schema", None
        return result

    async def match(self, pins):
        if len(pins) > 100:
            raise DomainError("inventory_limit", "At most 100 package versions per batch", 422)
        if any(
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", n)
            or not re.fullmatch(r"[A-Za-z0-9_.+!-]{1,100}", v)
            for n, v in pins
        ):
            raise DomainError("invalid_inventory", "Package names/versions are invalid", 422)
        kev = await self.kev()
        known = (
            {v.get("cveID") for v in kev.data["vulnerabilities"] if isinstance(v, dict)}
            if kev.data is not None
            else None
        )
        evidence, events, incomplete = [asdict(kev)], [], []
        if not pins:
            return {"events": [], "feeds": evidence, "incomplete": [], "inventory_empty": True}
        batch = await self.read(
            "osv",
            OSV_BATCH,
            {
                "queries": [
                    {"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in pins
                ]
            },
        )
        evidence.append(asdict(batch))
        if (
            batch.data is None
            or not isinstance(batch.data.get("results"), list)
            or len(batch.data["results"]) != len(pins)
        ):
            return {
                "events": [],
                "feeds": evidence,
                "incomplete": ["osv_batch_unavailable"],
                "inventory_empty": False,
            }
        fetched = {}
        for (name, version), match in zip(pins, batch.data["results"], strict=True):
            if match.get("next_page_token"):
                incomplete.append("osv_pagination_required:" + name)
            for item in match.get("vulns", []):
                advisory_id = item.get("id", "")
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", advisory_id):
                    incomplete.append("invalid_advisory_id")
                    continue
                if advisory_id not in fetched:
                    if len(fetched) >= 40:
                        incomplete.append("advisory_fetch_limit")
                        continue
                    fetched[advisory_id] = await self.read("osv", OSV_VULN + advisory_id)
                    evidence.append(asdict(fetched[advisory_id]))
                full = fetched[advisory_id]
                if full.data is None:
                    incomplete.append(advisory_id)
                    continue
                aliases = full.data.get("aliases", [])
                events.append(
                    {
                        "advisory_id": advisory_id,
                        "aliases": aliases,
                        "package": name,
                        "version": version,
                        "ecosystem": "PyPI",
                        "summary": str(full.data.get("summary", ""))[:500],
                        "affected_status": "affected",
                        "reachability": "unknown",
                        "kev_status": any(a in known for a in [advisory_id, *aliases])
                        if known is not None
                        else None,
                        "source": "osv",
                        "source_url": full.source_url,
                        "raw_content_hash": full.raw_content_hash,
                        "fetched_at": full.fetched_at,
                        "fixed_versions": sorted(
                            {
                                e["fixed"]
                                for affected in full.data.get("affected", [])
                                for r in affected.get("ranges", [])
                                for e in r.get("events", [])
                                if "fixed" in e
                            }
                        ),
                    }
                )
        return {
            "events": events,
            "feeds": evidence,
            "incomplete": sorted(set(incomplete)),
            "inventory_empty": False,
        }
