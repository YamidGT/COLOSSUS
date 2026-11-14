"""Project-scoped feed snapshots with durable provenance and outage visibility."""

import asyncio
import base64
import json
import time

from colossus.contracts.core import DomainError, content_hash, digest, utcnow
from colossus.contracts.models import IntelEvent


class IntelWatcher:
    def __init__(self, store, artifacts, gateway, runtime):
        self.store, self.artifacts, self.gateway, self.runtime = store, artifacts, gateway, runtime

    def previous(self, kind, key, project_id):
        try:
            return self.store.get(kind, key, project_id)
        except DomainError as exc:
            if exc.code != "not_found":
                raise
            return {}

    def inventory(self, project):
        manifest = json.loads(self.artifacts.get(project["source"]["manifest_hash"]))
        inventory = json.loads(self.artifacts.get(manifest["dependency_inventory_hash"]))
        pins = []
        omitted = []
        for package in inventory.get("packages", []):
            if (
                isinstance(package, dict)
                and package.get("ecosystem") == "PyPI"
                and isinstance(package.get("name"), str)
                and isinstance(package.get("version"), str)
            ):
                pins.append((package["name"], package["version"]))
            else:
                omitted.append(package)
        return sorted(set(pins)), inventory, omitted

    def ingest(self, project_id, manifest_hash, result, *, now=None, replay=False):
        now = time.time() if now is None else now
        raw_ids = {}
        for feed in result.get("feeds", []):
            if feed.get("raw_base64") is not None:
                raw = base64.b64decode(feed["raw_base64"], validate=True)
                if digest(raw) != feed["raw_content_hash"]:
                    raise DomainError("feed_integrity", "Feed bytes do not match their hash", 502)
                raw_ids[feed["raw_content_hash"]] = self.artifacts.put(raw)
        snapshot_id = self.artifacts.put(json.dumps(result, sort_keys=True).encode())
        events = []
        for value in result.get("events", []):
            raw_hash = value["raw_content_hash"]
            if raw_hash not in raw_ids:
                raise DomainError(
                    "missing_feed_evidence", "Advisory has no retained raw bytes", 502
                )
            event = IntelEvent(
                **{key: value[key] for key in IntelEvent.model_fields if key in value},
                raw_content_id=raw_ids[raw_hash],
                severity_source="not_assessed",
                replay=replay,
            ).model_dump()
            events.append(event)
        if replay:
            return {"mode": "replay", "snapshot_id": snapshot_id, "events": events, "trigger": None}
        changed = []
        # Advisory aliases are scoped to the matched ecosystem/package/version.
        groups = []
        for event in events:
            ids = {event["advisory_id"], *event["aliases"]}
            matching = [
                g
                for g in groups
                if g["package"] == (event["ecosystem"], event["package"], event["version"])
                and g["ids"] & ids
            ]
            if matching:
                group = matching[0]
                group["events"].append(event)
                group["ids"] |= ids
                for other in matching[1:]:
                    group["events"] += other["events"]
                    group["ids"] |= other["ids"]
                    groups.remove(other)
            else:
                groups.append(
                    {
                        "package": (event["ecosystem"], event["package"], event["version"]),
                        "ids": ids,
                        "events": [event],
                    }
                )
        for group in groups:
            aliases = sorted(group["ids"])
            key = content_hash(
                {"project": project_id, "package": group["package"], "aliases": aliases}
            )
            old = self.previous("intel_event", key, project_id)
            fingerprint = content_hash(
                [{k: v for k, v in e.items() if k not in {"fetched_at"}} for e in group["events"]]
            )
            item = {
                "intel_id": key,
                "aliases": aliases,
                "events": group["events"],
                "manifest_hash": manifest_hash,
                "snapshot_id": snapshot_id,
                "fingerprint": fingerprint,
                "observed_at": utcnow(),
                "reachability": "unknown",
            }
            self.store.put("intel_event", key, item, project_id)
            if old.get("fingerprint") != fingerprint and any(
                e["affected_status"] == "affected" for e in group["events"]
            ):
                changed.append(key)
        by_source = {}
        for feed in result.get("feeds", []):
            by_source.setdefault(feed["source"], []).append(feed)
        for source, feeds in by_source.items():
            key = content_hash({"project": project_id, "feed": source})
            old = self.previous("feed", key, project_id)
            fresh = all(f["status"] == "fresh" for f in feeds)
            state = old | {
                "source": source,
                "project_id": project_id,
                "last_attempt_at": utcnow(),
                "last_attempt_epoch": now,
                "status": "fresh"
                if fresh
                else "stale"
                if old.get("last_success_epoch")
                else "unavailable",
                "snapshot_id": snapshot_id,
                "manifest_hash": manifest_hash,
                "inventory_scope": result.get("inventory_scope", "unknown"),
                "inventory_empty": result.get("inventory_empty", False),
                "errors": [f["error"] for f in feeds if f.get("error")],
                "incomplete": result.get("incomplete", []),
            }
            if fresh:
                state |= {
                    "last_success_epoch": now,
                    "fetched_at": max(f["fetched_at"] for f in feeds),
                    "last_success_snapshot_id": snapshot_id,
                }
            state["age_seconds"] = (
                max(0, now - state["last_success_epoch"])
                if state.get("last_success_epoch")
                else None
            )
            self.store.put("feed", key, state, project_id)
        return {
            "mode": "live",
            "snapshot_id": snapshot_id,
            "changed_events": changed,
            "incomplete": result.get("incomplete", []),
            "inventory_empty": result.get("inventory_empty", False),
        }

    async def refresh(self, project, now=None):
        pins, inventory, omitted = self.inventory(project)
        if len(pins) > 100:
            raise DomainError("inventory_limit", "Inventory needs partitioned feed queries", 422)
        try:
            result = await asyncio.wait_for(
                self.gateway.call("/intel", {"pins": pins}), timeout=120
            )
        except (DomainError, TimeoutError) as exc:
            result = {
                "events": [],
                "feeds": [
                    {"source": s, "status": "unavailable", "error": type(exc).__name__}
                    for s in ("osv", "cisa-kev")
                ],
                "incomplete": ["feed_refresh_failed"],
            }
        result["inventory_scope"] = inventory.get("scope", "unknown")
        result["omitted_packages"] = omitted
        return self.ingest(
            project["project_id"], project["source"]["manifest_hash"], result, now=now
        )
