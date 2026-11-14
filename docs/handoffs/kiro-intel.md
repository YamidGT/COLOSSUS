# Handoff: threat intelligence lane (`wip/intel`)

Author: NigrumH0odo, with a coding agent. Base: `kiro/colossus` at `2f58b22`. Branch: `wip/intel`. Not merged anywhere. Host: Linux x86_64, Python 3.12.13, uv 0.12.17. No network, provider or Docker calls were made.

## What exists

`src/colossus/intel/` implements the fetch-cache, validate, normalize, match and label steps of the pipeline in [agents-intelligence.md](../agents-intelligence.md). The shared `IntelEvent` contract in `src/colossus/contracts/models.py` is used unchanged. Because `IntelEvent` is per dependency (it carries package, version and affected_status), feed records are first parsed into strict lane-local models (`intel/models.py`: `Advisory`, `KevCatalog`, `Provenance`) and become `IntelEvent` only when joined with a dependency.

- `parsers.py`: OSV records (single object, list, or `{"vulns": [...]}`) and the CISA KEV catalog. Size limits (OSV 8 MiB / 10,000 records, KEV 16 MiB / 50,000), nesting depth 32, duplicate JSON keys and NaN rejected, strict types, timestamps checked. Any bad record rejects the whole document with `invalid_feed` or `feed_limit`. Severity keeps the official vector, preferring CVSS_V4, then V3, then V2, with `severity_source` `osv:<type>` or `unavailable`.
- `versions.py`: stdlib PEP 440 and SemVer 2.0 ordering. Unorderable strings return `None`.
- `matching.py`: OSV `ECOSYSTEM` (PyPI) and `SEMVER` ranges with `introduced`, `fixed`, `last_affected` (inclusive), and `limit` (ignored). Unorderable dependency or event versions, unsupported ecosystems and GIT-only ranges give `unknown`, never `not_affected`. GIT ranges are skipped when a version-ordered range exists. `match_inventory` joins `DependencyEntry` records with advisories, merges advisories that share an id or alias for the same package, keeps conflicting statuses in `conflicts` (the most conservative status wins), and sets `kev_status` to True when listed, False only when the KEV feed is fresh, otherwise None. It refuses to join replay and live intel (`mixed_intel_modes`). Each `IntelMatch` carries the `IntelEvent`, `advisory_ids`, `severity_origin`, `feed_stale` and stale reasons for downstream Finding creation.
- `cache.py`: `FeedCache` keeps the latest validated content, its provenance (`raw_content_id`, `raw_content_hash`, `fetched_at`, `source_url`) and the last 50 fetch attempts. A feed is stale when older than 2x the poll period (default 15 min, so 1800 s) or when a fetch failed after the last success. A failure keeps the previous data and reports the reason. Malformed content is recorded as a failure and does not replace the cache. `export_snapshot` / `from_snapshot` / `load_replay` freeze and reload feeds; a replay cache is read-only and every advisory, KEV catalog and `IntelEvent` from it has `replay=True`. Snapshot hashes are re-checked on load.
- `fetcher.py`: `FeedFetcher` protocol (`fetch_feed(feed_id, cursor)`, matching docs/contracts.md) and `refresh()`, which records every failure.

## Wired vs not wired

- NOT WIRED: `GatewayFeedFetcher`. `colossus.gateway.server` only has `/health`, `/source` and `/complete`, so this stub always raises `feed_not_wired` and the cache records the failure. The gateway owner needs to add the feed route (with source allowlist, size limits and rate limits).
- NOT WIRED: nothing in control/detection calls `intel` yet. There is no scheduled 15-minute poll, no SQLite persistence of the cache (the controller's `feed` list in `control/service.py` is not filled from here), and no Finding creation from `IntelMatch`.
- Not implemented: OSV batch query (IDs then full records), GitHub advisory direct lookup, EPSS, NVD, non-PyPI `ECOSYSTEM` ordering, extracting the dependency inventory from lock files.

## Commands and observed results

```
export UV_PROJECT_ENVIRONMENT=$PWD/.uvenv
uv sync -q --python 3.12 --all-extras
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt tests/intel
  -> 71 passed in 0.55s
uv run pytest -q -p no:cacheprovider -m 'not gvisor' --basetemp=$PWD/.pt
  -> 202 passed, 10 deselected, 1 warning in 4.42s
uv run ruff check src tests
  -> All checks passed!
python3 scripts/check_design_docs.py
  -> PASS: 31 required handoff files, ...
```

Tests in `tests/intel/` use the synthetic fixtures in `fixtures/intel/` and patch out socket connects. They cover: fixed version not affected, introduced-before not affected, the inclusive last_affected boundary, PEP 440 vs lexical ordering, unknown versions staying unknown, GIT-only and unorderable ranges, SemVer prereleases, alias deduplication with preserved conflict, KEV absence semantics, stale detection at 2x poll, failure keeping stale provenance, malformed upstream content, the not-wired gateway fetcher, replay labelling and read-only replay, tampered snapshots, mixed replay/live refusal, and hostile JSON (oversized, deep nesting, duplicate keys, NaN, wrong types).
