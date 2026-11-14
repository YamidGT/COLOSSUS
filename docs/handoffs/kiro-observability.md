# Handoff: observability lane (`wip/observability`)

Author: NigrumH0odo, with a coding agent. Base: `kiro/colossus` at `908850e`. Branch: `wip/observability`. Not merged or pushed. Host: Linux x86_64, Python 3.12, uv. No network, provider, model or Docker calls were made. No dependencies were added; OpenTelemetry packages are not used.

Scope follows the Observability section of [deployment-observability.md](../deployment-observability.md) and the Output section of [evaluation.md](../evaluation.md). Ownership: `src/colossus/observability/**`, `tests/observability/**` and this file. `control/store.py` is unchanged and nothing in `control/` calls the new code.

## What exists

- `src/colossus/observability/tracing.py`
  - `Correlation` carries `project_id`, `cycle_id`, `case_id`, `task_id`, `candidate_id`, `deployment_id`. Children inherit the parent's trace ID, sampling decision and correlation. A child may add IDs but cannot change one already set (`ValueError`); unknown keys are refused.
  - `Tracer.span(...)` context manager (contextvars-based current span) and `start`/`end`. Durations come from `time.monotonic_ns`. `endTimeUnixNano` is `start wall time + monotonic duration`, so a wall-clock step cannot make a span negative or longer than it was.
  - `to_otlp` builds an OTLP/JSON `ExportTraceServiceRequest` (`resourceSpans` / `scopeSpans` / `spans`, hex IDs, string nanosecond times, typed attribute values, status codes). Correlation IDs are exported as `colossus.<key>` attributes. All attributes and status messages pass through `redact`.
  - `FileSink` appends one request per line with a byte budget; overflow or I/O errors increment `dropped`. `MemorySink` for tests.
  - `Sampler(ratio)` is a deterministic trace-ID ratio sampler (lower 64 bits of the trace ID).
  - Audit separation: a span started with `audit_kind=` is passed to the `audit` callable (signature of `Store.event(kind, data, project_id, actor)`) on end, before and independently of sampling or sink state. A failing audit writer raises; an audit span with no writer raises. Telemetry loss is counted, audit loss is an error.
- `src/colossus/observability/timing.py`: `stage_timings(store, project_id=None)`. Reads `Store.audit()` (`task.claimed`, `task.completed`) and the `tasks` table through a separate SQLite `mode=ro` connection on the Store's file (the Store has no public task reader, and its own connection is not used for queries). Per task: queue time, each claim, end, success, queue wait, run time of the last attempt, total, retries, and `cold_warm`. `cold_warm` is `cold`/`warm` only when the task payload or result carries `cache_state`/`warm_state` or a boolean `warm`; otherwise `unknown`. All values are wall clock (`clock: "wall"`), and missing values are `null`. Per-stage aggregates: count, completed, retried, cold/warm/unknown, median/max queue and run seconds with sample counts.
- `src/colossus/observability/report.py`: `build_run_report(store, project_id, *, versions, exclusions, run_id, generated_at)`, `render_markdown(report)`, `verify_report_hash(report)`.
  - Reads `cycle`, `case`, `gate`, `candidate`, `model_call` records via `Store.list` (paginated), `Store.budget(case_id)`, `Store.audit(project_id)` and `stage_timings`.
  - Every case record is listed. Exclusions must name an attempted case and give a reason; excluded cases stay listed with `excluded: true` and the reason. An exclusion for an unknown case or without a reason raises.
  - Versions: caller-declared `source_repository`, `source_revision`, `implementation_revision` (plus any extra keys). Absent or empty ones are `null` and listed in `versions.missing`. Model versions (provider, requested, returned, template, profile hash, price snapshot) and tool versions (`check_profile_id`, `tool_version`) are collected from records.
  - Proof scope: one row per obligation per formal gate (`GateResult.scope`), plus a row with `UNKNOWN` / "no formal gate result recorded" for any `case.obligation_ids` entry without a gate. `counts_as_pass` is true only for `status == "pass"` and `PROVED`/`BOUNDED_PASS`. Markdown shows `PASS (PROVED)` or `UNKNOWN (not a pass)`. A missing case formal summary renders as `UNKNOWN`.
  - Costs in integer micro-USD per call: reserved, actual (`null` when unreconciled) and `uncertain`. Totals: `settled_micro_usd` (known charges), `uncertain_reserved_micro_usd`, and `actual_total_micro_usd`, which is `null` whenever any call is uncertain. Token counts are under `usage: {unit, input, output}` because `redact` masks any key containing `token`.
  - Timings: cycle and gate elapsed seconds from their recorded `started_at`/`finished_at`, model call `elapsed_seconds`, and stage timings. Nothing is estimated.
  - Interventions: `manual_intervention_count` per case from a `manual_interventions` list or nonnegative int on the case record, `null` when absent. The summary total is `null` if any case has no record, with the count of unrecorded cases. `operator_operations` counts `operation.accepted` audit events whose actor is not `controller`; it is reported separately and not merged into interventions.
  - Evaluator boundary: records with `evaluator_only: true`, `visibility` in `evaluator`/`evaluator_only`/`gold`, or `trust_boundary: "evaluator"` are withheld; only `withheld_evaluator_records` is reported. Fields such as `gold_patch`, `expected_outcome`, `ground_truth`, `oracle_truth` are dropped from all records. Prompt/response content fields (`messages`, `prompt`, `response_content`, ...) become `[omitted]`.
  - The whole report passes through `redact`, then `report_hash = content_hash(report)` over canonical JSON. Records are sorted by `(created_at, id)` so the same Store and arguments give the same JSON, hash and Markdown. `generated_at` is caller-supplied and part of the hash.
  - Markdown escapes `|`, backticks, `<`/`>`, collapses newlines and truncates cells at 300 characters.
- `src/colossus/observability/redact.py`: API unchanged (`redact`, `redact_text`, `span`). Added text patterns for `Bearer <token>`, GitHub (`ghp_`/`gho_`/... and `github_pat_`), Groq-style `gsk_`, AWS `AKIA...` and Slack `xox?-` tokens. Before this, `Authorization: Bearer ghp_...` in free text left the token in place (only the word `Bearer` was replaced).

## Wired vs not wired

- NOT WIRED: no controller code creates spans, no `FileSink` path is configured, and no OTLP collector export exists. Suggested wiring for the controller owner:
  1. Build one `Tracer(FileSink(<state_dir>/telemetry/spans.jsonl, max_bytes=...), sampler=Sampler(<config ratio>), audit=store.event)` at controller start.
  2. Wrap `CycleRunner.run`, each case, each `launcher` call and each broker model call in `tracer.span(...)` with the IDs available there. Use `audit_kind=` only where an audit event is required and not already written by the Store (authority decisions, deployment swap/rollback). The Store's own `task.*`, `operation.*`, `budget.*` events stay the unsampled record; spans do not replace them.
  3. Worker processes should create spans with an explicit `parent` built from the task payload's trace/span IDs; cross-process context propagation (W3C `traceparent`) is not implemented.
- NOT WIRED: no CLI command or API route calls `build_run_report` or `stage_timings`. The report needs a `versions` dict from the caller (source repository/revision from the onboarding manifest, implementation revision from git). An endpoint should pass a fixed `generated_at` and store the JSON/Markdown as evidence.
- NOT WIRED: `cold_warm` is `unknown` for every real task today because no task payload sets `cache_state`. The worker/sandbox owner needs to set it.
- NOT WIRED: no case record sets `manual_interventions` or `obligation_ids` today, so real reports show interventions as `null` and only obligations named in formal gate scopes.
- Not implemented: metrics (CPU/RAM/disk, queue age gauges, feed age), logs signal, OTLP/HTTP export, W3C trace context, retention of the telemetry file, a sampler config key, results CSV/plots and per-row benchmark fields from evaluation.md (split, seed, source-view hash, known-reference flags); those belong to the evaluation runner.

## Limitations

- Stage timings use controller wall-clock timestamps (`tasks.created_at` is `time.time()`, audit times are ISO UTC). `run_seconds` covers the last attempt only. `task.completed` events carry no `project_id`, so tasks are scoped through the `tasks` table.
- `stage_timings` requires a file-backed Store (it reopens the file read-only).
- The evaluator boundary is a filter on known markers. It cannot recognise gold content stored under other field names; evaluator truth should stay out of the controller Store entirely.
- `redact` is pattern-based; unprefixed provider keys (for example a bare 32-character key) in free text are not detected unless next to a key name such as `api_key=`.

## Commands and observed results

```
export UV_PROJECT_ENVIRONMENT=$PWD/.uvenv
uv sync -q --python 3.12 --all-extras
  -> (no output, exit 0)
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt tests/observability
  -> 18 passed in 1.80s
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt tests/observability tests/security
  -> 112 passed, 20 skipped in 3.28s
uv run pytest -q -p no:cacheprovider -m 'not gvisor' --basetemp=$PWD/.pt
  -> 314 passed, 20 deselected, 1 warning in 19.61s
uv run ruff check src tests
  -> All checks passed!
python3 scripts/check_design_docs.py
  -> PASS: 31 required handoff files, local links/code fences, JSON examples, 10 candidate records and runtime accounting.
```

The 18 tests in `tests/observability/` use a temporary `Store` populated through `put`, `reserve`, `reconcile`, `enqueue`, `claim`, `complete_task` and `mutate`, and real `GateResult` models. They cover: correlation propagation across three span levels and into OTLP attributes; refusal to rewrite a correlation ID; monotonic duration under a backwards wall-clock step; ratio 0 sampling with every audit span still in `audit_events` and `verify_audit()` true; a full sink dropping telemetry but not audit; an audit span without a writer failing; OTLP JSON lines with error status and redacted attributes; deterministic sampling; stage timing for completed/running tasks, cold/warm/unknown, retries, and that `stage_timings` leaves the database bytes and audit count unchanged; all attempted cases listed with explicit exclusions and invalid exclusions refused; UNKNOWN (timeout gate and missing gate) never counted or rendered as a pass; an unreconciled cost staying `null` with the total `null` and `uncertain`; secrets (`sk-`, `ghp_` behind `Bearer`), gold fields, evaluator-only records and prompt bodies absent from JSON and Markdown; versions, missing versions, timings and intervention counts; same input giving equal reports, hashes and Markdown, with tampering detected; Markdown escaping of hostile text.
