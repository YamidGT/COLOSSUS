# Handoff: operator CLI on `wip/cli`

Author: NigrumH0odo, with a coding agent. Base: `kiro/colossus` at `2f58b22`. Scope: the commands in [cli.md](../cli.md), built against the routes that `src/colossus/control/api.py` serves today. No API, controller or contract changes. `doctor` and `src/colossus/cli/doctor.py` are unchanged.

## What changed

- `src/colossus/cli/client.py`: `ApiClient` over httpx. Bearer token from `COLOSSUS_OPERATOR_TOKEN` or `<data_dir>/operator.token` (symlinks refused), never printed. `--api-url` must be a loopback http(s) origin without path or credentials, so the token cannot be sent to a remote host (use an SSH tunnel). One `Idempotency-Key` per mutation (`--idempotency-key` wins); transport errors and 502/503/504 are retried up to 3 attempts with the same key and the same body. Exit mapping: 401/403/409 -> 3, 400/404/422 -> 2, other errors and transport -> 5. Route capability check reads `GET /api/v1/openapi.json`; a missing route exits 3 with "not available on this server". If the schema cannot be read, a 405 or the JSON "API route not found" 404 also exits 3.
- `src/colossus/cli/render.py`: JSON envelope `{schema_version,ok,operation_id,project_id,cycle_id,status,reason_code,message,action_url,data}`; human output strips ANSI (CSI/OSC/DCS, 7- and 8-bit), C0/C1 controls (except newline/tab), Unicode format characters (bidi overrides) and bounds text length; the token is redacted from any output. Diagnostics and watch progress go to stderr; with `--json` stdout holds exactly one object. Errors print to stderr in human mode.
- `src/colossus/cli/main.py`: `ui`, `enroll`, `projects` (follows cursors, max 50 pages of 100), `status [--watch]`, `actions`, `case [--diff]`, `run [--watch]`, `pause`, `resume`, `retry-setup`, `cancel [--yes]` (status `CANCEL_REQUESTED`), `configure --file`, `approve MANIFEST_HASH --destination [--yes]`, `reject --candidate --reason`, `rollback [--yes]`, `report --output [--force]`, `evaluate [--watch]`. `serve` and `doctor` are as before.
- Watching polls `GET /cycles/{id}` (or `GET /operations/{id}` for `evaluate`) every 2 s until a terminal status. Successful cycle outcomes (COMPLETE, NO_FINDINGS, NO_CHANGE) exit 0; other terminal outcomes exit 4; the new `--deadline SECONDS` option (default 1800) exits 6 with the IDs; Ctrl-C exits 130 and never calls cancel.
- Confirmation: `cancel`, `approve`, `rollback` ask once on a TTY (stderr prompt, default no; "no" exits 3 and sends nothing). Without a TTY they need `--yes`, otherwise exit 2 before any request. `--yes` skips only the prompt.
- `report` refuses an existing output without `--force` (exit 2, no request), refuses directories and symlinks, and writes through a temp file plus `os.replace`.
- `configure` validates the file locally: JSON object, only `ProjectConfigAmendment` fields, integer `expected_revision`; anything else exits 2.

## Commands blocked by missing routes (exit 3 today)

| Command | Route needed (not in api.py) |
|---|---|
| `case --diff` | GET `/cases/{id}/diff` |
| `approve` | POST `/authorizations` (and a decision-context lookup by manifest hash) |
| `reject` | POST `/cases/{id}/decisions` |
| `rollback` | GET `/deployments/{id}`, POST `/deployments/{id}/rollback` |
| `configure` | POST `/projects/{id}/configuration` |
| `evaluate` | POST `/evaluations` |

The request bodies these commands send are the CLI's reading of [contracts.md](../contracts.md): `approve` sends `{evidence_manifest_hash, destination_id}`; `reject` sends `ReviewDecision` with `expected_revision` from `GET /cases/{id}`; `rollback` sends `{expected_generation}` from the deployment; `configure` sends the amendment file; `evaluate` sends the manifest object. Session A should confirm or correct these shapes when the routes land. The CLI picks the routes up automatically once they appear in the OpenAPI schema.

## Tests

`tests/cli/test_cli_client.py` (httpx MockTransport) and `tests/cli/test_cli_api.py` (FastAPI TestClient over `create_app(..., execute_tasks=False)`), 43 tests: key and body reuse across transport retries, explicit key, retry exhaustion -> 5, status-to-exit mapping (401/403/409/422/404/500/503), stale 409 -> 3, idempotency conflict -> 3 and ineligible run -> 3 against the real API, non-loopback URL refused before any request, control-character and token stripping in output and error messages, envelope keys, watch deadline -> 6, terminal outcomes 0/4, Ctrl-C -> 130 without a cancel request, `status --watch`, report overwrite/symlink refusal and `--force`, non-TTY without `--yes` -> 2, TTY yes/no, missing routes -> 3 (schema path and 405 fallback), local validation for `approve` and `configure`, cursor pagination, enroll/status/projects/actions/pause/resume round trip.

Commands run in the worktree (`UV_PROJECT_ENVIRONMENT=$PWD/.uvenv`):

- `uv run pytest -q -p no:cacheprovider -m 'not gvisor' --basetemp=$PWD/.pt` -> `174 passed, 10 deselected, 1 warning`
- `uv run ruff check src tests` -> `All checks passed!`
- `python3 scripts/check_design_docs.py` -> `PASS: 31 required handoff files, ...`

## Remaining work and caveats

- No end-to-end URL-to-second-cycle run through the CLI; that needs a live worker and sandbox (cli.md step 5).
- `status --watch` follows the active cycle via `/cycles/{id}`; it does not use the snapshot ETag yet.
- `--no-color` only affects the Rich console that `doctor` uses; other output is plain text.
- Exit codes for 404 (2) and a declined prompt (3) are choices cli.md does not specify.
- `.uvenv/` and `.pt/` are not in `.gitignore` (outside this lane's ownership); do not stage them.
