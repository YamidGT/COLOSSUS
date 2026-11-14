# CLI contract and implementation plan

Owner A. Implement `colossus` as a thin Python [Typer](https://typer.tiangolo.com/) CLI backed by httpx and the operator API. Optional Rich output is only for interactive terminals. No command runs target code, accesses SQLite directly or calls a provider outside the gateway. Pin compatible dependency versions in M0. Commands below are design targets, not currently executable.

## User-facing commands

| Command | Behavior |
|---|---|
| `colossus doctor [--profile standard]` | Readiness checks; local static checks can run before services. Explicit `--check-model` permits the small paid capability check. Show absent/invalid credentials by provider name only. |
| `colossus serve [--host 127.0.0.1] [--port 8787]` | Foreground local service supervisor/API/static frontend. Non-loopback binding rejected in v1. Separate trusted child environments; model keys only in gateway. |
| `colossus ui [--no-open]` | Obtain one-use browser login code through host-authenticated API and open/print the local UI address; do not put credentials in URL. |
| `colossus enroll URL [--ref REF] [--subdir PATH] [--policy lab_auto\|review] [--assurance tested\|formal_required] [--requirements PROFILE] [--run]` | Create project/setup, return IDs. `--run` queues exactly one cycle after readiness. Approved requirement profile required for formal-required mode. |
| `colossus projects` | List projects, state and attention count; no target content execution. |
| `colossus run PROJECT_ID [--trigger manual] [--watch]` | Request one cycle. `--watch` follows accepted operation to terminal status. |
| `colossus status PROJECT_ID [--watch]` | Read setup, cycle, deployment, mirror, limits and action summary. |
| `colossus actions PROJECT_ID` | List attention items with IDs, reason, permitted action and case link. |
| `colossus case CASE_ID [--diff]` | Inspect finding, candidate, gate/proof scope and exact manifest; render escaped/bounded text. |
| `colossus approve MANIFEST_HASH --destination DESTINATION_ID [--yes]` | Fetch current decision context, confirm exact artifact/destination/generation, then submit authorization. Gates cannot be overridden. |
| `colossus reject CASE_ID --candidate CANDIDATE_ID --reason TEXT` | Reject the current review candidate; record reason and expected revision. |
| `colossus rollback DEPLOYMENT_ID [--yes]` | Inspect retained prior artifact/data policy, confirm, request bounded recovery with expected generation. |
| `colossus pause PROJECT_ID` / `colossus resume PROJECT_ID` | Change admission state; do not kill an active cycle. |
| `colossus cancel CYCLE_ID [--yes]` | Request termination/reconciliation; report CANCEL_REQUESTED until observed completion. |
| `colossus retry-setup PROJECT_ID` | Retry eligible failed setup with same config/source intent; retain earlier attempt. |
| `colossus configure PROJECT_ID --file PATH` | Submit a strict versioned configuration amendment for revision/subdir/approved profiles; reject arbitrary commands, secrets or policy bypasses. |
| `colossus report RUN_ID --output PATH` | Download the redacted report/export; default refuses overwrite. `--force` replaces only requested output. |
| `colossus evaluate MANIFEST_PATH [--watch]` | Submit a frozen campaign manifest for server-side validation and bounded execution; candidate-only roster is rejected. |

Global flags: `--api-url` (loopback or configured SSH tunnel), `--json`, `--no-color`, `--timeout SECONDS`, `--idempotency-key KEY` for mutations. Resolve API URL from flag > `COLOSSUS_API_URL` > localhost default. An operator token is read from a permission-restricted host config file or `COLOSSUS_OPERATOR_TOKEN`; never accept it as a positional argument. No provider-key flags. `.env` is host runtime configuration, not a CLI log/export artifact.

## Interaction and automation semantics

Default mutating commands return immediately with project/cycle/operation IDs and the action-center link. HTTP acceptance is not task success. `--watch` polls the shared snapshot, shows stages rather than fake percentages, and ends on terminal outcome. Ctrl-C detaches and exits 130; cancellation requires `cancel`. Watch timeout returns a timeout result with IDs so the user can reconnect. Diagnostics go to stderr; JSON stdout contains one object at completion, without progress output.

TTY approve/rollback/cancel shows consequence and asks once. `--yes` accepts that confirmation for scripts, but never bypasses policy, hashes, freshness or authorization. Non-TTY commands requiring confirmation fail with a useful error unless `--yes` is supplied. Enrollment/run follow chosen lab policy without additional confirmations. HTTP retries reuse the idempotency key and identical request body; a client must not generate a new key merely because the response was lost.

Exit codes: 0 = request accepted/read completed or watched run succeeded; 2 = invalid input/usage; 3 = readiness/auth/policy/gate precondition blocks action; 4 = watched work ended unsuccessfully (including cancelled/rejected/budget-stop); 5 = transport/server error; 6 = watch deadline expired with operation unresolved; 130 = interrupted watcher. A JSON envelope `{schema_version,ok,operation_id,project_id,cycle_id,status,reason_code,message,action_url,data}` uses null for inapplicable IDs. `ok` denotes the command's stated result, never blanket security success.

Human output example (illustrative IDs and figures only):

```text
VAmPI  /  cycle c_example
Verifying patch    elapsed 08:32    model cost $0.03
Security: pass     Functional: pass     Formal: unknown (optional)
Lab version: previous artifact retained
Next: review evidence at http://127.0.0.1:8787/projects/p_example
```

## Lifecycle and setup

`serve` starts controller, gateway, launcher and telemetry through trusted configured entrypoints and later the deployer when needed. It never starts arbitrary target scripts on the host. Handle SIGTERM with bounded drain/cancel/recovery; persist unresolved work before exit. Platform installation/runtime prerequisites and source tool images are set by M0/doctor, not silently installed from repository instructions. On Oracle use SSH port forwarding, then point the local CLI/browser at the forwarded endpoint.

## Build steps and acceptance

1. A freezes command arguments, error/JSON envelope and API fixtures with B/C/D.
2. Implement API/auth client, idempotency and bounded retry, then doctor/service lifecycle.
3. Implement enrollment/status/run/report; add actions/review/approval/recovery and pause/cancel.
4. Render terminal-safe output (strip control/ANSI sequences from target text), preserve machine-readable JSON and redact secrets.
5. D tests pipe/TTY modes, duplicate requests, stale approvals, interrupted watches and service restart. Exercise a real URL-to-second-cycle flow through CLI and verify matching API/audit evidence. Completion requires meaningful behavior, not one test per parser flag.
