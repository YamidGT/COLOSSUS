# Implementation evidence and remaining work

Active implementation branch: `implementation/full-system`. This file records observed progress, not a reduced definition of the product.

## Evidence recorded

- Remote inspection at implementation start: only `origin/main`; no teammate code branches available yet. Fetch again before integrating major slices.
- Shared contracts and JSON Schema export created, with strict enrollment/patch/evidence types and canonical hashing.
- SQLite controller foundation implements transactional record revisions/audit, operation receipts, leased tasks and atomic cost reservations.
- Content-addressed artifact storage rejects oversized, corrupted and symlink evidence.
- First focused suite: 23 tests pass (contract/source boundaries, idempotency/rollback, cross-connection budget race, unknown charges, expired task results, CAS, artifact tampering).
- Dedicated Colima profile `colossus`: Linux ARM64, 4 CPU, 8 GiB, 40 GiB disk; created with `--mount none --activate=false --port-forwarder none`. Default Docker context left unchanged. The first gVisor isolation probe passed; wider cross-case and cancellation checks remain pending.
- User template inspected: final English PDF must follow threat/build/evaluation/results/limits structure, maximum two pages, architecture figure, results table and 3–5 references. No invented results.

## Completion ledger

| Requirement | Status / required evidence |
|---|---|
| M0 contracts and shared fixtures | In progress; typed schemas exported, real service RPC and fixture exchange pending |
| Controller scheduling/restart/cancel/outbox | Foundation only; integrated runner and restart/recovery tests pending |
| Operator API/auth and CLI | Core authenticated intents/read models implemented; decision/configuration/evaluation commands remain pending |
| Tailwind action center | Implemented on real API data; desktop login/list/project/case inspected. Mobile, keyboard, full decision flow and accessibility acceptance remain |
| Source URL resolution and safe archive handling | Validated immutable DSVW snapshot and hostile archive rejection; broader GitHub error/size scenarios remain |
| Isolated build/target/worker execution | gVisor jobs and COPY-only immutable target packaging validated; broader lifecycle/network challenges pending |
| Stack setup and manifests | DSVW URL-to-ready manifest validated; additional stack adapters remain implementation work; do not run other repos yet |
| OSV/KEV/advisory intelligence | Gateway adapters integrated from lane B; controller polling, cache/replay and recurrence pending |
| Static/LLM triage and scoped reproduction | DSVW AST/rule detection and protected reproduction validated; generic triage/probe adapters integrated but broader coverage unmeasured |
| Broker and global model accounting | Separate gateway and actual Mistral capability/accounting validated; refusal/retry scenarios need broader coverage |
| Upstream and generated patch routes | Generated exact-span DSVW repair validated; upstream-update route remains pending |
| Security/functionality/static gates | One DSVW candidate passed protected positive and security checks plus AST regression checks; broader mutation controls pending |
| Dafny compiled runtime integration | Not implemented; real proof/compiler/wrapper evidence required |
| CrossHair/unsupported proof outcomes | Not implemented; no counterexample must remain UNKNOWN |
| Policy-bound staging/promotion | DSVW replay passed exact-artifact promotion and real 300-second observation; fresh model full-cycle acceptance remains |
| Rollback/mirror refresh/second cycle | DSVW replay passed mirror refresh, second NO_CHANGE cycle and rollback (10.397 s); restart/fault scenarios remain |
| Observability and redacted reports | Audit foundation only; traces, run reports and UI correlation pending |
| CTIBench/CyberSecEval/DafnyBench | Not run; frozen pilots and all outcomes required |
| Repository development/heldout campaign | Not run; all preflight hashes/oracles remain unresolved |
| Agent safety and gate challenges | Foundation boundary tests only; 12 injection and candidate-control campaign pending |
| Final template-based technical sheet | Template inspected; write from actual measured results after implementation |

Full objective remains active. Documentation checks or mocked service tests alone do not satisfy the runtime rows above.

## Second implementation slice

- 36 focused tests pass: authenticated API/source archive checks added to the foundation suite.
- Operator API now supports authenticated enrollment/status/actions, durable run/pause/resume/cancel/retry intents, reports, single-use login codes and CSRF-protected browser sessions. Execution task dispatch is still pending.
- Typer CLI entrypoint and initial operator commands are runnable; doctor explicitly reports unfinished pipeline/runtime preflight rather than claiming readiness. Remaining decision/evaluation commands are pending.
- Source resolver downloads exact GitHub commit archives without clone hooks; archive tests reject escapes, symlinks, devices and duplicate paths.
- gVisor release-20261109.0 installed in dedicated VM. Actual sandbox isolation job passed: uid 1000, gVisor kernel, external connection denied, host home/socket/provider keys absent and root filesystem read-only. Evidence: local artifacts/bootstrap/sandbox-isolation.json.
- The launcher uses digest-pinned Python image, bounded output/time, isolated networks, resource caps, labels/TTL and source transfer within gVisor. Full multi-container/egress/cancellation tests are still required.

## Updated execution scope from Daniel

Only DSVW (the smallest repository) is authorized for runtime validation during this implementation phase. Do not run the multi-repository benchmark campaign or other targets without a subsequent scope change. Continue implementing the broader product and evaluator adapters; distinguish implemented tooling from campaigns actually run. Check remote branches recurrently; Daniel does not yet know teammate branch names.

The real service calibration passed: immutable DSVW intake and sandbox compilation succeeded; Mistral returned `zai-glm-5-3-flash`, 36 input / 8 output tokens, 10 micro-USD settled. This is a capability/accounting check, not coding quality evidence.

## First real repair evidence

`uv run python scripts/check_repair.py` completed one DSVW case on commit `9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908` (only repository exercised). Warm elapsed time: **19.287 seconds**, including URL setup and candidate verification. One `zai-glm-5-3-flash` call, **1,273 micro-USD ($0.001273)** settled. The original bounded SQL expression probe reproduced; the generated patch passed scope/base, baseline reproduction, build/readiness, security, positive functionality, static regression and artifact-binding gates. Formal outcome was explicitly **UNSUPPORTED / not applicable** for the tested profile. The case stopped at REVIEW_READY; no deployment, rollback or full recurring cycle is claimed. Raw evidence is local `artifacts/bootstrap/repair.json` and content-addressed controller evidence.

Focused test suite: **47 passed**. This includes rejection of protected-path edits, ambiguous replacements, missing/failed gates and incompatible proof assurance. The static adapter currently uses three explicit Python AST rules, not Semgrep or Bandit; its narrow coverage is included in the evidence manifest. The candidate's unrelated findings remain unresolved.

The API now has worker dispatch wiring, leases/heartbeats, explicit cancellation termination and restart reconciliation code. These paths still need live API/restart tests before being called validated. A supervisor lock prevents competing service owners, and trusted child processes exit after parent death. Runtime job TTLs remain the independent fallback.

No teammate branches were present at the latest remote fetch. Continue fetching before integration; do not merge an unknown branch without inspecting its ownership, contracts and checks.

## Operator dispatch validation

`uv run python scripts/check_operator_api.py` passed against a real temporary API process: authenticated enrollment dispatched setup through the worker, DSVW reached READY, the durable operation reached succeeded, and a new cycle was rejected while paused. This calibration made no model calls and tore down its target afterward. The focused suite is now **49 passed**; pause-aware task admission and cross-case gate-reuse rejection were added. Restart/cancel fault-injection remains unvalidated.

Timing correction: subsequent gate reports record the actual check/bundle intervals; the initial repair calibration's per-gate timestamps were issuance timestamps, so use its measured whole-run 19.287 seconds only, not those initial per-gate fields for stage latency.

## Full lifecycle and action center checkpoint

Daniel authorized merging into `main` only when the full implementation is ready. Keep implementation on its branch until the remaining acceptance gates pass. The first and only target under test is **https://github.com/stamparm/DSVW**, pinned to `9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908`. No multi-repository campaign is authorized in this phase.

The DSVW **replayed-proposal** lifecycle completed on 2026-11-14: URL intake, fresh verification, promotion, actual 300-second observation and mirror refresh took **332.771 seconds**. The second cycle returned **NO_CHANGE** (no further supported repair, not absence of vulnerabilities). Rollback to the explicitly known-vulnerable retained baseline plus refresh took **10.397 seconds**. The audit chain validated. This replay made zero new model calls; the reused proposal came from the earlier $0.001273 generation. Two fresh lifecycle attempts stopped safely before promotion on an invalid provider response and HTTP 429. No fresh-inference end-to-end success or formal proof is claimed. Local evidence: `artifacts/bootstrap/full-cycle.json`.

An earlier replay exposed a deployment/authorization ID collision after the observation window. Independent deployment IDs and a controller-store regression check fixed it. Retirement now withdraws routing and clears current/previous slots when calibration targets are removed. The private lab front door is an authenticated request gateway, not public production traffic routing.

The React/Tailwind action center uses generated OpenAPI types and real controller data. Browser inspection verified local code exchange, repository navigation, project findings and case gate/replay/unsupported-proof labels. It found operator evidence visibility metadata missing; the fix explicitly publishes check/diff evidence while source archives remain internal. Backend tests cover project isolation and private evidence denial. Browser mobile/keyboard/decision-flow acceptance is still pending. Initial apparent blank rendering resolved before login; no application JavaScript error was observed beyond the expected unauthenticated session 401.

Current validation: **74 backend tests pass**; TypeScript/Vite production build passes, initial JavaScript **89.17 kB gzip**. Pause does not block queued rollback recovery. These are platform tests, not a benchmark score or a run against additional repositories.


## Integrated runtime hardening checkpoint

`origin/kiro/integracion-fs` merged into the implementation branch with its doctor and Docker-create safety guard, while preserving the stricter existing recipe validator. The doctor reads credential-file metadata only. Combined backend suite: **113 passed**; Ruff passes. A fresh real gVisor isolation check also passed after private IPC and create-flag validation were enabled. No extra target repository was run.

The six finished DSVW calibration enrollments now show **RETIRED** deployment summaries. Cleanup discovered Docker 29 reports missing objects in lowercase; idempotent teardown now handles both message cases while still failing on daemon errors. Existing diff/gate artifact publication metadata was corrected through audited store writes; source archives remain private. Follow-up browser inspection successfully loaded the actual source diff and verified the case layout at 375px. Broader UI acceptance remains pending.

Checkpoint pushed to `origin/implementation/full-system`; `origin/main` remains unchanged. Remaining full-scope work includes scheduled feed refresh/recurrence, broader setup and patch adapters, linked formal verification, benchmark runners, failure/restart acceptance, final interface acceptance and the template-based technical sheet.
