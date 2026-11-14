# Implementation evidence and remaining work

Active implementation branch: `implementation/full-system`. This file records observed progress, not a reduced definition of the product.

## Evidence recorded

- Remote inspection at implementation start: only `origin/main`; no teammate code branches available yet. Fetch again before integrating major slices.
- Shared contracts and JSON Schema export created, with strict enrollment/patch/evidence types and canonical hashing.
- SQLite controller foundation implements transactional record revisions/audit, operation receipts, leased tasks and atomic cost reservations.
- Content-addressed artifact storage rejects oversized, corrupted and symlink evidence.
- First focused suite: 23 tests pass (contract/source boundaries, idempotency/rollback, cross-connection budget race, unknown charges, expired task results, CAS, artifact tampering).
- Dedicated Colima profile `colossus`: Linux ARM64, 4 CPU, 8 GiB, 40 GiB disk; created with `--mount none --activate=false --port-forwarder none`. Default Docker context left unchanged. Isolation acceptance is pending.
- User template inspected: final English PDF must follow threat/build/evaluation/results/limits structure, maximum two pages, architecture figure, results table and 3–5 references. No invented results.

## Completion ledger

| Requirement | Status / required evidence |
|---|---|
| M0 contracts and shared fixtures | In progress; typed schemas exported, real service RPC and fixture exchange pending |
| Controller scheduling/restart/cancel/outbox | Foundation only; integrated runner and restart/recovery tests pending |
| Operator API/auth and CLI | Not implemented; all documented commands and security gates remain required |
| Tailwind action center | Not implemented; real API data, keyboard/mobile review and screenshots required |
| Source URL resolution and safe archive handling | Not implemented; immutable real snapshot and hostile archive checks required |
| Isolated build/target/worker execution | Dedicated VM created; runtime/network/resource checks pending |
| Stack setup and manifests | Not implemented; DSVW then VAmPI real URL-to-ready path required |
| OSV/KEV/advisory intelligence | Not implemented; live+cached+replay provenance and matching tests required |
| Static/LLM triage and scoped reproduction | Not implemented; actual findings and independent oracles required |
| Broker and global model accounting | Atomic ledger implemented; gateway, live capability and token accounting pending |
| Upstream and generated patch routes | Not implemented; exact protected-path application and actual repairs required |
| Security/functionality/static gates | Not implemented; valid/invalid candidate discrimination required |
| Dafny compiled runtime integration | Not implemented; real proof/compiler/wrapper evidence required |
| CrossHair/unsupported proof outcomes | Not implemented; no counterexample must remain UNKNOWN |
| Policy-bound staging/promotion | Not implemented; exact artifact generation and real canary required |
| Rollback/mirror refresh/second cycle | Not implemented; actual restored behavior and new snapshot required |
| Observability and redacted reports | Audit foundation only; traces, run reports and UI correlation pending |
| CTIBench/CyberSecEval/DafnyBench | Not run; frozen pilots and all outcomes required |
| Repository development/heldout campaign | Not run; all preflight hashes/oracles remain unresolved |
| Agent safety and gate challenges | Foundation boundary tests only; 12 injection and candidate-control campaign pending |
| Final template-based technical sheet | Template inspected; write from actual measured results after implementation |

Full objective remains active. Documentation checks or mocked service tests alone do not satisfy the runtime rows above.
