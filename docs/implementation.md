# Implementation plan and completion gates

Read architecture, contracts and runtime first. Preserve the entire recurring lifecycle. Milestones are dependency gates, not claims about how quickly AI-generated code will be reliable. Four lanes can implement behind shared fixtures, then integrate progressively.

## M0 Contract and environment foundation

A creates Python package/lockfile, strict schemas, Typer CLI/operator API skeleton, SQLite migrations and fixture exchange; initialize the React/TypeScript/Vite/Tailwind frontend package and shared generated API types. Freeze command/read-model/action semantics from cli.md and frontend.md before lanes branch. Define exact worker/broker interfaces before independent coding. B detects host architecture and validates sandbox tooling; D verifies a Dafny compiled-call smoke job; A calibrates the GLM Flash model profile; C defines local promotion artifact types. All use the same `RuntimeConfig` and contract package.

Exit: source-only setup fixture and valid/invalid schema fixtures exchange across all four lanes; actual runtime isolation/tool versions are recorded; a missing dependency yields explicit doctor output. A generic claim that Docker is installed is insufficient.

## M1 URL to reproducible target

First target: U03 DSVW; then U01 VAmPI, retaining U02 Vulpy for heldout evaluation. B implements URL resolver, detector, recipe validator, isolated builder, dependency cache, service seed/readiness and manifest generation. A supplies launcher profiles and event storage. C defines consumer-harness promotion for libraries. D supplies baseline tests and negative setup fixtures.

The CLI and frontend can enroll a repo and render real setup/status/error states. Exit: a real public repo URL produces a usable isolated target and frozen manifest; a second clean build works or records nondeterminism. Hostile recipes and missing SaaS config fail explicitly. No build code runs in control plane.

## M2 Detection and intelligence

B implements pinned static tools, OSV matching, KEV enrichment, triage and scoped probes; A integrates timers and case creation. Keep raw and suppressed findings. Implement replay mode separately from live feeds.

Exit: a known affected snapshot produces a reproducible finding; fixed/irrelevant-version controls are handled correctly; advisory replay is labelled; feed failure retains stale provenance; prompt injection cannot authorize an external tool effect.

## M3 Candidate generation and verification

C implements upstream and generated routes, exact patch application, fresh builds and bounded retries. D implements functional/security gates, obligation planner, Dafny and CrossHair adapters, trust-escape checks and artifact binding. C/D implement the separate guided VAmPI compiled-policy profile in vampi-formal-plan.md. Keep the CBMC interface with explicit UNSUPPORTED until the later C/C++ adapter milestone; it is not a dependency of the Python campaign.

Exit: one true generated repair passes meaningful positive/security checks; one official update follows the upstream route; known bad candidates fail; at least one linked formal obligation is actually run; UNKNOWN is never represented as PROVED. All selected obligations, including failures, appear in evidence and the case review page. CLI/UI read the same gate outcomes and cannot rewrite them.

## M4 Deploy recover and repeat

C implements deployment intents/generation locks, stage/observe/promotion, rollback and consumer pointer; A integrates authorization and schedules; B refreshes deployed mirror; D validates the second cycle.

Operator actions (review/reject, pause/resume, cancellation and rollback) obey the same contracts through both clients. Exit: complete URL -> repair -> verification -> authorized lab promotion -> healthy window -> refreshed mirror -> second cycle. Forced bad rollout restores prior artifact and required data behavior. Controller restart between external action and result persistence does not duplicate promotion.

## M5 Campaign and submission evidence

D freezes cohort cases after preflight, runs component benchmark pilots and end-to-end controls, and calculates results. A exports evidence/report with cost and status; B/C fix actual failures and rerun only affected cases with separate revision IDs.

Exit: report has all attempted cases, explicit exclusions, exact source/model/tool versions, proof scope, real timings, costs, intervention counts and three public benchmark families. Missing runs remain unrun. Update the two-page English technical sheet using only measured outcomes. Ten-repo expansion is governed by runtime.md, not assumed to finish during the hackathon.

## Proposed command surface

```text
colossus doctor --profile standard
colossus serve
colossus ui
colossus enroll https://github.com/OWNER/REPO --policy lab_auto
colossus run PROJECT_ID --trigger manual
colossus status PROJECT_ID
colossus approve MANIFEST_HASH --destination DESTINATION_ID
colossus rollback DEPLOYMENT_ID
colossus evaluate evaluation/campaign.lock.json
colossus report RUN_ID --output artifacts/report
```

The full command list, JSON/exit codes, authentication and terminal behavior are in [cli.md](cli.md). These commands are implementation targets, not currently executable. Doctor must check architecture, runtime isolation, network denies, resource enforcement, disk space, tool images, proof tools, model capability/quota, price configuration and destination readiness. Never echo secrets.

## File layout to create

`frontend/` (React/TypeScript/Vite/Tailwind), `src/colossus/cli`, `src/colossus/contracts`, `control`, `gateway`, `sandbox`, `onboarding`, `intel`, `detect`, `repair`, `verify`, `deploy`, `observability`; `tests/contracts`, `tests/integration`, `tests/security`; `evaluation/` manifests and adapters; `fixtures/` development inputs; `scripts/` bootstrap/reproduction. Runtime artifacts and evaluator-only truth live outside model-visible source mounts.

## Final acceptance checklist

- URL onboarding is real and reports unsupported cases honestly.
- Recurrence and mirror freshness work across at least two cycles.
- Upstream and generated fixes are separate result classes.
- All required gates bind to the promoted artifact; no mutable-tag promotion.
- Test-only versus formal-required assurance remains visible.
- Isolation, artifact tampering, prompt injection and restart/rollback failures are exercised.
- Budget reservations and duplicate messages are concurrency-safe.
- Functional behavior is preserved, not just attack disappearance.
- Public benchmarks use declared subsets and independent scoring.
- Reproduction instructions work on the selected host; no implementation claim relies only on mock tests.

Operator acceptance also requires keyboard/mobile review, stale-state and duplicate-action tests, CLI JSON/exit behavior, and no provider secrets in frontend assets. See PRODUCT.md, DESIGN.md and frontend.md; a dashboard against fixtures does not satisfy real runtime gates.
