# Documentation map and decision ownership

Version 1.1 is the implementer handoff. All implementation and duration statements are proposed until measured. The full product is URL onboarding -> recurring discovery -> repair -> verification -> controlled deployment -> recovery -> updated mirror.

| Document | Decision it owns | Implementer |
|---|---|---|
| project-context.md | User intent, resource constraints and decision rationale; read first | All |
| model-strategy.md | Exact model choices, price sources, capability/fallback and provider constraints | A with B/C/D |
| repository-catalog.md | Complete user-supplied 24-repository inventory and evidence status | D |
| vampi-formal-plan.md | Proposed REQ-1..4 and actual compiled-code integration | C/D |
| architecture.md | Components, topology, lifecycle and trust boundaries | All; A integrates |
| contracts.md | Object fields, statuses, API semantics, persistence | A |
| onboarding-sandbox.md | URL intake, recipes, target environments and isolation | B with A runtime support |
| agents-intelligence.md | Intelligence, investigation and patch-generation behavior | B and C |
| verification.md | Specifications, proof adapters and acceptance rules | D |
| deployment-observability.md | Promotion, rollback, events, reports and health | C; A telemetry |
| runtime.md | Units, stage deadlines, recurrence, concurrency and budgets | A |
| implementation.md | Ordered construction steps and acceptance criteria | All |
| integration.md | Worktrees, merges, migrations and integration tests | A/Daniel |
| evaluation.md | Experimental design, denominators and benchmark execution | D |
| repository-cohort.md | Candidate public repos, labels and freeze procedure | D with B/C |
| sessions/README.md | Exclusive file ownership and lane briefs | All |
| value-assessment.md | Motivation and research evidence, not runtime policy | All |
| design-audit.md | Consistency checks and unvalidated assumptions | A/D |
| technical-sheet.md | Two-page submission content; generated from scripts/build_technical_sheet.py | A/D |

Normative order: explicit user instructions > contracts and runtime policy > component specifications > implementation/session guidance > illustrative examples. When a conflict is discovered, resolve it in the owning document and update dependents before merging; do not silently choose one interpretation.

## Fixed technology decisions

Python 3.12 control plane, Pydantic v2 contracts, FastAPI operator API, httpx Mistral client, SQLite WAL task/event store with a single controller writer, content-addressed filesystem evidence, Docker/Compose managed by a dedicated launcher, OpenTelemetry instrumentation. Pin concrete compatible package versions during bootstrap and retain the lockfile. No Redis/PostgreSQL requirement in v1. Adapter interfaces preserve future replacement without introducing two competing implementations now.

Three persistent trusted processes: controller, gateway and sandbox launcher. Deployment is a credential-separated service started when a target is enrolled for promotion; telemetry collector is a separate process. Agents and target tools run as bounded jobs. Local Docker promotion is the required deployment adapter; real production integration is configured separately. The model broker is part of the gateway and the gateway also fetches fixed feed origins, under distinct capabilities.

## Readiness language

“Documented” means a component has inputs, outputs, limits, failure behavior, steps and acceptance criteria. “Implemented” requires working code. “Validated” requires observed test/evaluation evidence. The handoff is documented; no target or runtime is yet validated. Cohort commit hashes and image digests are deliberately populated by the preflight procedure, not invented in this document.

## Start the implementation

The documentation handoff is ready for implementation. Give each session [project context](project-context.md), [model strategy](model-strategy.md), [contracts](contracts.md) and its [lane brief](sessions/README.md). Daniel/session A starts M0 shared scaffolding/contracts; B and D can prepare environment and evaluator fixtures within their ownership. All four branches then start from the same M0 commit. Use [integration gates](integration.md) to combine the modules.

Runtime readiness is earned by M0-M5: the host isolation, actual model/account behavior, target builds/oracles, compiled proofs and deployment recovery have not been executed in this documentation task. Proposed VAmPI business requirements need owner acceptance before formal-required promotion; that does not block constructing the verifier or standard tested flow.
