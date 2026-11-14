# COLOSSUS: project context and decision record

Read this first when joining an implementation session. Owner: Daniel / session A. Updated 14 November 2026, documentation revision 1.1. This records the user's intent, evidence and design rationale; component documents own detailed contracts. It is a handoff, not evidence that the system has been built.

## What Daniel wants

A recurring automated cyberdefence system: submit a public GitHub repository URL; discover its stack; construct an isolated runnable copy; inspect code and dependencies; ingest current vulnerability intelligence; confirm findings locally; choose an official remediation or generate a patch; verify security and legitimate behavior; apply formal methods where justified; deploy under a previously selected autonomy policy; observe health and recover on failure; refresh the mirror and repeat. Each action must be observable and attributable to immutable inputs.

The original concept included red-team, patcher, verifier and orchestration roles, cheap frequent checks and more expensive escalations, a safe running copy, recent vulnerability feeds, permission policies, logs, independent metrics and attacks against the agents themselves. Those are retained. Runtime agents and the four coding sessions are different concepts.

Daniel explicitly rejected replacing this idea with a payment application or a verification-only demonstration. Do not reintroduce that substitution. Repository examples and staged implementation priorities are evaluation choices, not the definition of the product. Plug-and-play means automatic supported onboarding with explicit unsupported/setup-failed states; it cannot honestly mean every arbitrary repository builds or receives a mathematical proof without requirements.

## Resources and deliverables

- Team of four, each allowed to use coding agents. Daniel owns integration/session A; B owns onboarding/intelligence/detection, C repair/deployment, D verification/evaluation. See [ownership](sessions/README.md) and [merging runbook](integration.md).
- USD 150 Mistral credit at `https://api.mistral.ai/v1`. USD 120 automated ceiling plus USD 30 reserve; all workers share one ledger. No key was supplied in these documents. Never embed credentials in prompts, fixtures, logs or Git.
- Oracle instance: 4 CPU, 24 GB RAM; architecture and usable runtime are unverified. Local workers are possible. Detect architecture before choosing images; do not hardcode amd64 or assume ARM compatibility/emulation performance.
- The draft used an eight-hour hackathon window. Treat that as planning context, not a measured implementation promise. Complete product scope and experimental campaign duration are separate.
- Required deliverables: readable architecture with ASCII diagram; concrete contracts and implementation steps; four session briefs; integration/merge procedure; iteration units and budgets; evaluation protocol; an English technical sheet of at most two pages.

## Decisions and reasons

| Decision | Rationale / evidence | Owning document |
|---|---|---|
| Deterministic controller decides transitions; models propose bounded actions | Model prose cannot grant permissions, approve evidence or deploy | [Architecture](architecture.md), [contracts](contracts.md) |
| SQLite single writer and durable tasks in v1 | A single constrained host does not need Redis plus PostgreSQL to express leases, retries and audit events | [Contracts](contracts.md) |
| Separate gateway, launcher and deployer credentials | A compromised target or model job must not acquire cloud/runtime/deployment authority | [Sandbox](onboarding-sandbox.md) |
| Isolate builds as well as running targets | Package hooks and build scripts execute untrusted code; Docker networking alone is not a security boundary | [Sandbox](onboarding-sandbox.md) |
| Preserve full deployment/recovery/recurrence path | It is central to the user's product, not an optional PR-only endpoint | [Deployment](deployment-observability.md) |
| Formal claims bind named properties to actual implementation | Dafny verifies Dafny; an unrelated Python-to-Dafny model does not establish source correspondence | [Verification](verification.md), [VAmPI plan](vampi-formal-plan.md) |
| Start Python target evaluation, retain extensible architecture | Shared stack reduces setup confounders and lets the team measure a complete lifecycle early | [Cohort](repository-cohort.md) |
| Holdout and gold fixes stay outside worker views | Known safe implementations can make apparent repair performance misleading | [Evaluation](evaluation.md) |
| Preserve unsupported, failed and timed-out outcomes | Removing these from denominators inflates plug-and-play and end-to-end results | [Evaluation](evaluation.md) |

The initial large six-service proposal, blanket amd64 pinning, ten unrelated language/library targets and unconditional deployment claims are superseded by the current owning documents. The former R01-R10 roster is retired. Stable U01-U24 IDs now follow the user's original list; a later reordered list was deduplicated by repository identity. The original PagoSeguro transfer requirements are not VAmPI requirements; do not reuse their labels or claim they are already approved.

## Repository context supplied by Daniel

The complete list and supplied vulnerability hypotheses are preserved in [repository catalog](repository-catalog.md). The [candidate roster](../evaluation/repository-candidates.json) contains ten possible Python/API experiments. Selection: DSVW smoke, VAmPI development, Vulpy primary heldout, Tiredful-API predeclared compatibility fallback, DVGA optional static-only. DVPWA, legacy Flask/Bottle, PyGoat and crAPI require later admission. Non-Python, infrastructure/cloud and C incident examples remain cataloged, outside the immediate experiment.

Evidence changes the recommendations in four places:

1. VAmPI's source explicitly warns that its supposedly non-vulnerable switch still leaves behavior vulnerable; the debug path exposes sensitive fields. `vulnerable=0` is a scoped reference, never a globally safe negative. [Source](https://github.com/erev0s/VAmPI/blob/master/app.py).
2. Vulpy describes `good/` as unfinished. Validate each chosen behavior independently; do not declare all its findings false positives. [README](https://github.com/fportantier/vulpy).
3. DSVW's regression suite checks that attacks still work. Those tests cannot all be treated as protected positive functionality after repair. Its XML cases require lxml. [README](https://github.com/stamparm/DSVW).
4. Tiredful's upstream README links newer forks. A fork replacement requires a recorded campaign amendment before scoring; it is not the same target. [README](https://github.com/payatu/Tiredful-API).

Detailed vulnerability lists, challenge counts, relative difficulty and build-time claims supplied by the user are hypotheses until checked at frozen snapshots. The catalog distinguishes source documentation from reproduction; no repository has been built here.

## Research and claim boundaries

The [value assessment](value-assessment.md) contains the broader research basis. AIxCC and CodeMender motivate automated detection/repair; they do not establish that this prototype is reliable. CTIBench measures intelligence tasks, CyberSecEval Instruct measures insecure generation, DafnyBench measures proof-hint success. AutoPatchBench-style local gates are not an official AutoPatchBench score. AgentDojo motivates adversarial tool-use evaluation. None certifies the entire system.

Do not use the proposed pitch about a recent Microsoft zero-day causing a USD 100 billion valuation loss: the conversation supplied no supporting incident evidence. If an incident is used later, verify its date, cause and impact independently. Sudo and XZ are cataloged as historical motivation, not evidence of our detection/repair performance. No claims of invulnerability, guaranteed alignment, immutable logs merely because they are JSONL, or universally reversible data changes.

## What an incoming agent should do

1. Read this file, [documentation map](README.md), [architecture](architecture.md), [contracts](contracts.md), [runtime](runtime.md), [integration](integration.md), then the allocated session brief.
2. Run `python3 scripts/check_design_docs.py`; it validates the documentation, not the product.
3. Follow M0 shared bootstrap before creating implementation worktrees. Use exact shared schemas and runtime config; do not independently invent a second queue, budget or evidence format.
4. Work through [implementation gates](implementation.md). First real target is DSVW, followed by VAmPI; do not expose heldout gold source to development agents.
5. Record actual versions, commands, failures, assumptions and manual work. Populate commit/image/oracle hashes only from observed preflight. Never turn placeholders into invented results.
6. Leave a lane handoff with base/head revision, dependencies, tests, mocked boundaries and remaining work. Daniel integrates in the documented order.

## Later model-selection context

Daniel supplied prior model tests and pricing advice: GLM Flash through the Mistral key worked in a basic proof test, with reported 1M TPM account capacity; Groq GPT-OSS tests reportedly had 8k TPM limits. Use GLM Flash by default, keep Codestral/DeepSeek as calibrated alternatives, and Groq 20B/120B as optional separately funded comparators. These are not demonstrated quality rankings or measured refusal rates. The verified price snapshot, provider-policy sources, exact IDs, reasoning settings, fallback semantics and required calibration are in [model strategy](model-strategy.md). This replaces the earlier generic small/large-model plan while preserving T0/T1/T2 effort tiers.

Current state: architecture and implementation handoff exist; product code, sandbox validation, target builds, formal proofs and benchmark scores do not. The PDF describes the design and planned evaluation. Open operational decisions are host architecture/runtime, compatible pinned tool/model versions, exact target snapshots/oracles and approval of the proposed VAmPI business policy. These have explicit implementation gates; no paid model calls or target execution were needed to prepare this documentation.
