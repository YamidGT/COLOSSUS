# Lane B onboarding intelligence and investigation

Own `src/colossus/{onboarding,intel,detect}` and component tests. Implement onboarding-sandbox.md and the intel/detection sections of agents-intelligence.md. Consume A's launcher; do not invent a second runtime wrapper.

Steps:
1. URL normalization, source snapshot inspection and stack detectors; no source imports on host.
2. Generate/validate recipe proposals, run isolated setup, synthetic services/readiness and emit TargetManifest.
3. Resolve dependencies/SBOM; cache OSV records, aliases and KEV enrichments with source timestamps.
4. Run pinned deterministic scanners, retain raw evidence, add model triage and bounded reproduction.
5. Emit Finding and IntelEvent through shared schemas; implement trigger coalescing inputs and mirror refresh from C's observed deployment.
6. Work with D to preflight pilot/cohort recipes, distinguish manual setup from URL-only success, and supply CTI adapter context without answer leakage.

Acceptance: a real URL starts an actual target; setup/config/architecture failures are explicit; vulnerability confirmation works against selected snapshot and not its paired fixed behavior; raw findings are retained; stale feeds and unknown package matches stay visible; next cycle uses the promoted manifest. Neither a static scanner warning nor failed probe alone establishes truth.

Target sequence: DSVW then VAmPI. Do not tune on heldout Vulpy or expose its `good/`/solution view; D owns the filtered evaluation manifest. See [cohort](../repository-cohort.md). Model effort tiers follow [model strategy](../model-strategy.md).
