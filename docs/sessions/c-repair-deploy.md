# Lane C repair and deployment

Own `src/colossus/{repair,deploy}` and component tests. Implement repair sections of agents-intelligence.md and deployment-observability.md. Consume A's broker/launcher and D's GateResults. Do not edit shared schemas, tests/specifications or evaluator truth.

Steps:
1. Exact-hash patch applier, protected paths and structured proposals; build valid/invalid fixtures.
2. Official update and blind-generated routes with separate provenance; three-candidate limit.
3. Fresh candidate tree/build through launcher; produce Candidate and feed bounded diagnostics to repair loop.
4. Local deployment service with authorization/digest/generation checks, backend slots or library consumer pointer.
5. Synthetic canary traffic, health checks, recovery and restart reconciliation; keep previous deployable artifact.
6. Hand observed deployment manifest to B for refresh; coordinate second-cycle integration.
7. Supply Instruct model-generation adapter to D's scorer and target-specific positive behavior to independent evaluation.

Acceptance: upstream and generated fixes actually run; protected/base mismatches reject; good/bad artifact test controls are meaningful; no model/deployer bypass of gates; forced rollout failure recovers correctly; promotion/restoration is idempotent. No real production credentials or external PR publication is required for the lab adapter.

Coordinate the guided [VAmPI formal integration](../vampi-formal-plan.md) with D separately from ordinary repair cases. Frozen specs/recipes remain protected. Use [model strategy](../model-strategy.md); no fallback on a safety refusal and no model review can grant promotion authority.
