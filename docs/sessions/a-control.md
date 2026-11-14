# Lane A Daniel controller and integration

Own `src/colossus/{contracts,control,gateway,sandbox,observability}`, root config/lock/Compose, CLI/operator API and migrations. Implement contracts.md, runtime.md, architecture.md and the host execution boundary in onboarding-sandbox.md. Own root package/version pinning and lane dependency requests.

Steps:
1. Bootstrap shared Pydantic models, JSON fixtures, typed errors, RuntimeConfig and package entrypoints; commit common base before worktrees branch.
2. Build artifact store, single-writer SQLite transactions, task leases/outbox and restart reconciliation.
3. Build source/feed gateway and Mistral broker with capability checks, atomic budget reservations and price/model records.
4. Build fixed-profile launcher with quotas, denial tests, output import, termination and case-scoped teardown.
5. Integrate scheduler, state/policy decisions and operator authorization endpoint with C's deployer.
6. Instrument unsampled audit and OTel; expose status/report/diff/approval UI.
7. Merge lane slices using integration.md and record their evidence.

Acceptance: schema exchange works across every lane; duplicate/expired tasks cannot corrupt state; concurrent calls cannot overspend; target jobs cannot reach credentials/control/another project; stale/artifact-mismatched authorizations fail; complete lifecycle resumes safely after a controller kill. Coordinate a real isolated build backend early; never assume Docker build inherits runsc isolation automatically.

Model gateway implementation follows [model strategy](../model-strategy.md): GLM Flash default, exact IDs, capability checks, separate refusal/429 handling and shared reservations.
