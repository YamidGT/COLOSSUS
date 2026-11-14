# Four implementation sessions

The whole recurring defence system is the objective. Read docs/project-context.md, docs/model-strategy.md, docs/README.md, architecture.md, contracts.md, runtime.md and integration.md before implementing. Daniel owns integration. Lanes use separate worktrees after the common bootstrap commit; their runtime agent roles are a different concept.

| Lane | Owner | Exclusive source ownership | Brief |
|---|---|---|---|
| A | Daniel | contracts, control, gateway, sandbox, observability, root config/lock, CLI/API and frontend/ | [Controller and integration](a-control.md) |
| B | Teammate 2 | onboarding, intel, detect, component tests | [Onboarding and investigation](b-onboarding.md) |
| C | Teammate 3 | repair, deploy, component tests | [Repair and deployment](c-repair-deploy.md) |
| D | Teammate 4 | verify, evaluation adapters, independent acceptance tests | [Verification and evaluation](d-verification.md) |

All four may use coding agents. More agents must work within subdirectories/tasks allocated by the lane owner; adding agents does not grant shared-file write ownership. Heavy jobs use the same semaphore and API calls the same ledger. Do not run four private test stacks against the same ports/volumes.

Dependencies: A contracts/launcher first; B manifest; C candidate; D gate results; C deployment; B refreshed manifest. Develop against fixtures in parallel, integrate in this dependency order. Escalate schema changes to A, proof/scoring changes to D and target-behavior ambiguities to Daniel.

Each handoff states base/head commit, interface/version, dependencies, exact commands, actual results, mocked components, known failures and remaining work. No bare “done.” The integration gates determine readiness.
