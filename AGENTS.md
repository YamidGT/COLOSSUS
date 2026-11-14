# Implementation instructions

Build the complete recurring cyberdefence system described in docs/README.md. Do not replace the project with a single application or a verification-only demo. Read docs/project-context.md and docs/model-strategy.md first, then architecture.md, contracts.md, runtime.md, integration.md and your session brief before editing.

Use the four session ownership boundaries. Keep changes in your worktree. Propose shared-contract changes to Daniel/session A; do not independently fork interfaces or budget policy. Do not merge another lane or change scope without coordination. Do not treat example IDs/hashes as real benchmark evidence.

No repository build, test, import, dependency hook or model-produced code runs in the controller process or on the developer host. Use the sandbox execution boundary. Do not contact upstream maintainers or open PRs/issues without explicit authorization. Do not scan public deployments; enrolled local copies are the test targets.

Follow the implementation acceptance gates. Record actual commands and outcomes in the lane handoff. No fabricated results, silently skipped proof gates, hidden benchmark exclusions or weakened specifications. Document uncertainties and capability gaps as explicit states. Product tests, target reference tests and evaluator-only truth have separate trust boundaries.
