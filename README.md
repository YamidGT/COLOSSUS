# COLOSSUS

COLOSSUS is a recurring automated cyberdefence system. A public GitHub URL starts isolated setup, investigation, remediation, verification, policy-controlled deployment, recovery and mirror refresh. The next cycle uses the resulting deployed version.

**Status:** implementation specification v1.1, 14 November 2026. Product code, target builds, proof runs and benchmark results are not implemented or validated yet. The documents define the complete system; they do not claim all public repositories can be built or formally verified.

## Implementation handoff

Read [the documentation map](docs/README.md), then [architecture](docs/architecture.md), [contracts](docs/contracts.md) and your [session brief](docs/sessions/README.md).

- [Onboarding and sandbox execution](docs/onboarding-sandbox.md)
- [Agents and vulnerability intelligence](docs/agents-intelligence.md)
- [Formal verification and acceptance](docs/verification.md)
- [Deployment and observability](docs/deployment-observability.md)
- [Cycle timing, scheduling and budget](docs/runtime.md)
- [Implementation steps and acceptance gates](docs/implementation.md)
- [Merging and integration runbook](docs/integration.md)
- [Evaluation protocol](docs/evaluation.md)
- [Project context and decisions](docs/project-context.md)
- [Model selection and provider constraints](docs/model-strategy.md)
- [Full 24-repository catalog](docs/repository-catalog.md)
- [VAmPI formal integration](docs/vampi-formal-plan.md)
- [Up to ten public repositories](docs/repository-cohort.md)
- [Research and value assessment](docs/value-assessment.md)
- [Documentation audit and open validation items](docs/design-audit.md)
- [English technical sheet, two pages](output/pdf/colossus-technical-sheet.pdf)
- [Editable technical-sheet text](docs/technical-sheet.md)

The implementation sequence preserves every stage of Daniel's original lifecycle. Repository cohorts are evaluation subjects, not product restrictions. Human-readable specifications are authoritative; example JSON illustrates their wire format and is not a working runtime.
