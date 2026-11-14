# COLOSSUS

COLOSSUS is a recurring automated cyberdefence system. A public GitHub URL starts isolated setup, investigation, remediation, verification, policy-controlled deployment, recovery and mirror refresh. The next cycle uses the resulting deployed version.

**Status:** implementation in progress, 14 November 2026. The controller, API/CLI foundation, credential gateway, gVisor execution, immutable packaging and one DSVW repair path are implemented. A real DSVW candidate passed the tested-profile gates; deployment/recovery, formal adapters, intelligence feeds, frontend and benchmark execution remain incomplete. See the [implementation evidence and completion ledger](docs/implementation-status.md).

## Implementation handoff

Read [the documentation map](docs/README.md), then [architecture](docs/architecture.md), [contracts](docs/contracts.md) and your [session brief](docs/sessions/README.md).

- [Operator workflows](docs/user-workflows.md)
- [CLI specification](docs/cli.md)
- [Repository action center](docs/frontend.md)
- [Product brief](PRODUCT.md) and [visual design rules](DESIGN.md)
- [Local secrets configuration](docs/secrets-configuration.md)
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

## Development commands

Use `uv sync --python 3.12`, `uv run pytest -q` and `uv run ruff check src tests`. Start the service with `uv run colossus serve`; it binds to loopback, starts the gateway/launcher and dispatches durable tasks. `uv run colossus --help` lists currently implemented commands. The operator token stays in ignored `.colossus/operator.token`; provider keys stay in ignored `.env` and only the gateway reads them.

The local worker requires a **dedicated** Docker context with gVisor, selected through `COLOSSUS_DOCKER_CONTEXT` (default `colima-colossus`). Do not point it at a production Docker daemon. Runtime preflight fails closed if gVisor is missing. The validated local profile is a separate Colima Linux VM with no host directory mounts or port forwarding, a rootful daemon inside that disposable VM, and nonroot gVisor containers. Rootless Docker is not yet validated here.

Daniel has limited runtime validation to **DSVW only** for this implementation phase. `scripts/check_sandbox.py`, `scripts/check_services.py`, `scripts/check_onboarding.py` and `scripts/check_repair.py` record bounded calibration evidence locally. The last script uses the real paid model and stops at a verified candidate; it does not deploy. Do not launch the multi-repository campaign yet.
