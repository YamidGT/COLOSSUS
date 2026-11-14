# COLOSSUS

COLOSSUS is a recurring automated cyberdefence system. A public GitHub URL starts isolated setup, investigation, remediation, verification, policy-controlled deployment, recovery and mirror refresh. The next cycle uses the resulting deployed version.

**Status:** hackathon implementation, 14 November 2026. The controller, CLI and
React/Tailwind action center, credential gateway, recurring OSV/KEV intelligence,
gVisor execution, immutable packaging, DSVW repair/deployment/recovery and bounded
GLM-assisted Dafny workflow are implemented. Public-target proof coverage and
supported setup/repair profiles remain limited. See the [submission report](docs/submission.md)
for measured results and the [completion ledger](docs/implementation-status.md)
for remaining broader capabilities.

[Explore the recorded demo](https://colossus-defence-demo.netlify.app): inspect the
rejected first patch, corrected candidate, formal scope and all repository outcomes.
This public walkthrough displays completed evidence; it does not execute targets or
call models. [Demo build and presentation guide](docs/public-demo.md).

[Open the six-slide pitch](https://danidiaztech.github.io/colossus-presentation/):
architecture, DSVW repair, formal verification and measured results, with fullscreen
navigation and speaker notes. [Presentation source and publishing notes](presentation/README.md).

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

Daniel expanded the submission campaign to the full 24-repository catalog. Results
retain source-intake errors, unsupported stacks and failed setup; they are not 24
successful full-cycle repairs. The first complete lifecycle target is
[DSVW](https://github.com/stamparm/DSVW), pinned to
`9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908`. Only isolated local copies are exercised;
no public deployment or paid cloud laboratory is targeted.

## Start the action center

With the dedicated gVisor runtime configured and gateway credentials in `.env`:

```bash
uv sync --python 3.12
npm --prefix frontend ci
npm --prefix frontend run build
uv run colossus serve
```

In another terminal:

```bash
uv run colossus ui
uv run colossus --json enroll https://github.com/stamparm/DSVW \
  --ref 9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908 --run
uv run colossus projects
uv run colossus status PROJECT_ID --watch
uv run colossus report CYCLE_ID --output report.json
```

`ui` displays a one-use login code. Enter it in the browser; no provider key belongs
in the frontend. Enrollment with `--run` queues one cycle after readiness. Local
lab policy can promote a candidate only after its required checks pass. `doctor`
prints runtime diagnostics and currently exits 3 while full-product acceptance
remains incomplete; inspect the individual checks rather than interpreting that
exit as proof that every implemented path is unavailable.

## Verification and reproduction

```bash
uv run pytest -q
uv run ruff check src tests
uv run python scripts/check_design_docs.py
uv run python scripts/check_formal_agent.py
uv run python scripts/check_full_cycle.py --output evaluation/submission/dsvw-reproduction.json
```

The last two commands use the paid model gateway and existing isolated runtime.
Run one supervisor at a time against the same state directory. A fresh lifecycle
includes the real five-minute observation window. See [formal workflow](docs/formal-agent.md)
for the exact proof scope and plain mandatory-test fallback instructions. The
owned compiled-policy fixture is not a proof of DSVW's Python SQL implementation.
