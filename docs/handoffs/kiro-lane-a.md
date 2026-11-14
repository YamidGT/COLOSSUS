# Handoff: lane A bootstrap work (branch `kiro/integracion`)

Author: NigrumH0odo, with a coding agent. Base: `1a4d059` (docs v1.2 by Daniel). Each ticket is a branch merged into `kiro/integracion` with `--no-ff`. Nothing here is pushed or merged into `main`; Daniel owns integration.

Shared-contract owner is lane A. These files are a proposal for Daniel to accept, change or replace.

## A-M0-01 Contracts package and fixtures

Branch `kiro/a-m0-01-contracts`.

| Item | Path |
|---|---|
| Package, pinned deps, lock | `pyproject.toml`, `uv.lock` |
| Common types, canonical JSON hash | `src/colossus/contracts/common.py` |
| Typed error `{code,message,retryable,evidence_ids}` | `src/colossus/contracts/errors.py` |
| 13 payload types from contracts.md | `src/colossus/contracts/payloads.py` |
| 5 operator read/mutation types | `src/colossus/contracts/operator.py` |
| Envelope with payload hash check | `src/colossus/contracts/envelope.py` |
| RuntimeConfig (runtime.md limits) | `src/colossus/contracts/runtime_config.py` |
| Valid/invalid fixtures (synthetic) | `src/colossus/contracts/fixtures.py` |
| Exported JSON Schema and fixtures | `fixtures/contracts/` via `scripts/export_contracts.py` |

Commands and observed results (host: x86_64, Linux 7.2.11, Python 3.12.13, uv 0.12.17):

```text
uv sync --python 3.12 --extra dev          -> installed pydantic 2.14.3, typer 0.29.1, httpx 0.28.1, pytest 9.2.0
uv run --python 3.12 pytest                -> 47 passed
uv run --python 3.12 python scripts/export_contracts.py -> 20 schemas, 18 valid, 18 invalid fixtures
python3 scripts/check_design_docs.py       -> PASS
```

Rules enforced in code: `extra=forbid`, strict scalars, frozen objects, UTC timestamps, lowercase SHA-256, pinned `name@sha256:` images, relative paths without `..`, GitHub HTTPS URLs without credentials, non-formal gates with null `proof_outcome`, formal pass only with PROVED/BOUNDED_PASS plus evidence, required obligations approved and not inferred, failed model calls with a reason code.

Not done / open decisions for lane A:

- `ProjectSnapshot` and `CaseReview` are not defined: contracts.md does not specify their summary sub-objects field by field.
- `DeploymentStatus` values are taken from the architecture lifecycle; contracts.md does not list them.
- `Obligation.backend` is limited to `dafny`, `crosshair`, `cbmc`.
- SQLite migrations, CLI and frontend skeleton are separate tickets.
- All fixture IDs/hashes are synthetic and are not evidence.

## A-M0-02 Sandbox isolation profiles and recipe validator

Branch `kiro/a-m0-02-sandbox-policy`.

| Item | Path |
|---|---|
| IsolationProfile, JobProfile, hardened `docker create` argv, argv safety check | `src/colossus/sandbox/profiles.py` |
| Compose-like recipe validator | `src/colossus/sandbox/recipe_validator.py` |
| Tests (no Docker needed) | `tests/security/test_sandbox_policy.py` |

Observed: `uv run --python 3.12 pytest` -> 77 passed (47 contracts + 30 sandbox policy).

Behavior: untrusted repository jobs must use `runsc`; a `runc` profile is only valid for trusted fixture images and there is no automatic fallback. Every job gets `--network none` (or a `colossus-case-*` internal network), `--cap-drop ALL`, `no-new-privileges`, read-only root, nonroot user, private IPC, PID/memory/CPU limits, noexec tmpfs scratch, read-only `/in`, writable `/out` only, `--pull never`, digest-pinned image and a fixed entrypoint. Shell entrypoints and credential-looking env names are refused. The recipe validator refuses privileged/host modes, capabilities, devices, published ports, host or socket mounts, mutable tags, root users, provider credential env names, top-level networks/secrets and resource totals above 1 CPU / 6 GiB.

Not proven here: these tests check argv and plan shape only. Real isolation needs the launcher run in A-M0-03 and gVisor on the host.
