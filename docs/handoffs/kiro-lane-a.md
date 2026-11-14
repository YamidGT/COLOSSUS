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

## A-M0-03 Docker launcher with real denial tests

Branch `kiro/a-m0-03-launcher`.

| Item | Path |
|---|---|
| Launcher: stage, create, attach with deadline, stop/kill, remove, import, wipe | `src/colossus/sandbox/launcher.py` |
| Trusted probe run inside the sandbox | `tests/security/probe.py` |
| Real Docker tests (marker `docker`) | `tests/security/test_launcher_docker.py` |

Command: `uv run --python 3.12 pytest --basetemp="$KIROCREW_SCRATCH/pt3"` -> 83 passed (6 of them real Docker runs, about 18 s). After the run: 0 labelled containers, 0 labelled networks, 0 leftover job files.

Observed inside the sandbox (Docker 29.9.2, runtime `runc`, trusted image `python:3.12-bookworm` by digest):

| Check | Result |
|---|---|
| uid/gid | 65534/65534 |
| Effective capabilities | 0 |
| TCP to 1.1.1.1, IPv6, DNS, 169.254.169.254 | denied |
| Write to `/` and `/in` | denied |
| Write to `/scratch` | allowed (noexec tmpfs) |
| Docker socket present | no |
| cgroup `memory.max` / `pids.max` | 268435456 / 64 |
| Host env leak (sentinel, `MISTRAL_API_KEY`) | none |
| Per-case `--internal` network egress | denied |
| `/out` symlink and over-cap file | rejected, not imported |
| Timeout job | killed, no results imported, container removed |
| Untrusted profile without `runsc` | refused with `isolation_unavailable` |

Important limits:

- gVisor (`runsc`) is **not installed** on this host. Every real run above used `runc` with a trusted fixture image. Untrusted repository code is refused on this host, as designed. These runs show the hardening flags work; they do not show gVisor isolation.
- Docker here is not rootless (`dockerd` runs as user `nobody` inside a user namespace). Rootless Docker is still a preflight item.
- Job outputs are created by uid 65534, which the host process cannot delete. The launcher wipes `/out` in a second sandbox run as the job user; paths it cannot remove go to `launcher.orphans`.
- Builds, dependency proxy, image packaging and the reaper loop are not implemented.

## A-M0-04 `colossus doctor`

Branch `kiro/a-m0-04-doctor`.

| Item | Path |
|---|---|
| Typer CLI entrypoint `colossus` | `src/colossus/cli/main.py` |
| Host, runtime, tool, credential and repo checks | `src/colossus/cli/doctor.py` |
| Tests with a fake host | `tests/contracts/test_doctor.py` |

Behavior: states are `ok`, `warn`, `blocked`, `unknown`. Exit 3 when any check is `blocked`, as in cli.md. `--json` prints the cli.md envelope. Credentials show `configured`/`missing` by provider name; values are never printed (tested with a sentinel). `--check-model` makes no call yet and reports `unknown`.

Observed on this host (`uv run --python 3.12 colossus doctor`, exit 3):

| Check | State | Observed |
|---|---|---|
| architecture / kernel | ok | x86_64 / 7.2.11-arch1-1 |
| cpus / memory / disk | ok | 12 / 30.2 GiB / 105 GiB free |
| cgroup v2 | ok | cpu io memory pids |
| docker | ok | server 29.9.2 |
| gVisor `runsc` | blocked | not registered |
| rootless | warn | daemon not rootless |
| isolated build backend | blocked | none validated |
| dafny / crosshair | warn | missing |
| Mistral / Groq keys | warn | `.env` absent in this checkout |
| `.env` ignored by git | ok | ignored |

The build-backend check is blocked on purpose until a real isolated builder passes preflight.
