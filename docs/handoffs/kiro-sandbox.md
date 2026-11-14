# Handoff: sandbox work on top of `implementation/full-system`

Author: NigrumH0odo, with a coding agent. Base: `origin/implementation/full-system` at `82e3dca` (Daniel). Integration branch: `kiro/integracion-fs`. Each ticket is its own branch merged with `--no-ff`. Nothing is merged into Daniel's branch or `main`.

The earlier branches `kiro/integracion` and `kiro/a-m0-0*` were built on `main` before Daniel's implementation branch was visible. Daniel's branch supersedes them. Only pieces his branch lacked were carried over: recipe validator, doctor checks and launcher flag tests.

Host for every command below: Arch Linux x86_64, kernel 7.2.11, Docker 29.9.2 (`default` context, runc only), Python 3.12.13, uv 0.12.17.

## S1 `kiro/fs-sandbox-hardening`: refuse weakened `docker create`

- `src/colossus/sandbox/launcher.py`: `assert_safe_create` runs in `checked()` before every `create`. It needs `runsc`, network `none` or `colossus-net-*`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `--ipc private`, user `1000:1000`, `--memory-swap` equal to `--memory`, and `nosuid,nodev,size=` tmpfs. It refuses `--privileged`, `--cap-add`, `-v/--volume/--mount`, published ports, `--pid/--uts/--userns/--cgroupns`, `--sysctl` and any unknown flag. Only tokens before the image are parsed.
- Added `--ipc private` to `create`.
- `tests/security/test_launcher_policy.py`: 26 tests with a recorded fake Docker. They cover the hardened argv, bad roles/limits, foreign or external networks, unpinned images, 14 weakening mutations, unmanaged container inspection, the reaper removing only expired managed containers, and timeout plus env stripping in `bounded_process`.

## S2 `kiro/fs-recipe-validator`: hostile recipe plans

- `src/colossus/sandbox/recipe_validator.py`: `validate_recipe(recipe, execution=True)` returns violations for privileged/host modes, capabilities, devices, ports, security options, host or runtime-socket mounts, mutable tags at execution time, root users, provider credential env names, top-level networks/secrets/configs, more than 6 services, and totals above 1 CPU / 6 GiB.
- `tests/security/test_recipe_validator.py`: 24 tests.
- Not wired in yet. Onboarding (lane B) decides where recipe proposals are checked. Daniel's `discovery.py` accepts only its own recipe schema today, so nothing is bypassed.

## S3 `kiro/fs-doctor-preflight`: real doctor checks

- `src/colossus/cli/doctor.py`: architecture, free disk, cgroup v2 controllers (Linux), `SandboxLauncher.preflight()` on the configured context, provider keys as configured/missing only, `.env` permissions, `.env` ignored by git.
- `src/colossus/cli/main.py` `doctor`: keeps Daniel's keys and exit code 3, sets `runtime_preflight` from the checks and adds a `checks` list.
- `tests/contracts/test_doctor.py`: 7 tests, including a secret sentinel that never appears in output.

Observed: `COLOSSUS_DOCKER_CONTEXT=default uv run colossus --json doctor` -> `runtime_preflight: blocked`, exit 3. Architecture, disk (105 GiB) and cgroup checks ok; `sandbox.gvisor` blocked (`gVisor runtime missing`); provider keys missing (no `.env` in this checkout); `.env` ignored.

## Commands and results

```text
uv sync --python 3.12 --all-extras
uv run pytest -q          -> 106 passed (Daniel's 49 + 57 new)
uv run ruff check src tests -> All checks passed
```

## Not done

- No gVisor run on this Linux host: `runsc` is not installed, so Daniel's launcher refuses every job here, as designed. His Colima evidence remains the only real gVisor run.
- Multi-container egress, cancellation and cross-case challenges still need a gVisor host.
- Recipe validator wiring into onboarding.
