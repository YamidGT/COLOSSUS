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

## S4 live gVisor challenges on Linux

gVisor `runsc release-20261109.0` (same as Daniel) installed by the user on this host and registered in the `default` Docker context.

- `scripts/check_sandbox.py` reads `COLOSSUS_DOCKER_CONTEXT`. `COLOSSUS_DOCKER_CONTEXT=default uv run python scripts/check_sandbox.py` passed: uid 1000, gVisor kernel, external connection denied, host home/socket/provider keys absent, root read-only.
- `tests/security/test_gvisor_live.py` (marker `gvisor`, skipped without runsc): 11 live tests, all trusted fixture programs.

| Challenge | Observed |
|---|---|
| No-network job: IPv4, IPv6, cloud metadata address, DNS | all denied |
| Project network: own packaged target over HTTP | 200, body matches |
| Project network: internet, cloud metadata, DNS | denied |
| Other project's probe to the target address | denied |
| Other project joins target network / uses request API | refused (DomainError) |
| Job past deadline (3 s) | killed, container removed |
| 512 MiB allocation under a 128 MiB limit | process killed |
| 400 processes under pids-limit 128 | limited below 128 |
| Upload path `../evil.py` | refused |
| `terminate_project_work` | 2 workers and network removed, confirmed |
| Host `MISTRAL_API_KEY` sentinel | absent inside job |
| Kernel | gVisor |

- Bug fixed in `SandboxLauncher.destroy`: Docker 29 says `no such object` in lowercase, so an already-removed container raised. Now matched case-insensitively, with a unit test.

After the run: 0 managed containers, 0 managed networks, 0 managed images.

## Commands and results

```text
uv sync --python 3.12 --all-extras
COLOSSUS_DOCKER_CONTEXT=default uv run pytest -q -> 117 passed (Daniel's 49 + 68 new; 11 live gVisor)
uv run ruff check src tests -> All checks passed
```

## Not done

- Restart/cancel fault injection through the API and controller is still unvalidated.
- Docker here is not rootless.
- Recipe validator wiring into onboarding.

## S5 `wip/sandbox`: evidence before teardown, scratch caps, reaping, gateway isolation

Host: Arch Linux x86_64, Docker 29.9.2 `default` context (rootful), gVisor `runsc release-20261109.0`.

Launcher changes (`src/colossus/sandbox/launcher.py`, existing method signatures unchanged):

- `run_collect(...)` (new): create, copy, execute, then `export_files` **before** `destroy`. Returns `evidence: exported | quarantined | lost_timeout`. If the export raises (`unsafe_export`, `export_failed`, `export_timeout`), the worker is `docker pause`d and kept, and the result names it with the error code. A timed-out job is killed and reported `lost_timeout`; its tmpfs scratch is gone.
- Quarantine: `quarantine()`, `quarantined()`, `MAX_QUARANTINE = 4`. `create()` refuses new work with `quarantine_full` (507) at the cap. `reap()` skips paused workers. `destroy()` unpauses first, because runsc refuses `rm -f` on a paused sandbox (observed: `PID ... is zombie and can not be killed`).
- `reap()` now also removes expired, empty, managed `colossus-net-*` networks. Networks carry `org.colossus.expires` (`network(project_id, ttl_seconds=14400)`; `start_target` passes its TTL). Networks without an expiry label are left alone. `server.py` runs one `reap()` at launcher start, before serving.
- **Gap found and fixed:** a job on a project network reached a host listener bound to the network's bridge gateway (`172.27.0.1:<port>` -> `allowed`). Networks are now created with `--opt com.docker.network.bridge.inhibit_ipv4=true`, so the host has no address in the case subnet, and `_validate_network` refuses networks without that option.

Live checks (`tests/security/test_gvisor_evidence.py`, 10 tests, marker `gvisor`):

| Check | Observed |
|---|---|
| Job writes `/work/results/r.json`, `run_collect` | exported `{"ok": 1}`, worker gone |
| Results contain a symlink to `/etc/passwd` | `unsafe_export`, worker paused, `r.txt` still readable after unpause |
| Quarantined worker with TTL 1 s, then `reap()` | kept; `create` with cap reached -> `quarantine_full` |
| Fill `/tmp` (64 MiB) and `/work` (512 MiB) | `errno 28` inside the job, written <= cap, worker still answers, host `/` free space drop < 64 MiB |
| `reap()` with expired managed container + network, fresh managed network, unmanaged look-alikes (`colossus-plain-*` runc container never started, `colossus-net-plain-*` network, both labelled expired) | only the expired managed pair removed; look-alikes untouched, then removed by exact name |
| Two targets of the same project on two networks | probe on B: own target allowed, A denied |
| Target returns 302 to `http://1.1.1.1/x` and to `/hit` | `request()` returns 302 with Location; `/hit` counter stays 0 |
| Job identity | uid/gid 1000, CapEff and CapBnd 0, NoNewPrivs 1, write to `/` denied, exec from `/tmp` denied |
| Probe to host listener on `docker0` (172.17.0.1) and external IPv6 from a project network | denied; network IPAM has no gateway, no host address in the subnet |

Unit tests (`tests/security/test_launcher_evidence.py`, 7 tests, fake Docker): export-before-rm ordering, quarantine on export failure, admission refusal, timeout path, reaper selection of containers and networks, network expiry bounds, `inhibit_ipv4` required.

```text
COLOSSUS_DOCKER_CONTEXT=default uv run pytest -q -p no:cacheprovider -> 158 passed (21 live gVisor)
uv run ruff check src tests -> All checks passed!
python3 scripts/check_design_docs.py -> PASS
docker ps -aq / network ls -q / image ls -q --filter label=org.colossus.managed=true -> 0 / 0 / 0
```

Not done:

- `run_collect` is not exposed through `server.py` or used by `src/colossus/control/**`; callers still use `run()`, whose only evidence is stdout/stderr.
- Quarantine is bounded by count, not bytes; there is no operator release endpoint (only `destroy`).
- Partial results of a timed-out job are lost (`lost_timeout`); exporting after a kill would need the frozen worker kept alive.
- Networks created before this change lack `inhibit_ipv4` and an expiry label: `_validate_network` refuses them and `reap()` leaves them. Remove such leftovers by exact name.
- Docker is still not rootless here; clean rebuild, setup retry cap and incompatible-architecture checks from step 6 remain.
