# Handoff: CrossHair adapter (`wip/crosshair`)

Author: NigrumH0odo, with a coding agent. Base: `kiro/colossus` at `908850e`. Branch: `wip/crosshair`. Not merged anywhere. Host: Linux x86_64, Python 3.12.13, uv 0.12.17, Docker 29.9.2 (context `default`), runsc `release-20261109.0`. No provider/model calls. Only self-written fixtures were analyzed.

## What exists

- `tools/crosshair/Dockerfile`, `requirements.in`, `requirements.txt`: trusted toolchain image. Base is the launcher's pinned `python@sha256:5e2bdb1b…4fa5b` (Python 3.12.16). `crosshair-tool==0.0.113` and its dependency closure (`z3-solver==5.4.1.0`, `typeshed-client==2.15.0`, `pygls==2.1.1`, …) are installed wheel-only with `--require-hashes` (hashes from `uv pip compile --generate-hashes --python-version 3.12 --python-platform x86_64-manylinux_2_28`). The build asserts both versions. Labels `org.colossus.managed=true`, `org.colossus.toolchain=crosshair-0.0.113-z3-5.4.1.0`; `USER 1000:1000`, `HOME=/tmp`.
- `src/colossus/verification/crosshair.py`:
  - `inspect_harness` reads the harness with `ast` only (no execution): top-level `.py` file, unique non-async, undecorated function with a PEP 316 docstring containing at least one `post:`. It returns the contract text (`pre:/post:/raises:/inv:` lines, hashed as `spec_hash`), the postcondition line numbers and a body line used as the CrossHair target (`harness.py:<line>`). Anything else is an UNSUPPORTED reason and the sandbox is never started.
  - `CrossHairAdapter.execute(project_id, obligation, files, harness_path)` requires `backend == "crosshair"`, `approved`, `sha256(harness) == obligation.harness_hash` and recomputed `spec_hash == obligation.spec_hash` (else `DomainError` `formal_scope` / `formal_binding`). Bounds come from `Obligation.bounds` and are validated: `deadline_seconds` 1–480 (default 90, runtime.md), `per_condition_timeout` 1–480 (default 60, must be ≤ deadline), `per_path_timeout` 1–60 (default 5), `max_uninteresting_iterations` 1–10000 (default 50); unknown keys are refused. The image must be a `sha256:` id whose toolchain label matches. It runs `python -m crosshair check --report_all --analysis_kind PEP316 --per_condition_timeout … --per_path_timeout … --max_uninteresting_iterations … harness.py:<line>` through `SandboxLauncher.create(role="verify", network none, read-only root, 2048 MiB, ttl deadline+60)` / `copy_source` / `execute(deadline)` / `destroy`.
  - `parse_report` (pure): timeout or truncated output → UNKNOWN; an `error:` line containing ` when calling <call>` with exit code 1 → COUNTEREXAMPLE with `counterexample.call` (e.g. `double(750)`) and `returns`; `SideEffectDetected`, `NotDeterministic`, `CrosshairUnsupported`, `UnexploredPath`, `IgnoreAttempt` → UNSUPPORTED; other errors (e.g. contract syntax error), non-zero exit, lines for another path, malformed lines, duplicate lines, empty output, or a report that does not list exactly the harness's postcondition lines → UNKNOWN; any `Not confirmed.` → UNKNOWN (`exploration: incomplete`). Only when every postcondition reads `Confirmed over all paths.` is it BOUNDED_PASS, and only if the obligation has `required_evidence_kind == "bounded"` and `allowed_bound_profile_id == "crosshair-bounded-v1"`; for a proof obligation the same report is UNKNOWN (`exploration: exhausted`). PROVED is never produced.
  - `gate_status` / `to_gate_result` build a `GateResult` (category `formal`, `check_profile_id = "crosshair:<obligation_id>"`, `tool_version` = toolchain label, `command_profile_hash` = hash of the exact argv): BOUNDED_PASS+bounded obligation → `pass`; COUNTEREXAMPLE → `fail`; UNKNOWN with deadline hit → `timeout`; other UNKNOWN → `error`; UNSUPPORTED → `error` if the obligation is required, else `not_applicable`. `to_gate_result` refuses evidence for another obligation or labelled PROVED.

## Toolchain image (built on host, build-time network for wheels only)

```
docker --context default build -q -t colossus-crosshair:0.0.113 tools/crosshair
  -> sha256:664a473e0e89234aa20cda3bc933417cf94600c4c0f14c7eb3e6ec3c176f16d4
docker --context default image inspect colossus-crosshair:0.0.113 --format '{{.Id}} {{json .Config.Labels}} {{.Config.User}}'
  -> sha256:664a473e0e89234aa20cda3bc933417cf94600c4c0f14c7eb3e6ec3c176f16d4 {"org.colossus.managed":"true","org.colossus.toolchain":"crosshair-0.0.113-z3-5.4.1.0"} 1000:1000
```

The image id is a local build id, not a registry digest; rebuilding may change it if base layers or wheel timestamps differ. Configure the controller with the id actually present.

## Commands and observed results

```
export UV_PROJECT_ENVIRONMENT=$PWD/.uvenv COLOSSUS_DOCKER_CONTEXT=default
uv sync -q --python 3.12 --all-extras
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt tests/verification/test_crosshair.py
  -> 32 passed in 0.53s
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt tests/verification/test_crosshair_live.py tests/verification/test_crosshair.py -rs -v
  -> 39 passed in 35.69s (7 live, 0 skipped)
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt
  -> 355 passed, 1 warning in 74.72s
uv run ruff check src tests
  -> All checks passed!
python3 scripts/check_design_docs.py
  -> PASS: 31 required handoff files, ...
```

Live evidence (gVisor, network none) from the same fixtures:

| Fixture | Outcome | Gate | Exit / timed out | Wall s | CrossHair line |
|---|---|---|---|---|---|
| `double`, `post: __return__ < 1500`, `pre: 0<=x<=1000` | COUNTEREXAMPLE | fail | 1 / no | 1.7 | `error: false when calling double(750) (which returns 1500)` |
| `clamp` to [0,10], two posts | BOUNDED_PASS (bounded obligation); UNKNOWN for proof obligation | pass / error | 0 / no | 1.5 | `info: Confirmed over all paths.` ×2 |
| `spin`, `sum(range(10**11))`, deadline 8 s | UNKNOWN | timeout | -9 / yes | 6.0 | (none) |
| `walk`, infinite loop, condition budget 4 s | UNKNOWN (incomplete) | error | 0 / no | 6.3 | `info: Not confirmed.` |
| `touch`, writes `/tmp/x` | UNSUPPORTED | error | 1 / no | 1.5 | `error: SideEffectDetected: …` |

The live module fixture asserts no container labelled with the test project id remains afterwards; checked by hand with `docker --context default ps -a --filter label=org.colossus.project=00000000-0000-4000-8000-0000000000c1` → empty.

## Proven live vs unit-only

- Live under gVisor: counterexample with concrete input, bounded-clean exhaustion, hard deadline → UNKNOWN/timeout, budget exhaustion → UNKNOWN, side effect → UNSUPPORTED, tampered (weakened) harness refused before execution, wrong-toolchain image refused.
- Unit only: empty/truncated/crashed/duplicated/substituted-path/malformed reports, exception-type counterexamples, contract syntax errors, all static UNSUPPORTED cases (async, decorated, no contract, no post, unparseable, missing symbol, nested path, non-.py), bound-policy refusals, GateResult mapping.

## Not wired / remaining work

- NOT WIRED into `control/cycle.py` (per ticket). Suggested wiring for Daniel: for each approved `Obligation` with `backend == "crosshair"` in the candidate's obligation set, call `CrossHairAdapter(launcher, settings.crosshair_image).execute(project_id, obligation, files, harness_path)` inside the formal slice (≤ 5 obligations, ≤ 480 s total; pass the remaining slice as `bounds["deadline_seconds"]`), store the returned dict as content-addressed evidence, then `to_gate_result(...)` with that evidence id. `validate_gates` already rejects anything but PROVED for `formal_required`, so CrossHair can never satisfy a proof-required case. A COUNTEREXAMPLE's `counterexample.call` should become a regression input only after confirmation (verification.md); that confirmation step does not exist yet.
- Harness `files` beyond the harness file itself are copied and hashed (`source_hashes`) but not bound to the obligation; the cycle must bind them to the candidate tree hash.
- The adapter does not yet run through the sandbox server's controller-only HTTP endpoint (Dafny has `/formal/policy` in `sandbox/server.py`); adding a `/formal/crosshair` route is outside this ticket's owned files.
- Unsupported-marker list is from CrossHair 0.0.113 behaviour observed here plus its documented exception names; recheck on any version bump. Contract syntax inside the docstring is not validated on the host; CrossHair reports it and the parser maps it to UNKNOWN.
- No obligation registry/template for real targets (DSVW is not Python-contracted); fixtures are self-written.
