# Handoff: controller fault-injection and concurrency tests (lane: faults)

Branch `wip/faults` (from `kiro/colossus` at 908850e). Only `tests/faults/**` and this file were added; `src/**` is unchanged.
The tests make no network, docker, sandbox or model/provider calls. RPC peers are in-process fakes, HTTP is `httpx.MockTransport`, and storage faults are injected with an SQLite trigger on `audit_events`.

## Files

- `tests/faults/faultkit.py` holds the shared fakes: `FakeRPC`, the deployer/launcher fakes, project, case and approval builders, a restart helper (close and reopen the same SQLite file), the audit-fault trigger, valid deployer authority inputs, and the spawn-safe body for the cross-process budget test.
- `tests/faults/conftest.py` exposes the `env` fixture.
- `tests/faults/test_fault_leases.py` covers I06 (duplicate delivery and expired leases), cancellation reconciliation and queued-deadline expiry.
- `tests/faults/test_fault_restart.py` covers controller restart, outbox replay, in-flight model charges and I07 on both the controller side and the deployer side.
- `tests/faults/test_fault_stale_source.py` covers I11 in the controller coordinator, in approval binding and in the deployer's `validate_authority`/`promote`.
- `tests/faults/test_fault_budget.py` covers I13 with 4 OS processes (spawn) on one SQLite file, plus 8 threads through `Broker.complete`, near the global, case and request-count caps.
- `tests/faults/test_fault_storage.py` covers I15: an audit write failure blocks approve, run, rollback, claim, complete and reserve, and blocks authorization before any deployer call. The deployer `/abort` recovery is still attempted after a lost `/promote` response.
- `tests/faults/test_fault_source.py` covers `gateway/source.py` with mocked HTTP: cross-host and same-host redirects, a streamed oversize archive, too many entries, the expanded-size limit, links and special files, mixed roots, `.git` paths, traversal, duplicates, corrupt or empty archives, credentials and non-GitHub URLs, invalid refs and subdirs, ref percent-encoding, mutable or malformed SHAs, typed upstream HTTP errors, malformed commit JSON, and subdir prefix confusion.

## Commands and results

```
export UV_PROJECT_ENVIRONMENT=$PWD/.uvenv; uv sync -q --python 3.12 --all-extras
uv run ruff check src tests
  All checks passed!
uv run pytest -q -p no:cacheprovider -m 'not gvisor' --basetemp=$PWD/.pt
  383 passed, 20 deselected, 4 xfailed, 1 warning in 15.38s
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt tests/faults   (run 3 times)
  87 passed, 4 xfailed in ~9.0s  (each run)
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt tests/faults --runxfail
  4 failed: the xfails below, each failing on its own assertion
```

The warning is the existing Starlette `httpx` deprecation notice.

## Bugs found (kept as `xfail(strict=True)`)

1. **Restart aborts when a model charge was settled before its call record was written.**
   - Location: `src/colossus/control/worker.py:103-104` together with `src/colossus/control/store.py:409-413`.
   - Mechanism: `Broker.complete` calls `store.reconcile(call_id, actual)` at `broker.py:80`, then writes the `model_call` record at `broker.py:84-102`. If the controller dies between those two writes, the call is still `in_flight` but its reservation already has `actual` set. On restart, `Worker.reconcile` calls `store.reconcile(call_id, None)`, which raises `cost_conflict` ("Reconciled charge cannot change silently"), and controller startup fails.
   - Reproduction: `reserve("call-1", "case-1", 700, 1000, 1000)`, then put `model_call` `call-1` with status `in_flight`, then `reconcile("call-1", 250)`, then reopen the store and run `await Worker(...).reconcile()`.
   - Test: `test_fault_restart.py::test_restart_after_settled_charge_but_before_call_record`.
   - Suggested fix: skip the `reconcile(None)` when the reservation is already settled, or write the call status and the reconciliation in one transaction.

2. **A promotion interrupted by a controller crash leaves its case in `PROMOTING`, where the operator cannot see it.**
   - Location: `src/colossus/control/worker.py:65-139` (`reconcile` and `failed`). The case is invisible because of the status filter at `src/colossus/control/service.py:481`.
   - Mechanism: generation reconciliation itself works. The project deployment summary shows generation 1 with the new digest, the mirror is marked `STALE` and `/promote` is not replayed. But the case is never moved to `NEEDS_REVIEW`, which the in-process interruption path does at `deployment.py:229-246`, so it never appears in `Controller.actions`. Re-approval returns `stale_review` and a direct promote returns `case_not_ready`, so no route exists for the operator to resolve it (I20 visibility).
   - Reproduction: approve a `REVIEW_READY` case, claim the promote task, set the case to `PROMOTING`, then have the deployer report generation 1. Restart and run `Worker.reconcile()`.
   - Test: `test_fault_restart.py::test_crash_mid_promotion_surfaces_case_for_review`.

3. **A queued task that passes its deadline leaves its project bound to a dead cycle.**
   - Location: `src/colossus/control/store.py:294-296`.
   - Mechanism: `Store.claim` sets the task to `expired`, but nothing moves the cycle (stays `QUEUED`), clears `project.active_cycle_id` or finishes the operation (stays `accepted`). Every later `Controller.run` returns the dead cycle id (`service.py:95-96`). This can also happen while a project is paused, because queued deadlines keep running.
   - Reproduction: `controller.run(...)`, set `tasks.deadline` to the past, then call `store.claim(...)`. The claim returns None, but the cycle is still `QUEUED` and the project is still bound to it.
   - Test: `test_fault_leases.py::test_queued_task_past_deadline_releases_project`.

4. **The cancel operation receipt never reaches a terminal status.**
   - Location: `src/colossus/control/service.py:156-176`.
   - Mechanism: `Controller.cancel` returns the `mutate` receipt, but nothing calls `finish_operation` for it, unlike `admission` and `reject`. After the worker reconciles the cancellation (cycle `CANCELLED`, project released), the cancel receipt is still `accepted`.
   - Test: `test_fault_leases.py::test_cancel_receipt_reaches_a_terminal_status`.

## Observations (not xfail, no confirmed bug)

- **Malformed GitHub commit JSON produces untyped errors.** `source.py:123-136` raises `JSONDecodeError`, `KeyError` or `TypeError` instead of a `DomainError`. It still fails closed (no archive fetch, verified by a test), but the gateway answers with a generic 500 instead of a typed `source_fetch_failed`.
- **The deployer accepts no redirects, including GitHub's 301 for a renamed repository.** It returns `source_fetch_failed` HTTP 301. This is safe; it may deserve an explicit `repository_moved` capability state.
- **A suspended deployer promoter fails closed only by accident.** After another `LabDeployer` instance reconciles its intent, the suspended promoter fails because `state["intent"]` is None and `.get` raises `AttributeError` (`deployment/service.py:292` and `:316`). With a new intent present it would not check that the intent is its own (`authorization_id`), and the commit guard compares only the generation (`deployment/service.py:355-358`). Only one deployer process runs per state directory (`InstanceLock`), so this is a hardening note. The test covers the current fail-closed behaviour.
- **The ticket's "project cap" has no budget implementation.** `Store.reserve` enforces only the global (campaign) ceiling, the per-case ceiling and the request count. `budget_reservations` has no project column. I13 is tested against the caps that exist.
- **Settlement can exceed the cap.** `Store.reconcile` accepts an `actual` larger than the reservation, so committed spend can exceed the cap after settlement. The reservations themselves never exceed it.

## Remaining work

- Fix bugs 1 to 4 in `src/**` (owner: Daniel), then remove the `xfail` markers. They are strict, so each test will fail as XPASS once its bug is fixed.
- I07 with a real process kill (SIGKILL of the deployer or controller subprocess) is not covered. Kills are simulated by abandoning the coroutine and reopening the SQLite file.
- Cross-process duplicate delivery runs on threads with separate connections, not separate OS processes. The budget race does use OS processes.
