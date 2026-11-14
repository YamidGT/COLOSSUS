"""I13 simultaneous reservations near the cap, across threads and OS processes on one SQLite."""

import asyncio
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

import pytest
from faultkit import FakeRPC, reserve_worker

from colossus.contracts.core import DomainError, new_id
from colossus.contracts.runtime import RuntimeConfig
from colossus.control.artifacts import ArtifactStore
from colossus.control.broker import Broker
from colossus.control.store import Store
from colossus.gateway.model import request_reservation

PROCESSES = 4


def race(path, attempts, amount, global_cap, case_cap, max_calls, same_case):
    ctx = multiprocessing.get_context("spawn")
    barrier, results = ctx.Barrier(PROCESSES), ctx.Queue()
    procs = [
        ctx.Process(
            target=reserve_worker,
            args=(
                str(path),
                barrier,
                results,
                i,
                attempts,
                amount,
                global_cap,
                case_cap,
                max_calls,
                same_case,
            ),
        )
        for i in range(PROCESSES)
    ]
    for p in procs:
        p.start()
    accepted = [results.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0
    return accepted


def committed(path, case_id=None):
    store = Store(path)
    try:
        return store.budget(case_id)
    finally:
        store.close()


@pytest.mark.parametrize(
    ("amount", "global_cap", "case_cap", "max_calls", "same_case", "expected"),
    [
        (70, 1_000, 1_000, 20, False, 14),  # global (campaign) ceiling binds
        (30, 10_000, 200, 20, True, 6),  # per-case ceiling binds
        (0, 10_000, 10_000, 5, True, 5),  # request-count cap binds even at zero cost
    ],
)
def test_cross_process_reservations_never_exceed_cap(
    tmp_path, amount, global_cap, case_cap, max_calls, same_case, expected
):
    path = tmp_path / "shared.db"
    Store(path).close()
    accepted = race(path, 10, amount, global_cap, case_cap, max_calls, same_case)
    assert sum(accepted) == expected
    totals = committed(path, "case-shared" if same_case else None)
    assert totals["committed_micro_usd"] == expected * amount
    assert totals["committed_micro_usd"] <= min(global_cap, case_cap if same_case else global_cap)
    assert totals["calls"] == expected


def test_threaded_broker_admission_near_cap(tmp_path):
    """Broker.complete reserves before the gateway call; refused calls never reach it."""
    path = tmp_path / "shared.db"
    stores = [Store(path) for _ in range(4)]
    artifacts = ArtifactStore(tmp_path / "a")
    gateway = FakeRPC(
        lambda p, body: {
            "status": "succeeded",
            "content": "{}",
            "model_returned": "m",
            "input_tokens": 1,
            "output_tokens": 1,
            "actual_cost_micro_usd": None,  # unknown charge: the reservation stays committed
            "reason_code": None,
            "provider_request_id": None,
            "usage": {},
            "elapsed_seconds": 0.0,
        }
    )
    messages = [{"role": "user", "content": "x"}]
    amount = request_reservation(messages, 16)
    assert amount > 0
    cap = 7 * amount + amount // 2
    runtime = RuntimeConfig(automatic_ceiling_micro_usd=cap, case_ceiling_micro_usd=cap)

    def attempt(i):
        broker = Broker(stores[i % 4], artifacts, gateway, runtime)
        try:
            asyncio.run(broker.complete("p", "case-1", messages, 16))
            return True
        except DomainError as exc:
            assert exc.code == "budget_stop"
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        accepted = sum(pool.map(attempt, range(40)))
    budget = stores[0].budget("case-1")
    assert accepted == 7 == budget["calls"] == len(gateway.calls)
    assert budget["committed_micro_usd"] == 7 * amount <= cap
    for s in stores:
        s.close()


def test_uncertain_charge_is_kept_against_the_cap(tmp_path):
    store = Store(tmp_path / "s.db")

    async def failing(path, body):
        raise ConnectionError("gateway lost")

    gateway = FakeRPC()
    gateway.call = failing
    broker = Broker(
        store,
        ArtifactStore(tmp_path / "a"),
        gateway,
        RuntimeConfig(automatic_ceiling_micro_usd=10**7, case_ceiling_micro_usd=10**7),
    )
    with pytest.raises(ConnectionError):
        asyncio.run(broker.complete("p", "case-1", [{"role": "user", "content": "x"}], 16))
    budget = store.budget("case-1")
    assert budget["calls"] == 1 and budget["settled_micro_usd"] == 0
    assert budget["uncertain_micro_usd"] == budget["committed_micro_usd"] > 0
    call = store.list("model_call")[0]
    assert call["status"] == "uncertain" and call["reason_code"] == "gateway_error"
    with pytest.raises(DomainError, match="budget"):
        store.reserve(new_id(), "case-1", 10**7, 10**7, 10**7)
    store.close()
