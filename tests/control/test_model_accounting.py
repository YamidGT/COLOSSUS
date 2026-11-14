import httpx
import pytest

from colossus.gateway.model import ModelGateway, cost_micro_usd, request_reservation


def test_pricing_uses_billed_tokens_without_reasoning_double_count():
    assert cost_micro_usd(32000, 8000) == 8800
    assert request_reservation([{"role": "user", "content": "x" * 32000}], 8000) >= 8800


@pytest.mark.asyncio
async def test_refusal_keeps_cost_and_does_not_retry():
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "model": "test",
                "choices": [{"message": {"refusal": "no"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result = await ModelGateway("private-test-key", client).complete(
            [{"role": "user", "content": "test"}]
        )
    assert result.reason_code == "refused" and result.actual_cost_micro_usd == 40
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_provider_error_never_returns_echoed_key():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(403, json={"message": "private-test-key"})
        )
    ) as client:
        result = await ModelGateway("private-test-key", client).complete(
            [{"role": "user", "content": "test"}]
        )
    assert result.content is None and result.reason_code == "provider_policy_block"
    assert result.actual_cost_micro_usd is None


@pytest.mark.asyncio
async def test_gateway_accepts_text_chunks_without_retaining_thinking():
    import httpx

    from colossus.gateway.model import ModelGateway

    async def response(request):
        return httpx.Response(
            200,
            json={
                "model": "zai-glm-5-3-flash",
                "choices": [
                    {
                        "message": {
                            "content": [
                                {"type": "thinking", "thinking": [{"text": "private chain"}]},
                                {"type": "text", "text": '{"status":"ready"}'},
                            ]
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        gateway = ModelGateway("test-key", client)
        result = await gateway.complete([{"role": "user", "content": "ready"}], 50, "low", True)
    assert result.status == "succeeded" and result.content == '{"status":"ready"}'
    assert result.actual_cost_micro_usd is not None
    assert "private chain" not in str(result)


@pytest.mark.asyncio
async def test_cancelled_model_request_preserves_uncertain_budget(tmp_path):
    import asyncio

    from colossus.contracts.core import new_id
    from colossus.contracts.runtime import RuntimeConfig
    from colossus.control.artifacts import ArtifactStore
    from colossus.control.broker import Broker
    from colossus.control.store import Store

    entered = asyncio.Event()

    class Gateway:
        async def call(self, path, body):
            entered.set()
            await asyncio.Event().wait()

    store = Store(tmp_path / "state.sqlite3")
    broker = Broker(store, ArtifactStore(tmp_path / "artifacts"), Gateway(), RuntimeConfig())
    project_id, case_id = new_id(), new_id()
    task = asyncio.create_task(
        broker.complete(project_id, case_id, [{"role": "user", "content": "test"}])
    )
    await entered.wait()
    before = store.budget(case_id)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    record = store.list("model_call", project_id)[0]
    assert record["status"] == "uncertain" and record["reason_code"] == "cancelled_in_flight"
    assert record["actual_cost_micro_usd"] is None
    assert store.budget(case_id)["committed_micro_usd"] == before["committed_micro_usd"] > 0
    assert store.verify_audit()
    store.close()
