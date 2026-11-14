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
