"""Controller-side model admission and reconciliation across the gateway boundary."""

import asyncio

from colossus.contracts.core import content_hash, new_id, utcnow
from colossus.contracts.runtime import RuntimeConfig
from colossus.control.artifacts import ArtifactStore
from colossus.control.rpc import RPCClient
from colossus.control.store import Store
from colossus.gateway.model import PROFILE, Completion, request_reservation


class Broker:
    def __init__(
        self, store: Store, artifacts: ArtifactStore, gateway: RPCClient, runtime: RuntimeConfig
    ):
        self.store, self.artifacts, self.gateway, self.runtime = store, artifacts, gateway, runtime

    async def complete(
        self,
        project_id: str,
        case_id: str,
        messages: list[dict],
        max_tokens: int = 4096,
        reasoning: str = "low",
    ) -> tuple[str, Completion]:
        call_id = new_id()
        reservation = request_reservation(messages, max_tokens)
        self.store.reserve(
            call_id,
            case_id,
            reservation,
            self.runtime.automatic_ceiling_micro_usd,
            self.runtime.case_ceiling_micro_usd,
            self.runtime.max_model_requests,
        )
        record = dict(
            call_id=call_id,
            task_id=case_id,
            provider="mistral",
            endpoint_profile_id="mistral-chat-v1",
            model_profile_hash=content_hash(PROFILE),
            model_requested=PROFILE["model"],
            model_returned=None,
            reasoning_effort=reasoning,
            template_version="1",
            request_hash=content_hash(messages),
            response_content_id=None,
            input_tokens=None,
            output_tokens=None,
            billing_usage={},
            reserved_cost_micro_usd=reservation,
            actual_cost_micro_usd=None,
            status="in_flight",
            reason_code=None,
            provider_request_id=None,
            price_snapshot_id=PROFILE["price_date"],
            created_at=utcnow(),
        )
        self.store.put("model_call", call_id, record, project_id)
        try:
            raw = await self.gateway.call(
                "/complete",
                dict(
                    call_id=call_id,
                    messages=messages,
                    max_tokens=max_tokens,
                    reasoning=reasoning,
                    json_output=True,
                ),
            )
            result = Completion(**raw)
        except (Exception, asyncio.CancelledError) as exc:
            self.store.reconcile(call_id, None)
            self.store.put(
                "model_call",
                call_id,
                record
                | {
                    "status": "uncertain",
                    "reason_code": "cancelled_in_flight"
                    if isinstance(exc, asyncio.CancelledError)
                    else "gateway_error",
                },
                project_id,
            )
            raise
        self.store.reconcile(call_id, result.actual_cost_micro_usd)
        response_id = (
            self.artifacts.put(result.content.encode()) if result.content is not None else None
        )
        self.store.put(
            "model_call",
            call_id,
            record
            | {
                "status": result.status,
                "model_returned": result.model_returned,
                "response_content_id": response_id,
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "actual_cost_micro_usd": result.actual_cost_micro_usd,
                "reason_code": result.reason_code,
                "provider_request_id": result.provider_request_id,
                "billing_usage": result.usage,
                "elapsed_seconds": result.elapsed_seconds,
            },
            project_id,
        )
        return call_id, result
