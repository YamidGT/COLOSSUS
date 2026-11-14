"""Mistral transport; credentials never leave this process."""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from colossus.contracts.core import DomainError, canonical_json, content_hash

MODEL_ID = "zai-glm-5-3-flash"
API_URL = "https://api.mistral.ai/v1"
PROFILE = {
    "provider": "mistral",
    "model": MODEL_ID,
    "api_url": API_URL,
    "input_micro_usd_per_million": 150000,
    "output_micro_usd_per_million": 500000,
    "price_date": "2026-11-14",
    "source": "https://docs.mistral.ai/models/zai-glm-5-3-flash",
}


def load_provider_key(env_file: Path | None) -> str | None:
    """Read only the required variable; no shell expansion or file execution."""
    if value := os.environ.get("MISTRAL_API_KEY"):
        return value
    if env_file is None or not env_file.is_file() or env_file.is_symlink():
        return None
    for line in env_file.read_text().splitlines():
        if line.startswith("MISTRAL_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'") or None
    return None


def cost_micro_usd(input_tokens: int, output_tokens: int) -> int:
    return math.ceil(
        (
            input_tokens * PROFILE["input_micro_usd_per_million"]
            + output_tokens * PROFILE["output_micro_usd_per_million"]
        )
        / 1_000_000
    )


def request_reservation(messages: list[dict], max_tokens: int) -> int:
    # UTF-8 bytes plus protocol overhead is conservative for byte-based tokenizers.
    input_bound = len(canonical_json(messages)) + 256 * len(messages)
    return cost_micro_usd(input_bound, max_tokens)


@dataclass(frozen=True)
class Completion:
    status: str
    content: str | None
    model_returned: str | None
    provider_request_id: str | None
    input_tokens: int | None
    output_tokens: int | None
    actual_cost_micro_usd: int | None
    reason_code: str | None
    elapsed_seconds: float
    usage: dict


class ModelGateway:
    def __init__(self, key: str | None, client: httpx.AsyncClient):
        self._key = key
        self.client = client

    @property
    def configured(self) -> bool:
        return bool(self._key)

    async def complete(
        self,
        messages: list[dict],
        max_tokens: int = 4096,
        reasoning: str = "low",
        json_output: bool = True,
    ) -> Completion:
        if not self._key:
            raise DomainError(
                "missing_model_key", "Mistral gateway credential is not configured", 503
            )
        if reasoning not in {"low", "high", "max"} or not 1 <= max_tokens <= 8192:
            raise DomainError("invalid_model_profile", "Unsupported model effort/output limit", 422)
        if not messages or len(messages) > 30 or len(canonical_json(messages)) > 128_000:
            raise DomainError("context_limit", "Model context exceeds the configured limit", 413)
        for message in messages:
            if (
                set(message) != {"role", "content"}
                or message["role"] not in {"system", "user", "assistant"}
                or not isinstance(message["content"], str)
            ):
                raise DomainError("invalid_messages", "Invalid model message", 422)
        payload = {
            "model": MODEL_ID,
            "messages": messages,
            "max_tokens": max_tokens,
            "reasoning_effort": reasoning,
        }
        if json_output:
            payload["response_format"] = {"type": "json_object"}
        started = time.monotonic()
        request_id = None
        try:
            response = await self.client.post(
                API_URL + "/chat/completions",
                json=payload,
                headers={"Authorization": "Bearer " + self._key},
                timeout=180,
            )
            request_id = response.headers.get("x-request-id")
        except (httpx.TimeoutException, httpx.TransportError):
            return Completion(
                "uncertain",
                None,
                None,
                request_id,
                None,
                None,
                None,
                "transport_error",
                time.monotonic() - started,
                {},
            )
        elapsed = time.monotonic() - started
        if response.status_code != 200:
            reason = (
                "rate_limited"
                if response.status_code == 429
                else "provider_policy_block"
                if response.status_code == 403
                else "unsupported_parameter"
                if response.status_code == 400
                else "provider_error"
            )
            # Do not store raw upstream error content: it may echo credentials/input.
            return Completion(
                "failed",
                None,
                None,
                request_id,
                None,
                None,
                None,
                reason,
                elapsed,
                {"http_status": response.status_code},
            )
        try:
            data = response.json()
            usage = data.get("usage", {})
            input_tokens = usage.get("prompt_tokens")
            output_tokens = usage.get("completion_tokens")
            valid_usage = (
                type(input_tokens) is int
                and input_tokens >= 0
                and type(output_tokens) is int
                and output_tokens >= 0
            )
            actual = cost_micro_usd(input_tokens, output_tokens) if valid_usage else None
            choice = data["choices"][0]
            message = choice["message"]
            if message.get("refusal") or choice.get("finish_reason") == "content_filter":
                return Completion(
                    "failed",
                    None,
                    data.get("model"),
                    request_id,
                    input_tokens,
                    output_tokens,
                    actual,
                    "refused",
                    elapsed,
                    usage,
                )
            content = message.get("content")
            if not isinstance(content, str) or len(content.encode()) > 128_000:
                raise ValueError("Invalid content")
            # Never retain hidden reasoning content. Expected output is bounded task JSON.
            content = content.replace(self._key, "[REDACTED]")
            reason = None
            if choice.get("finish_reason") == "length":
                reason = "output_truncated"
            elif json_output:
                try:
                    if not isinstance(json.loads(content), dict):
                        reason = "invalid_output"
                except ValueError:
                    reason = "invalid_output"
            return Completion(
                "failed" if reason else "succeeded",
                content,
                data.get("model"),
                request_id,
                input_tokens if valid_usage else None,
                output_tokens if valid_usage else None,
                actual,
                reason,
                elapsed,
                usage,
            )
        except (KeyError, IndexError, ValueError, TypeError):
            return Completion(
                "uncertain",
                None,
                None,
                request_id,
                None,
                None,
                None,
                "invalid_response",
                elapsed,
                {},
            )

    def metadata(self) -> dict:
        return {
            "configured": self.configured,
            "profile": PROFILE,
            "profile_hash": content_hash(PROFILE),
        }
