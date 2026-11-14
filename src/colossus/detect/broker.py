"""Minimal Mistral chat client for the detection lane.

Budget is reserved before every call, usage is recorded afterwards, and every call
is appended to a JSONL audit log (hashes only, never the API key or full prompts).
Fallback happens only on transport/5xx failures, never on refusals.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

# USD per million tokens (docs/model-strategy.md price snapshot)
PRICES = {
    "deepseek-v4-1-flash-1017": (0.30, 1.20),
    "zai-glm-5-3-flash": (0.15, 0.50),
    "codestral-2508": (0.30, 0.90),
}
DEFAULT_MODELS = ("deepseek-v4-1-flash-1017", "zai-glm-5-3-flash")


class BudgetExceeded(Exception):
    pass


class ModelRefused(Exception):
    pass


def load_api_key(env_path: str | Path = ".env") -> str:
    key = os.environ.get("MISTRAL_API_KEY")
    if key:
        return key
    for line in Path(env_path).read_text().splitlines():
        name, _, value = line.strip().partition("=")
        if name == "MISTRAL_API_KEY":
            return value
    raise RuntimeError("MISTRAL_API_KEY missing")


def cost_micro_usd(model: str, tokens_in: int, tokens_out: int) -> int:
    pin, pout = PRICES.get(model, (0.30, 1.20))
    return round(tokens_in * pin + tokens_out * pout)  # USD/M tokens == micro-USD/token


@dataclass
class Broker:
    api_key: str
    base_url: str = "https://api.mistral.ai/v1"
    models: tuple[str, ...] = DEFAULT_MODELS
    budget_micro_usd: int = 2_000_000
    max_calls: int = 20
    max_output_tokens: int = 4096
    log_path: Path | None = None
    spent_micro_usd: int = 0
    calls: int = 0
    records: list[dict] = field(default_factory=list)

    def _log(self, rec: dict) -> None:
        self.records.append(rec)
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def complete(self, messages: list[dict], *, json_mode: bool = False, task: str = "") -> dict:
        """Return {'text', 'model', 'cost_micro_usd', 'call_id'}."""
        if self.calls >= self.max_calls:
            raise BudgetExceeded("call cap reached")
        prompt_chars = sum(len(m["content"]) for m in messages)
        reserve = cost_micro_usd(self.models[0], prompt_chars // 3, self.max_output_tokens)
        if self.spent_micro_usd + reserve > self.budget_micro_usd:
            raise BudgetExceeded("budget reservation exceeds ceiling")
        last_err: Exception | None = None
        for model in self.models:
            for attempt in range(2):
                body = {
                    "model": model,
                    "messages": messages,
                    "max_tokens": self.max_output_tokens,
                    "temperature": 0.0,
                }
                if json_mode:
                    body["response_format"] = {"type": "json_object"}
                t0 = time.monotonic()
                try:
                    r = httpx.post(
                        f"{self.base_url}/chat/completions",
                        headers={"Authorization": f"Bearer {self.api_key}"},
                        json=body,
                        timeout=120,
                    )
                except httpx.HTTPError as exc:
                    last_err = exc
                    continue
                if r.status_code >= 500 or r.status_code == 429:
                    last_err = RuntimeError(f"HTTP {r.status_code}")
                    time.sleep(1 + attempt)
                    continue
                if r.status_code != 200:
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
                data = r.json()
                usage = data.get("usage", {})
                cost = cost_micro_usd(
                    model, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
                )
                self.spent_micro_usd += cost
                self.calls += 1
                choice = data["choices"][0]
                text = choice["message"]["content"] or ""
                call_id = data.get("id", "")
                self._log(
                    {
                        "call_id": call_id,
                        "task": task,
                        "model_requested": model,
                        "model_returned": data.get("model"),
                        "input_tokens": usage.get("prompt_tokens"),
                        "output_tokens": usage.get("completion_tokens"),
                        "cost_micro_usd": cost,
                        "request_sha256": hashlib.sha256(
                            json.dumps(messages, sort_keys=True).encode()
                        ).hexdigest(),
                        "seconds": round(time.monotonic() - t0, 2),
                        "finish_reason": choice.get("finish_reason"),
                        "fallback": model != self.models[0],
                    }
                )
                if choice.get("finish_reason") == "content_filter":
                    raise ModelRefused("provider content filter")
                return {"text": text, "model": model, "cost_micro_usd": cost, "call_id": call_id}
        raise RuntimeError(f"all models failed: {last_err}")
