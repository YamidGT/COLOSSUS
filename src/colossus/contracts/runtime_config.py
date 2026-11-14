"""RuntimeConfig: limits from docs/runtime.md, in integer seconds and micro-USD."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, model_validator

from .common import MicroUsd, Seconds, StrictModel


class StandardLimits(StrictModel):
    case_seconds: Seconds = 90 * 60
    cycle_seconds: Seconds = 120 * 60
    onboarding_seconds: Seconds = 20 * 60
    investigation_seconds: Seconds = 15 * 60
    triage_seconds: Seconds = 5 * 60
    patch_seconds_per_candidate: Seconds = 6 * 60
    build_test_seconds_per_candidate: Seconds = 12 * 60
    proof_seconds_per_candidate: Seconds = 8 * 60
    proof_seconds_per_obligation: Seconds = 90
    max_obligations: Annotated[int, Field(ge=1, le=20)] = 5
    observation_seconds: Seconds = 5 * 60
    refresh_seconds: Seconds = 5 * 60
    max_candidates: Annotated[int, Field(ge=1, le=3)] = 3

    @model_validator(mode="after")
    def _nesting(self) -> "StandardLimits":
        if self.case_seconds > self.cycle_seconds:
            raise ValueError("case cap cannot exceed cycle cap")
        if self.proof_seconds_per_obligation > self.proof_seconds_per_candidate:
            raise ValueError("obligation slice cannot exceed candidate proof slice")
        return self


class HeavyLimits(StrictModel):
    case_seconds: Seconds = 180 * 60
    cycle_seconds: Seconds = 240 * 60
    observation_seconds: Seconds = 10 * 60


class SchedulerConfig(StrictModel):
    feed_poll_seconds: Seconds = 900
    source_poll_seconds: Seconds = 300
    source_debounce_seconds: Seconds = 60
    t1_seconds: Seconds = 6 * 3600
    t2_seconds: Seconds = 24 * 3600
    reaper_seconds: Seconds = 60


class ResourceConfig(StrictModel):
    heavy_workers: Annotated[int, Field(ge=1, le=1)] = 1
    model_requests_in_flight: Annotated[int, Field(ge=1, le=2)] = 2


class BudgetConfig(StrictModel):
    total_credit_micro_usd: MicroUsd = 150_000_000
    automatic_ceiling_micro_usd: MicroUsd = 120_000_000
    contingency_micro_usd: MicroUsd = 30_000_000
    case_ceiling_micro_usd: MicroUsd = 2_000_000

    @model_validator(mode="after")
    def _accounting(self) -> "BudgetConfig":
        if self.automatic_ceiling_micro_usd + self.contingency_micro_usd != self.total_credit_micro_usd:
            raise ValueError("ceiling + contingency must equal total credit")
        if self.case_ceiling_micro_usd > self.automatic_ceiling_micro_usd:
            raise ValueError("case ceiling cannot exceed automatic ceiling")
        return self


class RuntimeConfig(StrictModel):
    documentation_example: bool = False
    standard: StandardLimits = StandardLimits()
    heavy: HeavyLimits = HeavyLimits()
    scheduler: SchedulerConfig = SchedulerConfig()
    resources: ResourceConfig = ResourceConfig()
    budget: BudgetConfig = BudgetConfig()

    @classmethod
    def load(cls, path: str | Path) -> "RuntimeConfig":
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))
