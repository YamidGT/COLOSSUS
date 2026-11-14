"""Runtime deadlines and admission budgets shared by every service."""

from pydantic import Field

from .core import Contract


class RuntimeConfig(Contract):
    case_seconds: int = Field(default=5400, ge=1)
    cycle_seconds: int = Field(default=7200, ge=1)
    onboarding_seconds: int = Field(default=1200, ge=1)
    investigation_seconds: int = Field(default=900, ge=1)
    triage_seconds: int = Field(default=300, ge=1)
    patch_seconds: int = Field(default=360, ge=1)
    build_test_seconds: int = Field(default=720, ge=1)
    proof_seconds: int = Field(default=480, ge=1)
    proof_obligation_seconds: int = Field(default=90, ge=1)
    observation_seconds: int = Field(default=300, ge=1)
    health_interval_seconds: int = Field(default=15, ge=1)
    refresh_seconds: int = Field(default=300, ge=1)
    recovery_seconds: int = Field(default=300, ge=1)
    max_candidates: int = Field(default=3, ge=1, le=3)
    max_model_requests: int = Field(default=20, ge=1, le=20)
    max_obligations: int = Field(default=5, ge=1, le=5)
    automatic_ceiling_micro_usd: int = Field(default=120_000_000, ge=0, le=120_000_000)
    case_ceiling_micro_usd: int = Field(default=2_000_000, ge=0)
    heavy_workers: int = Field(default=1, ge=1, le=1)
    model_requests_in_flight: int = Field(default=2, ge=1, le=2)
    feed_poll_seconds: int = Field(default=900, ge=60)
    source_poll_seconds: int = Field(default=300, ge=60)
    t1_seconds: int = Field(default=21600, ge=60)
    t2_seconds: int = Field(default=86400, ge=60)
    reaper_seconds: int = Field(default=60, ge=10)
    evidence_bytes_per_case: int = Field(default=104_857_600, ge=1024)

    def deadline(self, *deadlines: float) -> float:
        return min(deadlines)
