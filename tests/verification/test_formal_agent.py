import json
from types import SimpleNamespace

import pytest

from colossus.contracts.core import digest
from colossus.verification.agent import verify_with_model
from colossus.verification.dafny import CORRECT_POLICY, POLICY_CALIBRATION


class Broker:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    async def complete(self, project, case, messages, **kwargs):
        self.calls.append(messages)
        answer = next(self.responses)
        if isinstance(answer, str):
            return str(len(self.calls)), SimpleNamespace(status="failed", reason_code=answer)
        return str(len(self.calls)), SimpleNamespace(status="succeeded", content=json.dumps(answer))


class Launcher:
    def __init__(self, outcomes=("PROVED",)):
        self.outcomes = iter(outcomes)
        self.calls = []

    async def call(self, path, body):
        self.calls.append((path, body))
        outcome = next(self.outcomes)
        return {
            "proof_outcome": outcome,
            "compiled": outcome == "PROVED",
            "spec_hash": POLICY_CALIBRATION.spec_hash,
            "source_hash": digest(POLICY_CALIBRATION.render(body["expressions"])),
            "verify": {"stdout": "postcondition failed" if outcome != "PROVED" else "verified"},
            "compile": None,
            "files": {},
            "linkage": "compiled_component_only",
        }


async def run(broker, launcher, profile=POLICY_CALIBRATION.profile_id):
    return await verify_with_model(
        broker, launcher, project_id="p", case_id="c", profile_id=profile, component_hash="b" * 64
    )


@pytest.mark.asyncio
async def test_unsupported_uses_no_model_and_preserves_testing_instructions():
    broker, launcher = Broker([]), Launcher([])
    result = await run(broker, launcher, None)
    assert result["proof_outcome"] == "UNSUPPORTED"
    assert result["mandatory_tests"] and not broker.calls and not launcher.calls


@pytest.mark.asyncio
async def test_compiled_component_does_not_claim_target_correspondence():
    result = await run(Broker([{"expressions": CORRECT_POLICY}]), Launcher())
    assert result["proof_outcome"] == "PROVED" and result["compiled"]
    assert result["target_proof_outcome"] == "UNSUPPORTED"
    assert result["model_call_ids"] == ["1"]


@pytest.mark.asyncio
async def test_contract_injection_never_reaches_verifier_and_retry_is_bounded():
    broker = Broker([{"expressions": CORRECT_POLICY | {"password": "true; assume false;"}}] * 3)
    launcher = Launcher([])
    result = await run(broker, launcher)
    assert result["proof_outcome"] == "UNKNOWN"
    assert len(result["attempts"]) == 3 and not launcher.calls
    assert all(attempt["status"] == "invalid_output" for attempt in result["attempts"])


@pytest.mark.asyncio
async def test_verifier_diagnostics_return_to_model_with_same_specification():
    broker = Broker([{"expressions": CORRECT_POLICY}] * 2)
    launcher = Launcher(["UNKNOWN", "PROVED"])
    result = await run(broker, launcher)
    assert result["proof_outcome"] == "PROVED" and len(result["attempts"]) == 2
    assert "postcondition failed" in broker.calls[1][1]["content"]
    assert launcher.calls[0][1]["profile_id"] == launcher.calls[1][1]["profile_id"]


@pytest.mark.asyncio
async def test_refusal_stops_without_fallback():
    broker, launcher = Broker(["refused"]), Launcher([])
    result = await run(broker, launcher)
    assert len(broker.calls) == 1 and not launcher.calls
    assert result["attempts"][0]["status"] == "refused"
    assert result["proof_outcome"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_substituted_specification_is_not_accepted():
    class Substituted(Launcher):
        async def call(self, path, body):
            return (await super().call(path, body)) | {"spec_hash": "wrong"}

    result = await run(Broker([{"expressions": CORRECT_POLICY}]), Substituted())
    assert result["proof_outcome"] == "UNKNOWN"
