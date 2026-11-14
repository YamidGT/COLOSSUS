import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from colossus.contracts import (
    ALL_TYPES,
    ContractError,
    Envelope,
    ErrorCode,
    RuntimeConfig,
    canonical_json,
    content_hash,
    wrap,
)
from colossus.contracts.fixtures import INVALID, U, VALID

ROOT = Path(__file__).resolve().parents[2]


def load(model, data):
    return model.model_validate_json(json.dumps(data))


def test_every_type_has_valid_and_invalid_fixture():
    assert set(VALID) == set(ALL_TYPES)
    assert set(INVALID) == set(ALL_TYPES)


@pytest.mark.parametrize("name", sorted(VALID))
def test_valid_fixture_round_trips(name):
    obj = load(ALL_TYPES[name], VALID[name])
    again = load(ALL_TYPES[name], obj.model_dump(mode="json"))
    assert content_hash(obj) == content_hash(again)


@pytest.mark.parametrize("name", sorted(INVALID))
def test_invalid_fixture_is_rejected(name):
    _, data = INVALID[name]
    with pytest.raises(ValidationError):
        load(ALL_TYPES[name], data)


def test_unknown_field_rejected_everywhere():
    for name, model in ALL_TYPES.items():
        with pytest.raises(ValidationError):
            load(model, {**VALID[name], "unexpected": 1})


def test_strict_bool_and_int():
    with pytest.raises(ValidationError):
        load(ALL_TYPES["Enrollment"], {**VALID["Enrollment"], "start_cycle": "true"})
    with pytest.raises(ValidationError):
        load(ALL_TYPES["DeploymentResult"], {**VALID["DeploymentResult"], "generation": 1.0})


def test_non_formal_gate_cannot_carry_proof_outcome():
    with pytest.raises(ValidationError):
        load(ALL_TYPES["GateResult"], {**VALID["GateResult"], "category": "security", "status": "pass"})


def test_formal_pass_needs_proved_or_bounded():
    good = {**VALID["GateResult"], "status": "pass", "proof_outcome": "PROVED"}
    assert load(ALL_TYPES["GateResult"], good).status == "pass"
    for outcome in ("UNKNOWN", "UNSUPPORTED", "COUNTEREXAMPLE"):
        with pytest.raises(ValidationError):
            load(ALL_TYPES["GateResult"], {**good, "proof_outcome": outcome})


def test_formal_required_enrollment_needs_requirements():
    with pytest.raises(ValidationError):
        load(ALL_TYPES["Enrollment"], {**VALID["Enrollment"], "assurance_profile": "formal_required"})


def test_canonical_json_is_stable_and_rejects_nan():
    assert canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_envelope_round_trip_and_tamper_detection():
    payload = load(ALL_TYPES["Finding"], VALID["Finding"])
    env = wrap(payload, message_id=U[30], project_id=U[1], producer="lane-b", created_at="2026-11-14T12:00:00Z")
    parsed = Envelope.model_validate_json(env.model_dump_json())
    assert parsed.verify() == payload
    tampered = parsed.model_copy(update={"payload": {**parsed.payload, "title": "other"}})
    with pytest.raises(ContractError) as err:
        tampered.verify()
    assert err.value.error.code is ErrorCode.PAYLOAD_HASH_MISMATCH


def test_envelope_rejects_unknown_kind_and_version():
    payload = load(ALL_TYPES["Finding"], VALID["Finding"])
    data = wrap(payload, message_id=U[30], project_id=U[1], producer="b", created_at="2026-11-14T12:00:00Z").model_dump(mode="json")
    with pytest.raises(ValidationError):
        Envelope.model_validate_json(json.dumps({**data, "kind": "ShellCommand"}))
    with pytest.raises(ValidationError):
        Envelope.model_validate_json(json.dumps({**data, "schema_version": "2.0"}))


def test_documented_examples_validate():
    enrollment = (ROOT / "docs/examples/enrollment.json").read_text()
    ALL_TYPES["Enrollment"].model_validate_json(enrollment)
    cfg = RuntimeConfig.load(ROOT / "docs/examples/runtime-config.json")
    assert cfg.standard.case_seconds == 5400 and cfg.budget.case_ceiling_micro_usd == 2_000_000
    assert cfg == RuntimeConfig(documentation_example=True)


def test_runtime_config_rejects_broken_accounting():
    with pytest.raises(ValidationError):
        RuntimeConfig.model_validate_json(json.dumps({"budget": {"contingency_micro_usd": 1}}))
    with pytest.raises(ValidationError):
        RuntimeConfig.model_validate_json(json.dumps({"standard": {"max_candidates": 4}}))
