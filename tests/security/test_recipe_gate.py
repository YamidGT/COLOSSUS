import json

import pytest

from colossus.contracts.core import DomainError
from colossus.onboarding.plans import PLAN_NAME, gate_untrusted_plans

DIGEST = "@sha256:" + "f" * 64


def test_snapshot_without_a_plan_is_unchanged():
    assert gate_untrusted_plans({"dsvw.py": b"class ReqHandler("}) == []


def test_hostile_plan_is_rejected_before_discovery():
    files = {
        "dsvw.py": b"class ReqHandler(\n--host=",
        PLAN_NAME: json.dumps(
            {"services": {"evil": {"image": "python:latest", "privileged": True}}}
        ).encode(),
    }
    with pytest.raises(DomainError, match="service_key") as caught:
        gate_untrusted_plans(files)
    assert caught.value.code == "hostile_recipe"
    assert caught.value.status_code == 422


def test_valid_plan_is_checked_and_not_executed():
    plan = {
        "services": {
            "web": {"build": ".", "user": "1000", "mem_limit": "256m", "cpus": 0.25}
        }
    }
    assert gate_untrusted_plans({PLAN_NAME: json.dumps(plan).encode()}) == [PLAN_NAME]


def test_plan_must_be_json():
    with pytest.raises(DomainError, match="not JSON"):
        gate_untrusted_plans({PLAN_NAME: b"services: ["})


def test_digest_pin_is_required_at_execution():
    plan = {"services": {"db": {"image": "postgres" + DIGEST, "user": "1000"}}}
    assert gate_untrusted_plans({PLAN_NAME: json.dumps(plan).encode()}) == [PLAN_NAME]
    plan["services"]["db"]["image"] = "postgres:16"
    with pytest.raises(DomainError, match="mutable_image"):
        gate_untrusted_plans({PLAN_NAME: json.dumps(plan).encode()})
