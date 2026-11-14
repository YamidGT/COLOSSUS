"""Live CrossHair runs under gVisor on tiny self-written harnesses.

Skipped unless runsc is registered in COLOSSUS_DOCKER_CONTEXT and the trusted toolchain
image (tools/crosshair/Dockerfile) is present; COLOSSUS_CROSSHAIR_IMAGE may pin its digest.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from colossus.contracts.core import DomainError
from colossus.contracts.models import Obligation
from colossus.sandbox.launcher import LABEL, SandboxLauncher
from colossus.verification.crosshair import (
    BOUND_PROFILE_ID,
    CrossHairAdapter,
    Harness,
    gate_status,
    inspect_harness,
)

CONTEXT = os.environ.get("COLOSSUS_DOCKER_CONTEXT", "colima-colossus")
PROJECT = "00000000-0000-4000-8000-0000000000c1"


def _image() -> str | None:
    try:
        launcher = SandboxLauncher(CONTEXT)
        if not launcher.preflight().get("ready"):
            return None
        ref = os.environ.get("COLOSSUS_CROSSHAIR_IMAGE", "colossus-crosshair:0.0.113")
        return launcher.checked("image", "inspect", ref, "--format", "{{.Id}}")
    except Exception:  # noqa: BLE001
        return None


IMAGE = _image()
pytestmark = [
    pytest.mark.gvisor,
    pytest.mark.skipif(IMAGE is None, reason=f"runsc or CrossHair image missing in {CONTEXT}"),
]

BUGGY = b'''def double(x: int) -> int:
    """
    pre: 0 <= x <= 1000
    post: __return__ < 1500
    """
    return x * 2
'''
CLEAN = b'''def clamp(x: int) -> int:
    """
    post: 0 <= __return__
    post: __return__ <= 10
    """
    if x < 0:
        return 0
    if x > 10:
        return 10
    return x
'''
SPIN = b'''def spin(x: int) -> int:
    """
    post: __return__ >= 0
    """
    return sum(range(10**11)) + abs(x)
'''
LOOP = b'''def walk(x: int) -> int:
    """
    post: __return__ == 0
    """
    while x != 7 or True:
        x += 1
    return 0
'''
SIDE = b'''def touch(x: int) -> int:
    """
    post: __return__ == x
    """
    with open("/tmp/x", "w") as handle:
        handle.write("a")
    return x
'''


def obligation(source: bytes, symbol: str, kind: str = "bounded", **bounds) -> Obligation:
    facts = inspect_harness("harness.py", source, symbol)
    assert isinstance(facts, Harness)
    return Obligation(
        obligation_id="obl-" + symbol,
        description="self-written CrossHair fixture",
        origin="approved_template",
        source_ref="harness.py:" + symbol,
        approved=True,
        required=True,
        component="fixture",
        symbol=symbol,
        backend="crosshair",
        spec_hash=facts.spec_hash,
        harness_hash=hashlib.sha256(source).hexdigest(),
        assumptions=["fixture only"],
        bounds={"deadline_seconds": 60, "per_condition_timeout": 20} | bounds,
        required_evidence_kind=kind,
        allowed_bound_profile_id=BOUND_PROFILE_ID if kind == "bounded" else None,
    )


@pytest.fixture(scope="module")
def adapter():
    launcher = SandboxLauncher(CONTEXT)
    yield CrossHairAdapter(launcher, IMAGE)
    left = launcher.checked(
        "ps", "-a", "--filter", "label=org.colossus.project=" + PROJECT, "--format", "{{.Names}}"
    )
    assert left == "", "CrossHair sandbox left behind: " + left


def check(adapter, source, symbol, kind="bounded", **bounds):
    ob = obligation(source, symbol, kind, **bounds)
    evidence = adapter.execute(PROJECT, ob, {"harness.py": source}, "harness.py")
    return evidence, gate_status(evidence, ob)


def test_real_counterexample(adapter):
    evidence, status = check(adapter, BUGGY, "double")
    assert evidence["proof_outcome"] == "COUNTEREXAMPLE", evidence
    call = evidence["counterexample"]["call"]
    assert call.startswith("double(")
    x = int(call.removeprefix("double(").removesuffix(")"))
    assert 750 <= x <= 1000 and x * 2 >= 1500  # the concrete input really violates the post
    assert status == "fail"
    assert evidence["network"] == "none" and evidence["toolchain_digest"] == IMAGE


def test_bounded_clean(adapter):
    evidence, status = check(adapter, CLEAN, "clamp")
    assert evidence["proof_outcome"] == "BOUNDED_PASS", evidence
    assert evidence["exploration"] == "exhausted" and status == "pass"
    assert {c["line"] for c in evidence["conditions"]} == {3, 4}
    # Same clean run for a proof-required obligation is not a pass.
    proof, proof_status = check(adapter, CLEAN, "clamp", kind="proof")
    assert proof["proof_outcome"] == "UNKNOWN" and proof_status != "pass"


def test_hard_deadline_is_unknown(adapter):
    evidence, status = check(adapter, SPIN, "spin", deadline_seconds=8, per_condition_timeout=5)
    assert evidence["proof_outcome"] == "UNKNOWN", evidence
    assert evidence["timed_out"] is True and status == "timeout"


def test_exhausted_budget_without_counterexample_is_unknown(adapter):
    evidence, status = check(adapter, LOOP, "walk", deadline_seconds=30, per_condition_timeout=4)
    assert evidence["proof_outcome"] == "UNKNOWN", evidence
    assert evidence["exploration"] == "incomplete" and status == "error"


def test_side_effect_is_unsupported(adapter):
    evidence, status = check(adapter, SIDE, "touch")
    assert evidence["proof_outcome"] == "UNSUPPORTED", evidence
    assert status == "error"


def test_tampered_harness_is_refused_before_execution(adapter):
    ob = obligation(CLEAN, "clamp")
    weakened = CLEAN.replace(b"post: __return__ <= 10", b"post: True")
    with pytest.raises(DomainError):
        adapter.execute(PROJECT, ob, {"harness.py": weakened}, "harness.py")


def test_wrong_toolchain_image_is_refused():
    launcher = SandboxLauncher(CONTEXT)
    base = json.loads(launcher.checked("image", "inspect", IMAGE))[0]
    assert base["Config"]["Labels"][LABEL] == "true"
    python = launcher.checked(
        "image",
        "inspect",
        "python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b",
        "--format",
        "{{.Id}}",
    )
    with pytest.raises(DomainError) as error:
        CrossHairAdapter(launcher, python).execute(
            PROJECT, obligation(CLEAN, "clamp"), {"harness.py": CLEAN}, "harness.py"
        )
    assert error.value.code == "formal_toolchain"
