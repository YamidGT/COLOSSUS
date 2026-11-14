import pytest

from colossus.contracts.core import DomainError, digest, new_id, utcnow
from colossus.contracts.models import Edit, GateResult, PatchProposal
from colossus.gateway.source import tree_hash
from colossus.repair.patch import apply_proposal
from colossus.verification.policy import REQUIRED_CHECKS, validate_gates


def proposal(files, path="app.py", old="bad()", new="safe()"):
    return PatchProposal(
        proposal_id=new_id(),
        base_tree_hash=tree_hash(files),
        finding_ids=[new_id()],
        route="generated",
        rationale="test",
        edits=[Edit(path=path, base_file_hash=digest(files[path]), exact_old=old, exact_new=new)],
    )


def test_patch_preserves_exact_base_and_protected_files():
    files = {"app.py": b"bad()\n", "tests.py": b"bad()\n"}
    patched, diff = apply_proposal(files, proposal(files), ["app.py"], ["tests.py"])
    assert patched == {"app.py": b"safe()\n", "tests.py": b"bad()\n"}
    assert "-bad()" in diff and "+safe()" in diff
    with pytest.raises(DomainError, match="protected"):
        apply_proposal(
            files, proposal(files, path="tests.py"), ["app.py", "tests.py"], ["tests.py"]
        )
    with pytest.raises(DomainError, match="snapshot"):
        apply_proposal(files | {"other.py": b"new()"}, proposal(files), ["app.py"], [])


def test_ambiguous_span_and_duplicate_edits_fail():
    files = {"app.py": b"bad(); bad()"}
    with pytest.raises(DomainError, match="exact nonempty"):
        apply_proposal(files, proposal(files), ["app.py"], [])


def gates():
    result = []
    case_id, candidate_id = new_id(), new_id()
    for profile in REQUIRED_CHECKS:
        result.append(
            GateResult(
                gate_id=new_id(),
                case_id=case_id,
                candidate_id=candidate_id,
                candidate_hash="a" * 64,
                check_profile_id=profile,
                category="policy",
                status="pass",
                scope=["test"],
                tool_version="1",
                command_profile_hash="b" * 64,
                started_at=utcnow(),
                finished_at=utcnow(),
                evidence_ids=[],
            )
        )
    result.append(
        GateResult(
            gate_id=new_id(),
            case_id=case_id,
            candidate_id=candidate_id,
            candidate_hash="a" * 64,
            check_profile_id="formal",
            category="formal",
            status="not_applicable",
            proof_outcome="UNSUPPORTED",
            scope=["test"],
            tool_version="1",
            command_profile_hash="b" * 64,
            started_at=utcnow(),
            finished_at=utcnow(),
            evidence_ids=[],
        )
    )
    return result


def test_required_gates_fail_closed_on_missing_failure_and_wrong_candidate():
    items = gates()
    validate_gates(items, "a" * 64, "tested")
    with pytest.raises(DomainError, match="missing"):
        validate_gates(items[1:], "a" * 64, "tested")
    items[0] = items[0].model_copy(update={"status": "fail"})
    with pytest.raises(DomainError, match="did not pass"):
        validate_gates(items, "a" * 64, "tested")
    with pytest.raises(DomainError, match="another candidate"):
        validate_gates(items, "c" * 64, "tested")


def test_tested_profile_does_not_upgrade_unsupported_to_proof():
    with pytest.raises(DomainError, match="Required proof"):
        validate_gates(gates(), "a" * 64, "formal_required")


def test_gates_from_another_case_cannot_be_reused():
    items = gates()
    items[0] = items[0].model_copy(update={"case_id": new_id()})
    with pytest.raises(DomainError, match="another candidate"):
        validate_gates(items, "a" * 64, "tested")
