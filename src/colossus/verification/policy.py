"""Promotion eligibility is derived from required checks, never a model verdict."""

from colossus.contracts.core import DomainError, content_hash
from colossus.contracts.models import EvidenceManifest, GateResult

REQUIRED_CHECKS = frozenset(
    {
        "scope-base-v1",
        "baseline-reproduction-v1",
        "build-readiness-v1",
        "dsvw-security-v1",
        "dsvw-functional-v1",
        "static-regression-v1",
        "artifact-binding-v1",
    }
)


def validate_gates(gates: list[GateResult], candidate_hash: str, assurance: str):
    by_profile = {}
    binding = (gates[0].case_id, gates[0].candidate_id) if gates else None
    for gate in gates:
        if (
            gate.candidate_hash != candidate_hash
            or gate.check_profile_id in by_profile
            or (gate.case_id, gate.candidate_id) != binding
        ):
            raise DomainError(
                "gate_binding", "Gate is duplicated or bound to another candidate", 409
            )
        by_profile[gate.check_profile_id] = gate
    missing = REQUIRED_CHECKS - by_profile.keys()
    if missing:
        raise DomainError(
            "missing_gates", "Required checks missing: " + ", ".join(sorted(missing)), 409
        )
    if any(by_profile[name].status != "pass" for name in REQUIRED_CHECKS):
        raise DomainError("failed_gates", "A required candidate check did not pass", 409)
    formal = [g for g in gates if g.category == "formal"]
    if not formal:
        raise DomainError(
            "missing_formal_coverage", "Formal scope must be explicitly reported", 409
        )
    if assurance == "formal_required" and any(
        g.status != "pass" or g.proof_outcome != "PROVED" for g in formal
    ):
        raise DomainError(
            "formal_incomplete", "Required proof is unsupported, incomplete or failed", 409
        )


def validate_manifest_hash(manifest: EvidenceManifest):
    data = manifest.model_dump(exclude={"content_hash"})
    if content_hash(data) != manifest.content_hash:
        raise DomainError("evidence_tampered", "Evidence manifest hash is invalid", 409)
