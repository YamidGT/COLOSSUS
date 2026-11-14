"""Typed payloads from docs/contracts.md "Typed payloads" (schema 1.0).

Field names and enums follow the table exactly. Optional fields are nullable,
never sentinel strings. Hash-bearing objects contain no floats.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from .common import (
    BoundedList,
    ImageDigest,
    LongText,
    MicroUsd,
    Platform,
    ProfileId,
    RelPath,
    Sha256,
    ShortText,
    StrictModel,
    TokenCount,
    UtcTimestamp,
    Uuid,
)

_GITHUB_URL = re.compile(r"^https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")


def _check_github_url(value: str) -> str:
    if "@" in value or not _GITHUB_URL.fullmatch(value) or value.endswith((".", ".git")):
        raise ValueError("repo_url must be https://github.com/OWNER/REPO without credentials or .git")
    return value


GitHubUrl = Annotated[str, AfterValidator(_check_github_url)]
GitRef = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._/-]+$")]
GitCommit = Annotated[str, Field(pattern=r"^[0-9a-f]{40}([0-9a-f]{24})?$")]
Port = Annotated[int, Field(ge=1, le=65535)]


# ---------------------------------------------------------------- enrollment

class AssuranceProfile(StrEnum):
    TESTED = "tested"
    FORMAL_REQUIRED = "formal_required"


class Enrollment(StrictModel):
    repo_url: GitHubUrl
    requested_ref: GitRef | None
    subdir: RelPath | None
    owner_policy_id: ProfileId
    deployment_profile_id: ProfileId
    assurance_profile: AssuranceProfile
    requirement_ids: BoundedList(ProfileId, 64)
    start_cycle: bool = False

    @model_validator(mode="after")
    def _formal_needs_requirements(self) -> "Enrollment":
        if self.assurance_profile is AssuranceProfile.FORMAL_REQUIRED and not self.requirement_ids:
            raise ValueError("formal_required enrollment needs approved requirement_ids")
        return self


# ---------------------------------------------------------------- target

class TargetKind(StrEnum):
    WEB = "web"
    MULTISERVICE = "multiservice"
    LIBRARY = "library"


class ServiceSpec(StrictModel):
    """Never host mounts or credentials: there are deliberately no such fields."""

    service_id: ProfileId
    artifact_digest: ImageDigest
    command_profile_id: ProfileId
    internal_ports: BoundedList(Port, 16)
    resource_profile_id: ProfileId
    dependency_service_ids: BoundedList(ProfileId, 16)
    health_check_id: ProfileId
    writable_paths: BoundedList(RelPath, 16)


class TargetManifest(StrictModel):
    manifest_id: Uuid
    revision: Annotated[int, Field(ge=1)]
    project_id: Uuid
    repo_url: GitHubUrl
    commit: GitCommit
    tree_sha256: Sha256
    platform: Platform
    target_kind: TargetKind
    recipe_id: ProfileId
    recipe_hash: Sha256
    artifact_digest: ImageDigest
    services: BoundedList(ServiceSpec, 16)
    dependency_inventory_id: Uuid
    dependency_inventory_hash: Sha256
    test_profile_ids: BoundedList(ProfileId, 64)
    readiness_profile_id: ProfileId
    data_seed_id: ProfileId
    obligation_ids: BoundedList(ProfileId, 64)
    protected_paths: BoundedList(RelPath)
    allowed_patch_paths: BoundedList(RelPath)
    network_profile_id: ProfileId
    deployment_profile_id: ProfileId
    policy_hash: Sha256
    toolchain_manifest_id: Uuid
    setup_provenance: BoundedList(ShortText, 64)

    @model_validator(mode="after")
    def _services_consistent(self) -> "TargetManifest":
        ids = [s.service_id for s in self.services]
        if len(ids) != len(set(ids)):
            raise ValueError("service_id values must be unique")
        known = set(ids)
        for s in self.services:
            missing = set(s.dependency_service_ids) - known
            if missing:
                raise ValueError(f"service {s.service_id} depends on unknown services")
        if self.target_kind is not TargetKind.LIBRARY and not self.services:
            raise ValueError("web and multiservice targets need at least one service")
        overlap = set(self.allowed_patch_paths) & set(self.protected_paths)
        if overlap:
            raise ValueError("a path cannot be both protected and patchable")
        return self


# ---------------------------------------------------------------- intel / findings

class AffectedStatus(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


class IntelEvent(StrictModel):
    source: ProfileId
    source_url: Annotated[str, Field(max_length=2048, pattern=r"^https://")]
    raw_content_id: Uuid
    raw_content_hash: Sha256
    fetched_at: UtcTimestamp
    published_at: UtcTimestamp | None
    modified_at: UtcTimestamp | None
    advisory_id: ShortText
    aliases: BoundedList(ShortText, 64)
    package: ShortText
    ecosystem: ShortText
    version: ShortText
    affected_status: AffectedStatus
    fixed_versions: BoundedList(ShortText, 64)
    severity_vector: ShortText | None
    severity_source: ShortText
    kev_status: bool | None
    replay: bool


class FindingStatus(StrEnum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"


class SeverityOrigin(StrEnum):
    OFFICIAL = "official"
    PREDICTED = "predicted"
    HEURISTIC = "heuristic"


class Disposition(StrEnum):
    RETAIN = "retain"
    SUPPRESS = "suppress"
    NEEDS_REVIEW = "needs_review"


class FindingLocation(StrictModel):
    file: RelPath | None
    symbol: ShortText | None
    route: ShortText | None

    @model_validator(mode="after")
    def _some_location(self) -> "FindingLocation":
        if self.file is None and self.symbol is None and self.route is None:
            raise ValueError("location needs at least one of file, symbol or route")
        return self


class Finding(StrictModel):
    finding_id: Uuid
    manifest_hash: Sha256
    fingerprint: Sha256
    title: ShortText
    cwe: Annotated[str, Field(pattern=r"^CWE-[0-9]{1,5}$")] | None
    location: FindingLocation
    status: FindingStatus
    source_tools: BoundedList(ProfileId, 32)
    evidence_ids: BoundedList(Uuid, 128)
    advisory_ids: BoundedList(ShortText, 64)
    severity_origin: SeverityOrigin
    cvss_vector: ShortText | None
    disposition: Disposition
    disposition_reason: ShortText

    @model_validator(mode="after")
    def _confirmed_needs_evidence(self) -> "Finding":
        if self.status is FindingStatus.CONFIRMED and not self.evidence_ids:
            raise ValueError("a confirmed finding needs evidence_ids")
        return self


# ---------------------------------------------------------------- repair

class PatchRoute(StrEnum):
    UPSTREAM = "upstream"
    GENERATED = "generated"


class PatchEdit(StrictModel):
    path: RelPath
    base_file_hash: Sha256
    exact_old: Annotated[str, Field(max_length=65536)]
    exact_new: Annotated[str, Field(max_length=65536)]

    @model_validator(mode="after")
    def _changes_something(self) -> "PatchEdit":
        if self.exact_old == self.exact_new:
            raise ValueError("edit must change content")
        return self


class DependencyUpdate(StrictModel):
    ecosystem: ShortText
    package: ShortText
    from_version: ShortText
    to_version: ShortText


class PatchProposal(StrictModel):
    proposal_id: Uuid
    base_tree_hash: Sha256
    finding_ids: Annotated[list[Uuid], Field(min_length=1, max_length=32)]
    route: PatchRoute
    edits: BoundedList(PatchEdit, 64)
    proposed_dependency_updates: BoundedList(DependencyUpdate, 32)
    rationale: LongText
    model_call_ids: BoundedList(Uuid, 32)

    @model_validator(mode="after")
    def _non_empty(self) -> "PatchProposal":
        if not self.edits and not self.proposed_dependency_updates:
            raise ValueError("proposal needs edits or dependency updates")
        return self


class Candidate(StrictModel):
    candidate_id: Uuid
    proposal_id: Uuid
    source_tree_hash: Sha256
    diff_hash: Sha256
    artifact_digest: ImageDigest
    generated_code_hash: Sha256 | None
    manifest_hash: Sha256
    build_evidence_ids: BoundedList(Uuid, 64)


# ---------------------------------------------------------------- verification

class ObligationOrigin(StrEnum):
    EXISTING_CONTRACT = "existing_contract"
    APPROVED_TEMPLATE = "approved_template"
    OWNER_APPROVED = "owner_approved"
    INFERRED = "inferred"


class EvidenceKind(StrEnum):
    PROOF = "proof"
    BOUNDED = "bounded"


class Obligation(StrictModel):
    obligation_id: ProfileId
    description: LongText
    origin: ObligationOrigin
    source_ref: ShortText
    approved: bool
    required: bool
    component: ShortText
    symbol: ShortText
    backend: Literal["dafny", "crosshair", "cbmc"]
    spec_hash: Sha256
    harness_hash: Sha256
    assumptions: BoundedList(ShortText, 64)
    bounds: dict[ShortText, int] = {}
    required_evidence_kind: EvidenceKind
    allowed_bound_profile_id: ProfileId | None

    @model_validator(mode="after")
    def _required_is_approved(self) -> "Obligation":
        if self.required and not self.approved:
            raise ValueError("a required obligation must be approved")
        if self.origin is ObligationOrigin.INFERRED and self.required:
            raise ValueError("inferred obligations cannot be required")
        return self


class GateCategory(StrEnum):
    BUILD = "build"
    FUNCTIONAL = "functional"
    SECURITY = "security"
    STATIC = "static"
    FORMAL = "formal"
    POLICY = "policy"


class GateStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    TIMEOUT = "timeout"
    NOT_APPLICABLE = "not_applicable"


class ProofOutcome(StrEnum):
    PROVED = "PROVED"
    BOUNDED_PASS = "BOUNDED_PASS"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class GateResult(StrictModel):
    gate_id: Uuid
    case_id: Uuid
    candidate_id: Uuid
    candidate_hash: Sha256
    check_profile_id: ProfileId
    category: GateCategory
    status: GateStatus
    proof_outcome: ProofOutcome | None
    scope: BoundedList(ShortText, 64)
    assumptions: BoundedList(ShortText, 64)
    tool_version: ShortText
    command_profile_hash: Sha256
    exit_code: int | None
    started_at: UtcTimestamp
    finished_at: UtcTimestamp
    evidence_ids: BoundedList(Uuid, 64)
    reason: ShortText

    @model_validator(mode="after")
    def _proof_rules(self) -> "GateResult":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        if self.category is GateCategory.FORMAL:
            if self.status is not GateStatus.NOT_APPLICABLE and self.proof_outcome is None:
                raise ValueError("a formal gate needs proof_outcome")
            if self.status is GateStatus.PASS and self.proof_outcome not in (
                ProofOutcome.PROVED,
                ProofOutcome.BOUNDED_PASS,
            ):
                raise ValueError("UNKNOWN/UNSUPPORTED/COUNTEREXAMPLE can never pass a formal gate")
            if self.status is GateStatus.PASS and not self.evidence_ids:
                raise ValueError("a formal pass without underlying results is invalid")
        elif self.proof_outcome is not None:
            raise ValueError("a non-formal gate must use null proof_outcome")
        return self


class EvidenceManifest(StrictModel):
    manifest_id: Uuid
    case_id: Uuid
    baseline_hash: Sha256
    candidate_hash: Sha256
    artifact_digest: ImageDigest
    diff_hash: Sha256
    target_manifest_hash: Sha256
    policy_hash: Sha256
    spec_hashes: BoundedList(Sha256, 64)
    harness_hashes: BoundedList(Sha256, 64)
    test_hashes: BoundedList(Sha256, 128)
    required_gate_ids: BoundedList(Uuid, 128)
    gate_result_ids: BoundedList(Uuid, 128)
    assurance_profile: AssuranceProfile
    proof_summary: BoundedList(ShortText, 64)
    exclusions: BoundedList(ShortText, 64)
    model_call_ids: BoundedList(Uuid, 128)
    total_cost_micro_usd: MicroUsd
    issued_at: UtcTimestamp
    content_hash: Sha256

    @model_validator(mode="after")
    def _required_gates_present(self) -> "EvidenceManifest":
        missing = set(self.required_gate_ids) - set(self.gate_result_ids)
        if missing:
            raise ValueError("every required gate needs a gate result")
        return self


# ---------------------------------------------------------------- deployment

class AuthorizationMode(StrEnum):
    OWNER_APPROVAL = "owner_approval"
    PREAUTHORIZED_POLICY = "preauthorized_policy"


class Authorization(StrictModel):
    authorization_id: Uuid
    project_id: Uuid
    evidence_manifest_hash: Sha256
    destination_id: ProfileId
    expected_deployment_generation: Annotated[int, Field(ge=0)]
    mode: AuthorizationMode
    actor_or_policy_id: ProfileId
    issued_at: UtcTimestamp
    expires_at: UtcTimestamp

    @model_validator(mode="after")
    def _expiry(self) -> "Authorization":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must follow issued_at")
        return self


class DeploymentStatus(StrEnum):
    STAGING = "STAGING"
    OBSERVING = "OBSERVING"
    PROMOTED = "PROMOTED"
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLED_BACK = "ROLLED_BACK"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    REJECTED = "REJECTED"


class RollbackResult(StrictModel):
    restored_digest: ImageDigest | None
    status: Literal["ROLLED_BACK", "RECOVERY_FAILED"]
    evidence_ids: BoundedList(Uuid, 64)


class DeploymentResult(StrictModel):
    deployment_id: Uuid
    authorization_id: Uuid
    previous_digest: ImageDigest | None
    candidate_digest: ImageDigest
    generation: Annotated[int, Field(ge=1)]
    status: DeploymentStatus
    readiness_evidence_ids: BoundedList(Uuid, 64)
    observation_evidence_ids: BoundedList(Uuid, 64)
    rollback_result: RollbackResult | None
    refreshed_manifest_hash: Sha256 | None


# ---------------------------------------------------------------- model calls

class ModelCallStatus(StrEnum):
    RESERVED = "reserved"
    IN_FLIGHT = "in_flight"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


class ModelReasonCode(StrEnum):
    REFUSED = "refused"
    PROVIDER_POLICY_BLOCK = "provider_policy_block"
    RATE_LIMITED = "rate_limited"
    UNSUPPORTED_PARAMETER = "unsupported_parameter"
    INVALID_OUTPUT = "invalid_output"
    TRANSPORT_ERROR = "transport_error"
    TIMEOUT = "timeout"


class ModelCall(StrictModel):
    call_id: Uuid
    task_id: Uuid
    provider: Literal["mistral", "groq"]
    endpoint_profile_id: ProfileId
    model_profile_hash: Sha256
    model_requested: ShortText
    model_returned: ShortText | None
    reasoning_effort: ShortText | None
    template_version: ShortText
    request_hash: Sha256
    response_content_id: Uuid | None
    input_tokens: TokenCount | None
    output_tokens: TokenCount | None
    billing_usage: dict[ShortText, int] = {}
    reserved_cost_micro_usd: MicroUsd
    actual_cost_micro_usd: MicroUsd | None
    status: ModelCallStatus
    reason_code: ModelReasonCode | None
    provider_request_id: ShortText | None
    price_snapshot_id: ProfileId

    @model_validator(mode="after")
    def _status_rules(self) -> "ModelCall":
        if self.status is ModelCallStatus.FAILED and self.reason_code is None:
            raise ValueError("a failed call needs reason_code")
        if self.status is ModelCallStatus.SUCCEEDED and self.reason_code is not None:
            raise ValueError("a succeeded call cannot carry a failure reason_code")
        return self


PAYLOAD_TYPES: dict[str, type[StrictModel]] = {
    cls.__name__: cls
    for cls in (
        Enrollment,
        ServiceSpec,
        TargetManifest,
        IntelEvent,
        Finding,
        PatchProposal,
        Candidate,
        Obligation,
        GateResult,
        EvidenceManifest,
        Authorization,
        DeploymentResult,
        ModelCall,
    )
}
