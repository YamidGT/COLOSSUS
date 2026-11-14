"""Versioned interchange objects used by all implementation lanes."""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from .core import Contract, Hash, Identifier, NonNegative, Text, safe_relative_path

ProofOutcome = Literal["PROVED", "BOUNDED_PASS", "COUNTEREXAMPLE", "UNKNOWN", "UNSUPPORTED"]
GateStatus = Literal["pass", "fail", "error", "timeout", "not_applicable"]
Assurance = Literal["tested", "formal_required"]


class Enrollment(Contract):
    repo_url: str = Field(max_length=512)
    requested_ref: str | None = Field(default=None, max_length=200)
    subdir: str | None = None
    owner_policy_id: Literal["lab-auto-v1", "review-v1"] = "lab-auto-v1"
    deployment_profile_id: Literal["local-web-v1", "local-consumer-v1"] = "local-web-v1"
    assurance_profile: Assurance = "tested"
    requirement_ids: list[str] = Field(default_factory=list, max_length=5)
    start_cycle: bool = False

    @field_validator("repo_url")
    @classmethod
    def github_url(cls, value: str) -> str:
        u = urlsplit(value)
        if (
            u.scheme != "https"
            or u.netloc != "github.com"
            or u.query
            or u.fragment
            or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", u.path)
        ):
            raise ValueError("Use a public https://github.com/OWNER/REPO URL")
        owner, repo = u.path.strip("/").split("/")
        repo = repo.removesuffix(".git")
        if owner in (".", "..") or repo in ("", ".", ".."):
            raise ValueError("Invalid GitHub repository")
        return f"https://github.com/{owner}/{repo}"

    @field_validator("subdir")
    @classmethod
    def subdirectory(cls, value: str | None) -> str | None:
        return safe_relative_path(value) if value is not None else None

    @field_validator("requested_ref")
    @classmethod
    def ref(cls, value: str | None) -> str | None:
        if value is not None and (
            not value or value.startswith("-") or any(ord(c) < 32 for c in value)
        ):
            raise ValueError("Invalid revision")
        return value

    @model_validator(mode="after")
    def requirements(self):
        if self.assurance_profile == "formal_required" and not self.requirement_ids:
            raise ValueError("Formal-required enrollment needs approved requirements")
        return self


class ServiceSpec(Contract):
    service_id: str
    artifact_digest: str
    command_profile_id: str
    internal_ports: list[int] = Field(default_factory=list, max_length=8)
    resource_profile_id: str = "standard"
    dependency_service_ids: list[str] = Field(default_factory=list)
    health_check_id: str
    writable_paths: list[str] = Field(default_factory=list)

    @field_validator("internal_ports")
    @classmethod
    def ports(cls, values):
        if any(type(v) is not int or not 1 <= v <= 65535 for v in values):
            raise ValueError("Invalid port")
        return values


class TargetManifest(Contract):
    manifest_id: Identifier
    revision: NonNegative
    project_id: Identifier
    repo_url: str
    commit: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    tree_sha256: Hash
    platform: str
    target_kind: Literal["web", "multiservice", "library"]
    recipe_id: str
    recipe_hash: Hash
    artifact_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    services: list[ServiceSpec]
    dependency_inventory_id: Hash
    dependency_inventory_hash: Hash
    test_profile_ids: list[str]
    readiness_profile_id: str
    data_seed_id: str
    obligation_ids: list[str] = Field(default_factory=list)
    protected_paths: list[str]
    allowed_patch_paths: list[str]
    network_profile_id: str = "isolated-case-v1"
    deployment_profile_id: str
    policy_hash: Hash
    toolchain_manifest_id: Hash
    setup_provenance: list[dict] = Field(default_factory=list)


class IntelEvent(Contract):
    source: str
    source_url: str
    raw_content_id: Hash
    raw_content_hash: Hash
    fetched_at: str
    published_at: str | None = None
    modified_at: str | None = None
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)
    package: str
    ecosystem: str
    version: str
    affected_status: Literal["affected", "not_affected", "unknown"]
    fixed_versions: list[str] = Field(default_factory=list)
    severity_vector: str | None = None
    severity_source: str
    kev_status: bool | None = None
    replay: bool = False


class Finding(Contract):
    finding_id: Identifier
    manifest_hash: Hash
    fingerprint: Hash
    title: str = Field(max_length=300)
    cwe: str | None = Field(default=None, pattern=r"^CWE-[0-9]+$")
    location: dict[str, str | int]
    status: Literal["suspected", "confirmed", "unconfirmed"] = "suspected"
    source_tools: list[str]
    evidence_ids: list[Hash]
    advisory_ids: list[str] = Field(default_factory=list)
    severity_origin: Literal["official", "predicted", "heuristic"] = "heuristic"
    cvss_vector: str | None = None
    disposition: Literal["retain", "suppress", "needs_review"] = "retain"
    disposition_reason: Text = ""


class Edit(Contract):
    path: str = Field(max_length=500)
    base_file_hash: Hash
    exact_old: str = Field(max_length=200_000)
    exact_new: str = Field(max_length=200_000)

    @field_validator("path")
    @classmethod
    def path_safe(cls, value):
        return safe_relative_path(value)


class PatchProposal(Contract):
    proposal_id: Identifier
    base_tree_hash: Hash
    finding_ids: list[Identifier]
    route: Literal["upstream", "generated"]
    edits: list[Edit] = Field(min_length=1, max_length=5)
    proposed_dependency_updates: list[dict] = Field(default_factory=list)
    rationale: Text
    model_call_ids: list[Identifier] = Field(default_factory=list)


class Candidate(Contract):
    candidate_id: Identifier
    proposal_id: Identifier
    source_tree_hash: Hash
    diff_hash: Hash
    artifact_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    generated_code_hash: Hash | None = None
    manifest_hash: Hash
    build_evidence_ids: list[Hash]


class Obligation(Contract):
    obligation_id: str
    description: Text
    origin: Literal["existing_contract", "approved_template", "owner_approved", "inferred"]
    source_ref: str
    approved: bool
    required: bool
    component: str
    symbol: str
    backend: Literal["dafny", "crosshair", "cbmc"]
    spec_hash: Hash
    harness_hash: Hash
    assumptions: list[str]
    bounds: dict[str, int | str]
    required_evidence_kind: Literal["proof", "bounded"]
    allowed_bound_profile_id: str | None = None


class GateResult(Contract):
    gate_id: Identifier
    case_id: Identifier
    candidate_id: Identifier
    candidate_hash: Hash
    check_profile_id: str
    category: Literal["build", "functional", "security", "static", "formal", "policy"]
    status: GateStatus
    proof_outcome: ProofOutcome | None = None
    scope: list[str]
    assumptions: list[str] = Field(default_factory=list)
    tool_version: str
    command_profile_hash: Hash
    exit_code: int | None = None
    started_at: str
    finished_at: str
    evidence_ids: list[Hash]
    reason: Text = ""

    @model_validator(mode="after")
    def proof_consistency(self):
        if self.category != "formal" and self.proof_outcome is not None:
            raise ValueError("Only formal gates can carry proof outcomes")
        if (
            self.category == "formal"
            and self.status == "pass"
            and self.proof_outcome not in ("PROVED", "BOUNDED_PASS")
        ):
            raise ValueError("Formal pass requires proved or bounded evidence")
        return self


class EvidenceManifest(Contract):
    manifest_id: Identifier
    case_id: Identifier
    baseline_hash: Hash
    candidate_hash: Hash
    artifact_digest: str
    diff_hash: Hash
    target_manifest_hash: Hash
    policy_hash: Hash
    spec_hashes: list[Hash]
    harness_hashes: list[Hash]
    test_hashes: list[Hash]
    required_gate_ids: list[Identifier]
    gate_result_ids: list[Identifier]
    assurance_profile: Assurance
    proof_summary: list[dict]
    exclusions: list[str]
    model_call_ids: list[Identifier]
    total_cost_micro_usd: NonNegative
    issued_at: str
    content_hash: Hash


class Authorization(Contract):
    authorization_id: Identifier
    project_id: Identifier
    evidence_manifest_hash: Hash
    destination_id: str
    expected_deployment_generation: NonNegative
    mode: Literal["owner_approval", "preauthorized_policy"]
    actor_or_policy_id: str
    issued_at: str
    expires_at: str


class DeploymentResult(Contract):
    deployment_id: Identifier
    authorization_id: Identifier
    previous_digest: str | None
    candidate_digest: str
    generation: NonNegative
    status: str
    readiness_evidence_ids: list[Hash]
    observation_evidence_ids: list[Hash]
    rollback_result: dict | None = None
    refreshed_manifest_hash: Hash | None = None


class ModelCall(Contract):
    call_id: Identifier
    task_id: Identifier
    provider: str
    endpoint_profile_id: str
    model_profile_hash: Hash
    model_requested: str
    model_returned: str | None = None
    reasoning_effort: str | None = None
    template_version: str
    request_hash: Hash
    response_content_id: Hash | None = None
    input_tokens: NonNegative | None = None
    output_tokens: NonNegative | None = None
    billing_usage: dict = Field(default_factory=dict)
    reserved_cost_micro_usd: NonNegative
    actual_cost_micro_usd: NonNegative | None = None
    status: Literal["reserved", "in_flight", "succeeded", "failed", "uncertain"]
    reason_code: str | None = None
    provider_request_id: str | None = None
    price_snapshot_id: str


class AllowedAction(Contract):
    action: str
    resource_id: str
    expected_revision: NonNegative
    eligible: bool
    disabled_reason: str | None = None
    required_confirmation: bool = False


class ActionItem(Contract):
    action_id: str
    project_id: Identifier
    case_id: Identifier | None = None
    kind: str
    priority: NonNegative
    title: str
    reason_code: str
    reason: Text
    created_at: str
    updated_at: str
    evidence_refs: list[Hash] = Field(default_factory=list)
    allowed_actions: list[AllowedAction] = Field(default_factory=list)
    disabled_reasons: dict[str, str] = Field(default_factory=dict)


class ProjectSnapshot(Contract):
    project_id: Identifier
    display_name: str
    repo_url: str
    revision: NonNegative
    observed_at: str
    setup_state: str
    admission_state: Literal["active", "paused"]
    source_summary: dict
    mirror_summary: dict
    deployment_summary: dict
    active_cycle: dict | None
    attention_count: NonNegative
    cost_summary: dict
    feed_freshness: list[dict]
    allowed_actions: list[AllowedAction]
    owner_policy_id: str
    assurance_profile: Assurance
    reason: str | None = None


class CaseReview(Contract):
    title: str
    status: str
    cycle_id: Identifier
    created_at: str
    reason: str | None = None
    generation_mode: str = "fresh_inference"
    case_id: Identifier
    project_id: Identifier
    revision: NonNegative
    finding_refs: list[Identifier]
    candidate_id: Identifier | None
    diff_ref: Hash | None
    gate_results: list[GateResult]
    assurance_summary: dict
    evidence_manifest_hash: Hash | None
    destination_id: str
    expected_deployment_generation: NonNegative
    allowed_actions: list[AllowedAction]


class OperationReceipt(Contract):
    operation_id: Identifier
    idempotency_key: str
    request_hash: Hash
    kind: str
    resource_ids: dict[str, str]
    status: Literal["accepted", "running", "succeeded", "failed"]
    reason_code: str | None = None
    created_at: str
    updated_at: str
    result_ref: str | None = None


class ProjectConfigAmendment(Contract):
    expected_revision: NonNegative
    requested_ref: str | None = Field(default=None, max_length=200)
    subdir: str | None = None
    owner_policy_id: Literal["lab-auto-v1", "review-v1"]
    deployment_profile_id: Literal["local-web-v1", "local-consumer-v1"]
    assurance_profile: Assurance
    requirement_ids: list[str] = Field(default_factory=list, max_length=5)

    @model_validator(mode="after")
    def validate_setup_fields(self):
        # Apply exactly the same revision, path and assurance rules as enrollment.
        Enrollment(
            repo_url="https://github.com/colossus/validation",
            **self.model_dump(exclude={"expected_revision"}),
        )
        return self


class ApprovalRequest(Contract):
    candidate_id: Identifier
    evidence_manifest_hash: Hash
    expected_revision: NonNegative
    expected_deployment_generation: NonNegative


class RollbackRequest(Contract):
    expected_generation: NonNegative


class RejectionRequest(Contract):
    candidate_id: Identifier
    expected_revision: NonNegative
    reason: str = Field(min_length=1, max_length=2000)


class ReviewDecision(Contract):
    case_id: Identifier
    candidate_id: Identifier
    expected_revision: NonNegative
    decision: Literal["reject"] = "reject"
    reason: str = Field(min_length=1, max_length=2000)


class Envelope(Contract):
    schema_version: Literal["1.0"] = "1.0"
    message_id: Identifier
    project_id: Identifier
    cycle_id: Identifier | None = None
    case_id: Identifier | None = None
    task_id: Identifier | None = None
    parent_message_id: Identifier | None = None
    kind: str
    producer: str
    created_at: str
    payload: dict
    payload_sha256: Hash
