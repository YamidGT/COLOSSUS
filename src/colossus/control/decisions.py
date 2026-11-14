"""Operator decision checks. These do not promote a slot or score a benchmark."""

from __future__ import annotations

import json
import re

from pydantic import ValidationError

from colossus.contracts.core import DomainError
from colossus.contracts.models import ProjectConfigAmendment

_SECRET = re.compile(r"(?i)(api[_-]?key|secret|token|password|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)")
_REQUIRED = ("source_commit", "source_archive_sha256", "oracle_id")


def reject_secrets(value) -> None:
    if isinstance(value, str):
        if _SECRET.search(value):
            raise DomainError(
                "secret_in_configuration", "Configuration cannot carry credentials", 422
            )
        return
    if isinstance(value, dict):
        for item in value.values():
            reject_secrets(item)
    elif isinstance(value, list):
        for item in value:
            reject_secrets(item)


def read_configuration(text: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError:
        raise DomainError("invalid_configuration", "Configuration file is not JSON", 422) from None
    if not isinstance(data, dict):
        raise DomainError("invalid_configuration", "Configuration file must be an object", 422)
    reject_secrets(data)
    try:
        ProjectConfigAmendment.model_validate(data)
    except ValidationError:
        raise DomainError(
            "invalid_configuration",
            "Configuration does not match the amendment schema",
            422,
        ) from None
    return data


def assess_campaign(manifest: dict) -> dict:
    if not isinstance(manifest, dict):
        raise DomainError("campaign_shape", "Campaign manifest must be an object", 422)
    if manifest.get("status") == "candidate_only":
        raise DomainError(
            "candidate_only", "Candidate-only roster is not an evaluation campaign", 422
        )
    if manifest.get("scored_execution_allowed") is True:
        raise DomainError(
            "campaign_not_executed", "This adapter does not start scored execution", 422
        )
    if manifest.get("status") != "frozen":
        raise DomainError("campaign_not_frozen", "Campaign lock is not frozen", 422)
    repositories = manifest.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise DomainError("campaign_shape", "Frozen campaign needs a repository list", 422)
    cases = []
    for repo in repositories:
        if not isinstance(repo, dict) or not repo.get("repo_id"):
            raise DomainError("campaign_shape", "Each campaign row needs a repo_id", 422)
        missing = [field for field in _REQUIRED if not repo.get(field)]
        cases.append(
            {
                "repo_id": repo["repo_id"],
                "outcome": "unrun",
                "reason": "preflight incomplete" if missing else "campaign execution was not started",
                "missing": missing,
            }
        )
    return {"executed": False, "scores": None, "cases": cases}
