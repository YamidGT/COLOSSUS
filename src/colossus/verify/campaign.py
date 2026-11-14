"""Campaign lock checks. This adapter records unrun cases and does not score a benchmark."""

from __future__ import annotations

from colossus.contracts.core import DomainError

_REQUIRED = ("source_commit", "source_archive_sha256", "oracle_id")


def assess_campaign(manifest: dict) -> dict:
    if not isinstance(manifest, dict):
        raise DomainError("campaign_shape", "Campaign manifest must be an object", 422)
    status = manifest.get("status")
    if status == "candidate_only":
        raise DomainError(
            "candidate_only",
            "Candidate-only roster is not an evaluation campaign",
            422,
        )
    if manifest.get("scored_execution_allowed") is True:
        raise DomainError(
            "campaign_not_executed",
            "This adapter does not start scored execution",
            422,
        )
    if status != "frozen":
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
