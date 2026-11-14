"""Official-update route. Advisory text is data and is never executed."""

from __future__ import annotations

import re

from colossus.contracts.core import DomainError, digest, new_id
from colossus.contracts.models import Edit, PatchProposal
from colossus.gateway.source import tree_hash

_COMMAND = re.compile(
    r"(?:^|[\n;|&])\s*(?:sudo|bash|sh|curl|wget|pip3?|npm|apt(?:-get)?|chmod|rm)\b",
    re.IGNORECASE,
)


def propose_upstream(
    files: dict[str, bytes],
    finding_id: str,
    path: str,
    exact_old: str,
    exact_new: str,
    advisory_id: str,
    advisory_text: str,
) -> PatchProposal:
    if _COMMAND.search(advisory_text) or _COMMAND.search(exact_new):
        raise DomainError(
            "advisory_command",
            "Upstream route does not execute commands found in an advisory",
            422,
        )
    if not advisory_id or advisory_id.startswith("-"):
        raise DomainError("advisory_identity", "Upstream route needs a pinned advisory id", 422)
    try:
        original = files[path]
    except KeyError:
        raise DomainError("stale_patch", "Advisory path is not in this snapshot", 409) from None
    return PatchProposal(
        proposal_id=new_id(),
        base_tree_hash=tree_hash(files),
        finding_ids=[finding_id],
        route="upstream",
        edits=[
            Edit(
                path=path,
                base_file_hash=digest(original),
                exact_old=exact_old,
                exact_new=exact_new,
            )
        ],
        proposed_dependency_updates=[{"advisory_id": advisory_id, "path": path}],
        rationale=f"Pinned upstream update {advisory_id}",
        model_call_ids=[],
    )
