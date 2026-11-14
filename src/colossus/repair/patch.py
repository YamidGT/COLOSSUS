import difflib

from colossus.contracts.core import DomainError, digest
from colossus.contracts.models import PatchProposal
from colossus.gateway.source import tree_hash


def apply_proposal(
    files: dict[str, bytes],
    proposal: PatchProposal,
    allowed_paths: list[str],
    protected_paths: list[str],
):
    if tree_hash(files) != proposal.base_tree_hash:
        raise DomainError("stale_patch", "Proposal does not target this source snapshot", 409)
    result = dict(files)
    touched = set()
    for edit in proposal.edits:
        if edit.path in touched or edit.path not in allowed_paths or edit.path in protected_paths:
            raise DomainError(
                "patch_scope", "Patch touches a protected, duplicate or disallowed path", 422
            )
        original = files.get(edit.path)
        if original is None or digest(original) != edit.base_file_hash:
            raise DomainError("stale_patch", "File hash differs from the patch precondition", 409)
        try:
            text = original.decode()
        except UnicodeError:
            raise DomainError(
                "patch_encoding", "Only UTF-8 source edits are supported", 422
            ) from None
        if (
            not edit.exact_old
            or text.count(edit.exact_old) != 1
            or edit.exact_old == edit.exact_new
        ):
            raise DomainError(
                "ambiguous_patch", "Patch must replace one exact nonempty source span", 422
            )
        updated = text.replace(edit.exact_old, edit.exact_new, 1).encode()
        if len(updated) > 500_000:
            raise DomainError("patch_limit", "Patched file exceeds size limit", 413)
        result[edit.path] = updated
        touched.add(edit.path)
    diff = "".join(
        "".join(
            difflib.unified_diff(
                files[p].decode().splitlines(True),
                result[p].decode().splitlines(True),
                fromfile="a/" + p,
                tofile="b/" + p,
            )
        )
        for p in sorted(touched)
    )
    return result, diff
