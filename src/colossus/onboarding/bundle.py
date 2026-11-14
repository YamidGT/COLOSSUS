"""Keep editable source separate from immutable installed runtime inputs."""

import base64

from colossus.contracts.core import DomainError
from colossus.gateway.source import MAX_SOURCE, tree_hash


def runtime_files(source: dict) -> dict[str, bytes]:
    encoded = source.get("runtime_files", {})
    if (
        not isinstance(encoded, dict)
        or any(not isinstance(data, str) for data in encoded.values())
        or sum(map(len, encoded.values())) > 140 * 1024 * 1024
    ):
        raise DomainError("runtime_bundle_invalid", "Runtime bundle exceeds transfer limits", 422)
    try:
        files = {path: base64.b64decode(data, validate=True) for path, data in encoded.items()}
    except (ValueError, TypeError):
        raise DomainError(
            "runtime_bundle_invalid", "Runtime bundle has invalid bytes", 422
        ) from None
    if sum(map(len, files.values())) > MAX_SOURCE or any(
        not path.startswith(("vendor/", "_colossus_runtime/")) for path in files
    ):
        raise DomainError(
            "runtime_bundle_invalid", "Runtime files are outside their protected namespace", 422
        )
    if files and source.get("runtime_tree_sha256") != tree_hash(files):
        raise DomainError("runtime_bundle_invalid", "Runtime input hash mismatch", 422)
    return files


def assembled_files(files: dict[str, bytes], runtime: dict[str, bytes]) -> dict[str, bytes]:
    if set(files) & set(runtime):
        raise DomainError(
            "runtime_bundle_collision", "Source collides with installed runtime inputs", 422
        )
    return files | runtime
