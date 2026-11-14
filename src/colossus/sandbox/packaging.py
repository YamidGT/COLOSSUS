"""Assemble source bytes without running repository Dockerfiles or build hooks."""

import io
import json
import tarfile

from colossus.contracts.core import DomainError, safe_relative_path
from colossus.gateway.source import MAX_FILES, MAX_SOURCE, tree_hash


def package_context(files: dict[str, bytes], base: str, argv: list[str]) -> tuple[bytes, str]:
    if not files or len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_SOURCE:
        raise DomainError("package_limit", "Invalid source package size", 413)
    if not argv or any(not isinstance(a, str) or "\x00" in a for a in argv):
        raise DomainError("invalid_command", "Invalid application command", 422)
    source_hash = tree_hash(files)
    # Everything supplied by a repository is below app/, including its Dockerfile.
    recipe = (
        f"FROM {base}\n"
        "COPY --chown=0:0 app/ /app/\n"
        "WORKDIR /app\n"
        "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/vendor\n"
        "USER 1000:1000\n"
        "ENTRYPOINT []\n"
        f"CMD {json.dumps(argv)}\n"
        'LABEL org.colossus.managed="true"\n'
        f'LABEL org.colossus.tree="{source_hash}"\n'
    ).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data in [
            ("Dockerfile", recipe),
            *[("app/" + safe_relative_path(p), d) for p, d in sorted(files.items())],
        ]:
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.uid, item.gid, item.mtime = len(data), 0o644, 0, 0, 0
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue(), source_hash
