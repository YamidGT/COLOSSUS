"""Fetch immutable public GitHub source without cloning or running hooks."""

from __future__ import annotations

import io
import tarfile
from urllib.parse import quote

import httpx

from colossus.contracts.core import DomainError, content_hash, digest, safe_relative_path
from colossus.contracts.models import Enrollment

MAX_ARCHIVE = 25 * 1024 * 1024
MAX_SOURCE = 100 * 1024 * 1024
MAX_FILES = 10_000


def unpack_source(archive: bytes) -> dict[str, bytes]:
    if len(archive) > MAX_ARCHIVE:
        raise DomainError("source_limit", "Source archive exceeds size limit", 413)
    files: dict[str, bytes] = {}
    root = None
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for index, member in enumerate(tar):
                if index >= MAX_FILES:
                    raise DomainError(
                        "source_limit", "Source archive contains too many entries", 413
                    )
                name = member.name.rstrip("/")
                safe_relative_path(name)
                parts = name.split("/", 1)
                if root is None:
                    root = parts[0]
                if parts[0] != root:
                    raise DomainError(
                        "invalid_archive", "Archive has inconsistent source root", 422
                    )
                if member.isdir():
                    continue
                if not member.isfile() or len(parts) != 2:
                    raise DomainError(
                        "invalid_archive", "Source links and special files are not supported", 422
                    )
                path = safe_relative_path(parts[1])
                if any(p == ".git" for p in path.split("/")) or path in files:
                    raise DomainError(
                        "invalid_archive", "Duplicate or repository metadata path", 422
                    )
                total += member.size
                if member.size < 0 or total > MAX_SOURCE:
                    raise DomainError("source_limit", "Expanded source exceeds size limit", 413)
                stream = tar.extractfile(member)
                if stream is None:
                    raise DomainError("invalid_archive", "Missing archive file", 422)
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise DomainError("invalid_archive", "Source file size mismatch", 422)
                files[path] = data
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise DomainError("invalid_archive", "Source archive is invalid or unsafe", 422) from exc
    if not files:
        raise DomainError("empty_source", "Repository contains no source files", 422)
    return files


def tree_hash(files: dict[str, bytes]) -> str:
    return content_hash(
        [
            {"path": path, "sha256": digest(data), "size": len(data)}
            for path, data in sorted(files.items())
        ]
    )


def source_tar(files: dict[str, bytes], root: str = "source") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for path, data in sorted(files.items()):
            safe_relative_path(path)
            entry = tarfile.TarInfo(f"{root}/{path}")
            entry.size = len(data)
            entry.mode = 0o644
            entry.uid = entry.gid = 1000
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


class GitHubSource:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def _read(self, url: str, limit: int) -> bytes:
        async with self.client.stream(
            "GET",
            url,
            follow_redirects=False,
            timeout=45,
            headers={"User-Agent": "COLOSSUS/0.1", "Accept": "application/vnd.github+json"},
        ) as response:
            if response.status_code != 200:
                raise DomainError(
                    "source_fetch_failed",
                    f"GitHub source request returned HTTP {response.status_code}",
                    502,
                )
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > limit:
                    raise DomainError("source_limit", "Source response exceeds size limit", 413)
            return bytes(data)

    async def fetch(self, request: Enrollment) -> dict:
        import json

        owner_repo = request.repo_url.removeprefix("https://github.com/")
        ref = request.requested_ref
        if ref is None:
            metadata = json.loads(
                await self._read(f"https://api.github.com/repos/{owner_repo}", 200_000)
            )
            ref = metadata["default_branch"]
        commit_record = json.loads(
            await self._read(
                f"https://api.github.com/repos/{owner_repo}/commits/{quote(ref, safe='')}",
                2_000_000,
            )
        )
        commit = commit_record["sha"]
        import re

        if not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise DomainError(
                "invalid_revision", "GitHub did not resolve an immutable revision", 502
            )
        archive = await self._read(
            f"https://codeload.github.com/{owner_repo}/tar.gz/{commit}", MAX_ARCHIVE
        )
        files = unpack_source(archive)
        if request.subdir:
            prefix = request.subdir + "/"
            files = {
                path[len(prefix) :]: data for path, data in files.items() if path.startswith(prefix)
            }
            if not files:
                raise DomainError(
                    "missing_subdir", "Requested source directory is empty or absent", 422
                )
        return {
            "repo_url": request.repo_url,
            "requested_ref": ref,
            "commit": commit,
            "source_archive_sha256": digest(archive),
            "tree_sha256": tree_hash(files),
            "files": files,
        }
