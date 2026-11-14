"""Bounded content-addressed evidence; callers provide bytes, never host paths."""

import os
import re
import tempfile
from pathlib import Path

from colossus.contracts.core import DomainError, digest


class ArtifactStore:
    def __init__(self, root: Path, max_bytes: int = 104_857_600):
        if root.is_symlink():
            raise ValueError("Artifact root cannot be a symlink")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = root.resolve()
        self.max_bytes = max_bytes

    def path(self, key: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{64}", key):
            raise DomainError("invalid_artifact_id", "Invalid content identifier", 422)
        p = self.root / key
        if p.is_symlink():
            raise DomainError("invalid_artifact", "Symbolic links are not evidence")
        return p

    def put(self, data: bytes) -> str:
        if not isinstance(data, bytes) or len(data) > self.max_bytes:
            raise DomainError("artifact_limit", "Evidence exceeds byte limit", 413)
        key = digest(data)
        dest = self.path(key)
        if dest.exists():
            self.get(key)
            return key
        fd, filename = tempfile.mkstemp(prefix=".pending-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(filename, dest)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(filename).unlink(missing_ok=True)
        return key

    def get(self, key: str) -> bytes:
        path = self.path(key)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError as exc:
            raise DomainError("not_found", "Evidence not found", 404) from exc
        try:
            import stat

            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > self.max_bytes:
                raise DomainError("invalid_artifact", "Evidence is not a bounded regular file")
            with os.fdopen(fd, "rb", closefd=False) as f:
                data = f.read(self.max_bytes + 1)
        finally:
            os.close(fd)
        if len(data) > self.max_bytes or digest(data) != key:
            raise DomainError("artifact_corrupt", "Evidence hash does not match its identifier")
        return data
