"""Host configuration excludes provider credentials from the controller."""

import os
import secrets
from pathlib import Path

from pydantic import Field

from colossus.contracts.core import Contract
from colossus.contracts.runtime import RuntimeConfig


class Settings(Contract):
    data_dir: Path
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8787, ge=1024, le=65535)
    docker_context: str = "colima-colossus"
    sandbox_runtime: str = "runsc"
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    frontend_dir: Path = Path("frontend/dist")

    @classmethod
    def from_environment(cls):
        return cls(
            data_dir=Path(os.environ.get("COLOSSUS_DATA_DIR", ".colossus")).resolve(),
            docker_context=os.environ.get("COLOSSUS_DOCKER_CONTEXT", "colima-colossus"),
            sandbox_runtime=os.environ.get("COLOSSUS_SANDBOX_RUNTIME", "runsc"),
        )

    def prepare(self):
        if self.data_dir.is_symlink():
            raise ValueError("State directory cannot be a symlink")
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.data_dir, 0o700)
        path = self.data_dir / "operator.token"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            if path.is_symlink() or not path.is_file():
                raise ValueError("Operator credential is not a regular file") from None
            os.chmod(path, 0o600)
        else:
            with os.fdopen(fd, "w") as stream:
                stream.write(secrets.token_urlsafe(32))
        return path.read_text().strip()
