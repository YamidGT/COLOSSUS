"""Process ownership and crash boundaries for trusted local services."""

import fcntl
import os
import threading
import time
from pathlib import Path

from colossus.contracts.core import DomainError


class InstanceLock:
    def __init__(self, path: Path):
        self.path = path
        self.fd = None

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise DomainError(
                "instance_running",
                "This state directory already has an active service supervisor",
                503,
            ) from None
        self.fd = fd

    def release(self):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def watch_parent():
    """Children exit when their owning controller dies; runtime jobs have separate TTLs."""
    parent = os.getppid()

    def watch():
        while True:
            time.sleep(1)
            if os.getppid() != parent:
                os._exit(70)

    threading.Thread(target=watch, name="parent-watch", daemon=True).start()
