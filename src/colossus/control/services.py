"""Start trusted child services with separate credentials and private sockets."""

import asyncio
import os
import secrets
import socket as socket_module
import subprocess
import sys
from pathlib import Path

from colossus.contracts.core import DomainError
from colossus.control.config import Settings
from colossus.control.lifecycle import InstanceLock
from colossus.control.rpc import RPCClient


class ServiceSupervisor:
    def __init__(self, settings: Settings, env_file: Path | None = None):
        self.settings = settings
        self.env_file = (env_file or Path(".env")).resolve()
        self.processes = {}
        self.clients = {}
        self.directory = settings.data_dir / "run"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = InstanceLock(self.directory / "services.lock")

    async def start(self):
        self.lock.acquire()
        try:
            await self._start()
        except BaseException:
            await self.stop()
            raise

    async def _start(self):
        env = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "DOCKER_CONFIG", "VIRTUAL_ENV")
            if key in os.environ
        }
        for name, module, extra in [
            ("gateway", "colossus.gateway.server", ["--env-file", str(self.env_file)]),
            ("launcher", "colossus.sandbox.server", ["--context", self.settings.docker_context]),
        ]:
            socket = self.directory / (name + ".sock")
            # A held supervisor lock excludes another compliant starter. Only remove
            # a socket after the kernel confirms that no listener accepts it.
            if socket.exists():
                if socket.is_symlink():
                    raise DomainError("unsafe_socket", "Service socket is a symlink", 503)
                probe = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
                probe.settimeout(1)
                try:
                    probe.connect(str(socket))
                except (ConnectionRefusedError, FileNotFoundError):
                    socket.unlink(missing_ok=True)
                else:
                    raise DomainError(
                        "service_socket_exists",
                        f"A prior {name} process is still listening; retry after its parent watchdog exits",
                        503,
                    )
                finally:
                    probe.close()
            token = secrets.token_urlsafe(32)
            token_file = self.directory / (name + ".token")
            fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as file:
                file.write(token)
            log = open(self.directory / (name + ".log"), "ab")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    module,
                    "--socket",
                    str(socket),
                    "--token-file",
                    str(token_file),
                    *extra,
                ],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
            )
            log.close()
            self.processes[name] = process
            client = self.clients[name] = RPCClient(socket, token)
            for _ in range(100):
                if process.poll() is not None:
                    await self.stop()
                    raise DomainError(
                        "service_start_failed", f"Trusted service failed to start: {name}", 503
                    )
                try:
                    await client.call("/health")
                    break
                except DomainError:
                    await asyncio.sleep(0.1)
            else:
                await self.stop()
                raise DomainError(
                    "service_start_timeout", f"Trusted service did not become ready: {name}", 503
                )

    async def stop(self):
        for process in self.processes.values():
            if process.poll() is None:
                process.terminate()
        for name, process in self.processes.items():
            try:
                await asyncio.to_thread(process.wait, 5)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait)
            (self.directory / (name + ".sock")).unlink(missing_ok=True)
        for client in self.clients.values():
            await client.close()
        self.clients.clear()
        self.processes.clear()
        self.lock.release()
