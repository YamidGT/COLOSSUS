"""Sole Docker boundary: named, quota-limited gVisor environments and bounded jobs."""

from __future__ import annotations

import io
import json
import os
import re
import signal
import subprocess
import tarfile
import threading
import time
from dataclasses import dataclass

from colossus.contracts.core import DomainError, new_id, safe_relative_path
from colossus.gateway.source import source_tar
from colossus.sandbox.packaging import package_context

PYTHON_IMAGE = "python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
LABEL = "org.colossus.managed"
MAX_LOG = 1024 * 1024
INHIBIT_IPV4 = "com.docker.network.bridge.inhibit_ipv4"
# Environments whose evidence export failed are paused, not destroyed. Each one holds
# its scratch tmpfs in memory, so the count is bounded; at the cap no new work starts.
MAX_QUARANTINE = 4


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    truncated: bool = False


def bounded_process(
    args: list[str], timeout: int, stdin: bytes | None = None, max_output: int = MAX_LOG
) -> ProcessResult:
    started = time.monotonic()
    env = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_CONFIG") if key in os.environ}
    process = subprocess.Popen(
        args,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    buffers = [bytearray(), bytearray()]
    truncated = [False]

    def drain(stream, output):
        while chunk := stream.read(8192):
            remaining = max_output - len(output)
            if len(chunk) > remaining:
                truncated[0] = True
            output.extend(chunk[: max(0, remaining)])

    threads = [
        threading.Thread(target=drain, args=(stream, buffers[index]), daemon=True)
        for index, stream in enumerate((process.stdout, process.stderr))
    ]
    for thread in threads:
        thread.start()

    def feed():
        if process.stdin:
            try:
                process.stdin.write(stdin)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass

    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    for thread in threads:
        thread.join(timeout=2)
    feeder.join(timeout=2)
    return ProcessResult(
        process.returncode,
        buffers[0].decode(errors="replace"),
        buffers[1].decode(errors="replace"),
        timed_out,
        time.monotonic() - started,
        truncated[0],
    )


_FORBIDDEN_CREATE_FLAGS = frozenset(
    {
        "--privileged", "--cap-add", "--device", "--pid", "--userns", "--uts", "--cgroupns",
        "--volumes-from", "-v", "--volume", "--mount", "-p", "--publish", "-P", "--publish-all",
        "--add-host", "--env-file", "--group-add", "--isolation", "--sysctl",
    }
)
_REQUIRED_CREATE = {
    "--read-only": None,
    "--cap-drop": "ALL",
    "--security-opt": "no-new-privileges",
    "--ipc": "private",
    "--user": "1000:1000",
}


def assert_safe_create(args: list[str], runtime: str = "runsc") -> None:
    """Second line of defence: refuse any `docker create` that weakens isolation.

    Only option tokens before the image are checked; the container command after
    it is never parsed as docker flags.
    """

    def deny(why: str):
        raise DomainError("sandbox_policy", "Sandbox create refused: " + why, 422)

    if not args or args[0] != "create":
        deny("not a create command")
    takes_value = {
        "--name", "--runtime", "--network", "--cap-drop", "--security-opt", "--ipc", "--user",
        "--pids-limit", "--memory", "--memory-swap", "--cpus", "--stop-timeout", "--tmpfs",
        "--workdir", "--label",
    }
    values: dict[str, list[str]] = {}
    seen: set[str] = set()
    i = 1
    while i < len(args) and args[i].startswith("-"):  # stop at the image
        flag, eq, inline = args[i].partition("=")
        if flag in _FORBIDDEN_CREATE_FLAGS:
            deny(f"forbidden flag {flag}")
        if flag == "--read-only":
            seen.add(flag)
            i += 1
            continue
        if flag not in takes_value:
            deny(f"unexpected flag {flag}")
        value = inline if eq else (args[i + 1] if i + 1 < len(args) else "")
        values.setdefault(flag, []).append(value)
        seen.add(flag)
        i += 1 if eq else 2
    if values.get("--runtime") != [runtime] or runtime != "runsc":
        deny("runtime must be runsc")
    net = values.get("--network", [])
    if len(net) != 1 or not (net[0] == "none" or net[0].startswith("colossus-net-")):
        deny("network must be none or a colossus-net-* internal network")
    for flag, want in _REQUIRED_CREATE.items():
        if want is None:
            if flag not in seen:
                deny(f"missing {flag}")
        elif want not in values.get(flag, []):
            deny(f"missing {flag} {want}")
    if any("unconfined" in v for v in values.get("--security-opt", [])):
        deny("unconfined security option")
    if values.get("--memory") != values.get("--memory-swap"):
        deny("memory-swap must equal memory")
    for tmpfs in values.get("--tmpfs", []):
        opts = tmpfs.split(":", 1)[1] if ":" in tmpfs else ""
        if "nosuid" not in opts or "nodev" not in opts or "size=" not in opts:
            deny("tmpfs must be nosuid,nodev and size-bounded")


class SandboxLauncher:
    def __init__(self, context: str = "colima-colossus", runtime: str = "runsc"):
        if not context or runtime != "runsc":
            raise ValueError("A configured Docker context with gVisor is required")
        self.context = context
        self.runtime = runtime
        self._lock = threading.RLock()

    def docker(self, *args: str, timeout: int = 30, stdin: bytes | None = None) -> ProcessResult:
        return bounded_process(["docker", "--context", self.context, *args], timeout, stdin)

    def checked(self, *args: str, timeout: int = 30, stdin: bytes | None = None) -> str:
        if args and args[0] == "create":
            assert_safe_create(list(args), self.runtime)
        result = self.docker(*args, timeout=timeout, stdin=stdin)
        if result.exit_code != 0 or result.timed_out:
            raise DomainError(
                "sandbox_command_failed", "Sandbox operation failed: " + result.stderr[:2000], 503
            )
        return result.stdout.strip()

    def preflight(self) -> dict:
        result = self.docker("info", "--format", "{{json .}}")
        if result.exit_code:
            return {"ready": False, "reason": "Docker context unavailable", "context": self.context}
        data = json.loads(result.stdout)
        runsc = self.runtime in data.get("Runtimes", {})
        return {
            "ready": runsc,
            "context": self.context,
            "runtime": self.runtime,
            "architecture": data.get("Architecture"),
            "cpus": data.get("NCPU"),
            "memory_bytes": data.get("MemTotal"),
            "server_version": data.get("ServerVersion"),
            "reason": None if runsc else "gVisor runtime missing",
        }

    def ensure_image(self, image: str = PYTHON_IMAGE):
        if image != PYTHON_IMAGE:
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
                raise DomainError("image_not_allowed", "Use a pinned managed image", 422)
            data = json.loads(self.checked("image", "inspect", image))[0]
            if data.get("Config", {}).get("Labels", {}).get(LABEL) != "true":
                raise DomainError("image_not_allowed", "Image is not a managed artifact", 422)
            return
        result = self.docker("image", "inspect", image)
        if result.exit_code:
            self.checked("pull", image, timeout=300)

    def network(self, project_id: str, ttl_seconds: int = 14400) -> str:
        if not 1 <= ttl_seconds <= 14400:
            raise DomainError("invalid_limits", "Sandbox limit is outside allowed range", 422)
        name = "colossus-net-" + new_id()
        self.checked(
            "network",
            "create",
            "--internal",
            # No host address on the bridge: jobs cannot reach host listeners via the gateway.
            "--opt",
            INHIBIT_IPV4 + "=true",
            "--label",
            LABEL + "=true",
            "--label",
            "org.colossus.project=" + project_id,
            "--label",
            "org.colossus.expires=" + str(int(time.time()) + ttl_seconds),
            name,
        )
        return name

    def _validate_network(self, network: str, project_id: str):
        if network == "none":
            return
        if not network.startswith("colossus-net-"):
            raise DomainError("network_not_allowed", "Only case-owned networks are allowed", 422)
        data = json.loads(self.checked("network", "inspect", network))[0]
        if (
            not data.get("Internal")
            or (data.get("Options") or {}).get(INHIBIT_IPV4) != "true"
            or data.get("Labels", {}).get("org.colossus.project") != project_id
        ):
            raise DomainError(
                "network_not_allowed", "Network is not an isolated project network", 422
            )

    def create(
        self,
        project_id: str,
        role: str,
        network: str = "none",
        memory_mb: int = 1024,
        ttl_seconds: int = 1200,
        image: str = PYTHON_IMAGE,
        application: bool = False,
    ) -> str:
        if role not in {"build", "target", "candidate", "probe", "verify", "scan"}:
            raise DomainError("invalid_role", "Unknown sandbox role", 422)
        if not 64 <= memory_mb <= 6144 or not 1 <= ttl_seconds <= 14400:
            raise DomainError("invalid_limits", "Sandbox limit is outside allowed range", 422)
        self._validate_network(network, project_id)
        self._admit()
        self.ensure_image(image)
        name = "colossus-" + new_id()
        self.checked(
            "create",
            "--name",
            name,
            "--runtime",
            self.runtime,
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--ipc",
            "private",
            "--user",
            "1000:1000",
            "--pids-limit",
            "128",
            "--memory",
            f"{memory_mb}m",
            "--memory-swap",
            f"{memory_mb}m",
            "--cpus",
            "2",
            "--stop-timeout",
            "5",
            "--tmpfs",
            "/work:rw,exec,nosuid,nodev,size=536870912,uid=1000,gid=1000,mode=0700",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=0700",
            "--workdir",
            "/app" if application else "/work",
            "--label",
            LABEL + "=true",
            "--label",
            "org.colossus.project=" + project_id,
            "--label",
            "org.colossus.role=" + role,
            "--label",
            "org.colossus.expires=" + str(int(time.time()) + ttl_seconds),
            image,
            *([] if application else ["python", "-c", "import time; time.sleep(14400)"]),
        )
        try:
            self.checked("start", name)
        except BaseException:
            self.docker("rm", "-f", name)
            raise
        return name

    def package(self, files: dict[str, bytes], argv: list[str]) -> dict:
        with self._lock:
            self.ensure_image()
            base = json.loads(self.checked("image", "inspect", PYTHON_IMAGE))[0]
            if base.get("Config", {}).get("OnBuild"):
                raise DomainError("unsafe_base", "Packaging base has ONBUILD hooks", 422)
            context, source_hash = package_context(files, PYTHON_IMAGE, argv)
            # This controller-owned recipe has no RUN/ADD and cannot execute source.
            tag = "colossus-artifact:" + new_id()
            result = self.docker(
                "build",
                "--network=none",
                "--pull=false",
                "--tag",
                tag,
                "-",
                stdin=context,
                timeout=300,
            )
            if result.exit_code or result.timed_out:
                raise DomainError(
                    "packaging_failed",
                    "COPY-only image assembly failed: " + result.stderr[-2000:],
                    503,
                )
            info = json.loads(self.checked("image", "inspect", tag))[0]
            return {
                "artifact_digest": info["Id"],
                "tree_sha256": source_hash,
                "platform": info["Os"] + "/" + info["Architecture"],
                "base_digest": PYTHON_IMAGE,
            }

    def start_target(self, project_id: str, artifact_digest: str, ttl_seconds: int = 7200) -> dict:
        network = self.network(project_id, ttl_seconds=ttl_seconds)
        try:
            name = self.create(
                project_id,
                "target",
                network,
                image=artifact_digest,
                ttl_seconds=ttl_seconds,
                application=True,
            )
            info = self.inspect(name)
            address = info["NetworkSettings"]["Networks"][network]["IPAddress"]
            return {
                "environment_id": name,
                "network_id": network,
                "address": address,
                "artifact_digest": artifact_digest,
                "project_id": project_id,
            }
        except BaseException:
            self.destroy_network(network, project_id)
            raise

    def request(
        self,
        project_id: str,
        environment_id: str,
        port: int,
        path: str = "/",
        method: str = "GET",
        body: str | None = None,
    ) -> dict:
        info = self.inspect(environment_id)
        if info["Config"]["Labels"].get("org.colossus.project") != project_id:
            raise DomainError("target_scope", "Target belongs to another project", 403)
        if (
            not 1 <= port <= 65535
            or not path.startswith("/")
            or path.startswith("//")
            or len(path) > 8192
            or any(ord(c) < 32 for c in path)
        ):
            raise DomainError("invalid_probe", "Invalid internal request", 422)
        if method not in {"GET", "HEAD", "POST"} or (
            body is not None and len(body.encode()) > 16384
        ):
            raise DomainError("invalid_probe", "Request exceeds probe policy", 422)
        networks = info["NetworkSettings"]["Networks"]
        if len(networks) != 1:
            raise DomainError("invalid_network", "Target must have one isolated network", 422)
        network, endpoint = next(iter(networks.items()))
        self._validate_network(network, project_id)
        target = {
            "host": endpoint["IPAddress"],
            "port": port,
            "path": path,
            "method": method,
            "body": body,
        }
        # http.client never follows redirects; destination comes from runtime inspection.
        script = "import http.client,json,sys\na=json.loads(sys.argv[1]); c=http.client.HTTPConnection(a['host'],a['port'],timeout=5)\nc.request(a['method'],a['path'],body=a['body']); r=c.getresponse(); b=r.read(65537)\nprint(json.dumps({'status':r.status,'headers':dict(r.getheaders()),'body':b[:65536].decode(errors='replace'),'truncated':len(b)>65536}))\n"
        result = self.run(
            project_id,
            "probe",
            {"probe.py": script.encode()},
            ["python", "probe.py", json.dumps(target)],
            15,
            network,
        )
        if result.exit_code or result.timed_out:
            return {
                "status": None,
                "error": "target_unreachable",
                "evidence": result.stderr[-1000:],
            }
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise DomainError(
                "invalid_probe_result", "Probe returned invalid evidence", 503
            ) from None

    def inspect(self, environment_id: str) -> dict:
        if not environment_id.startswith("colossus-"):
            raise DomainError("invalid_environment", "Unknown sandbox identity", 422)
        data = json.loads(self.checked("inspect", environment_id))[0]
        if data.get("Config", {}).get("Labels", {}).get(LABEL) != "true":
            raise DomainError("invalid_environment", "Container is not managed by COLOSSUS", 403)
        return data

    def copy_source(self, environment_id: str, files: dict[str, bytes]):
        self.inspect(environment_id)
        self.checked(
            "exec",
            "-i",
            environment_id,
            "tar",
            "-xf",
            "-",
            "-C",
            "/work",
            "--no-same-owner",
            "--no-same-permissions",
            stdin=source_tar(files),
            timeout=60,
        )

    def execute(
        self, environment_id: str, argv: list[str], timeout: int = 60, workdir: str = "/work/source"
    ) -> ProcessResult:
        result = self._exec(environment_id, argv, timeout, workdir)
        if result.timed_out:
            self.destroy(environment_id)
        return result

    def _exec(
        self, environment_id: str, argv: list[str], timeout: int, workdir: str
    ) -> ProcessResult:
        self.inspect(environment_id)
        if (
            not argv
            or len(argv) > 100
            or any(not isinstance(a, str) or "\x00" in a or len(a) > 100_000 for a in argv)
        ):
            raise DomainError("invalid_job", "Invalid sandbox command", 422)
        if workdir not in {"/work", "/work/source", "/tmp"} or not 1 <= timeout <= 3600:
            raise DomainError("invalid_job", "Invalid sandbox directory or deadline", 422)
        result = self.docker(
            "exec",
            "--workdir",
            workdir,
            "--env",
            "PYTHONPATH=/work/vendor",
            environment_id,
            *argv,
            timeout=timeout,
        )
        if result.timed_out:
            # Killing the docker CLI does not stop the in-sandbox process; freeze it.
            self.docker("kill", environment_id)
        return result

    def run(
        self,
        project_id: str,
        role: str,
        files: dict[str, bytes],
        argv: list[str],
        timeout: int = 60,
        network: str = "none",
    ) -> ProcessResult:
        with self._lock:
            environment_id = self.create(project_id, role, network, ttl_seconds=timeout + 60)
            try:
                self.copy_source(environment_id, files)
                return self.execute(environment_id, argv, timeout)
            finally:
                self.destroy(environment_id)

    def run_collect(
        self,
        project_id: str,
        role: str,
        files: dict[str, bytes],
        argv: list[str],
        timeout: int = 60,
        network: str = "none",
        results_dir: str = "/work/results",
        max_bytes: int = 25 * 1024 * 1024,
    ) -> dict:
        """Run a job and export its results BEFORE the worker is destroyed.

        If the export fails the worker is paused and kept (quarantined) with its
        scratch intact, and the failure is reported instead of losing evidence.
        """
        with self._lock:
            environment_id = self.create(project_id, role, network, ttl_seconds=timeout + 60)
            try:
                self.copy_source(environment_id, files)
                result = self._exec(environment_id, argv, timeout, "/work/source")
            except BaseException:
                self.destroy(environment_id)
                raise
            if result.timed_out:
                # The job was killed; its tmpfs scratch died with it.
                self.destroy(environment_id)
                return {"result": result, "files": {}, "evidence": "lost_timeout"}
            try:
                exported = self.export_files(environment_id, results_dir, max_bytes)
            except DomainError as error:
                self.quarantine(environment_id)
                return {
                    "result": result,
                    "files": {},
                    "evidence": "quarantined",
                    "environment_id": environment_id,
                    "error": error.code,
                }
            self.destroy(environment_id)
            return {"result": result, "files": exported, "evidence": "exported"}

    def quarantine(self, environment_id: str):
        """Freeze a worker whose evidence could not be exported; the reaper skips it."""
        self.inspect(environment_id)
        self.checked("pause", environment_id)

    def quarantined(self) -> list[str]:
        return self.checked(
            "ps", "-a", "--filter", "label=" + LABEL + "=true", "--filter", "status=paused",
            "--format", "{{.Names}}",
        ).splitlines()

    def _admit(self):
        if len(self.quarantined()) >= MAX_QUARANTINE:
            raise DomainError(
                "quarantine_full",
                "Evidence quarantine is full; no new sandbox work is admitted",
                507,
            )

    def destroy(self, environment_id: str):
        if not environment_id.startswith("colossus-"):
            raise DomainError("invalid_environment", "Unknown sandbox identity", 422)
        check = self.docker("inspect", environment_id)
        if check.exit_code and "no such" in check.stderr.lower():
            return  # already gone (Docker wording differs by version: "No such" / "no such")
        info = self.inspect(environment_id)
        if info.get("State", {}).get("Paused"):
            # runsc cannot kill a frozen sandbox ("PID is zombie"); thaw it first.
            self.checked("unpause", environment_id)
        self.checked("rm", "-f", environment_id)

    def destroy_network(self, network_id: str, project_id: str):
        self._validate_network(network_id, project_id)
        if network_id != "none":
            self.checked("network", "rm", network_id)

    def terminate_project_work(self, project_id: str, keep: list[str]) -> dict:
        names = self.checked(
            "ps",
            "-a",
            "--filter",
            "label=" + LABEL + "=true",
            "--filter",
            "label=org.colossus.project=" + project_id,
            "--format",
            "{{.Names}}",
        ).splitlines()
        removed = []
        for name in names:
            if name not in keep:
                self.destroy(name)
                removed.append(name)
        networks = self.checked(
            "network",
            "ls",
            "--filter",
            "label=" + LABEL + "=true",
            "--filter",
            "label=org.colossus.project=" + project_id,
            "--format",
            "{{.Name}}",
        ).splitlines()
        for name in networks:
            info = json.loads(self.checked("network", "inspect", name))[0]
            if not info.get("Containers"):
                self.destroy_network(name, project_id)
        remaining = self.checked(
            "ps",
            "-a",
            "--filter",
            "label=" + LABEL + "=true",
            "--filter",
            "label=org.colossus.project=" + project_id,
            "--format",
            "{{.Names}}",
        ).splitlines()
        if any(name not in keep for name in remaining):
            raise DomainError(
                "termination_unconfirmed", "Some project workers are still present", 503
            )
        return {"terminated": removed, "preserved": remaining, "termination_confirmed": True}

    def reap(self) -> list[str]:
        """Remove expired COLOSSUS containers, then expired empty COLOSSUS networks.

        Only resources carrying org.colossus.managed=true are listed, and each is
        re-inspected before removal. Quarantined (paused) workers are kept.
        """
        names = self.checked(
            "ps", "-a", "--filter", "label=" + LABEL + "=true", "--format", "{{.Names}}"
        ).splitlines()
        removed = []
        now = time.time()
        for name in names:
            try:
                info = self.inspect(name)
            except DomainError:
                continue  # vanished or not ours
            if info.get("State", {}).get("Paused"):
                continue
            if _expiry(info["Config"]["Labels"]) <= now:
                self.destroy(name)
                removed.append(name)
        networks = self.checked(
            "network", "ls", "--filter", "label=" + LABEL + "=true", "--format", "{{.Name}}"
        ).splitlines()
        for name in networks:
            if not name.startswith("colossus-net-"):
                continue
            result = self.docker("network", "inspect", name)
            if result.exit_code:
                continue
            info = json.loads(result.stdout)[0]
            labels = info.get("Labels") or {}
            if labels.get(LABEL) != "true" or info.get("Containers"):
                continue
            if "org.colossus.expires" in labels and _expiry(labels) <= now:
                if self.docker("network", "rm", name).exit_code == 0:
                    removed.append(name)
        return removed

    def export_files(
        self, environment_id: str, directory: str, max_bytes: int = 25 * 1024 * 1024
    ) -> dict[str, bytes]:
        """Export text-sized results only. Large dependency artifacts use a separate build path."""
        self.inspect(environment_id)
        if directory not in {"/work/results", "/work/source"}:
            raise DomainError("invalid_export", "Export directory is not allowed", 422)
        # Binary tar must not pass through the text/log subprocess adapter.
        process = subprocess.Popen(
            [
                "docker",
                "--context",
                self.context,
                "exec",
                environment_id,
                "tar",
                "-cf",
                "-",
                "-C",
                directory,
                ".",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        output = bytearray()

        def read():
            while chunk := process.stdout.read(8192):
                output.extend(chunk)
                if len(output) > max_bytes:
                    process.kill()
                    break

        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise DomainError("export_timeout", "Sandbox export timed out", 503) from None
        thread.join(timeout=2)
        if process.returncode or len(output) > max_bytes:
            raise DomainError("export_failed", "Sandbox export failed or exceeded limit", 413)
        files = {}
        with tarfile.open(fileobj=io.BytesIO(output), mode="r:") as archive:
            for item in archive:
                name = item.name.removeprefix("./").rstrip("/")
                if item.isdir():
                    continue
                safe_relative_path(name)
                if not item.isfile() or name in files:
                    raise DomainError(
                        "unsafe_export", "Sandbox export contains links or duplicate files", 422
                    )
                stream = archive.extractfile(item)
                files[name] = stream.read()
        return files


def _expiry(labels: dict) -> int:
    try:
        return int(labels.get("org.colossus.expires", "0"))
    except ValueError:
        return 0
