"""Local Docker launcher: the only component with runtime access.

Flow per job: stage inputs -> docker create (hardened argv) -> start/attach with
deadline -> stop/kill on timeout -> record exit -> remove container -> import
bounded regular files from /out. Results are imported only after the worker is
destroyed. The launcher never runs a shell and never prunes global resources.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from colossus.contracts.errors import ColossusError, ContractError, ErrorCode

from .profiles import LABEL_PREFIX, IsolationProfile, JobProfile, NetworkMode, build_run_argv, container_name

MAX_OUTPUT_FILES = 256
MAX_STDIO_BYTES = 256 * 1024
KILL_GRACE_SECONDS = 10


class JobStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    INFRA_FAILED = "infra_failed"


@dataclass(frozen=True)
class CollectedFile:
    path: str
    sha256: str
    size: int


@dataclass
class JobResult:
    job_id: str
    status: JobStatus
    exit_code: int | None
    stdout: bytes
    stdout_truncated: bool
    elapsed_seconds: float
    files: list[CollectedFile] = field(default_factory=list)
    rejected_outputs: list[str] = field(default_factory=list)
    output_root: Path | None = None


def _deny(code: ErrorCode, message: str) -> ContractError:
    return ContractError(ColossusError.of(code, message))


class DockerLauncher:
    def __init__(self, work_root: Path | None = None, docker: str = "docker"):
        self.docker = docker
        self.orphans: list[str] = []  # host paths that could not be removed; reported by doctor/reaper
        self.work_root = Path(work_root) if work_root is not None else None
        if self.work_root is not None:
            # A fresh, private root: host users cannot reach the job dirs below it.
            self.work_root.mkdir(parents=True, exist_ok=False, mode=0o700)

    # ------------------------------------------------------------ helpers
    def _run(self, *args: str, timeout: float = 60, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        proc = subprocess.run([self.docker, *args], capture_output=True, timeout=timeout, check=False)
        if check and proc.returncode != 0:
            raise _deny(ErrorCode.INFRA_FAILED, f"docker {args[0]} failed: {proc.stderr[:200].decode(errors='replace')}")
        return proc

    def available_runtimes(self) -> set[str]:
        proc = self._run("info", "--format", "{{json .Runtimes}}", timeout=30)
        return set(json.loads(proc.stdout or b"{}").keys())

    # ------------------------------------------------------------ environments
    def create_case_network(self, case_id: str) -> str:
        """Per-case internal network: no external route, labelled for the reaper."""
        name = f"colossus-case-{case_id[:8]}"
        self._run(
            "network", "create", "--internal", "--driver", "bridge",
            "--label", f"{LABEL_PREFIX}.managed=true", "--label", f"{LABEL_PREFIX}.case={case_id}",
            "--opt", "com.docker.network.bridge.enable_ip_masquerade=false",
            name,
        )
        return name

    def destroy_case(self, case_id: str) -> None:
        """Remove only containers/networks positively labelled for this case."""
        label = f"label={LABEL_PREFIX}.case={case_id}"
        ids = self._run("ps", "-aq", "--filter", label, timeout=30).stdout.split()
        if ids:
            self._run("rm", "-f", *[i.decode() for i in ids], timeout=60)
        nets = self._run("network", "ls", "-q", "--filter", label, timeout=30).stdout.split()
        if nets:
            self._run("network", "rm", *[n.decode() for n in nets], timeout=60)

    # ------------------------------------------------------------ jobs
    def _stage(self, job_id: str, inputs: dict[str, bytes]) -> tuple[Path, Path, Path]:
        if self.work_root is None:
            raise _deny(ErrorCode.INVALID_INPUT, "launcher has no work_root")
        root = self.work_root / job_id
        if root.exists():
            raise _deny(ErrorCode.CONFLICT, "job id already used")
        in_dir, out_dir = root / "in", root / "out"
        root.mkdir(mode=0o700)
        in_dir.mkdir()
        out_dir.mkdir()
        for name, data in inputs.items():
            if "/" in name or name in ("", ".", ".."):
                raise _deny(ErrorCode.INVALID_INPUT, "input names must be plain file names")
            path = in_dir / name
            path.write_bytes(data)
            os.chmod(path, 0o444)
        os.chmod(in_dir, 0o555)
        return in_dir, out_dir, root

    def run_job(
        self,
        *,
        job: JobProfile,
        isolation: IsolationProfile,
        case_id: str,
        job_id: str,
        inputs: dict[str, bytes] | None = None,
        network_name: str | None = None,
        max_output_bytes: int | None = None,
    ) -> JobResult:
        if isolation.runtime.value not in self.available_runtimes():
            raise _deny(
                ErrorCode.ISOLATION_UNAVAILABLE,
                f"runtime {isolation.runtime.value} is not installed; job not started (no fallback)",
            )
        if isolation.network is NetworkMode.CASE_INTERNAL and network_name is None:
            raise _deny(ErrorCode.POLICY_DENIED, "case_internal profile needs a case network")
        in_dir, out_dir, root = self._stage(job_id, inputs or {})
        # The bind-mounted dir's own mode is what the container user sees. Parents
        # stay 0700, so only the daemon and this process can reach it on the host.
        os.chmod(out_dir, 0o777)
        argv = build_run_argv(
            job=job, isolation=isolation, case_id=case_id, job_id=job_id,
            input_dir=str(in_dir), output_dir=str(out_dir), network_name=network_name,
        )
        name = container_name(case_id, job_id)
        cap = max_output_bytes or isolation.output_mib * 1024 * 1024
        start = time.monotonic()
        status, exit_code, stdout = JobStatus.INFRA_FAILED, None, b""
        try:
            subprocess.run(argv, capture_output=True, timeout=60, check=True)
            try:
                proc = subprocess.run(
                    [self.docker, "start", "--attach", name],
                    capture_output=True, timeout=job.timeout_seconds,
                )
                stdout = proc.stdout + proc.stderr
                state = json.loads(self._run("inspect", "--format", "{{json .State}}", name).stdout)
                exit_code = int(state["ExitCode"])
                status = JobStatus.SUCCEEDED if exit_code == 0 else JobStatus.FAILED
                if state.get("OOMKilled"):
                    status = JobStatus.FAILED
            except subprocess.TimeoutExpired:
                self._run("stop", "--time", str(KILL_GRACE_SECONDS), name, timeout=KILL_GRACE_SECONDS + 30, check=False)
                self._run("kill", name, check=False)
                status = JobStatus.TIMEOUT  # late results from this attempt are never imported
        except subprocess.CalledProcessError as exc:
            stdout = exc.stderr[:MAX_STDIO_BYTES]
        finally:
            # destroy worker before importing results
            self._run("rm", "-f", name, timeout=60, check=False)
        elapsed = time.monotonic() - start
        result = JobResult(
            job_id=job_id, status=status, exit_code=exit_code,
            stdout=stdout[:MAX_STDIO_BYTES], stdout_truncated=len(stdout) > MAX_STDIO_BYTES,
            elapsed_seconds=elapsed,
        )
        if status is not JobStatus.TIMEOUT:
            result.files, result.rejected_outputs, result.output_root = self._import(out_dir, root / "collected", cap)
        self._wipe_output(job=job, isolation=isolation, case_id=case_id, job_id=job_id, out_dir=out_dir)
        return result

    def _wipe_output(self, *, job: JobProfile, isolation: IsolationProfile, case_id: str, job_id: str, out_dir: Path) -> None:
        """Delete job-owned files as the job user, under the same isolation profile.

        The host process may not own files the sandbox user created, so deletion
        happens inside a fresh sandbox. Leftovers are reported, never ignored.
        """
        wipe = job.model_copy(update={"argv": ["find", "/out", "-mindepth", "1", "-delete"], "env": {}})
        wipe_id = "w" + job_id[1:]
        argv = build_run_argv(
            job=wipe, isolation=isolation.model_copy(update={"network": NetworkMode.NONE}),
            case_id=case_id, job_id=wipe_id, input_dir=None, output_dir=str(out_dir),
        )
        name = container_name(case_id, wipe_id)
        try:
            subprocess.run(argv, capture_output=True, timeout=60, check=True)
            subprocess.run([self.docker, "start", "--attach", name], capture_output=True, timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        finally:
            self._run("rm", "-f", name, timeout=60, check=False)
        try:
            out_dir.rmdir()
        except OSError:
            self.orphans.append(str(out_dir))

    def release_job(self, job_id: str) -> None:
        """Delete a job's staging and collected files after evidence export."""
        if self.work_root is None:
            return
        root = self.work_root / job_id
        if (root / "in").is_dir():
            os.chmod(root / "in", 0o700)
        shutil.rmtree(root, ignore_errors=True)

    def _import(self, out_dir: Path, dest: Path, cap: int) -> tuple[list[CollectedFile], list[str], Path]:
        """Copy only regular files (no symlinks/devices) under a size and count cap."""
        dest.mkdir()
        files: list[CollectedFile] = []
        rejected: list[str] = []
        total = 0
        for dirpath, dirnames, filenames in os.walk(out_dir, followlinks=False):
            for d in list(dirnames):
                if os.path.islink(os.path.join(dirpath, d)):
                    rejected.append(os.path.relpath(os.path.join(dirpath, d), out_dir) + ": symlink")
                    dirnames.remove(d)
            for fname in sorted(filenames):
                src = Path(dirpath) / fname
                rel = src.relative_to(out_dir).as_posix()
                st = os.lstat(src)
                if not stat.S_ISREG(st.st_mode):
                    rejected.append(f"{rel}: not a regular file")
                    continue
                if len(files) >= MAX_OUTPUT_FILES or total + st.st_size > cap:
                    rejected.append(f"{rel}: output cap exceeded")
                    continue
                fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as fh:
                    data = fh.read(cap - total + 1)
                if len(data) != st.st_size:
                    rejected.append(f"{rel}: changed during import")
                    continue
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                total += len(data)
                files.append(CollectedFile(rel, hashlib.sha256(data).hexdigest(), len(data)))
        return files, rejected, dest
