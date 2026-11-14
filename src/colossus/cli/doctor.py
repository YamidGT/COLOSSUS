"""`colossus doctor` local readiness checks (docs/cli.md, docs/implementation.md M0).

Static host checks only: no target code, no provider calls, no secret values.
Each check reports what was actually observed on this host.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Callable

MIN_FREE_DISK_GIB = 20
MIN_MEMORY_GIB = 16
MIN_CPUS = 4
PROVIDER_VARS = ("MISTRAL_API_KEY", "GROQ_API_KEY")


class CheckState(StrEnum):
    OK = "ok"
    WARN = "warn"  # works, but below the documented profile or an optional tool is absent
    BLOCKED = "blocked"  # blocks the standard profile
    UNKNOWN = "unknown"  # could not be measured


@dataclass
class Check:
    check_id: str
    state: CheckState
    observed: str
    remedy: str | None = None


@dataclass
class Host:
    """Injectable view of the host so tests never depend on the real machine."""

    machine: Callable[[], str] = platform.machine
    kernel: Callable[[], str] = platform.release
    cpu_count: Callable[[], int | None] = os.cpu_count
    which: Callable[[str], str | None] = shutil.which
    read_text: Callable[[str], str] = lambda p: Path(p).read_text()
    run: Callable[[list[str]], tuple[int, str]] = field(default=None)  # type: ignore[assignment]
    disk_free_bytes: Callable[[str], int] = lambda p: shutil.disk_usage(p).free

    def __post_init__(self) -> None:
        if self.run is None:
            def _run(argv: list[str]) -> tuple[int, str]:
                try:
                    p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
                    return p.returncode, p.stdout
                except (OSError, subprocess.TimeoutExpired) as exc:
                    return 127, type(exc).__name__
            self.run = _run


def _mem_total_gib(host: Host) -> float | None:
    try:
        for line in host.read_text("/proc/meminfo").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) / (1024 * 1024)
    except OSError:
        return None
    return None


def check_host(host: Host, work_dir: str) -> list[Check]:
    out: list[Check] = []
    arch = host.machine()
    out.append(Check("host.architecture", CheckState.OK if arch in ("x86_64", "aarch64") else CheckState.BLOCKED,
                     arch, None if arch in ("x86_64", "aarch64") else "use a linux/amd64 or linux/arm64 host"))
    out.append(Check("host.kernel", CheckState.OK, host.kernel()))
    cpus = host.cpu_count() or 0
    out.append(Check("host.cpus", CheckState.OK if cpus >= MIN_CPUS else CheckState.WARN, str(cpus),
                     None if cpus >= MIN_CPUS else f"standard profile assumes {MIN_CPUS} CPUs"))
    mem = _mem_total_gib(host)
    if mem is None:
        out.append(Check("host.memory", CheckState.UNKNOWN, "unreadable /proc/meminfo"))
    else:
        out.append(Check("host.memory", CheckState.OK if mem >= MIN_MEMORY_GIB else CheckState.WARN, f"{mem:.1f} GiB",
                         None if mem >= MIN_MEMORY_GIB else f"standard profile assumes about 24 GiB"))
    try:
        free = host.disk_free_bytes(work_dir) / 1024**3
        out.append(Check("host.disk_free", CheckState.OK if free >= MIN_FREE_DISK_GIB else CheckState.BLOCKED,
                         f"{free:.0f} GiB free at {work_dir}",
                         None if free >= MIN_FREE_DISK_GIB else f"need {MIN_FREE_DISK_GIB} GiB for images and evidence"))
    except OSError as exc:
        out.append(Check("host.disk_free", CheckState.UNKNOWN, type(exc).__name__))
    try:
        ctrls = set(host.read_text("/sys/fs/cgroup/cgroup.controllers").split())
        need = {"cpu", "memory", "pids"}
        missing = sorted(need - ctrls)
        out.append(Check("host.cgroup_v2", CheckState.OK if not missing else CheckState.BLOCKED,
                         "controllers: " + " ".join(sorted(ctrls & (need | {"io"}))),
                         None if not missing else "enable cgroup v2 controllers: " + ",".join(missing)))
    except OSError:
        out.append(Check("host.cgroup_v2", CheckState.BLOCKED, "no unified cgroup v2 hierarchy",
                         "resource limits cannot be enforced"))
    return out


def check_runtime(host: Host) -> list[Check]:
    out: list[Check] = []
    if not host.which("docker"):
        return [Check("runtime.docker", CheckState.BLOCKED, "docker not found", "install Docker Engine")]
    code, ver = host.run(["docker", "version", "--format", "{{.Server.Version}}"])
    if code != 0:
        return [Check("runtime.docker", CheckState.BLOCKED, "daemon unreachable", "start the Docker daemon")]
    out.append(Check("runtime.docker", CheckState.OK, f"server {ver.strip()}"))
    code, info = host.run(["docker", "info", "--format", "{{json .Runtimes}}|{{json .SecurityOptions}}"])
    runtimes: set[str] = set()
    secopts = ""
    if code == 0 and "|" in info:
        rt, secopts = info.strip().split("|", 1)
        try:
            runtimes = set(json.loads(rt))
        except ValueError:
            pass
    if "runsc" in runtimes:
        out.append(Check("runtime.gvisor", CheckState.OK, "runsc registered with Docker"))
    else:
        out.append(Check(
            "runtime.gvisor", CheckState.BLOCKED,
            "runsc not registered (runtimes: " + ",".join(sorted(runtimes)) + ")",
            "install gVisor and register runsc (https://gvisor.dev/docs/user_guide/install/); "
            "untrusted repository jobs are refused until then",
        ))
    out.append(Check(
        "runtime.rootless", CheckState.OK if "rootless" in secopts else CheckState.WARN,
        "rootless" if "rootless" in secopts else "daemon is not rootless",
        None if "rootless" in secopts else "selected profile is rootless Docker + gVisor",
    ))
    out.append(Check(
        "runtime.untrusted_build_backend", CheckState.BLOCKED,
        "no validated isolated build backend",
        "builds of repository code need a preflighted isolated builder (docs/onboarding-sandbox.md)",
    ))
    return out


def check_tools(host: Host) -> list[Check]:
    out = []
    for tool, purpose in (("dafny", "formal gates (lane D)"), ("crosshair", "Python formal checks (lane D)")):
        path = host.which(tool)
        out.append(Check(f"tools.{tool}", CheckState.OK if path else CheckState.WARN,
                         "found" if path else "missing", None if path else f"needed for {purpose}; run via a pinned tool image"))
    return out


def check_credentials(repo_root: Path) -> list[Check]:
    """Report configured/missing by provider name only. Values are never read into output."""
    env = repo_root / ".env"
    if not env.exists():
        return [Check(f"credentials.{v.split('_')[0].lower()}", CheckState.WARN, "missing (.env absent)",
                      "create .env from .env.example on this host") for v in PROVIDER_VARS]
    out = []
    mode = stat.S_IMODE(env.stat().st_mode)
    out.append(Check("credentials.env_permissions", CheckState.OK if mode & 0o077 == 0 else CheckState.BLOCKED,
                     oct(mode), None if mode & 0o077 == 0 else "chmod 600 .env"))
    configured = set()
    for line in env.read_text(encoding="utf-8", errors="replace").splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() in PROVIDER_VARS and value.strip():
            configured.add(name.strip())
    for var in PROVIDER_VARS:
        state = CheckState.OK if var in configured else CheckState.WARN
        out.append(Check(f"credentials.{var.split('_')[0].lower()}", state, "configured" if var in configured else "missing"))
    return out


def check_repo(host: Host, repo_root: Path) -> list[Check]:
    code, _ = host.run(["git", "-C", str(repo_root), "check-ignore", "-q", ".env"])
    return [Check("repo.env_ignored", CheckState.OK if code == 0 else CheckState.BLOCKED,
                  "ignored" if code == 0 else "not ignored", None if code == 0 else "add .env to .gitignore")]


def run_doctor(repo_root: Path, work_dir: str, host: Host | None = None) -> list[Check]:
    host = host or Host()
    return [
        *check_host(host, work_dir),
        *check_runtime(host),
        *check_tools(host),
        *check_credentials(repo_root),
        *check_repo(host, repo_root),
    ]


def summarize(checks: list[Check]) -> tuple[str, int]:
    """Return (status, exit_code) per cli.md: 0 ready, 3 readiness blocks action."""
    if any(c.state is CheckState.BLOCKED for c in checks):
        return "blocked", 3
    if any(c.state in (CheckState.WARN, CheckState.UNKNOWN) for c in checks):
        return "degraded", 0
    return "ready", 0


def as_dicts(checks: list[Check]) -> list[dict]:
    return [{**asdict(c), "state": c.state.value} for c in checks]
