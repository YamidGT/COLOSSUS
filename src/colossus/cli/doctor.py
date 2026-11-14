"""Local readiness checks for `colossus doctor`.

Static host checks plus the sandbox launcher preflight. No target code runs,
no provider is called and no credential value is read into output.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

MIN_FREE_DISK_GIB = 20
PROVIDER_VARS = ("MISTRAL_API_KEY", "GROQ_API_KEY")


@dataclass
class Check:
    check_id: str
    state: str  # ok | warn | blocked | unknown
    observed: str
    remedy: str | None = None


def check_host(
    work_dir: str, read_text: Callable[[str], str] = lambda p: Path(p).read_text()
) -> list[Check]:
    out = []
    arch = platform.machine()
    supported = arch in ("x86_64", "aarch64", "arm64")
    out.append(
        Check(
            "host.architecture",
            "ok" if supported else "blocked",
            arch,
            None if supported else "use a linux/amd64 or linux/arm64 runtime",
        )
    )
    try:
        free = shutil.disk_usage(work_dir).free / 1024**3
        ok = free >= MIN_FREE_DISK_GIB
        out.append(
            Check(
                "host.disk_free",
                "ok" if ok else "blocked",
                f"{free:.0f} GiB free",
                None if ok else f"need {MIN_FREE_DISK_GIB} GiB for images and evidence",
            )
        )
    except OSError as exc:
        out.append(Check("host.disk_free", "unknown", type(exc).__name__))
    if platform.system() == "Linux":
        try:
            ctrls = set(read_text("/sys/fs/cgroup/cgroup.controllers").split())
            missing = sorted({"cpu", "memory", "pids"} - ctrls)
            out.append(
                Check(
                    "host.cgroup_v2",
                    "blocked" if missing else "ok",
                    "missing: " + ",".join(missing) if missing else "cpu memory pids",
                    "enable cgroup v2 controllers" if missing else None,
                )
            )
        except OSError:
            out.append(
                Check(
                    "host.cgroup_v2",
                    "blocked",
                    "no unified cgroup v2 hierarchy",
                    "resource limits cannot be enforced",
                )
            )
    else:
        out.append(
            Check(
                "host.cgroup_v2",
                "unknown",
                f"{platform.system()} host; limits live in the runtime VM",
            )
        )
    return out


def check_sandbox(preflight: Callable[[], dict]) -> list[Check]:
    try:
        info = preflight()
    except Exception as exc:  # noqa: BLE001 - report, never crash doctor
        return [Check("sandbox.preflight", "blocked", f"preflight failed: {type(exc).__name__}")]
    if info.get("ready"):
        return [
            Check(
                "sandbox.gvisor",
                "ok",
                f"context {info.get('context')}: runsc, {info.get('architecture')}, "
                f"{info.get('cpus')} CPU, Docker {info.get('server_version')}",
            )
        ]
    return [
        Check(
            "sandbox.gvisor",
            "blocked",
            f"context {info.get('context')}: {info.get('reason')}",
            "install gVisor and register runsc in that Docker context, or set COLOSSUS_DOCKER_CONTEXT; "
            "untrusted repository jobs are refused until then",
        )
    ]


def check_credentials(repo_root: Path) -> list[Check]:
    """Report configured/missing by provider name only."""
    env = repo_root / ".env"
    names = [v.split("_")[0].lower() for v in PROVIDER_VARS]
    if not env.is_file() or env.is_symlink():
        return [
            Check(
                f"credentials.{n}", "warn", "missing (.env absent)", "create .env from .env.example"
            )
            for n in names
        ]
    mode = stat.S_IMODE(env.stat().st_mode)
    out = [
        Check(
            "credentials.env_permissions",
            "ok" if mode & 0o077 == 0 else "blocked",
            oct(mode),
            None if mode & 0o077 == 0 else "chmod 600 .env",
        )
    ]
    for name in names:
        out.append(
            Check(
                f"credentials.{name}",
                "unknown",
                "gateway check required",
                "provider values are read only by the credential gateway",
            )
        )
    return out


def check_repo(repo_root: Path) -> list[Check]:
    try:
        code = subprocess.run(
            ["git", "-C", str(repo_root), "check-ignore", "-q", ".env"],
            capture_output=True,
            timeout=10,
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return [Check("repo.env_ignored", "unknown", "git unavailable")]
    return [
        Check(
            "repo.env_ignored",
            "ok" if code == 0 else "blocked",
            "ignored" if code == 0 else "not ignored",
            None if code == 0 else "add .env to .gitignore",
        )
    ]


def run_checks(repo_root: Path, preflight: Callable[[], dict]) -> list[Check]:
    return [
        *check_host(str(repo_root)),
        *check_sandbox(preflight),
        *check_credentials(repo_root),
        *check_repo(repo_root),
    ]


def overall(checks: list[Check]) -> str:
    if any(c.state == "blocked" for c in checks):
        return "blocked"
    if any(c.state in ("warn", "unknown") for c in checks):
        return "degraded"
    return "ready"


def as_dicts(checks: list[Check]) -> list[dict]:
    return [asdict(c) for c in checks]


def repo_root() -> Path:
    return Path(os.environ.get("COLOSSUS_HOME", Path.cwd()))
