"""Isolation and job profiles, and the hardened `docker` argv they produce."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import Field, model_validator

from colossus.contracts.common import BoundedList, ImageDigest, ProfileId, StrictModel
from colossus.contracts.errors import ColossusError, ContractError, ErrorCode

LABEL_PREFIX = "io.colossus"
_SAFE_ARG = re.compile(r"^[A-Za-z0-9_./:=,@+%-]{1,512}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")


class Runtime(StrEnum):
    RUNSC = "runsc"  # gVisor: required for untrusted repository code
    RUNC = "runc"  # only for trusted fixture images (never repository code)


class TrustLevel(StrEnum):
    UNTRUSTED_REPOSITORY = "untrusted_repository"
    TRUSTED_FIXTURE = "trusted_fixture"


class NetworkMode(StrEnum):
    NONE = "none"  # default deny
    CASE_INTERNAL = "case_internal"  # per-case internal network, no egress


class IsolationProfile(StrictModel):
    profile_id: ProfileId
    trust: TrustLevel
    runtime: Runtime
    user: Annotated[str, Field(pattern=r"^[1-9][0-9]{2,5}:[1-9][0-9]{2,5}$")] = "65534:65534"
    cpus_milli: Annotated[int, Field(ge=100, le=2000)] = 1000
    memory_mib: Annotated[int, Field(ge=64, le=12288)] = 1024
    pids_limit: Annotated[int, Field(ge=16, le=4096)] = 256
    scratch_mib: Annotated[int, Field(ge=1, le=4096)] = 256
    output_mib: Annotated[int, Field(ge=1, le=1024)] = 64
    network: NetworkMode = NetworkMode.NONE

    @model_validator(mode="after")
    def _untrusted_needs_gvisor(self) -> "IsolationProfile":
        if self.trust is TrustLevel.UNTRUSTED_REPOSITORY and self.runtime is not Runtime.RUNSC:
            raise ValueError("untrusted repository jobs require the runsc (gVisor) runtime; no fallback")
        return self


class JobProfile(StrictModel):
    """Fixed image + argv. Workers choose inputs, never the executable."""

    job_profile_id: ProfileId
    image: ImageDigest
    platform: Annotated[str, Field(pattern=r"^linux/(amd64|arm64)$")]
    argv: Annotated[list[Annotated[str, Field(pattern=_SAFE_ARG.pattern)]], Field(min_length=1, max_length=64)]
    timeout_seconds: Annotated[int, Field(ge=1, le=3600)]
    isolation_profile_id: ProfileId
    env: dict[Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")], Annotated[str, Field(pattern=_SAFE_ARG.pattern)]] = {}
    input_mounts: BoundedList(ProfileId, 8) = []

    @model_validator(mode="after")
    def _no_secrets(self) -> "JobProfile":
        if self.argv[0].rsplit("/", 1)[-1] in ("sh", "bash", "dash", "zsh", "ash", "busybox"):
            raise ValueError("job entrypoint cannot be a shell")
        for key in self.env:
            if any(word in key for word in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
                raise ValueError("job env must not carry credentials")
        return self


def container_name(case_id: str, job_id: str) -> str:
    name = f"colossus-{case_id[:8]}-{job_id[:8]}".lower()
    if not _NAME.fullmatch(name):
        raise ContractError(ColossusError.of(ErrorCode.INVALID_INPUT, "bad container name"))
    return name


def build_run_argv(
    *,
    job: JobProfile,
    isolation: IsolationProfile,
    case_id: str,
    job_id: str,
    input_dir: str | None,
    output_dir: str,
    network_name: str | None = None,
) -> list[str]:
    """Return `docker create` argv for one job. No shell is ever involved."""
    if job.isolation_profile_id != isolation.profile_id:
        raise ContractError(ColossusError.of(ErrorCode.POLICY_DENIED, "job and isolation profile do not match"))
    if isolation.network is NetworkMode.NONE:
        net = "none"
    else:
        if not network_name or not network_name.startswith("colossus-case-"):
            raise ContractError(ColossusError.of(ErrorCode.POLICY_DENIED, "case network must be a colossus-case-* internal network"))
        net = network_name
    labels = {
        f"{LABEL_PREFIX}.managed": "true",
        f"{LABEL_PREFIX}.case": case_id,
        f"{LABEL_PREFIX}.job": job_id,
        f"{LABEL_PREFIX}.profile": job.job_profile_id,
    }
    argv = [
        "docker", "create",
        "--name", container_name(case_id, job_id),
        "--runtime", isolation.runtime.value,
        "--platform", job.platform,
        "--pull", "never",
        "--network", net,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true",
        "--read-only",
        "--user", isolation.user,
        "--ipc", "private",
        "--pids-limit", str(isolation.pids_limit),
        "--memory", f"{isolation.memory_mib}m",
        "--memory-swap", f"{isolation.memory_mib}m",
        "--cpus", f"{isolation.cpus_milli / 1000:.3f}",
        "--tmpfs", f"/scratch:rw,noexec,nosuid,nodev,size={isolation.scratch_mib}m",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={isolation.scratch_mib}m",
        "--mount", f"type=bind,source={output_dir},target=/out,readonly=false",
        "--workdir", "/scratch",
        "--stop-timeout", "10",
        "--log-driver", "none",
    ]
    if input_dir is not None:
        argv += ["--mount", f"type=bind,source={input_dir},target=/in,readonly=true"]
    for k, v in sorted(labels.items()):
        argv += ["--label", f"{k}={v}"]
    for k, v in sorted(job.env.items()):
        argv += ["--env", f"{k}={v}"]
    argv += ["--entrypoint", job.argv[0], job.image, *job.argv[1:]]
    assert_safe_argv(argv)
    return argv


_FORBIDDEN_FLAGS = (
    "--privileged",
    "--cap-add",
    "--device",
    "--pid",
    "--userns",
    "--uts",
    "--volumes-from",
    "-v",
    "--volume",
    "-p",
    "--publish",
    "-P",
    "--publish-all",
    "--add-host",
    "--env-file",
    "--group-add",
)


def assert_safe_argv(argv: list[str]) -> None:
    """Second line of defence: reject any argv that weakens isolation."""

    def deny(why: str) -> None:
        raise ContractError(ColossusError.of(ErrorCode.POLICY_DENIED, why))

    if argv[:2] != ["docker", "create"]:
        deny("only docker create is built here")
    if "--entrypoint" not in argv:
        deny("missing fixed --entrypoint")
    options = argv[: argv.index("--entrypoint")]  # container args after the image are not docker flags
    for i, arg in enumerate(options):
        flag = arg.split("=", 1)[0]
        if flag in _FORBIDDEN_FLAGS:
            deny(f"forbidden flag {flag}")
        nxt = options[i + 1] if i + 1 < len(options) else ""
        if flag == "--network" and (nxt in ("host", "bridge", "default") or nxt.startswith("container:")):
            deny("host/bridge/container networks are not allowed")
        if flag == "--ipc" and nxt != "private":
            deny("ipc must be private")
        if flag == "--security-opt" and "unconfined" in nxt:
            deny("unconfined security options are not allowed")
        if flag == "--mount":
            if "docker.sock" in nxt or "containerd" in nxt or "/proc" in nxt or "/sys" in nxt:
                deny("runtime sockets and kernel filesystems cannot be mounted")
            if "target=/out" not in nxt and "readonly=true" not in nxt:
                deny("only /out may be writable")
    for required in ("--read-only", "--cap-drop"):
        if required not in options:
            deny(f"missing {required}")
