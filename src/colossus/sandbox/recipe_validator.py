"""Recipe validator for Compose-like service plans (docs/onboarding-sandbox.md).

A recipe is untrusted text. This checks the plan shape only; build commands
inside the isolated builder are still untrusted code, and this list is not a
substitute for the runtime boundary.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

MAX_SERVICES = 6
MAX_TOTAL_MEMORY_MIB = 6 * 1024
MAX_TOTAL_CPUS_MILLI = 1000
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
_ALLOWED_SERVICE_KEYS = {
    "image",
    "build",
    "command",
    "environment",
    "depends_on",
    "expose",
    "healthcheck",
    "mem_limit",
    "cpus",
    "working_dir",
    "user",
    "tmpfs",
    "volumes",
}
_SOCKETS = ("docker.sock", "containerd.sock", "podman.sock", "crio.sock", "buildkitd")


@dataclass(frozen=True)
class Violation:
    service: str
    rule: str
    detail: str


def _mem_mib(value: Any) -> int | None:
    if value is None:
        return None
    m = re.fullmatch(r"(\d+)([kKmMgG])?[bB]?", str(value))
    if not m:
        return None
    n, unit = int(m.group(1)), (m.group(2) or "").lower()
    return {"": n // (1024 * 1024), "k": n // 1024, "m": n, "g": n * 1024}[unit]


def validate_recipe(recipe: Any, *, execution: bool = True) -> list[Violation]:
    """Return every violation. Empty list means the plan shape is acceptable.

    execution=True enforces digest-pinned images (required at execution time).
    """
    out: list[Violation] = []

    def bad(svc: str, rule: str, detail: str) -> None:
        out.append(Violation(svc, rule, detail))

    if not isinstance(recipe, dict) or not isinstance(recipe.get("services"), dict):
        return [Violation("*", "shape", "recipe needs a services mapping")]
    for key in recipe:
        if key not in ("services", "volumes", "name"):
            bad(
                "*",
                "top_level_key",
                f"{key!r} is not allowed (networks, secrets, configs are controller-owned)",
            )
    volumes = recipe.get("volumes") or {}
    if not isinstance(volumes, dict):
        bad("*", "volumes", "named volumes must be a mapping")
        volumes = {}
    for name, options in volumes.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name)
            or options not in (None, {})
        ):
            bad("*", "volume_options", "only empty, controller-created named volumes are allowed")
    services = recipe["services"]
    if not services or len(services) > MAX_SERVICES:
        bad("*", "service_count", f"1..{MAX_SERVICES} services allowed, got {len(services)}")

    total_mem = 0
    total_cpu = 0
    for name, svc in services.items():
        name = str(name)
        if not isinstance(svc, dict):
            bad(name, "shape", "service must be a mapping")
            continue
        for key in svc:
            if key not in _ALLOWED_SERVICE_KEYS:
                bad(name, "service_key", f"{key!r} is not allowed")
        image = svc.get("image")
        if image is None and "build" not in svc:
            bad(name, "image", "service needs image or build")
        if image is not None and execution and not _DIGEST.search(str(image)):
            bad(name, "mutable_image", f"{image!r} is not pinned by sha256 digest")
        user = str(svc.get("user", ""))
        if user in ("0", "root") or user.startswith(("0:", "root:")):
            bad(name, "root_user", "services must not run as root")
        mounts = svc.get("volumes") or []
        if not isinstance(mounts, list):
            bad(name, "volumes", "volumes must be a list")
            mounts = []
        for vol in mounts:
            if isinstance(vol, str):
                pieces = vol.split(":")
                src = pieces[0]
                destination = pieces[1] if len(pieces) > 1 else ""
                valid = len(pieces) in (2, 3) and (len(pieces) < 3 or pieces[2] in ("ro", "rw"))
            elif isinstance(vol, dict):
                src, destination = vol.get("source"), vol.get("target", "")
                valid = vol.get("type") == "volume" and set(vol) <= {
                    "type",
                    "source",
                    "target",
                    "read_only",
                }
            else:
                src, destination, valid = "", "", False
            if (
                not valid
                or not isinstance(src, str)
                or src not in volumes
                or not isinstance(destination, str)
                or not destination.startswith("/")
                or ".." in destination.split("/")
                or any(s in str(vol) for s in _SOCKETS)
            ):
                bad(
                    name,
                    "host_mount",
                    "only declared, controller-owned named volumes may be mounted",
                )
        env = svc.get("environment") or {}
        if isinstance(env, dict):
            items = env.items()
        elif isinstance(env, list) and all(isinstance(e, str) and "=" in e for e in env):
            items = [e.split("=", 1) for e in env]
        else:
            bad(
                name,
                "environment",
                "environment must contain explicit key/value pairs; no host inheritance",
            )
            items = []
        for key, value in items:
            if any(w in str(key).upper() for w in ("AWS_", "MISTRAL", "GROQ", "GITHUB_TOKEN")) or (
                isinstance(value, str)
                and ("${" in value or re.search(r"(?:gsk_|mstrl_)[A-Za-z0-9_-]{20,}", value))
            ):
                bad(
                    name,
                    "credential_env",
                    "provider credentials or host-variable expansion are forbidden",
                )
        mem = _mem_mib(svc.get("mem_limit"))
        if svc.get("mem_limit") is not None and (mem is None or mem <= 0):
            bad(name, "mem_limit", "unparseable mem_limit")
        total_mem += mem or 512
        try:
            cpu = float(svc.get("cpus", 0.25))
            if not math.isfinite(cpu) or cpu <= 0:
                raise ValueError()
            total_cpu += int(cpu * 1000)
        except (TypeError, ValueError):
            bad(name, "cpus", "unparseable cpus")
    if total_mem > MAX_TOTAL_MEMORY_MIB:
        bad("*", "resources", f"total memory {total_mem} MiB exceeds {MAX_TOTAL_MEMORY_MIB}")
    if total_cpu > MAX_TOTAL_CPUS_MILLI:
        bad(
            "*", "resources", f"total cpus {total_cpu / 1000} exceeds {MAX_TOTAL_CPUS_MILLI / 1000}"
        )
    return out
