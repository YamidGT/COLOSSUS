"""Launcher hardening checks with a recorded fake Docker (no daemon needed)."""

import json
import time

import pytest

from colossus.contracts.core import DomainError
from colossus.sandbox import launcher as launcher_mod
from colossus.sandbox.launcher import (
    PYTHON_IMAGE,
    ProcessResult,
    SandboxLauncher,
    assert_safe_create,
)

PROJECT = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"


class FakeDocker:
    def __init__(self, networks=None, containers=None):
        self.calls: list[list[str]] = []
        self.networks = networks or {}
        self.containers = containers or {}

    def __call__(self, args, timeout, stdin=None, max_output=0):
        assert args[:3] == ["docker", "--context", "ctx"]
        cmd = args[3:]
        self.calls.append(cmd)
        ok = lambda out="": ProcessResult(0, out, "", False, 0.0)  # noqa: E731
        if cmd[:2] == ["image", "inspect"]:
            return ok(json.dumps([{"Config": {}}]))
        if cmd[:2] == ["network", "inspect"]:
            return ok(json.dumps([self.networks[cmd[2]]]))
        if cmd[0] == "inspect":
            if cmd[1] not in self.containers:
                return ProcessResult(1, "", "No such object", False, 0.0)
            return ok(json.dumps([self.containers[cmd[1]]]))
        if cmd[:2] == ["ps", "-a"]:
            return ok("\n".join(self.containers))
        return ok()

    def creates(self):
        return [c for c in self.calls if c[0] == "create"]


@pytest.fixture
def fake(monkeypatch):
    fd = FakeDocker()
    monkeypatch.setattr(launcher_mod, "bounded_process", fd)
    return fd


def values(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


def test_constructor_refuses_non_gvisor_runtime():
    with pytest.raises(ValueError):
        SandboxLauncher("ctx", runtime="runc")


def test_create_uses_hardened_flags(fake):
    SandboxLauncher("ctx").create(PROJECT, "verify")
    (argv,) = fake.creates()
    assert values(argv, "--runtime") == ["runsc"]
    assert values(argv, "--network") == ["none"]
    assert values(argv, "--cap-drop") == ["ALL"]
    assert values(argv, "--ipc") == ["private"]
    assert values(argv, "--user") == ["1000:1000"]
    assert values(argv, "--memory") == values(argv, "--memory-swap")
    assert "--read-only" in argv and "no-new-privileges" in values(argv, "--security-opt")
    assert PYTHON_IMAGE in argv
    assert not any(a in ("-v", "--volume", "--mount", "--privileged", "-p") for a in argv)
    labels = values(argv, "--label")
    assert f"org.colossus.project={PROJECT}" in labels and "org.colossus.managed=true" in labels


@pytest.mark.parametrize(
    "kw", [{"role": "shell"}, {"memory_mb": 32}, {"memory_mb": 99999}, {"ttl_seconds": 0}]
)
def test_create_rejects_bad_role_or_limits(fake, kw):
    args = {"role": "verify", **kw}
    with pytest.raises(DomainError):
        SandboxLauncher("ctx").create(PROJECT, args.pop("role"), **args)
    assert fake.creates() == []


def test_create_rejects_foreign_or_external_network(fake):
    fake.networks["colossus-net-x"] = {"Internal": True, "Labels": {"org.colossus.project": OTHER}}
    fake.networks["colossus-net-ext"] = {
        "Internal": False,
        "Labels": {"org.colossus.project": PROJECT},
    }
    ln = SandboxLauncher("ctx")
    for net in ("bridge", "host", "colossus-net-x", "colossus-net-ext"):
        with pytest.raises(DomainError):
            ln.create(PROJECT, "verify", network=net)
    assert fake.creates() == []


def test_unpinned_image_refused(fake):
    with pytest.raises(DomainError):
        SandboxLauncher("ctx").create(PROJECT, "target", image="python:latest")


def _good_argv():
    return [
        "create",
        "--name",
        "colossus-1",
        "--runtime",
        "runsc",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--ipc",
        "private",
        "--user",
        "1000:1000",
        "--cpus",
        "2",
        "--pids-limit",
        "128",
        "--memory",
        "64m",
        "--memory-swap",
        "64m",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=1",
        PYTHON_IMAGE,
        "python",
        "-v",
    ]


def test_safe_create_accepts_good_argv_and_ignores_container_args():
    assert_safe_create(_good_argv())  # trailing "-v" belongs to the container command


def _ins(*tokens):
    def go(a):
        a[1:1] = list(tokens)

    return go


def _swap(old, new, after=None):
    def go(a):
        a[a.index(old, a.index(after) if after else 0)] = new

    return go


@pytest.mark.parametrize(
    "mutate",
    [
        _ins("--privileged"),
        _ins("--read-only=false"),
        _ins("--user", "0:0"),
        _ins("--ipc", "host"),
        _swap("64m", "0m"),
        _swap("2", "0", after="--cpus"),
        _ins("--cap-add=SYS_ADMIN"),
        _ins("-v", "/var/run/docker.sock:/s"),
        _ins("--mount", "type=bind,source=/,target=/h"),
        _ins("--pid=host"),
        _ins("--sysctl=net.ipv4.ip_forward=1"),
        _swap("runsc", "runc"),
        _swap("none", "host"),
        _swap("private", "host"),
        _swap("no-new-privileges", "seccomp=unconfined"),
        _swap("1000:1000", "0:0"),
        _swap("64m", "1g", after="--memory-swap"),
        _swap("/tmp:rw,noexec,nosuid,nodev,size=1", "/tmp:rw,exec"),
        lambda a: a.remove("--read-only"),
    ],
)
def test_safe_create_refuses_weakening(mutate):
    argv = _good_argv()
    mutate(argv)
    with pytest.raises(DomainError):
        assert_safe_create(argv)


def test_inspect_refuses_unmanaged_container(fake):
    fake.containers["colossus-evil"] = {"Config": {"Labels": {}}}
    with pytest.raises(DomainError):
        SandboxLauncher("ctx").inspect("colossus-evil")
    with pytest.raises(DomainError):
        SandboxLauncher("ctx").inspect("postgres")


def test_reaper_removes_only_expired_managed(fake):
    now = int(time.time())

    def managed(exp):
        return {
            "Config": {"Labels": {"org.colossus.managed": "true", "org.colossus.expires": str(exp)}}
        }

    fake.containers = {"colossus-old": managed(now - 5), "colossus-new": managed(now + 600)}
    assert SandboxLauncher("ctx").reap() == ["colossus-old"]
    removed = [c for c in fake.calls if c[:2] == ["rm", "-f"]]
    assert removed == [["rm", "-f", "colossus-old"]]
    assert not any(c[:2] in (["system", "prune"], ["container", "prune"]) for c in fake.calls)


def test_bounded_process_kills_on_timeout_and_strips_env(monkeypatch):
    monkeypatch.setenv("MISTRAL_API_KEY", "must-not-leak")
    res = launcher_mod.bounded_process(
        ["python3", "-c", "import os,time;print(os.environ.get('MISTRAL_API_KEY'));time.sleep(30)"],
        2,
    )
    assert res.timed_out and "must-not-leak" not in res.stdout
