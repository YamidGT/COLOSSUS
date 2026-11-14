"""Evidence-before-teardown, quarantine admission and orphan reaping (fake Docker)."""

import json
import time

import pytest

from colossus.contracts.core import DomainError
from colossus.sandbox import launcher as launcher_mod
from colossus.sandbox.launcher import MAX_QUARANTINE, ProcessResult, SandboxLauncher

PROJECT = "00000000-0000-4000-8000-000000000001"


def ok(out=""):
    return ProcessResult(0, out, "", False, 0.0)


class FakeDocker:
    def __init__(self):
        self.calls: list[list[str]] = []
        self.containers: dict[str, dict] = {}
        self.networks: dict[str, dict] = {}
        self.exec_result = ok("done")

    def __call__(self, args, timeout, stdin=None, max_output=0):
        cmd = args[3:]
        self.calls.append(cmd)
        if cmd[:2] == ["image", "inspect"]:
            return ok(json.dumps([{"Config": {}}]))
        if cmd[:2] == ["network", "ls"]:
            return ok("\n".join(self.networks))
        if cmd[:2] == ["network", "inspect"]:
            if cmd[2] not in self.networks:
                return ProcessResult(1, "", "no such network", False, 0.0)
            return ok(json.dumps([self.networks[cmd[2]]]))
        if cmd[:2] == ["network", "rm"]:
            self.networks.pop(cmd[2], None)
            return ok()
        if cmd[0] == "create":
            name = cmd[cmd.index("--name") + 1]
            self.containers[name] = {
                "Config": {"Labels": {"org.colossus.managed": "true"}},
                "State": {"Paused": False},
            }
            return ok(name)
        if cmd[0] == "inspect":
            if cmd[1] not in self.containers:
                return ProcessResult(1, "", "no such object", False, 0.0)
            return ok(json.dumps([self.containers[cmd[1]]]))
        if cmd[:2] == ["ps", "-a"]:
            paused_only = "status=paused" in cmd
            return ok(
                "\n".join(
                    n for n, c in self.containers.items()
                    if not paused_only or c["State"]["Paused"]
                )
            )
        if cmd[0] == "pause":
            self.containers[cmd[1]]["State"]["Paused"] = True
            return ok()
        if cmd[:2] == ["rm", "-f"]:
            self.containers.pop(cmd[2], None)
            return ok()
        if cmd[0] == "exec" and "--workdir" in cmd:
            return self.exec_result
        return ok()

    def verbs(self):
        return [c[0] if c[0] not in ("rm", "network") else " ".join(c[:2]) for c in self.calls]


@pytest.fixture
def fake(monkeypatch):
    fd = FakeDocker()
    monkeypatch.setattr(launcher_mod, "bounded_process", fd)
    return fd


def test_results_are_exported_before_worker_is_destroyed(fake, monkeypatch):
    ln = SandboxLauncher("ctx")
    order = []

    def export(env, directory, max_bytes):
        assert env in fake.containers, "worker destroyed before export"
        order.append("export")
        return {"report.json": b"{}"}

    monkeypatch.setattr(ln, "export_files", export)
    out = ln.run_collect(PROJECT, "verify", {"j.py": b"0"}, ["python", "j.py"], 10)
    assert out["evidence"] == "exported" and out["files"] == {"report.json": b"{}"}
    assert out["result"].stdout == "done"
    assert order == ["export"] and fake.containers == {}
    assert fake.verbs().index("rm -f") > fake.verbs().index("exec")


def test_export_failure_quarantines_instead_of_destroying(fake, monkeypatch):
    ln = SandboxLauncher("ctx")

    def export(*a):
        raise DomainError("unsafe_export", "links", 422)

    monkeypatch.setattr(ln, "export_files", export)
    out = ln.run_collect(PROJECT, "verify", {"j.py": b"0"}, ["python", "j.py"], 10)
    assert out["evidence"] == "quarantined" and out["error"] == "unsafe_export"
    env = out["environment_id"]
    assert fake.containers[env]["State"]["Paused"]
    assert ["rm", "-f", env] not in fake.calls
    assert ln.quarantined() == [env]


def test_full_quarantine_stops_admitting_new_work(fake):
    for i in range(MAX_QUARANTINE):
        fake.containers[f"colossus-q{i}"] = {"Config": {"Labels": {}}, "State": {"Paused": True}}
    with pytest.raises(DomainError) as err:
        SandboxLauncher("ctx").create(PROJECT, "verify")
    assert err.value.code == "quarantine_full"
    assert not any(c[0] == "create" for c in fake.calls)


def test_timeout_reports_lost_evidence_and_destroys(fake):
    fake.exec_result = ProcessResult(-9, "", "", True, 3.0)
    out = SandboxLauncher("ctx").run_collect(PROJECT, "verify", {"j.py": b"0"}, ["python"], 3)
    assert out["evidence"] == "lost_timeout" and fake.containers == {}


def test_reaper_skips_quarantine_and_removes_only_expired_empty_managed_networks(fake):
    now = int(time.time())

    def managed(exp, paused=False):
        labels = {"org.colossus.managed": "true", "org.colossus.expires": str(exp)}
        return {"Config": {"Labels": labels}, "State": {"Paused": paused}}

    fake.containers = {
        "colossus-old": managed(now - 5),
        "colossus-quarantined": managed(now - 5, paused=True),
        "colossus-new": managed(now + 600),
    }

    def net(exp=None, containers=None, managed="true"):
        labels = {"org.colossus.managed": managed}
        if exp is not None:
            labels["org.colossus.expires"] = str(exp)
        return {"Labels": labels, "Containers": containers or {}}

    fake.networks = {
        "colossus-net-old": net(now - 5),
        "colossus-net-busy": net(now - 5, {"x": {}}),
        "colossus-net-fresh": net(now + 600),
        "colossus-net-legacy": net(None),
        "colossus-net-forged": net(now - 5, managed="false"),
        "bridge": net(now - 5),
    }
    removed = SandboxLauncher("ctx").reap()
    assert removed == ["colossus-old", "colossus-net-old"]
    assert set(fake.containers) == {"colossus-quarantined", "colossus-new"}
    assert "bridge" in fake.networks and "colossus-net-legacy" in fake.networks
    assert not any("prune" in c for c in fake.calls)


def test_network_carries_bounded_expiry(fake):
    ln = SandboxLauncher("ctx")
    ln.network(PROJECT, ttl_seconds=60)
    (create,) = [c for c in fake.calls if c[:2] == ["network", "create"]]
    expiry = [v for v in create if v.startswith("org.colossus.expires=")]
    assert expiry and int(expiry[0].split("=")[1]) <= time.time() + 61
    with pytest.raises(DomainError):
        ln.network(PROJECT, ttl_seconds=0)


def test_network_has_no_host_address_and_networks_without_it_are_refused(fake):
    ln = SandboxLauncher("ctx")
    ln.network(PROJECT)
    (create,) = [c for c in fake.calls if c[:2] == ["network", "create"]]
    assert "--internal" in create
    assert create[create.index("--opt") + 1] == "com.docker.network.bridge.inhibit_ipv4=true"
    fake.networks["colossus-net-gw"] = {
        "Internal": True, "Options": {}, "Labels": {"org.colossus.project": PROJECT},
    }
    with pytest.raises(DomainError):
        ln.create(PROJECT, "verify", network="colossus-net-gw")
    assert not any(c[0] == "create" for c in fake.calls)
