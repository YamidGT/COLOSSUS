"""Real Docker runs of a TRUSTED fixture probe (never repository code).

These use the `runc` trusted-fixture profile because gVisor (runsc) is not
installed on the development host. They check the hardening flags, not gVisor.
"""

import json
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from colossus.contracts import ContractError, ErrorCode
from colossus.sandbox.launcher import DockerLauncher, JobStatus
from colossus.sandbox.profiles import IsolationProfile, JobProfile, NetworkMode, Runtime, TrustLevel

PROBE = (Path(__file__).parent / "probe.py").read_bytes()
FIXTURE_TAG = "python:3.12-bookworm"


def _docker_ok():
    if not shutil.which("docker"):
        return None
    proc = subprocess.run(["docker", "image", "inspect", FIXTURE_TAG, "--format", "{{index .RepoDigests 0}}"],
                          capture_output=True, text=True)
    return proc.stdout.strip() or None


IMAGE = _docker_ok()
pytestmark = [pytest.mark.docker, pytest.mark.skipif(IMAGE is None, reason="docker or fixture image missing")]


def iso(**kw):
    base = dict(profile_id="fixture", trust=TrustLevel.TRUSTED_FIXTURE, runtime=Runtime.RUNC, memory_mib=256, pids_limit=64)
    base.update(kw)
    return IsolationProfile(**base)


def job(mode, timeout=60, **kw):
    return JobProfile(job_profile_id=f"probe-{mode}", image=IMAGE, platform="linux/amd64",
                      argv=["python3", "/in/probe.py", mode], timeout_seconds=timeout,
                      isolation_profile_id=kw.pop("isolation_profile_id", "fixture"), **kw)


@pytest.fixture
def launcher(tmp_path):
    ln = DockerLauncher(tmp_path / "launcher")
    yield ln
    assert ln.orphans == []
    for child in (tmp_path / "launcher").iterdir():
        ln.release_job(child.name)


@pytest.fixture
def case_id():
    cid = str(uuid.uuid4())
    yield cid
    DockerLauncher().destroy_case(cid)  # only removes resources labelled with this case


def run(launcher, case_id, j, isolation, **kw):
    return launcher.run_job(job=j, isolation=isolation, case_id=case_id, job_id=str(uuid.uuid4()),
                            inputs={"probe.py": PROBE}, **kw)


def test_isolation_denials(launcher, case_id, monkeypatch):
    monkeypatch.setenv("COLOSSUS_TEST_SECRET_TOKEN", "must-not-leak")
    monkeypatch.setenv("MISTRAL_API_KEY", "must-not-leak")
    res = run(launcher, case_id, job("isolation"), iso())
    assert res.status is JobStatus.SUCCEEDED, res.stdout
    rep = json.loads(res.stdout.strip().splitlines()[-1])
    assert (rep["uid"], rep["gid"]) == (65534, 65534)
    assert int(rep["cap_eff"], 16) == 0
    for k in ("egress_ip", "egress_ipv6", "dns", "metadata", "write_root", "write_in"):
        assert rep[k].startswith("denied"), (k, rep[k])
    assert rep["write_scratch"] == "allowed"
    assert rep["docker_sock"] is False
    assert rep["memory_max"] == str(256 * 1024 * 1024)
    assert rep["pids_max"] == "64"
    # GPG_KEY is a public value baked into the python image; host variables must not appear.
    assert "COLOSSUS_TEST_SECRET_TOKEN" not in rep["env_has_keys"]
    assert "MISTRAL_API_KEY" not in rep["env_has_keys"]


def test_case_internal_network_has_no_egress(launcher, case_id):
    net = launcher.create_case_network(case_id)
    res = run(launcher, case_id, job("isolation", isolation_profile_id="fixture-net"),
              iso(profile_id="fixture-net", network=NetworkMode.CASE_INTERNAL), network_name=net)
    rep = json.loads(res.stdout.strip().splitlines()[-1])
    assert rep["egress_ip"].startswith("denied") and rep["metadata"].startswith("denied")


def test_output_import_rejects_symlinks_and_caps_size(launcher, case_id):
    res = run(launcher, case_id, job("outputs"), iso(), max_output_bytes=1024 * 1024)
    assert res.status is JobStatus.SUCCEEDED, res.stdout
    paths = {f.path for f in res.files}
    assert {"result.json", "sub/log.txt"} <= paths
    assert "leak" not in paths and "big.bin" not in paths
    assert any(r.startswith("leak") for r in res.rejected_outputs)
    assert any(r.startswith("big.bin") for r in res.rejected_outputs)
    assert json.loads((res.output_root / "result.json").read_text()) == {"ok": True}


def test_timeout_kills_and_discards_results(launcher, case_id):
    res = run(launcher, case_id, job("sleep", timeout=3), iso())
    assert res.status is JobStatus.TIMEOUT and res.files == []
    left = subprocess.run(["docker", "ps", "-aq", "--filter", f"label=io.colossus.case={case_id}"],
                          capture_output=True, text=True).stdout.strip()
    assert left == ""


def test_nonzero_exit_is_failed(launcher, case_id):
    res = run(launcher, case_id, job("fail"), iso())
    assert res.status is JobStatus.FAILED and res.exit_code == 3


def test_untrusted_job_refused_without_gvisor(launcher, case_id):
    if "runsc" in launcher.available_runtimes():
        pytest.skip("runsc installed; this checks the missing-runtime path")
    untrusted = IsolationProfile(profile_id="repo", trust=TrustLevel.UNTRUSTED_REPOSITORY, runtime=Runtime.RUNSC)
    with pytest.raises(ContractError) as err:
        run(launcher, case_id, job("isolation", isolation_profile_id="repo"), untrusted)
    assert err.value.error.code is ErrorCode.ISOLATION_UNAVAILABLE
