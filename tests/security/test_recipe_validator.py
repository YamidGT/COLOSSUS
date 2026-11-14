import pytest

from colossus.sandbox.recipe_validator import validate_recipe

DIGEST = "@sha256:" + "f" * 64


def rules(recipe):
    return {v.rule for v in validate_recipe(recipe)}


def test_good_recipe_passes():
    recipe = {
        "services": {
            "web": {"build": ".", "expose": [5000], "mem_limit": "512m", "cpus": 0.5, "user": "1000"},
            "db": {
                "image": "postgres" + DIGEST,
                "mem_limit": "512m",
                "cpus": 0.25,
                "volumes": ["dbdata:/var/lib/postgresql/data"],
            },
        },
        "volumes": {"dbdata": {}},
    }
    assert validate_recipe(recipe) == []


@pytest.mark.parametrize(
    "svc, rule",
    [
        ({"image": "x" + DIGEST, "privileged": True}, "service_key"),
        ({"image": "x" + DIGEST, "network_mode": "host"}, "service_key"),
        ({"image": "x" + DIGEST, "pid": "host"}, "service_key"),
        ({"image": "x" + DIGEST, "ipc": "host"}, "service_key"),
        ({"image": "x" + DIGEST, "cap_add": ["NET_ADMIN"]}, "service_key"),
        ({"image": "x" + DIGEST, "devices": ["/dev/fuse"]}, "service_key"),
        ({"image": "x" + DIGEST, "ports": ["80:80"]}, "service_key"),
        ({"image": "x" + DIGEST, "security_opt": ["seccomp:unconfined"]}, "service_key"),
        ({"image": "x" + DIGEST, "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}, "host_mount"),
        ({"image": "x" + DIGEST, "volumes": ["./:/app"]}, "host_mount"),
        ({"image": "x" + DIGEST, "volumes": ["~/.ssh:/k"]}, "host_mount"),
        ({"image": "x" + DIGEST, "volumes": [{"type": "bind", "source": "/etc"}]}, "host_mount"),
        ({"image": "python:latest"}, "mutable_image"),
        ({"image": "python:3.12"}, "mutable_image"),
        ({"image": "x" + DIGEST, "user": "root"}, "root_user"),
        ({"image": "x" + DIGEST, "user": "0:0"}, "root_user"),
        ({"image": "x" + DIGEST, "environment": {"MISTRAL_API_KEY": "x"}}, "credential_env"),
        ({"image": "x" + DIGEST, "environment": ["AWS_SECRET_ACCESS_KEY=x"]}, "credential_env"),
        ({"image": "x" + DIGEST, "mem_limit": "64g"}, "resources"),
        ({"image": "x" + DIGEST, "cpus": 4}, "resources"),
        ({}, "image"),
    ],
)
def test_hostile_service_rejected(svc, rule):
    assert rule in rules({"services": {"evil": svc}})


def test_top_level_networks_secrets_and_count():
    assert "top_level_key" in rules({"services": {"a": {"build": "."}}, "networks": {"x": {}}})
    assert "top_level_key" in rules({"services": {"a": {"build": "."}}, "secrets": {"x": {}}})
    assert "service_count" in rules({"services": {f"s{i}": {"build": "."} for i in range(7)}})
    assert "shape" in rules("services: [")


def test_tag_allowed_only_before_execution():
    recipe = {"services": {"db": {"image": "postgres:16"}}}
    assert "mutable_image" in rules(recipe)
    assert validate_recipe(recipe, execution=False) == []
