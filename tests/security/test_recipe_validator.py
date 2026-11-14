import pytest

from colossus.sandbox.recipe_validator import validate_recipe


def recipe(**changes):
    return {
        "services": {"app": {"image": "python@sha256:" + "a" * 64, "user": "1000:1000", **changes}}
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"privileged": True},
        {"network_mode": "host"},
        {"pid": "host"},
        {"ports": ["8080:80"]},
        {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]},
        {"environment": ["MISTRAL_API_KEY"]},
        {"cpus": "nan"},
        {"cpus": -1},
        {"mem_limit": 0},
        {"volumes": [42]},
        {"environment": 42},
    ],
)
def test_untrusted_recipes_fail_closed(changes):
    assert validate_recipe(recipe(**changes))


def test_named_volume_cannot_hide_a_host_bind_or_runtime_socket():
    plan = recipe(volumes=["data:/data"])
    plan["volumes"] = {"data": {"driver_opts": {"type": "none", "device": "/", "o": "bind"}}}
    assert validate_recipe(plan)
    plan["volumes"] = {"data": {}}
    assert not validate_recipe(plan)


def test_execution_requires_immutable_images():
    assert validate_recipe(recipe(image="python:latest"))
    assert not validate_recipe(recipe())
