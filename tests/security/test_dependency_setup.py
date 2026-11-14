import base64
import json

import pytest

from colossus.contracts.core import DomainError
from colossus.gateway.source import tree_hash
from colossus.onboarding.bundle import assembled_files, runtime_files
from colossus.onboarding.dependencies import requirements_from_source, validate_requirements
from colossus.onboarding.discovery import discover
from colossus.sandbox.dependency_builder import registry_origins
from colossus.sandbox.launcher import ProcessResult, SandboxLauncher
from colossus.sandbox.registry_proxy import FILE, PACKAGE, WheelIndex


@pytest.mark.parametrize(
    "requirement",
    [
        "--index-url https://evil.invalid",
        "-e .",
        "thing @ https://evil.invalid/x.whl",
        "git+https://github.com/a/b",
        "../local",
        "Flask\nrequests",
        "--extra-index-url=https://evil.invalid",
    ],
)
def test_dependency_input_cannot_select_origins_or_execute_hooks(requirement):
    with pytest.raises(DomainError):
        validate_requirements([requirement])


def test_static_requirement_includes_and_markers_preserve_constraints():
    values, inputs = requirements_from_source(
        {
            "requirements.txt": b"-r config/base.txt\nFlask==3.1.2 # pinned\n",
            "config/base.txt": b"typing-extensions>=4; python_version < '3.13'\n",
        }
    )
    assert "Flask==3.1.2" in values and len(values) == 2
    assert inputs == ["config/base.txt", "requirements.txt"]
    with pytest.raises(DomainError):
        requirements_from_source({"requirements.txt": b"-r requirements.txt"})
    with pytest.raises(DomainError, match="escapes"):
        requirements_from_source({"requirements.txt": b"-r ../outside.txt"})
    with pytest.raises(DomainError, match="Dynamic"):
        requirements_from_source({"pyproject.toml": b'[project]\ndynamic=["dependencies"]'})


def test_registry_index_excludes_foreign_hosts_sdists_and_unsafe_paths():
    path = "/packages/ab/cd/" + "e" * 60 + "/pkg-1-py3-none-any.whl"
    parser = WheelIndex()
    parser.feed(
        f'<a href="https://files.pythonhosted.org{path}#sha256={"a" * 64}" data-requires-python="&gt;=3.9">good</a>'
    )
    parser.feed(f'<a href="https://evil.invalid{path}#sha256={"a" * 64}">foreign</a>')
    parser.feed(
        f'<a href="https://files.pythonhosted.org{path.replace(".whl", ".tar.gz")}#sha256={"a" * 64}">source</a>'
    )
    parser.feed('<a href="https://files.pythonhosted.org/packages/../metadata">escape</a>')
    assert len(parser.links) == 1 and 'href="/files/packages/' in parser.links[0]
    assert "data-requires-python" in parser.links[0]
    assert not FILE.fullmatch("/packages/../metadata")
    assert not PACKAGE.fullmatch("/simple/flask/?origin=evil")


def test_registry_dns_cannot_bind_metadata_or_private_hosts(monkeypatch):
    import socket

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))
        ],
    )
    with pytest.raises(DomainError, match="public addresses"):
        registry_origins()


def test_framework_discovery_is_static_and_rejects_ambiguous_apps(tmp_path):
    marker = tmp_path / "must-not-execute"
    app = f"from flask import Flask\napp=Flask(__name__)\nopen({str(marker)!r}, 'w').write('bad')\nif __name__ == '__main__':\n app.run(debug=True)\n".encode()
    recipe = discover({"app.py": app, "requirements.txt": b"Flask==3.1.2"})
    assert recipe.runtime_mode == "flask-script" and recipe.requirements == ["Flask==3.1.2"]
    assert not marker.exists()
    with pytest.raises(DomainError, match="Multiple"):
        discover({"app.py": app, "other.py": app})
    with pytest.raises(DomainError, match="trusted runtime"):
        discover({"_colossus_runtime/start.py": b"bad"})


def test_custom_recipe_cannot_claim_security_or_formal_authority():
    recipe = {
        "recipe_id": "dsvw-python-v1",
        "command": ["python", "app.py"],
        "port": 5000,
        "test_profile_ids": ["dsvw-security-v1"],
        "limitations": [],
    }
    with pytest.raises(DomainError, match="trusted security"):
        discover({"app.py": b"", "colossus-app.json": json.dumps(recipe).encode()})


def test_dependency_bundle_is_bound_and_separate_from_patchable_source():
    files = {"vendor/pkg.py": b"locked"}
    source = {
        "runtime_files": {p: base64.b64encode(d).decode() for p, d in files.items()},
        "runtime_tree_sha256": tree_hash(files),
    }
    assert runtime_files(source) == files
    assert assembled_files({"app.py": b"changed"}, files) == {"app.py": b"changed"} | files
    with pytest.raises(DomainError, match="hash mismatch"):
        runtime_files(source | {"runtime_tree_sha256": "0" * 64})
    with pytest.raises(DomainError, match="collides"):
        assembled_files(files, files)


def test_registry_network_cleanup_is_idempotent_and_refuses_foreign_resources(monkeypatch):
    launcher = SandboxLauncher("fixture")
    monkeypatch.setattr(
        launcher, "docker", lambda *args: ProcessResult(1, "", "network not found", False, 0)
    )
    launcher.destroy_network("colossus-egress-missing", "project")
    monkeypatch.setattr(
        launcher,
        "docker",
        lambda *args: ProcessResult(
            0,
            json.dumps(
                [{"Labels": {"org.colossus.managed": "true", "org.colossus.project": "other"}}]
            ),
            "",
            False,
            0,
        ),
    )
    with pytest.raises(DomainError, match="owned"):
        launcher.destroy_network("colossus-egress-foreign", "project")
    monkeypatch.setattr(
        launcher, "docker", lambda *args: ProcessResult(1, "", "daemon unavailable", False, 0)
    )
    with pytest.raises(DomainError, match="teardown state"):
        launcher.destroy_network("colossus-egress-unknown", "project")
