import pytest
from pydantic import ValidationError

from colossus.contracts.core import content_hash, safe_relative_path
from colossus.contracts.models import Enrollment


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://github.com.evil/a/b",
        "https://u@github.com/a/b",
        "https://github.com/a/b?x=y",
        "https://127.0.0.1/a/b",
        "https://github.com/../b",
    ],
)
def test_enrollment_rejects_noncanonical_source(url):
    with pytest.raises(ValidationError):
        Enrollment(repo_url=url)


def test_enrollment_preserves_only_declared_authority():
    with pytest.raises(ValidationError):
        Enrollment(repo_url="https://github.com/a/b", privileged=True)
    with pytest.raises(ValidationError):
        Enrollment(repo_url="https://github.com/a/b", start_cycle="true")
    with pytest.raises(ValidationError):
        Enrollment(repo_url="https://github.com/a/b", assurance_profile="formal_required")
    assert Enrollment(repo_url="https://github.com/a/b.git").repo_url == "https://github.com/a/b"


@pytest.mark.parametrize(
    "path", ["../key", "/etc/passwd", "a/../b", "a//b", "a\\b", "./a", "a\x00b"]
)
def test_path_rejects_escape_and_ambiguity(path):
    with pytest.raises(ValueError):
        safe_relative_path(path)


def test_content_hash_is_canonical_and_rejects_nonfinite_numbers():
    assert content_hash({"a": 1, "b": 2}) == content_hash({"b": 2, "a": 1})
    with pytest.raises(ValueError):
        content_hash({"value": float("nan")})
