import pytest

from colossus.contracts.core import DomainError, digest
from colossus.control.artifacts import ArtifactStore


def test_evidence_is_immutable_by_content_and_tampering_is_detected(tmp_path):
    store = ArtifactStore(tmp_path / "evidence", max_bytes=100)
    key = store.put(b"verified artifact")
    assert store.put(b"verified artifact") == key
    assert store.get(key) == b"verified artifact"
    store.path(key).write_bytes(b"changed")
    with pytest.raises(DomainError, match="hash"):
        store.get(key)
    with pytest.raises(DomainError, match="byte limit"):
        store.put(b"x" * 101)


def test_evidence_never_follows_host_symlink(tmp_path):
    store = ArtifactStore(tmp_path / "evidence")
    secret = tmp_path / "host-secret"
    secret.write_bytes(b"sensitive")
    key = digest(b"sensitive")
    (store.root / key).symlink_to(secret)
    with pytest.raises(DomainError, match="Symbolic"):
        store.get(key)
    with pytest.raises(DomainError, match="identifier"):
        store.get("../host-secret")
