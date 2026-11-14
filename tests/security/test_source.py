import io
import tarfile

import pytest

from colossus.contracts.core import DomainError
from colossus.gateway.source import tree_hash, unpack_source


def archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for path, kind in entries:
            entry = tarfile.TarInfo(path)
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = 1
            else:
                entry.linkname = "/host/secret"
            tar.addfile(entry, io.BytesIO(b"x") if kind == tarfile.REGTYPE else None)
    return out.getvalue()


@pytest.mark.parametrize(
    "entries",
    [
        [("repo/../outside", tarfile.REGTYPE)],
        [("/absolute", tarfile.REGTYPE)],
        [("repo/link", tarfile.SYMTYPE)],
        [("repo/link", tarfile.LNKTYPE)],
        [("repo/device", tarfile.CHRTYPE)],
        [("repo/a", tarfile.REGTYPE), ("other/b", tarfile.REGTYPE)],
        [("repo/a", tarfile.REGTYPE), ("repo/a", tarfile.REGTYPE)],
        [("repo/.git/config", tarfile.REGTYPE)],
    ],
)
def test_source_rejects_escape_links_duplicate_and_special_files(entries):
    with pytest.raises(DomainError):
        unpack_source(archive(entries))


def test_source_hash_covers_paths_and_contents():
    source = unpack_source(archive([("repo/a.py", tarfile.REGTYPE)]))
    assert source == {"a.py": b"x"}
    assert tree_hash(source) != tree_hash({"b.py": b"x"})
    assert tree_hash(source) != tree_hash({"a.py": b"y"})
