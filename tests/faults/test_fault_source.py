"""Source intake edge cases for gateway/source.py using mocked HTTP only."""

import io
import json
import tarfile

import httpx
import pytest
from pydantic import ValidationError

from colossus.contracts.core import DomainError
from colossus.contracts.models import Enrollment
from colossus.gateway import source as source_module
from colossus.gateway.source import GitHubSource, unpack_source

SHA = "0123456789abcdef0123456789abcdef01234567"


def archive(files, root="owner-repo-0123456", extra=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        info = tarfile.TarInfo(root)
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
        for path, data in files.items():
            info = tarfile.TarInfo(f"{root}/{path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for member, data in extra or []:
            tar.addfile(member, io.BytesIO(data) if data is not None else None)
    return out.getvalue()


class GitHubMock:
    """Serves api.github.com and codeload.github.com; records every requested URL."""

    def __init__(self, tarball=None, commit=SHA, overrides=None):
        self.requests: list[httpx.URL] = []
        self.tarball = tarball if tarball is not None else archive({"app.py": b"print(1)\n"})
        self.commit = commit
        self.overrides = overrides or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request.url)
        for match, response in self.overrides.items():
            if match in str(request.url):
                return response() if callable(response) else response
        if request.url.host == "api.github.com":
            if "/commits/" in request.url.raw_path.decode():
                return httpx.Response(200, json={"sha": self.commit})
            return httpx.Response(200, json={"default_branch": "main"})
        if request.url.host == "codeload.github.com":
            return httpx.Response(200, content=self.tarball)
        return httpx.Response(599, text="unexpected host contacted")

    def hosts(self):
        return {url.host for url in self.requests}


async def fetch(mock, **enrollment):
    request = Enrollment(repo_url="https://github.com/owner/repo", **enrollment)
    async with httpx.AsyncClient(transport=httpx.MockTransport(mock)) as client:
        return await GitHubSource(client).fetch(request)


async def test_mocked_fetch_resolves_immutable_revision():
    mock = GitHubMock()
    result = await fetch(mock)
    assert result["commit"] == SHA and result["requested_ref"] == "main"
    assert result["files"] == {"app.py": b"print(1)\n"}
    assert mock.hosts() == {"api.github.com", "codeload.github.com"}
    assert str(mock.requests[-1]).endswith(f"/owner/repo/tar.gz/{SHA}")


@pytest.mark.parametrize("stage", ["/repos/owner/repo", "/commits/", "/tar.gz/"])
async def test_redirect_to_another_host_is_not_followed(stage):
    redirect = httpx.Response(302, headers={"Location": "https://evil.example/x.tar.gz"})
    mock = GitHubMock(overrides={stage: redirect})
    with pytest.raises(DomainError) as exc:
        await fetch(mock)
    assert exc.value.code == "source_fetch_failed" and "302" in exc.value.message
    assert "evil.example" not in mock.hosts()


async def test_same_host_redirect_for_renamed_repository_is_also_refused():
    moved = httpx.Response(301, headers={"Location": "https://api.github.com/repositories/1"})
    mock = GitHubMock(overrides={"/repos/owner/repo": moved})
    with pytest.raises(DomainError, match="HTTP 301"):
        await fetch(mock)
    assert len(mock.requests) == 1


async def test_oversize_streamed_archive_is_cut_off(monkeypatch):
    monkeypatch.setattr(source_module, "MAX_ARCHIVE", 4096)
    mock = GitHubMock(tarball=b"\0" * 10_000)
    with pytest.raises(DomainError) as exc:
        await fetch(mock)
    assert exc.value.code == "source_limit" and exc.value.status_code == 413


def test_oversize_archive_bytes_rejected_before_parsing(monkeypatch):
    monkeypatch.setattr(source_module, "MAX_ARCHIVE", 100)
    with pytest.raises(DomainError, match="Source archive exceeds"):
        unpack_source(b"x" * 101)


def test_too_many_entries(monkeypatch):
    monkeypatch.setattr(source_module, "MAX_FILES", 5)
    files = {f"f{i}.py": b"x" for i in range(10)}
    with pytest.raises(DomainError, match="too many entries"):
        unpack_source(archive(files))
    assert unpack_source(archive({f"f{i}.py": b"x" for i in range(4)}))


def test_expanded_size_limit_uses_header_sizes(monkeypatch):
    monkeypatch.setattr(source_module, "MAX_SOURCE", 1000)
    with pytest.raises(DomainError, match="Expanded source"):
        unpack_source(archive({"a": b"x" * 600, "b": b"y" * 600}))


def special(name, kind, **attrs):
    info = tarfile.TarInfo(name)
    info.type = kind
    for key, value in attrs.items():
        setattr(info, key, value)
    return info


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (
            [(special("owner-repo-0123456/link", tarfile.SYMTYPE, linkname="/etc/passwd"), None)],
            "links",
        ),
        (
            [
                (
                    special(
                        "owner-repo-0123456/hard",
                        tarfile.LNKTYPE,
                        linkname="owner-repo-0123456/app.py",
                    ),
                    None,
                )
            ],
            "links",
        ),
        ([(special("owner-repo-0123456/fifo", tarfile.FIFOTYPE), None)], "special"),
        ([(special("other-root/x.py", tarfile.REGTYPE, size=1), b"x")], "inconsistent"),
        ([(special("owner-repo-0123456/.git/config", tarfile.REGTYPE, size=1), b"x")], "metadata"),
        (
            [(special("owner-repo-0123456/../escape", tarfile.REGTYPE, size=1), b"x")],
            "invalid or unsafe",
        ),
        ([(special("/abs/x", tarfile.REGTYPE, size=1), b"x")], "invalid or unsafe"),
        ([(special("owner-repo-0123456/app.py", tarfile.REGTYPE, size=1), b"x")], "Duplicate"),
    ],
)
def test_unsafe_archive_members_rejected(extra, message):
    with pytest.raises(DomainError, match=message):
        unpack_source(archive({"app.py": b"ok"}, extra=extra))


def test_corrupt_and_empty_archives():
    with pytest.raises(DomainError) as exc:
        unpack_source(b"not a gzip stream")
    assert exc.value.code == "invalid_archive"
    with pytest.raises(DomainError) as exc:
        unpack_source(archive({}))
    assert exc.value.code == "empty_source"


@pytest.mark.parametrize(
    "url",
    [
        "https://user:token@github.com/owner/repo",
        "https://token@github.com/owner/repo",
        "https://github.com:443/owner/repo",
        "http://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://github.com.evil.example/owner/repo",
        "https://api.github.com/owner/repo",
        "https://codeload.github.com/owner/repo",
        "https://GITHUB.COM/owner/repo",
        "https://github.com/owner/repo?token=x",
        "https://github.com/owner/repo#frag",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/owner",
        "https://github.com/../repo",
        "https://github.com/owner/.git",
        "https://github.com/owner/%2e%2e",
        "git@github.com:owner/repo.git",
        "file:///etc/passwd",
    ],
)
def test_enrollment_rejects_credentials_and_non_github_urls(url):
    with pytest.raises(ValidationError):
        Enrollment(repo_url=url)


def test_enrollment_normalizes_git_suffix_and_trailing_slash():
    assert Enrollment(repo_url="https://github.com/o/r.git").repo_url == "https://github.com/o/r"
    assert Enrollment(repo_url="https://github.com/o/r/").repo_url == "https://github.com/o/r"


@pytest.mark.parametrize("ref", ["", "-uupload-pack", "main\n", "a\x00b", "x" * 201])
def test_enrollment_rejects_invalid_refs(ref):
    with pytest.raises(ValidationError):
        Enrollment(repo_url="https://github.com/o/r", requested_ref=ref)


@pytest.mark.parametrize("subdir", ["../x", "/abs", "a/../b", "a\\b", ""])
def test_enrollment_rejects_unsafe_subdir(subdir):
    with pytest.raises(ValidationError):
        Enrollment(repo_url="https://github.com/o/r", subdir=subdir)


async def test_ref_with_path_characters_is_percent_encoded():
    mock = GitHubMock()
    await fetch(mock, requested_ref="../../orgs/x?y#z")
    commit_url = mock.requests[0]
    assert commit_url.host == "api.github.com"
    raw = commit_url.raw_path.decode()
    assert raw.startswith("/repos/owner/repo/commits/")
    assert raw.removeprefix("/repos/owner/repo/commits/") == "..%2F..%2Forgs%2Fx%3Fy%23z"
    assert not commit_url.query


@pytest.mark.parametrize("commit", ["main", SHA.upper(), SHA[:39], SHA + "0", "../" + SHA[:37]])
async def test_mutable_or_malformed_revision_is_refused(commit):
    mock = GitHubMock(commit=commit)
    with pytest.raises(DomainError) as exc:
        await fetch(mock, requested_ref="main")
    assert exc.value.code == "invalid_revision"
    assert "codeload.github.com" not in mock.hosts()


@pytest.mark.parametrize("status", [404, 403, 429, 500])
async def test_upstream_errors_are_typed(status):
    mock = GitHubMock(overrides={"/commits/": httpx.Response(status, text="no")})
    with pytest.raises(DomainError, match=f"HTTP {status}"):
        await fetch(mock, requested_ref="main")


@pytest.mark.parametrize(
    "body",
    [b"not json", json.dumps({"no_sha": True}).encode(), json.dumps({"sha": 7}).encode()],
)
async def test_malformed_commit_metadata_never_yields_source(body):
    mock = GitHubMock(overrides={"/commits/": httpx.Response(200, content=body)})
    with pytest.raises(Exception):  # noqa: B017 - fail closed; untyped today, see handoff
        await fetch(mock, requested_ref="main")
    assert "codeload.github.com" not in mock.hosts()


async def test_missing_subdir_and_subdir_prefix_confusion():
    tarball = archive({"srcfoo/a.py": b"a", "src/b.py": b"b"})
    result = await fetch(GitHubMock(tarball=tarball), subdir="src")
    assert result["files"] == {"b.py": b"b"}
    with pytest.raises(DomainError, match="empty or absent"):
        await fetch(GitHubMock(tarball=tarball), subdir="missing")
