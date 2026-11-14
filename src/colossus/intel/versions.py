"""Stdlib-only version ordering for OSV range evaluation.

PEP 440 (PyPI ``ECOSYSTEM`` ranges) and SemVer 2.0 (``SEMVER`` ranges). A parser returns
``None`` for anything it cannot order; callers must then report ``unknown``. Lexical string
comparison is never used.
"""

from __future__ import annotations

import re
from typing import Any

MAX_VERSION_LENGTH = 128

_PEP440 = re.compile(
    r"""
    ^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$
    """,
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}

_SEMVER = re.compile(
    r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def _bounded(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAX_VERSION_LENGTH:
        return None
    return value


def pep440_key(value: Any) -> tuple | None:
    """Sort key equivalent to PEP 440 ordering, or None when the string is not PEP 440."""
    text = _bounded(value)
    if text is None:
        return None
    m = _PEP440.match(text)
    if m is None:
        return None
    release = [int(part) for part in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    has_pre = m.group("pre") is not None
    has_post = m.group("post") is not None
    has_dev = m.group("dev") is not None
    if has_pre:
        pre = (1, _PRE_RANK[m.group("pre_l").lower()], int(m.group("pre_n") or 0))
    elif has_dev and not has_post:
        pre = (0,)  # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (2,)
    if has_post:
        post = (1, int(m.group("post_n1") or m.group("post_n2") or 0))
    else:
        post = (0,)
    dev = (1, int(m.group("dev_n") or 0)) if has_dev else (2,)
    local_text = m.group("local")
    if local_text is None:
        local: tuple = (0,)
    else:
        parts = re.split(r"[-_.]", local_text.lower())
        local = (1, tuple((1, int(p), "") if p.isdigit() else (0, 0, p) for p in parts))
    return (int(m.group("epoch") or 0), tuple(release), pre, post, dev, local)


def semver_key(value: Any) -> tuple | None:
    text = _bounded(value)
    if text is None:
        return None
    m = _SEMVER.match(text)
    if m is None:
        return None
    major, minor, patch, pre = m.groups()
    if pre is None:
        pre_key: tuple = (1,)
    else:
        ids = []
        for ident in pre.split("."):
            if ident.isdigit():
                if len(ident) > 1 and ident.startswith("0"):
                    return None
                ids.append((0, int(ident), ""))
            else:
                ids.append((1, 0, ident))
        pre_key = (0, tuple(ids))
    return (int(major), int(minor), int(patch), pre_key)


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalized project name."""
    return re.sub(r"[-_.]+", "-", name).lower()
