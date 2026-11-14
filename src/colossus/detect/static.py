"""T0: deterministic static detection. No model. Reads source, never executes it."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "tests", "test", "_colossus_detector"}

# Pinned local rules (cheap regex complement to Bandit; (id, cwe, title, regex))
RULES = [
    (
        "sqli-format",
        "CWE-89",
        "SQL built with string formatting",
        re.compile(
            r"(execute|executescript|query)\s*\(\s*[\"'][^\"']*(%s|%d|\{)[^\"']*[\"']\s*%|"
            r"(execute|executescript|query)\s*\(\s*f[\"']|"
            r"(SELECT|INSERT|UPDATE|DELETE)[^\n]*[\"']\s*\+\s*\w+",
            re.I,
        ),
    ),
    (
        "sqli-concat",
        "CWE-89",
        "SQL built with string concatenation",
        re.compile(r"(SELECT|UPDATE|DELETE|INSERT)\b[^\n]*(%s|\+ ?\w+|\.format\()", re.I),
    ),
    (
        "cmd-injection",
        "CWE-78",
        "OS command built from input",
        re.compile(r"(os\.system|os\.popen|subprocess\.\w+)\(.*(\+|%|format|f[\"'])"),
    ),
    (
        # A command held in a variable (e.g. produced by an LLM tool call) reaching a shell.
        # Single-line match only: a call whose arguments span lines is not seen by this rule.
        "shell-nonliteral",
        "CWE-78",
        "Non-literal command passed to a shell",
        re.compile(
            r"subprocess\.\w+\(\s*(?![\"'\[(])[A-Za-z_][\w.\[\]\"']*\s*,.*\bshell\s*=\s*True|"
            r"\bos\.(system|popen)\(\s*(?![\"'])[A-Za-z_]"
        ),
    ),
    (
        "yaml-load",
        "CWE-502",
        "yaml.load without safe loader",
        re.compile(r"yaml\.load\((?!.*Loader\s*=\s*(yaml\.)?(Safe|CSafe))"),
    ),
    ("pickle", "CWE-502", "Unsafe deserialization (pickle)", re.compile(r"pickle\.loads?\(")),
    (
        "jwt-noverify",
        "CWE-347",
        "JWT decoded without verification",
        re.compile(r"verify\s*=\s*False|verify_signature['\"]?\s*:\s*False"),
    ),
    (
        "hardcoded-secret",
        "CWE-798",
        "Hard-coded secret",
        re.compile(r"(secret|passw(or)?d|api_?key|token)\w*\s*=\s*[\"'][^\"']{4,}[\"']", re.I),
    ),
    ("md5", "CWE-327", "Weak hash (MD5/SHA1)", re.compile(r"hashlib\.(md5|sha1)\(")),
    ("debug", "CWE-489", "Debug mode enabled", re.compile(r"debug\s*=\s*True")),
    ("ssti", "CWE-1336", "Template rendered from string", re.compile(r"render_template_string\(")),
    (
        "xxe",
        "CWE-611",
        "XML parsed with external entities possible",
        re.compile(r"(etree\.(parse|fromstring)|XMLParser)\("),
    ),
    (
        "path-join",
        "CWE-22",
        "File path built from request data",
        re.compile(r"open\((.*(request|args|form|params)|.*\+)"),
    ),
]


@dataclass
class RawFinding:
    tool: str
    rule: str
    cwe: str | None
    title: str
    file: str
    line: int
    code: str
    extra: dict = field(default_factory=dict)

    def key(self) -> str:
        return f"{self.file}:{self.line}"


def iter_py(root: Path):
    for p in sorted(root.rglob("*.py"))[:2000]:
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if not p.is_symlink() and p.stat().st_size <= 500_000:
            yield p


def run_rules(root: Path) -> list[RawFinding]:
    out: list[RawFinding] = []
    for p in iter_py(root):
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            for rid, cwe, title, rx in RULES:
                if rx.search(line):
                    out.append(
                        RawFinding(
                            "rules",
                            rid,
                            cwe,
                            title,
                            p.relative_to(root).as_posix(),
                            i,
                            line.strip()[:300],
                        )
                    )
    return out


def run_bandit(root: Path) -> list[RawFinding]:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            str(root),
            "-f",
            "json",
            "-q",
            "-x",
            ",".join(f"*/{d}" for d in SKIP_DIRS),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        raise RuntimeError("Bandit output unavailable or invalid") from None
    if proc.returncode not in (0, 1) or not data.get("metrics"):
        raise RuntimeError("Bandit did not complete; do not interpret this as zero findings")
    out = []
    for r in data.get("results", []):
        cwe = r.get("issue_cwe", {}).get("id")
        out.append(
            RawFinding(
                "bandit",
                r["test_id"],
                f"CWE-{cwe}" if cwe else None,
                r["issue_text"][:300],
                Path(r["filename"]).resolve().relative_to(root.resolve()).as_posix(),
                r["line_number"],
                (r.get("code") or "").strip()[:300],
                {"severity": r["issue_severity"], "confidence": r["issue_confidence"]},
            )
        )
    return out


def scan(root: Path) -> list[RawFinding]:
    """Run all T0 tools; raw findings are retained, duplicates are merged by location+CWE."""
    return run_rules(root)
