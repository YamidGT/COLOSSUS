"""Restricted policy synthesis and evidence from the actual Dafny toolchain."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import time
from dataclasses import asdict, dataclass

from colossus.contracts.core import DomainError, content_hash
from colossus.sandbox.launcher import ProcessResult, SandboxLauncher


def checked_expression(expression: str, variables: frozenset[str]) -> str:
    """Parse a closed expression language; no declarations, attributes or statements."""
    if len(expression) > 2048:
        raise DomainError("formal_scope", "Expression exceeds policy limit", 422)
    pattern = re.compile(r"\s*([A-Za-z][A-Za-z0-9_]*|&&|\|\||==|!=|[!(),])")
    tokens, offset = [], 0
    while offset < len(expression.rstrip()):
        match = pattern.match(expression, offset)
        if not match:
            raise DomainError("formal_scope", "Unsupported expression syntax", 422)
        tokens.append(match[1])
        offset = match.end()
    index = 0

    def take():
        nonlocal index
        token = tokens[index] if index < len(tokens) else None
        index += 1
        return token

    def peek():
        return tokens[index] if index < len(tokens) else None

    def atom():
        token = take()
        if token == "!":
            atom()
        elif token == "(":
            term()
            if take() != ")":
                raise ValueError
        elif token == "Public":
            if take() != "(":
                raise ValueError
            term()
            if take() != ",":
                raise ValueError
            term()
            if take() != ")":
                raise ValueError
        elif token not in variables | {"true", "false"}:
            raise ValueError

    def term():
        atom()
        while peek() in {"&&", "||", "==", "!="}:
            take()
            atom()

    try:
        term()
        if index != len(tokens):
            raise ValueError
    except (ValueError, RecursionError):
        raise DomainError("formal_scope", "Expression is outside approved grammar", 422) from None
    return expression.strip()


@dataclass(frozen=True)
class PolicyProfile:
    profile_id: str
    template: str
    slots: dict[str, frozenset[str]]
    expected_symbols: frozenset[str]
    assumptions: tuple[str, ...]

    @property
    def spec_hash(self) -> str:
        return content_hash(
            {
                "profile_id": self.profile_id,
                "template": self.template,
                "slots": {key: sorted(value) for key, value in self.slots.items()},
                "expected_symbols": sorted(self.expected_symbols),
                "assumptions": self.assumptions,
            }
        )

    def render(self, replacements: dict[str, str]) -> bytes:
        if replacements.keys() != self.slots.keys():
            raise DomainError("formal_scope", "Policy implementation slots do not match", 422)
        result = self.template
        for name, variables in self.slots.items():
            result = result.replace(
                "{{" + name + "}}", checked_expression(replacements[name], variables)
            )
        return result.encode()


POLICY_CALIBRATION = PolicyProfile(
    profile_id="authorization-policy-calibration-v1",
    template="""module Policy {
  datatype PublicUser = Public(username: string, email: string)
  method MayChangePassword(authenticated: bool, actor: string, target: string, resourceExists: bool) returns (allowed: bool)
    ensures allowed == (authenticated && resourceExists && actor == target)
  { allowed := {{password}}; }
  method MayReadBookSecret(authenticated: bool, actor: string, owner: string, resourceExists: bool) returns (allowed: bool)
    ensures allowed == (authenticated && resourceExists && actor == owner)
  { allowed := {{book}}; }
  method RegistrationRole(requestedAdmin: bool) returns (admin: bool)
    ensures !admin
  { admin := {{role}}; }
  method PublicUserProjection(username: string, email: string, password: string, admin: bool) returns (user: PublicUser)
    ensures user == Public(username, email)
  { user := {{projection}}; }
}
""",
    slots={
        "password": frozenset({"authenticated", "actor", "target", "resourceExists"}),
        "book": frozenset({"authenticated", "actor", "owner", "resourceExists"}),
        "role": frozenset({"requestedAdmin"}),
        "projection": frozenset({"username", "email", "password", "admin"}),
    },
    expected_symbols=frozenset(
        {
            "Policy.MayChangePassword",
            "Policy.MayReadBookSecret",
            "Policy.RegistrationRole",
            "Policy.PublicUserProjection",
        }
    ),
    assumptions=(
        "Dafny compiler and Z3 solver correctness",
        "Wrapper binds authenticated identity and resource ownership correctly",
        "Calibration policy is not approval of a target's business requirements",
    ),
)

CORRECT_POLICY = {
    "password": "authenticated && resourceExists && actor == target",
    "book": "authenticated && resourceExists && actor == owner",
    "role": "false",
    "projection": "Public(username, email)",
}


def proof_passed(result: ProcessResult, csv_bytes: bytes, expected: frozenset[str]) -> bool:
    if result.exit_code or result.timed_out or result.truncated or not expected:
        return False
    summaries = re.findall(
        r"Dafny program verifier finished with (\d+) verified, (\d+) errors", result.stdout
    )
    if len(summaries) != 1 or int(summaries[0][0]) < len(expected) or int(summaries[0][1]):
        return False
    try:
        rows = list(csv.DictReader(io.StringIO(csv_bytes.decode())))
    except (UnicodeDecodeError, csv.Error):
        return False
    # Column names and symbol rendering are pinned by the toolchain calibration.
    successes = {
        row.get("TestResult.DisplayName")
        for row in rows
        if row.get("TestResult.Outcome") == "Passed"
    }
    required = {symbol + " (correctness)" for symbol in expected}
    return required <= successes and all(row.get("TestResult.Outcome") == "Passed" for row in rows)


def compiled_binding(files: dict[str, bytes], expected_hashes: dict[str, str]) -> bool:
    generated = {
        path: hashlib.sha256(data).hexdigest()
        for path, data in files.items()
        if path.startswith("policy-py/")
    }
    return bool(expected_hashes) and generated == expected_hashes


class DafnyAdapter:
    def __init__(self, launcher: SandboxLauncher, image_digest: str):
        self.launcher, self.image_digest = launcher, image_digest

    def execute(
        self,
        project_id: str,
        profile: PolicyProfile,
        expressions: dict[str, str],
        timeout: int = 90,
    ) -> dict:
        source = profile.render(expressions)
        if not 1 <= timeout <= 480:
            raise DomainError("formal_limit", "Proof timeout outside allowed range", 422)
        image = self.launcher.checked("image", "inspect", self.image_digest)
        labels = json.loads(image)[0].get("Config", {}).get("Labels", {})
        if labels.get("org.colossus.toolchain") != "dafny-4.11.0-z3-4.13.0":
            raise DomainError(
                "formal_toolchain", "Image is not the configured Dafny toolchain", 422
            )
        started = time.monotonic()
        env = self.launcher.create(
            project_id,
            "verify",
            image=self.image_digest,
            memory_mb=2048,
            ttl_seconds=timeout + 60,
        )
        try:
            self.launcher.copy_source(env, {"policy.dfy": source})
            self.launcher.execute(env, ["mkdir", "-p", "/work/results"], 10)
            args = [
                "dafny",
                "verify",
                "policy.dfy",
                "--solver-path",
                "/usr/local/bin/z3",
                "--cores",
                "1",
                "--verification-time-limit",
                str(timeout),
                "--log-format",
                "csv;LogFileName=/work/results/verify.csv",
            ]
            remaining = max(1, int(timeout - (time.monotonic() - started)))
            verified = self.launcher.execute(env, args, remaining)
            outputs = {} if verified.timed_out else self.launcher.export_files(env, "/work/results")
            passed = proof_passed(
                verified, outputs.get("verify.csv", b""), profile.expected_symbols
            )
            compiled = None
            remaining = int(timeout - (time.monotonic() - started))
            if passed and remaining > 0:
                compiled = self.launcher.execute(
                    env,
                    [
                        "dafny",
                        "build",
                        "policy.dfy",
                        "--target",
                        "py",
                        "--output",
                        "/work/results/policy",
                        "--solver-path",
                        "/usr/local/bin/z3",
                        "--cores",
                        "1",
                    ],
                    remaining,
                )
                outputs = (
                    {} if compiled.timed_out else self.launcher.export_files(env, "/work/results")
                )
            return {
                "proof_outcome": "PROVED" if passed else "UNKNOWN",
                "compiled": bool(
                    compiled
                    and not compiled.exit_code
                    and not compiled.timed_out
                    and not compiled.truncated
                ),
                "profile_id": profile.profile_id,
                "spec_hash": profile.spec_hash,
                "source_hash": hashlib.sha256(source).hexdigest(),
                "toolchain_digest": self.image_digest,
                "verify": asdict(verified),
                "compile": asdict(compiled) if compiled else None,
                "files": outputs,
                "assumptions": list(profile.assumptions),
                "scope": sorted(profile.expected_symbols),
                "linkage": "compiled_component_only; target integration requires separate wrapper and artifact gates",
            }
        finally:
            self.launcher.destroy(env)
