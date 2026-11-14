"""Bounded CrossHair analysis of approved PEP 316 Python obligations under gVisor.

CrossHair executes the code it analyzes, so every run goes through SandboxLauncher
(runsc, ``--network none``). The adapter never yields PROVED: a counterexample is
COUNTEREXAMPLE, clean exhaustion of every path is BOUNDED_PASS only for an obligation
that explicitly accepts bounded evidence under this bound profile, and everything else
(budget exhausted, timeout, crash, empty or malformed report) is UNKNOWN. Constructs
CrossHair cannot analyze safely (side effects, non-determinism, async code, missing
contracts) are UNSUPPORTED.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass

from colossus.contracts.core import DomainError, content_hash
from colossus.contracts.models import GateResult, Obligation
from colossus.sandbox.launcher import ProcessResult, SandboxLauncher

TOOLCHAIN = "crosshair-0.0.113-z3-5.4.1.0"
BOUND_PROFILE_ID = "crosshair-bounded-v1"
DEFAULT_DEADLINE = 90  # runtime.md: default 90 seconds per obligation
MAX_DEADLINE = 480  # runtime.md: 8 minutes of formal checks per candidate
LIMITS = {
    "deadline_seconds": (1, MAX_DEADLINE, DEFAULT_DEADLINE),
    "per_condition_timeout": (1, MAX_DEADLINE, 60),
    "per_path_timeout": (1, 60, 5),
    "max_uninteresting_iterations": (1, 10_000, 50),
}
ASSUMPTIONS = (
    "CrossHair 0.0.113 symbolic execution and Z3 5.4.1.0 solver correctness",
    "Only paths explored within the recorded bounds are covered; this is not a proof",
    "PEP 316 contracts in the approved harness state the property under analysis",
    "Callers outside the analyzed function are not covered",
)
UNSUPPORTED_MARKERS = (
    "SideEffectDetected",
    "NotDeterministic",
    "CrosshairUnsupported",
    "UnexploredPath",
    "IgnoreAttempt",
)
_LINE = re.compile(r"^(?P<path>/work/source/[^:\n]+):(?P<line>\d+): (?P<level>error|info): (?P<msg>.*)$")
_CALL = re.compile(r" when calling (?P<call>.+?)(?: \(which returns (?P<returns>.*)\))?$")


@dataclass(frozen=True)
class Harness:
    """Static (non-executing) facts about the obligation harness, from ``ast`` only."""

    path: str
    symbol: str
    target_line: int
    post_lines: tuple[int, ...]
    contract_text: str

    @property
    def spec_hash(self) -> str:
        return hashlib.sha256(self.contract_text.encode()).hexdigest()


def inspect_harness(path: str, source: bytes, symbol: str) -> Harness | str:
    """Return harness facts, or the reason the obligation is outside CrossHair support."""
    if not path.endswith(".py") or "/" in path:
        return "harness must be a top-level .py file"
    try:
        tree = ast.parse(source.decode(), filename=path)
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return "harness is not parseable Python"
    matches = [n for n in tree.body if getattr(n, "name", None) == symbol]
    if len(matches) != 1:
        return "symbol is not a unique top-level function"
    node = matches[0]
    if isinstance(node, ast.AsyncFunctionDef):
        return "async functions are not supported"
    if not isinstance(node, ast.FunctionDef):
        return "symbol is not a function"
    if node.decorator_list:
        return "decorated functions are not supported by this profile"
    doc = ast.get_docstring(node, clean=False)
    if not doc or not node.body:
        return "function has no PEP 316 contract"
    first = node.body[0]
    start = first.lineno
    raw = doc.split("\n")
    contract, posts = [], []
    for offset, text in enumerate(raw):
        stripped = text.strip()
        if stripped.startswith(("pre:", "post:", "post[", "raises:", "inv:")):
            contract.append(stripped)
            if stripped.startswith(("post:", "post[")):
                posts.append(start + offset)
    if not posts:
        return "function has no PEP 316 postcondition"
    body_line = node.body[1].lineno if len(node.body) > 1 else first.end_lineno or start
    return Harness(path, symbol, body_line, tuple(posts), "\n".join(contract))


def _bounds(obligation: Obligation) -> dict[str, int]:
    unknown = set(obligation.bounds) - LIMITS.keys()
    if unknown:
        raise DomainError("formal_limit", "Unknown CrossHair bound: " + sorted(unknown)[0], 422)
    result = {}
    for name, (low, high, default) in LIMITS.items():
        value = obligation.bounds.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise DomainError("formal_limit", f"CrossHair bound {name} outside policy", 422)
        result[name] = value
    if result["per_condition_timeout"] > result["deadline_seconds"]:
        raise DomainError("formal_limit", "Condition budget exceeds obligation deadline", 422)
    return result


def bounded_allowed(obligation: Obligation) -> bool:
    return (
        obligation.required_evidence_kind == "bounded"
        and obligation.allowed_bound_profile_id == BOUND_PROFILE_ID
    )


def parse_report(result: ProcessResult, harness: Harness, bounded_ok: bool) -> dict:
    """Map one ``crosshair check --report_all`` run to a proof outcome. Pure function."""
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    parsed, malformed = [], []
    expected_path = "/work/source/" + harness.path
    for line in lines:
        match = _LINE.match(line)
        if not match or match["path"] != expected_path:
            malformed.append(line)
        else:
            parsed.append(match.groupdict() | {"line": int(match["line"])})
    base = {
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "truncated": result.truncated,
        "conditions": parsed,
        "malformed_lines": malformed[:20],
        "counterexample": None,
        "exploration": None,
    }

    def outcome(name: str, reason: str, **extra) -> dict:
        return base | {"proof_outcome": name, "reason": reason} | extra

    if result.timed_out:
        return outcome("UNKNOWN", "obligation deadline reached", exploration="interrupted")
    if result.truncated:
        return outcome("UNKNOWN", "report truncated")
    errors = [p for p in parsed if p["level"] == "error"]
    for item in errors:
        if any(marker in item["msg"] for marker in UNSUPPORTED_MARKERS):
            continue
        call = _CALL.search(item["msg"])
        if call and result.exit_code == 1:
            return outcome(
                "COUNTEREXAMPLE",
                "contract violated on a concrete input",
                counterexample={
                    "line": item["line"],
                    "message": item["msg"],
                    "call": call["call"],
                    "returns": call["returns"],
                },
            )
    if any(marker in p["msg"] for p in errors for marker in UNSUPPORTED_MARKERS):
        return outcome("UNSUPPORTED", "analysis hit a construct CrossHair cannot explore safely")
    if errors:
        return outcome("UNKNOWN", "analysis error without a concrete counterexample")
    if result.exit_code != 0 or malformed:
        return outcome("UNKNOWN", "unexpected exit code or malformed report")
    reported = {p["line"]: p["msg"] for p in parsed}
    if not parsed or set(reported) != set(harness.post_lines) or len(reported) != len(parsed):
        return outcome("UNKNOWN", "report does not cover exactly the obligation postconditions")
    if any(msg != "Confirmed over all paths." for msg in reported.values()):
        return outcome(
            "UNKNOWN",
            "no counterexample within bounds, but exploration incomplete",
            exploration="incomplete",
        )
    if not bounded_ok:
        return outcome(
            "UNKNOWN",
            "all paths explored within bounds; obligation requires proof, not bounded evidence",
            exploration="exhausted",
        )
    return outcome("BOUNDED_PASS", "all paths explored within bounds", exploration="exhausted")


def gate_status(evidence: dict, obligation: Obligation) -> str:
    outcome = evidence["proof_outcome"]
    if outcome == "BOUNDED_PASS" and bounded_allowed(obligation):
        return "pass"
    if outcome == "COUNTEREXAMPLE":
        return "fail"
    if outcome == "UNSUPPORTED":
        return "error" if obligation.required else "not_applicable"
    if evidence.get("timed_out"):
        return "timeout"
    return "error"


def to_gate_result(
    evidence: dict,
    obligation: Obligation,
    *,
    gate_id: str,
    case_id: str,
    candidate_id: str,
    candidate_hash: str,
    started_at: str,
    finished_at: str,
    evidence_ids: list[str],
) -> GateResult:
    if evidence.get("obligation_id") != obligation.obligation_id:
        raise DomainError("formal_binding", "Evidence belongs to another obligation", 409)
    if evidence["proof_outcome"] == "PROVED":
        raise DomainError("formal_binding", "CrossHair evidence cannot be PROVED", 409)
    return GateResult(
        gate_id=gate_id,
        case_id=case_id,
        candidate_id=candidate_id,
        candidate_hash=candidate_hash,
        check_profile_id="crosshair:" + obligation.obligation_id,
        category="formal",
        status=gate_status(evidence, obligation),
        proof_outcome=evidence["proof_outcome"],
        scope=[obligation.component + ":" + obligation.symbol],
        assumptions=list(obligation.assumptions) + list(ASSUMPTIONS),
        tool_version=TOOLCHAIN,
        command_profile_hash=evidence["command_profile_hash"],
        exit_code=evidence.get("exit_code"),
        started_at=started_at,
        finished_at=finished_at,
        evidence_ids=evidence_ids,
        reason=evidence["reason"][:2000],
    )


class CrossHairAdapter:
    def __init__(self, launcher: SandboxLauncher, image_digest: str):
        self.launcher, self.image_digest = launcher, image_digest

    def _checked_image(self):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_digest):
            raise DomainError("formal_toolchain", "CrossHair image must be pinned by digest", 422)
        image = json.loads(self.launcher.checked("image", "inspect", self.image_digest))[0]
        labels = image.get("Config", {}).get("Labels") or {}
        if labels.get("org.colossus.toolchain") != TOOLCHAIN or image.get("Id") != self.image_digest:
            raise DomainError("formal_toolchain", "Image is not the configured CrossHair toolchain", 422)

    def execute(
        self,
        project_id: str,
        obligation: Obligation,
        files: dict[str, bytes],
        harness_path: str,
    ) -> dict:
        """Run one approved obligation; ``files`` are the harness and its local imports."""
        if obligation.backend != "crosshair":
            raise DomainError("formal_scope", "Obligation is not a CrossHair obligation", 422)
        if not obligation.approved:
            raise DomainError("formal_scope", "Obligation is not approved", 422)
        source = files.get(harness_path)
        if source is None or hashlib.sha256(source).hexdigest() != obligation.harness_hash:
            raise DomainError("formal_binding", "Harness does not match the obligation", 409)
        bounds = _bounds(obligation)
        command = [
            "python",
            "-m",
            "crosshair",
            "check",
            "--report_all",
            "--analysis_kind",
            "PEP316",
            "--per_condition_timeout",
            str(bounds["per_condition_timeout"]),
            "--per_path_timeout",
            str(bounds["per_path_timeout"]),
            "--max_uninteresting_iterations",
            str(bounds["max_uninteresting_iterations"]),
        ]
        record = {
            "obligation_id": obligation.obligation_id,
            "backend": "crosshair",
            "toolchain": TOOLCHAIN,
            "toolchain_digest": self.image_digest,
            "bound_profile_id": BOUND_PROFILE_ID,
            "bounds": bounds,
            "harness_hash": obligation.harness_hash,
            "source_hashes": {p: hashlib.sha256(d).hexdigest() for p, d in sorted(files.items())},
            "assumptions": list(obligation.assumptions) + list(ASSUMPTIONS),
            "scope": [obligation.component + ":" + obligation.symbol],
            "network": "none",
            "process": None,
        }
        harness = inspect_harness(harness_path, source, obligation.symbol)
        if isinstance(harness, str):
            record["command_profile_hash"] = content_hash({"command": command})
            return record | {"proof_outcome": "UNSUPPORTED", "reason": harness}
        if harness.spec_hash != obligation.spec_hash:
            raise DomainError("formal_binding", "Contract text does not match the obligation", 409)
        command.append(f"{harness.path}:{harness.target_line}")
        record["command_profile_hash"] = content_hash({"command": command})
        record["spec_hash"] = harness.spec_hash
        self._checked_image()
        deadline = bounds["deadline_seconds"]
        started = time.monotonic()
        env = self.launcher.create(
            project_id,
            "verify",
            image=self.image_digest,
            memory_mb=2048,
            ttl_seconds=deadline + 60,
        )
        try:
            self.launcher.copy_source(env, files)
            remaining = max(1, int(deadline - (time.monotonic() - started)))
            result = self.launcher.execute(env, command, remaining)
        finally:
            self.launcher.destroy(env)
        parsed = parse_report(result, harness, bounded_allowed(obligation))
        return record | parsed | {"process": asdict(result)}
