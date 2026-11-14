"""Fresh bounded GLM review of cached catalog signals through a running shared gateway.

No provider key access, target execution, probe execution or gold adjudication.
Start the normal controller/services first; this command never starts/stops them.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import stat
import time
from collections import Counter
from pathlib import Path

from colossus.contracts.core import DomainError, digest, new_id, utcnow
from colossus.control.artifacts import ArtifactStore
from colossus.control.broker import Broker
from colossus.control.config import Settings
from colossus.control.rpc import RPCClient
from colossus.control.store import Store
from colossus.detect.redteam import dedupe, triage
from colossus.detect.static import RawFinding
from colossus.gateway.model import MODEL_ID
from colossus.gateway.source import tree_hash

OUTPUT = Path("evaluation/submission/model-triage.json")


def write_report(rows, started):
    report = {
        "kind": "fresh_model_catalog_signal_triage",
        "model": MODEL_ID,
        "generated_at": utcnow(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "catalog_count": len(rows),
        "status_counts": dict(Counter(r["status"] for r in rows)),
        "model_calls": sum(r.get("model_calls", 0) for r in rows),
        "committed_micro_usd": sum(r.get("cost", {}).get("committed_micro_usd", 0) for r in rows),
        "settled_micro_usd": sum(r.get("cost", {}).get("settled_micro_usd", 0) for r in rows),
        "uncertain_micro_usd": sum(r.get("cost", {}).get("uncertain_micro_usd", 0) for r in rows),
        "rows": rows,
        "limitations": [
            "One serial T1 request per eligible repository, at most eight deduplicated static signals.",
            "Only Python snippets were reviewed; helper scripts do not establish coverage of the repository's main language.",
            "Model judgments are unconfirmed; suggested probes are recorded but never executed.",
            "No gold adjudication, precision, recall, repair, formal proof or deployment score is claimed.",
            "No second provider or refusal bypass; incomplete outcomes stay in the denominator.",
        ],
    }
    OUTPUT.parent.mkdir(exist_ok=True, parents=True)
    temporary = OUTPUT.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(OUTPUT)
    lines = [
        "# Fresh GLM catalog triage",
        "",
        f"Measured: {report['generated_at']}",
        "",
        f"Model calls: {report['model_calls']}; settled cost: ${report['settled_micro_usd'] / 1_000_000:.6f}; uncertain reservation: {report['uncertain_micro_usd']} micro-USD.",
        "",
        "| ID | Repository | Outcome | Selected / available groups | Valid model judgments |",
        "|---|---|---|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['repo_id']} | {row['repository']} | {row['status']} | {row.get('selected_groups', 0)} / {row.get('available_groups', 0)} | {len(row.get('verdicts', []))} |"
        )
    lines += [
        "",
        *["- " + x for x in report["limitations"]],
        "",
        "Reproduce while the normal local gateway is running:",
        "",
        "```bash",
        "uv run python scripts/check_catalog_triage.py --seconds 90",
        "```",
        "",
        "Exact commits, source/snippet hashes, call IDs, token accounting references and bounded verdicts are retained in [model-triage.json](model-triage.json).",
    ]
    OUTPUT.with_suffix(".md").write_text("\n".join(lines) + "\n")
    return report


def gateway_client(settings):
    token_file = settings.data_dir / "run/gateway.token"
    fd = os.open(token_file, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise DomainError("unsafe_service_token", "Gateway capability must be owner-only", 403)
        token = stream.read(4096).strip()
    return RPCClient(settings.data_dir / "run/gateway.sock", token)


async def main(seconds):
    started = time.monotonic()
    deadline = started + seconds
    settings = Settings.from_environment()
    store = Store(settings.data_dir / "state.sqlite3")
    gateway = None
    rows = []
    for path in sorted(OUTPUT.parent.glob("U[0-9][0-9].json")):
        raw = json.loads(path.read_text())
        rows.append(
            {
                "repo_id": raw["repo_id"],
                "repository": raw["repository"],
                "commit": raw.get("source", {}).get("commit"),
                "tree_sha256": raw.get("source", {}).get("tree_sha256"),
                "subdir": raw.get("subdir"),
                "status": "pending",
                "model_calls": 0,
                "verdicts": [],
                "precision": None,
                "recall": None,
            }
        )
    try:
        try:
            gateway = gateway_client(settings)
            await asyncio.wait_for(gateway.call("/health"), timeout=5)
        except (DomainError, OSError, TimeoutError):
            for row in rows:
                row.update(
                    status="gateway_unavailable",
                    reason="Existing shared gateway unavailable; no calls attempted",
                )
            return write_report(rows, started)
        broker = Broker(
            store, ArtifactStore(settings.data_dir / "artifacts"), gateway, settings.runtime
        )
        for row in rows:
            raw = json.loads((OUTPUT.parent / (row["repo_id"] + ".json")).read_text())
            if raw["source"]["status"] != "accepted":
                row.update(
                    status="unsupported", reason="Source intake did not accept this snapshot"
                )
                continue
            signals = raw.get("static", {}).get("findings", [])
            if not signals:
                row.update(
                    status="no_eligible_signals",
                    reason="No static Python signal available; not a claim of security",
                )
                continue
            if time.monotonic() >= deadline:
                row.update(status="not_run_deadline", reason="Global model review deadline reached")
                continue
            project_id, case_id = new_id(), new_id()
            row.update(project_id=project_id, case_id=case_id)
            diagnostics = []
            try:
                cache = json.loads(
                    (
                        settings.data_dir / "submission-source" / (row["repo_id"] + ".json")
                    ).read_text()
                )
                files = {p: base64.b64decode(b, validate=True) for p, b in cache["files"].items()}
                if cache["commit"] != row["commit"] or tree_hash(files) != row["tree_sha256"]:
                    raise DomainError(
                        "source_binding", "Cached source differs from recorded snapshot", 409
                    )
                raw_findings = []
                for f in signals:
                    lines = files[f["file"]].decode(errors="replace").splitlines()
                    if not 1 <= f["line"] <= len(lines):
                        raise DomainError(
                            "source_binding", "Static location not present in cached source", 409
                        )
                    raw_findings.append(
                        RawFinding(
                            "rules",
                            f["rule"],
                            f["cwe"],
                            f["title"],
                            f["file"],
                            f["line"],
                            lines[f["line"] - 1],
                        )
                    )
                groups = dedupe(raw_findings)
                row.update(
                    available_groups=len(groups),
                    selected_groups=min(8, len(groups)),
                    input_coverage=[],
                )
                for group in groups[:8]:
                    finding = group[0]
                    lines = files[finding.file].decode(errors="replace").splitlines()
                    snippet = "\n".join(lines[max(0, finding.line - 7) : finding.line + 6])[:4000]
                    row["input_coverage"].append(
                        {
                            "file": finding.file,
                            "line": finding.line,
                            "cwe_hint": finding.cwe,
                            "snippet_sha256": digest(snippet.encode()),
                            "snippet_characters": len(snippet),
                        }
                    )
                verdicts = await asyncio.wait_for(
                    triage(broker, project_id, case_id, files, groups[:8], diagnostics=diagnostics),
                    timeout=max(0.01, deadline - time.monotonic()),
                )
                for index, verdict in sorted(verdicts.items()):
                    cwe = verdict.get("cwe")
                    row["verdicts"].append(
                        {
                            "index": index,
                            "file": groups[index][0].file,
                            "line": groups[index][0].line,
                            "model_suspects_real": verdict["real"],
                            "status": "unconfirmed",
                            "cwe": cwe
                            if isinstance(cwe, str) and re.fullmatch(r"CWE-[1-9][0-9]*", cwe)
                            else None,
                            "reason": str(verdict.get("reason", ""))[:1000],
                            "suggested_probe": {
                                k: str(v)[:200]
                                for k, v in verdict.get("probe", {}).items()
                                if k in {"profile", "path", "param"}
                            }
                            if isinstance(verdict.get("probe"), dict)
                            else None,
                            "probe_executed": False,
                        }
                    )
                row["status"] = (
                    "reviewed" if len(verdicts) == len(groups[:8]) else "partial_or_invalid_output"
                )
            except TimeoutError:
                row.update(
                    status="timeout", reason="Model triage exceeded remaining global deadline"
                )
            except (DomainError, ValueError, KeyError, OSError) as exc:
                row.update(
                    status="unavailable",
                    reason=exc.code if isinstance(exc, DomainError) else type(exc).__name__,
                )
            finally:
                calls = store.list("model_call", project_id)
                row["model_calls"] = len(calls)
                row["model_call_ids"] = [call["call_id"] for call in calls]
                row["call_outcomes"] = [
                    {
                        k: call.get(k)
                        for k in [
                            "call_id",
                            "model_returned",
                            "status",
                            "reason_code",
                            "input_tokens",
                            "output_tokens",
                            "actual_cost_micro_usd",
                        ]
                    }
                    for call in calls
                ]
                failures = [
                    call.get("reason_code") for call in calls if call.get("status") != "succeeded"
                ]
                if failures and row["status"] == "partial_or_invalid_output":
                    row["status"] = failures[0] or "model_failed"
                row["diagnostics"] = diagnostics
                row["cost"] = store.budget(case_id)
                write_report(rows, started)
                print(
                    json.dumps(
                        {
                            "repo_id": row["repo_id"],
                            "status": row["status"],
                            "model_calls": row["model_calls"],
                            "valid_verdicts": len(row["verdicts"]),
                        }
                    ),
                    flush=True,
                )
        report = write_report(rows, started)
        print(
            json.dumps(
                {
                    k: report[k]
                    for k in [
                        "model_calls",
                        "settled_micro_usd",
                        "uncertain_micro_usd",
                        "elapsed_seconds",
                        "status_counts",
                    ]
                }
            ),
            flush=True,
        )
        return report
    finally:
        if gateway:
            await gateway.close()
        store.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=90)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 180:
        parser.error("--seconds must be 1..180")
    asyncio.run(main(args.seconds))
