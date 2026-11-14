import base64
import json
from importlib.resources import files as resources
from urllib.parse import quote

from colossus.contracts.core import DomainError, content_hash, new_id
from colossus.contracts.models import Finding


async def static_scan(launcher, project_id, encoded_files):
    worker = resources("colossus.detection").joinpath("static_worker.py").read_bytes()
    path = "_colossus_static_worker.py"
    if path in encoded_files:
        raise DomainError(
            "reserved_source_path", "Repository collides with analyzer entrypoint", 422
        )
    result = await launcher.call(
        "/run",
        {
            "project_id": project_id,
            "role": "scan",
            "files": encoded_files | {path: base64.b64encode(worker).decode()},
            "argv": ["python", "-I", path],
            "timeout": 60,
        },
    )
    if result["exit_code"] or result["timed_out"]:
        raise DomainError("analysis_failed", "Static analyzer did not complete", 503)
    try:
        return json.loads(result["stdout"])
    except ValueError:
        raise DomainError(
            "analysis_failed", "Analyzer returned invalid structured evidence", 503
        ) from None


def finding_from_signal(signal, manifest_hash, evidence_id):
    return Finding(
        finding_id=new_id(),
        manifest_hash=manifest_hash,
        fingerprint=content_hash({k: signal[k] for k in ("path", "symbol", "cwe", "expression")}),
        title=signal["title"],
        cwe=signal["cwe"],
        location={"file": signal["path"], "line": signal["line"], "symbol": signal["symbol"]},
        source_tools=["colossus-ast-v1"],
        evidence_ids=[evidence_id],
    )


async def dsvw_checks(launcher, project_id, environment_id, port):
    """Fixed bounded oracle: baseline positive functionality and boolean read-only SQL comparison."""
    paths = {
        "home": "/",
        "record_1": "/?id=1",
        "record_2": "/?id=2",
        "sql_true": "/?id=" + quote("1 AND 1=1", safe=""),
        "sql_false": "/?id=" + quote("1 AND 1=2", safe=""),
    }
    responses = {}
    for name, path in paths.items():
        responses[name] = await launcher.call(
            "/targets/request",
            {
                "project_id": project_id,
                "environment_id": environment_id,
                "port": port,
                "path": path,
            },
        )
    r = responses
    functional = (
        all(r[k].get("status") == 200 for k in ("home", "record_1", "record_2"))
        and "Damn Small Vulnerable Web" in r["home"].get("body", "")
        and "<td>admin</td>" in r["record_1"].get("body", "")
        and "<td>dricci</td>" in r["record_2"].get("body", "")
    )
    vulnerable = (
        r["sql_true"].get("status") == 200
        and r["sql_false"].get("status") == 200
        and "<td>admin</td>" in r["sql_true"].get("body", "")
        and "<td>admin</td>" not in r["sql_false"].get("body", "")
    )
    blocked = all(
        r[k].get("status") in {200, 400, 422} and "<td>admin</td>" not in r[k].get("body", "")
        for k in ("sql_true", "sql_false")
    )
    return {
        "profile": "dsvw-functional-security-v1",
        "functional_pass": functional,
        "vulnerability_confirmed": vulnerable,
        "security_pass": blocked,
        "responses": responses,
        "scope": "id parameter SQL expression evaluation only; no claim about other injection routes",
    }
