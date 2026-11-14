"""Bounded, non-scored submission preflight over Daniel's 24-repository catalog.

Repository bytes are data on the host; target execution is confined to the
existing gVisor launcher. No repository Dockerfiles or cloud stacks are run.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import httpx

from colossus.contracts.core import DomainError, digest, new_id, utcnow
from colossus.contracts.models import Enrollment
from colossus.detect.static import RULES, SKIP_DIRS
from colossus.gateway.source import MAX_ARCHIVE, GitHubSource, tree_hash, unpack_source
from colossus.onboarding.discovery import discover

CATALOG = [
    ("U01", "erev0s/VAmPI", None),
    ("U02", "fportantier/vulpy", "bad"),
    ("U03", "stamparm/DSVW", None),
    ("U04", "we45/Vulnerable-Flask-App", None),
    ("U05", "anxolerd/dvpwa", None),
    ("U06", "payatu/Tiredful-API", None),
    ("U07", "mattvaldes/vulnerable-api", None),
    ("U08", "dolevf/Damn-Vulnerable-GraphQL-Application", None),
    ("U09", "adeyosemanputra/pygoat", None),
    ("U10", "digininja/DVWA", None),
    ("U11", "webpwnized/mutillidae-docker", None),
    ("U12", "juice-shop/juice-shop", None),
    ("U13", "appsecco/dvna", None),
    ("U14", "OWASP/NodeGoat", None),
    ("U15", "OWASP/railsgoat", None),
    ("U16", "snyk-labs/nodejs-goof", None),
    ("U17", "globocom/secDevLabs", None),
    ("U18", "OWASP/crAPI", None),
    ("U19", "bridgecrewio/terragoat", None),
    ("U20", "madhuakula/kubernetes-goat", None),
    ("U21", "RhinoSecurityLabs/cloudgoat", None),
    ("U22", "vulhub/vulhub", None),
    ("U23", "sudo-project/sudo", None),
    ("U24", "tukaani-project/xz", None),
]
OUTPUT = Path("evaluation/submission")
CACHE = Path(".colossus/submission-source")


def save(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def static_signals(files):
    """Apply the shipped cheap rules to text only, without imports or hooks."""
    findings, selected = [], []
    for path, data in sorted(files.items()):
        if not path.endswith(".py") or set(path.split("/")) & SKIP_DIRS or len(data) > 500_000:
            continue
        if len(selected) >= 2000:
            break
        selected.append(path)
        for line_number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for rule, cwe, title, regex in RULES:
                if regex.search(line):
                    findings.append(
                        {
                            "rule": rule,
                            "cwe": cwe,
                            "title": title,
                            "file": path,
                            "line": line_number,
                            "status": "unconfirmed",
                        }
                    )
    return {
        "status": "completed" if selected else "unsupported",
        "tool": "colossus-rules-v1",
        "files_scanned": len(selected),
        "finding_count": len(findings),
        "findings": findings,
        "scope": "Python text patterns only; no execution, dataflow proof, or confirmation",
        "precision": None,
        "recall": None,
    }


def fallback(repo_id, recipe=None):
    if repo_id in {"U19", "U20", "U21"}:
        return [
            "Use a dedicated IaC/cluster adapter and static policy checks.",
            "Do not deploy cloud resources or grant cloud credentials for this submission.",
            "No application functional or security suite was executed.",
        ]
    if repo_id in {"U17", "U22"}:
        return [
            "Select one lab/CVE subdirectory and freeze its source and dependencies.",
            "Run its build and tests in a separately admitted isolated profile.",
            "A collection-wide static signal is not a reproduced lab vulnerability.",
        ]
    if recipe:
        return [
            "Run the discovered recipe in the existing isolated runtime.",
            "Run bounded HTTP readiness; preserve HTTP status and body hash.",
            "Run applicable protected functional/security tests when installed.",
            "If no protected oracle exists, report test coverage unsupported; do not promote.",
        ]
    return [
        "Install an appropriate isolated stack adapter or provide an approved explicit recipe.",
        "Build and run the application and its tests only inside that sandbox.",
        "Separate attack-preserving training tests from legitimate positive tests.",
        "No formal proof or security guarantee follows from source-pattern results.",
    ]


async def intake_one(client, item, semaphore):
    repo_id, repository, subdir = item
    async with semaphore:
        started = time.monotonic()
        row = {
            "repo_id": repo_id,
            "repository": repository,
            "repo_url": "https://github.com/" + repository,
            "subdir": subdir,
            "started_at": utcnow(),
            "source": {"status": "pending"},
            "setup": {"status": "not_run"},
            "tests": {"status": "not_run"},
            "formal": {
                "outcome": "UNSUPPORTED",
                "reason": "No approved linked requirement for this catalog preflight",
            },
            "full_cycle": {"status": "not_run"},
            "model_calls": 0,
            "cost_micro_usd": 0,
            "runner_sha256": digest(Path(__file__).read_bytes()),
            "evaluation_kind": "compatibility_and_static_preflight; not a scored security benchmark",
            "fallback_instructions": fallback(repo_id),
        }
        source = GitHubSource(client)
        try:
            async with asyncio.timeout(100):
                # Resolve once and retain the immutable commit even when archive intake fails.
                record = json.loads(
                    await source._read(
                        f"https://api.github.com/repos/{repository}/commits/{quote('HEAD', safe='')}",
                        2_000_000,
                    )
                )
                commit = record["sha"]
                import re

                if not re.fullmatch(r"[a-f0-9]{40}", commit):
                    raise DomainError(
                        "invalid_revision", "GitHub did not return an immutable commit", 502
                    )
                row["source"]["commit"] = commit
                archive = await source._read(
                    f"https://codeload.github.com/{repository}/tar.gz/{commit}", MAX_ARCHIVE
                )
                row["source"]["archive_sha256"] = digest(archive)
                files = unpack_source(archive)
                if subdir:
                    prefix = subdir + "/"
                    files = {
                        name[len(prefix) :]: data
                        for name, data in files.items()
                        if name.startswith(prefix)
                    }
                    if not files:
                        raise DomainError("missing_subdir", "Requested source view is absent", 422)
                row["source"].update(
                    status="accepted",
                    tree_sha256=tree_hash(files),
                    file_count=len(files),
                    total_bytes=sum(map(len, files.values())),
                )
                encoded = {name: base64.b64encode(data).decode() for name, data in files.items()}
                save(
                    CACHE / f"{repo_id}.json",
                    {
                        "repo_url": row["repo_url"],
                        "requested_ref": commit,
                        "commit": commit,
                        "source_archive_sha256": digest(archive),
                        "tree_sha256": tree_hash(files),
                        "files": encoded,
                    },
                )
                row["static"] = static_signals(files)
                try:
                    recipe = discover(files)
                    row["discovery"] = {"status": "supported_recipe", "recipe": recipe.model_dump()}
                    row["fallback_instructions"] = fallback(repo_id, recipe)
                except DomainError as exc:
                    row["discovery"] = {"status": exc.code, "reason": exc.message}
        except DomainError as exc:
            row["source"].update(status="rejected", reason_code=exc.code, reason=exc.message)
        except (TimeoutError, httpx.HTTPError) as exc:
            row["source"].update(
                status="failed",
                reason_code=type(exc).__name__,
                reason="Bounded source request did not complete",
            )
        except (ValueError, KeyError) as exc:
            row["source"].update(
                status="failed", reason_code=type(exc).__name__, reason="Invalid source response"
            )
        row["intake_seconds"] = round(time.monotonic() - started, 3)
        row["finished_at"] = utcnow()
        save(OUTPUT / f"{repo_id}.json", row)
        print(
            json.dumps(
                {
                    "repo": repository,
                    "source": row["source"]["status"],
                    "discovery": row.get("discovery", {}).get("status"),
                    "signals": row.get("static", {}).get("finding_count"),
                }
            ),
            flush=True,
        )
        return row


async def intake():
    async with httpx.AsyncClient(trust_env=False, limits=httpx.Limits(max_connections=4)) as client:
        semaphore = asyncio.Semaphore(4)
        await asyncio.gather(*(intake_one(client, item, semaphore) for item in CATALOG))
    summarize()


def summarize():
    # This is a distinct fresh-inference experiment performed by the integration lane.
    lifecycle_path = OUTPUT / "dsvw-full-cycle.json"
    dsvw_path = OUTPUT / "U03.json"
    if lifecycle_path.exists() and dsvw_path.exists():
        lifecycle = json.loads(lifecycle_path.read_text())
        dsvw = json.loads(dsvw_path.read_text())
        if (
            lifecycle.get("generation_mode") == "fresh_inference"
            and lifecycle.get("promoted", {}).get("status") == "COMPLETE"
            and dsvw["source"].get("commit") == "9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908"
        ):
            dsvw["setup"] = {
                "status": "ready",
                "evidence_origin": "separate_integration_run",
                "project_id": lifecycle["project_id"],
            }
            dsvw["tests"] = {
                "status": "protected_repair_gates_passed",
                "evidence": "dsvw-full-cycle.json",
                "scope": "Registered DSVW functionality/security/static and artifact gates; formal unsupported",
            }
            dsvw["full_cycle"] = {
                "status": "COMPLETE",
                "generation_mode": "fresh_inference",
                "evidence": "dsvw-full-cycle.json",
                "seconds": lifecycle["first_cycle_seconds"],
                "case_id": lifecycle["case_id"],
                "performed_by": "integration_lane",
                "cost_micro_usd": lifecycle["cost"]["settled_micro_usd"],
                "model_calls": lifecycle["cost"]["calls"],
            }
            save(dsvw_path, dsvw)
    rows = [
        json.loads((OUTPUT / f"{repo_id}.json").read_text())
        for repo_id, _, _ in CATALOG
        if (OUTPUT / f"{repo_id}.json").exists()
    ]
    report = {
        "schema_version": "1.0",
        "generated_at": utcnow(),
        "catalog_count": len(CATALOG),
        "recorded_count": len(rows),
        "source_status_counts": dict(Counter(row["source"]["status"] for row in rows)),
        "setup_status_counts": dict(Counter(row["setup"]["status"] for row in rows)),
        "runtime_attempt_status_counts": dict(
            Counter(
                attempt["setup"]["status"]
                for row in rows
                for attempt in row.get("runtime_attempts", [])
            )
        ),
        "runtime_attempt_count": sum(len(row.get("runtime_attempts", [])) for row in rows),
        "runtime_attempt_scope": "Catalog runner only; separate fresh DSVW lifecycle is additional and source intake is not execution",
        "python_rule_covered_repositories": sum(
            row.get("static", {}).get("status") == "completed" for row in rows
        ),
        "model_calls": sum(row["model_calls"] for row in rows),
        "cost_micro_usd": sum(row["cost_micro_usd"] for row in rows),
        "cost_scope": "Compatibility runner only; separate model-triage.json, vampi-setup-advice.json and dsvw-full-cycle.json report their own calls and cost",
        "repositories": rows,
        "limitations": [
            "One source preflight per repository, with explicitly retained assisted runtime attempts; no gold adjudication or security score.",
            "Runner instrumentation evolved during this exploratory campaign; this is not a frozen performance benchmark. Source commits and per-attempt input hashes are retained.",
            "Python text-pattern signals are unconfirmed, not distinct proven vulnerabilities.",
            "No CTIBench, CyberSecEval or DafnyBench benchmark score is produced by this campaign.",
            "Fresh-inference DSVW full-cycle evidence is a separate integration run, linked in dsvw-full-cycle.json; other rows are compatibility preflights.",
        ],
    }
    save(OUTPUT / "results.json", report)
    lines = [
        "# Submission repository preflight",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "All 24 catalog entries are retained. This is a compatibility/static pilot, not a security certification or a scored benchmark.",
        "",
        "| ID | Repository | Source | Python signals | Setup | Software tests |",
        "|---|---|---|---:|---|---|",
    ]
    for row in rows:
        signals = (
            row.get("static", {}).get("finding_count")
            if row.get("static", {}).get("status") == "completed"
            else None
        )
        setup_label = row["setup"]["status"]
        if row["repo_id"] == "U09" and row.get("assisted_attempt"):
            setup_label += " (one BOPLA lab; assisted)"
        elif row["repo_id"] == "U01" and len(row.get("runtime_attempts", [])) > 1:
            setup_label = "failed original pin; " + setup_label + " modified pin (assisted)"
        elif row.get("assisted_attempt"):
            setup_label += " (assisted entrypoint/view)"
        elif row["repo_id"] == "U03" and row.get("full_cycle", {}).get("status") == "COMPLETE":
            setup_label += " (fresh full cycle)"
        test_label = row["tests"]["status"]
        if "total" in row["tests"]:
            test_label = f"{row['tests']['passed']}/{row['tests']['total']} bounded HTTP checks"
        lines.append(
            f"| {row['repo_id']} | [{row['repository']}]({row['repo_url']}) | {row['source']['status']} | {signals if signals is not None else '—'} | {setup_label} | {test_label} |"
        )
    lines += [
        "",
        "## Interpretation",
        "",
        *["- " + x for x in report["limitations"]],
        "",
        "Static counts concern the original admitted source view. Assisted runtime subdirectories and dependency changes have separate hashes; PyGoat's runtime checks cover one lab only. Model rationales are unverified suggestions, not compatibility evidence; the observed build/tests decide outcomes.",
        "",
        "Each JSON row retains the resolved commit, source hash where available, scope, failure reason, stage timing and plain fallback-testing instructions. Source intake failures remain in the denominator. `unsupported` does not mean secure.",
        "",
        "## Observed execution and cleanup",
        "",
        f"Source intake: {report['recorded_count']}/{report['catalog_count']} entries recorded; {report['source_status_counts']}. Python rule coverage: {report['python_rule_covered_repositories']} repositories.",
        f"Catalog runtime attempts: {report['runtime_attempt_count']}; outcomes {report['runtime_attempt_status_counts']}. The separately linked fresh DSVW lifecycle is additional. Original failed attempts remain in each row's runtime_attempts.",
        "The commands below were executed on 14 November 2026. Ruff and Python compilation checks passed for the runner. Final cleanup inventory is in [cleanup.json](cleanup.json); only the pre-existing DSVW mirror was retained.",
        "",
        "## Related measured experiments",
        "",
        "- [Fresh DSVW full cycle](dsvw-full-cycle.json): separate integration-lane fresh inference, promotion, second cycle and rollback.",
        "- [GLM triage](model-triage.json): separate bounded model review of static signals; not dynamic confirmation.",
        "- [VAmPI setup advice](vampi-setup-advice.json): separately accounted model dependency proposal, when available.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "uv run python scripts/run_submission_campaign.py intake",
        "uv run python scripts/run_submission_campaign.py runtime --assisted --ids U09 U01 U06 U04 U02 U03 U05 U07 U08 U10 U11 U12 U13 U14 U15 U16 U17 U18 U19 U20 U21 U22 U23 U24",
        "uv run python scripts/run_submission_campaign.py runtime --assisted --vampi-compatible-wheels --ids U01 --seconds 120",
        "```",
        "",
        "Runtime uses the existing gVisor launcher; it never executes repository Dockerfiles or package hooks on the host. Cloud/Kubernetes/C targets are not deployed by this runner.",
    ]
    (OUTPUT / "README.md").write_text("\n".join(lines) + "\n")


def prepare_assisted(repo_id, source, compatibility=False):
    """Explicit evaluator setup hints; retain the unassisted source and discovery row."""
    files = {name: base64.b64decode(data) for name, data in source["files"].items()}
    changes = []
    if repo_id == "U01" and compatibility:
        advice = json.loads((OUTPUT / "vampi-setup-advice.json").read_text())
        expected = {"package": "MarkupSafe", "old_version": "2.1.2", "new_version": "2.1.5"}
        if (
            advice.get("model_status") != "succeeded"
            or not advice.get("permitted_change_validated")
            or advice.get("commit") != source["commit"]
            or advice.get("source_tree_sha256") != source["tree_sha256"]
            or advice.get("requirements_sha256") != digest(files["requirements.txt"])
            or any(advice.get("proposal", {}).get(k) != v for k, v in expected.items())
        ):
            raise ValueError("Setup advice does not match the permitted source-bound change")
        original = files["requirements.txt"]
        if original.count(b"markupsafe==2.1.2") != 1:
            raise ValueError("Dependency change is ambiguous")
        files["requirements.txt"] = original.replace(b"markupsafe==2.1.2", b"markupsafe==2.1.5")
        evidence = {
            "kind": "model_advised_assisted_compatibility_variant",
            "advice_evidence": "vampi-setup-advice.json",
            "call_id": advice["call_id"],
            "change": expected,
            "original_requirements": original.decode(),
            "modified_requirements": files["requirements.txt"].decode(),
            "original_requirements_sha256": digest(original),
            "modified_requirements_sha256": digest(files["requirements.txt"]),
            "scope": "Compatibility experiment only; not a security fix or original-source onboarding success",
        }
        save(OUTPUT / "evidence" / "U01-compatibility-input.json", evidence)
        changes.append(
            "Applied the source-bound GLM proposal MarkupSafe 2.1.2 -> 2.1.5; see evidence/U01-compatibility-input.json"
        )
    if repo_id == "U01":
        # Existing application imports a connexion.App from config.py, not a direct Flask constructor.
        files["colossus-app.json"] = json.dumps(
            {
                "recipe_id": "declared-python-v1",
                "command": ["python", "_submission_start.py"],
                "port": 5000,
                "test_profile_ids": ["http-readiness-v1"],
                "limitations": ["Assisted entrypoint selection for existing Connexion application"],
            }
        ).encode()
        files["_submission_start.py"] = b"""import os,sys,shutil,runpy
shutil.copytree('/app','/work/application',ignore=shutil.ignore_patterns('vendor'))
os.chdir('/work/application')
sys.path[:0]=['/work/application','/app/vendor']
import flask
original=flask.Flask.run
def run(self,*args,**kwargs):
 return original(self,host='0.0.0.0',port=5000,debug=False,use_reloader=False,use_debugger=False,threaded=False)
flask.Flask.run=run
runpy.run_path('app.py',run_name='__main__')
"""
        changes.append(
            "Evaluator supplied a bounded Connexion startup recipe; application source logic preserved; separately recorded compatibility pin retained"
            if compatibility
            else "Evaluator supplied a bounded Connexion startup recipe; source logic and dependency pins unchanged"
        )
    elif repo_id == "U06":
        nested = {
            name.removeprefix("Tiredful-API/"): data
            for name, data in files.items()
            if name.startswith("Tiredful-API/")
        }
        nested["requirements.txt"] = files["requirements.txt"]
        files = nested
        changes.append(
            "Evaluator selected Tiredful-API/ and carried root requirements into that view; dependency pins unchanged"
        )
    elif repo_id == "U09":
        prefix = "challenge/labs/bopla_lab/"
        files = {
            name.removeprefix(prefix): data
            for name, data in files.items()
            if name.startswith(prefix)
        }
        changes.append(
            "Evaluator selected challenge/labs/bopla_lab/; this is one lab, not the full PyGoat application"
        )
    else:
        return source, []
    return source | {
        "files": {name: base64.b64encode(data).decode() for name, data in files.items()},
        "tree_sha256": tree_hash(files),
    }, changes


class BudgetedLauncher:
    def __init__(self, client, seconds):
        self.client, self.seconds = client, seconds

    async def call(self, path, payload=None):
        if path == "/dependencies":
            payload = payload | {"timeout": min(45, self.seconds)}
        return await self.client.call(path, payload)


class CachedSource:
    def __init__(self, value):
        self.value = value

    async def call(self, path, body):
        assert path == "/source"
        return self.value


async def runtime(ids, seconds, assisted=False, compatibility=False):
    # Imported here: intake needs no Docker and no service/credential initialization.
    import tempfile

    from colossus.control.artifacts import ArtifactStore
    from colossus.control.config import Settings
    from colossus.control.cycle import CycleEngine
    from colossus.control.service import Controller
    from colossus.control.services import ServiceSupervisor
    from colossus.control.store import Store
    from colossus.onboarding.service import Onboarding

    with tempfile.TemporaryDirectory(prefix="colossus-catalog-") as directory:
        settings = Settings(data_dir=Path(directory))
        settings.prepare()
        services = ServiceSupervisor(settings)
        state = Store(settings.data_dir / "state.sqlite3")
        artifacts = ArtifactStore(settings.data_dir / "artifacts")
        controller = Controller(state, settings.runtime)
        try:
            await services.start()
            for repo_id in ids:
                path = OUTPUT / f"{repo_id}.json"
                row = json.loads(path.read_text())
                if row["source"]["status"] != "accepted":
                    row["setup"] = {
                        "status": "not_run",
                        "reason": "Source intake rejected; execution boundary not bypassed",
                    }
                    save(path, row)
                    continue
                source = json.loads((CACHE / f"{repo_id}.json").read_text())
                if (
                    source["commit"] != row["source"]["commit"]
                    or source["tree_sha256"] != row["source"]["tree_sha256"]
                ):
                    raise ValueError("Cached source does not match the frozen campaign row")
                decoded = {
                    name: base64.b64decode(data, validate=True)
                    for name, data in source["files"].items()
                }
                if tree_hash(decoded) != source["tree_sha256"]:
                    raise ValueError("Cached source content hash mismatch")
                hints = []
                if assisted:
                    source, hints = prepare_assisted(repo_id, source, compatibility)
                if hints:
                    row["assisted_attempt"] = {
                        "changes": hints,
                        "source_tree_sha256": source["tree_sha256"],
                    }
                    row["automatic_discovery"] = row.get("discovery")
                try:
                    discover(
                        {name: base64.b64decode(data) for name, data in source["files"].items()}
                    )
                except DomainError as exc:
                    row["setup"] = {
                        "status": "unsupported",
                        "reason_code": exc.code,
                        "reason": exc.message,
                    }
                    row["tests"] = {"status": "not_run", "reason": "No supported runtime recipe"}
                    save(path, row)
                    continue
                if repo_id == "U03":
                    row["setup"] = {
                        "status": "not_run",
                        "reason": "DSVW full-cycle run is owned by the integration agent; earlier evidence remains separate",
                    }
                    save(path, row)
                    continue
                receipt = controller.enroll(
                    Enrollment(
                        repo_url=row["repo_url"],
                        requested_ref=row["source"]["commit"],
                        subdir=row.get("subdir"),
                    ),
                    new_id(),
                    "submission-preflight",
                )
                project_id = receipt["resource_ids"]["project_id"]
                attempt_number = len(row.get("runtime_attempts", [])) + 1
                evidence_name = f"{repo_id}-attempt-{attempt_number}-manifest.json"
                onboarding = Onboarding(
                    state,
                    artifacts,
                    CachedSource(source),
                    BudgetedLauncher(services.clients["launcher"], seconds),
                )
                started = time.monotonic()
                stage = "setup"
                try:
                    async with asyncio.timeout(seconds):
                        await onboarding.run(project_id)
                        project = state.get("project", project_id)
                        target = project["mirror"]
                        row["setup"] = {
                            "status": "ready",
                            "artifact_digest": target["artifact_digest"],
                            "recipe_id": target["recipe"]["recipe_id"],
                            "project_id": project_id,
                        }
                        stage = "tests"
                        checks = []
                        cases = [("/", 200), ("/", 200)]
                        if repo_id == "U01" and compatibility:
                            cases = [
                                ("/", 200),
                                ("/createdb", 200),
                                ("/users/v1", 200),
                                ("/books/v1", 200),
                                ("/books/v1/submission-missing", 401),
                                ("/missing-submission-route", 404),
                            ]
                        if repo_id == "U09" and assisted:
                            cases = [
                                ("/", 200),
                                ("/health", 200),
                                ("/login", 200),
                                ("/dashboard", 302),
                                ("/api/project/1/details", 401),
                                ("/api/project/1/safe", 401),
                                ("/missing-submission-route", 404),
                            ]
                        for test_path, expected_status in cases:
                            response = await services.clients["launcher"].call(
                                "/targets/request",
                                {
                                    "project_id": project_id,
                                    "environment_id": target["environment_id"],
                                    "port": target["port"],
                                    "path": test_path,
                                },
                            )
                            checks.append(
                                {
                                    "path": test_path,
                                    "status": response.get("status"),
                                    "body_sha256": digest(response.get("body", "").encode()),
                                    "expected_status": expected_status,
                                    "passed": response.get("status") == expected_status,
                                }
                            )
                        row["tests"] = {
                            "status": "readiness_only",
                            "checks": checks,
                            "outcome": "pass" if all(c["passed"] for c in checks) else "fail",
                            "passed": sum(c["passed"] for c in checks),
                            "total": len(checks),
                            "functional_suite": "UNSUPPORTED: no protected application oracle registered",
                            "security_suite": "UNSUPPORTED: no bounded target-specific reproduction registered",
                            "command": "launcher /targets/request GET / twice on isolated target",
                        }
                        if repo_id == "U09" and assisted:
                            row["tests"].update(
                                status="bounded_http_checks",
                                functional_suite="GET home/health/login; dashboard redirects before login; unknown route 404",
                                security_suite="Two project APIs deny unauthenticated reads (401); no authenticated property-disclosure test",
                                command="launcher /targets/request for seven fixed GET paths on the frozen BOPLA lab artifact",
                            )
                        if repo_id == "U01" and compatibility:
                            row["tests"].update(
                                status="bounded_http_checks",
                                functional_suite="Home, synthetic database initialization, user list, book list and unknown-route checks",
                                security_suite="Book detail rejects unauthenticated access (401); no authenticated BOLA or SQLi repair claim",
                                command="launcher /targets/request for six fixed local GET paths; /createdb resets only disposable lab data",
                            )
                        manifest = json.loads(artifacts.get(project["source"]["manifest_hash"]))
                        save(OUTPUT / "evidence" / evidence_name, manifest)
                        row["manifest_evidence"] = f"evidence/{evidence_name}"
                        bundle = json.loads(artifacts.get(project["source"]["source_id"]))
                        if bundle.get("dependency_evidence_id"):
                            dependencies = json.loads(
                                artifacts.get(bundle["dependency_evidence_id"])
                            )
                            dependency_name = (
                                f"{repo_id}-attempt-{attempt_number}-dependencies.json"
                            )
                            save(OUTPUT / "evidence" / dependency_name, dependencies)
                            row["dependency_evidence"] = f"evidence/{dependency_name}"
                        row["dependency_inventory"] = json.loads(
                            artifacts.get(manifest["dependency_inventory_hash"])
                        )
                        stage = "investigation_cycle"
                        cycle_receipt = controller.run(
                            project_id, new_id(), "submission-preflight", tier="T0"
                        )
                        cycle_id = cycle_receipt["resource_ids"]["cycle_id"]
                        cycle = await CycleEngine(
                            state,
                            artifacts,
                            services.clients["launcher"],
                            None,
                            onboarding,
                            settings.runtime,
                        ).run(cycle_id)
                        row["investigation_cycle"] = cycle
                        save(
                            OUTPUT / "evidence" / f"{repo_id}-attempt-{attempt_number}-cycle.json",
                            cycle,
                        )
                        row["full_cycle"] = {
                            "status": "unsupported",
                            "reason": "No approved repair/security oracle for generic runtime profile; no patch or promotion attempted",
                        }
                except DomainError as exc:
                    row[stage] = {
                        "status": "failed",
                        "reason_code": exc.code,
                        "reason": exc.message,
                    }
                    if stage == "setup":
                        row["tests"] = {
                            "status": "not_run",
                            "reason": "Application setup did not become ready",
                        }
                except TimeoutError:
                    row[stage] = {
                        "status": "timeout",
                        "reason": f"Per-repository runtime budget {seconds}s exceeded during {stage}",
                    }
                    if stage == "setup":
                        row["tests"] = {"status": "not_run", "reason": "Setup exceeded budget"}
                finally:
                    row["runtime_seconds"] = round(time.monotonic() - started, 3)
                    try:
                        await services.clients["launcher"].call(
                            "/terminate-work", {"project_id": project_id, "keep": []}
                        )
                        row["cleanup"] = "completed"
                    except DomainError as exc:
                        row["cleanup"] = exc.code
                    row["finished_at"] = utcnow()
                    audit_name = f"{repo_id}-attempt-{attempt_number}-audit.json"
                    save(
                        OUTPUT / "evidence" / audit_name,
                        {
                            "project_id": project_id,
                            "audit_chain_verified_in_original_store": state.verify_audit(),
                            "events": state.audit(project_id),
                        },
                    )
                    row["audit_evidence"] = f"evidence/{audit_name}"
                    row.setdefault("runtime_attempts", []).append(
                        {
                            "attempt": attempt_number,
                            "runner_sha256": digest(Path(__file__).read_bytes()),
                            "finished_at": row["finished_at"],
                            "seconds": row["runtime_seconds"],
                            "setup": row["setup"],
                            "tests": row["tests"],
                            "cleanup": row["cleanup"],
                            "assistance": hints,
                            "source_tree_sha256": source["tree_sha256"],
                            "manifest_evidence": row.get("manifest_evidence"),
                        }
                    )
                    save(path, row)
                    summarize()
                    print(
                        json.dumps(
                            {
                                "repo_id": repo_id,
                                "setup": row["setup"],
                                "runtime_seconds": row["runtime_seconds"],
                            }
                        ),
                        flush=True,
                    )
        finally:
            await services.stop()
            state.close()
    summarize()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["intake", "runtime", "summarize"])
    parser.add_argument("--ids", nargs="+", default=[item[0] for item in CATALOG])
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("--assisted", action="store_true")
    parser.add_argument("--vampi-compatible-wheels", action="store_true")
    args = parser.parse_args()
    if any(repo_id not in {item[0] for item in CATALOG} for repo_id in args.ids):
        parser.error("Unknown catalog ID")
    if not 1 <= args.seconds <= 180:
        parser.error("Runtime limit must be 1..180 seconds")
    if args.vampi_compatible_wheels and not args.assisted:
        parser.error("Compatibility variant requires explicit --assisted")
    if args.mode == "intake":
        asyncio.run(intake())
    elif args.mode == "runtime":
        asyncio.run(runtime(args.ids, args.seconds, args.assisted, args.vampi_compatible_wheels))
    else:
        summarize()
