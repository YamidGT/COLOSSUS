"""Exercise fresh GLM synthesis and the existing compiled-policy fixture in isolation."""

import asyncio
import base64
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from colossus.contracts.core import content_hash, new_id
from colossus.control.artifacts import ArtifactStore
from colossus.control.broker import Broker
from colossus.control.config import Settings
from colossus.control.services import ServiceSupervisor
from colossus.control.store import Store
from colossus.sandbox.launcher import SandboxLauncher
from colossus.verification.agent import verify_with_model
from colossus.verification.dafny import POLICY_CALIBRATION, compiled_binding


async def main():
    root = Path(__file__).resolve().parents[1]
    image = json.loads((root / "artifacts/bootstrap/formal-toolchain.json").read_text())[
        "image_digest"
    ]
    settings = Settings.from_environment().model_copy(update={"formal_toolchain_digest": image})
    settings.prepare()
    services = ServiceSupervisor(settings)
    store = Store(settings.data_dir / "state.sqlite3")
    artifacts = ArtifactStore(settings.data_dir / "artifacts")
    project_id, case_id = new_id(), new_id()
    try:
        await services.start()
        broker = Broker(store, artifacts, services.clients["gateway"], settings.runtime)
        launcher = services.clients["launcher"]
        report = await verify_with_model(
            broker,
            launcher,
            project_id=project_id,
            case_id=case_id,
            profile_id=POLICY_CALIBRATION.profile_id,
            component_hash=content_hash({"fixture": "owned-policy-v1"}),
        )
        report.update(
            kind="fresh_model_owned_formal_fixture",
            project_id=project_id,
            case_id=case_id,
            target_repositories_run=[],
            cost=store.budget(case_id),
        )
        if report["proof_outcome"] == "PROVED":
            outputs = report["verification"].pop("files")
            generated = {
                p: base64.b64decode(b, validate=True)
                for p, b in outputs.items()
                if p.startswith("policy-py/")
            }
            hashes = {p: hashlib.sha256(b).hexdigest() for p, b in generated.items()}
            assert compiled_binding(generated, hashes)
            wrapper = (root / "fixtures/formal/policy_wrapper.py").read_bytes()
            harness = (root / "fixtures/formal/check_wrapper.py").read_bytes()
            checks = {}
            for name, implementation in {
                "valid": wrapper,
                "bypass_decision": wrapper.replace(b"if not decision:", b"if False:"),
            }.items():
                inputs = generated | {
                    "policy_wrapper.py": implementation,
                    "check_wrapper.py": harness,
                }
                sandbox = SandboxLauncher(settings.docker_context, settings.sandbox_runtime)
                image = sandbox.package(inputs, ["python", "-c", "import time;time.sleep(90)"])
                env = sandbox.create(
                    project_id,
                    "verify",
                    image=image["artifact_digest"],
                    application=True,
                    ttl_seconds=90,
                )
                try:
                    checks[name] = asdict(
                        sandbox.execute(
                            env, ["python", "-I", "/app/check_wrapper.py"], 30, workdir="/work"
                        )
                    )
                finally:
                    sandbox.destroy(env)
            report["wrapper_checks"] = checks
            report["generated_hashes"] = hashes
            report["generated_file_substitution_rejected"] = not compiled_binding(
                generated | {"policy-py/Policy.py": b"# changed"}, hashes
            )
            report["fixture_runtime_linkage"] = bool(
                checks["valid"]["exit_code"] == 0
                and checks["bypass_decision"]["exit_code"] != 0
                and report["generated_file_substitution_rejected"]
            )
        report["audit_valid"] = store.verify_audit()
        target = root / "evaluation/submission/formal-agent.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2) + "\n")
        print(
            json.dumps(
                {
                    k: report.get(k)
                    for k in [
                        "proof_outcome",
                        "target_proof_outcome",
                        "fixture_runtime_linkage",
                        "elapsed_seconds",
                        "cost",
                        "reason",
                    ]
                },
                indent=2,
            ),
            flush=True,
        )
        assert report["proof_outcome"] == "PROVED" and report.get("fixture_runtime_linkage"), (
            "Formal calibration did not pass; inspect retained report"
        )
    finally:
        await services.stop()
        store.close()


asyncio.run(main())
