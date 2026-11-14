"""Calibrate a compiled policy fixture; does not run any additional target repo."""

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from colossus.contracts.core import new_id
from colossus.sandbox.launcher import SandboxLauncher
from colossus.verification.dafny import (
    CORRECT_POLICY,
    POLICY_CALIBRATION,
    DafnyAdapter,
    compiled_binding,
)


def main():
    root = Path(__file__).resolve().parents[1]
    directory = root / "artifacts/bootstrap"
    manifest = json.loads((directory / "formal-toolchain.json").read_text())
    adapter = DafnyAdapter(SandboxLauncher(), manifest["image_digest"])
    cases = {}
    compiled_files = {}
    for name, expressions in {
        "valid": CORRECT_POLICY,
        "allow_everyone": CORRECT_POLICY | {"password": "true"},
        "deny_everyone": CORRECT_POLICY | {"password": "false"},
        "public_admin": CORRECT_POLICY | {"role": "requestedAdmin"},
        "secret_projection": CORRECT_POLICY | {"projection": "Public(username, password)"},
    }.items():
        result = adapter.execute(new_id(), POLICY_CALIBRATION, expressions)
        files = result.pop("files")
        if name == "valid":
            compiled_files = {
                path: data for path, data in files.items() if path.startswith("policy-py/")
            }
        target = directory / "formal" / name
        target.mkdir(parents=True, exist_ok=True)
        for path, data in files.items():
            output = target / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        result["file_hashes"] = {
            path: hashlib.sha256(data).hexdigest() for path, data in files.items()
        }
        cases[name] = result
        print(name, result["proof_outcome"], "compiled", result["compiled"], flush=True)
    report = {
        "kind": "owned_policy_toolchain_calibration",
        "target_repositories_run": [],
        "cases": cases,
    }
    (directory / "formal.json").write_text(json.dumps(report, indent=2) + "\n")
    assert cases["valid"]["proof_outcome"] == "PROVED" and cases["valid"]["compiled"]
    assert all(cases[name]["proof_outcome"] != "PROVED" for name in cases if name != "valid")
    hashes = {path: hashlib.sha256(data).hexdigest() for path, data in compiled_files.items()}
    assert compiled_binding(compiled_files, hashes)
    assert not compiled_binding(compiled_files | {"policy-py/Policy.py": b"# replaced"}, hashes)
    assert not compiled_binding(
        {p: d for p, d in compiled_files.items() if p != "policy-py/Policy.py"}, hashes
    )
    wrapper = (root / "fixtures/formal/policy_wrapper.py").read_bytes()
    harness = (root / "fixtures/formal/check_wrapper.py").read_bytes()
    wrapper_results = {}
    for name, implementation in {
        "valid": wrapper,
        "bypass_decision": wrapper.replace(b"if not decision:", b"if False:"),
    }.items():
        inputs = compiled_files | {"policy_wrapper.py": implementation, "check_wrapper.py": harness}
        assert compiled_binding(inputs, hashes)
        image = adapter.launcher.package(inputs, ["python", "-c", "import time;time.sleep(300)"])
        env = adapter.launcher.create(
            new_id(), "verify", image=image["artifact_digest"], application=True, ttl_seconds=90
        )
        try:
            result = adapter.launcher.execute(
                env, ["python", "-I", "/app/check_wrapper.py"], 30, workdir="/work"
            )
            wrapper_results[name] = {"artifact": image, "execution": asdict(result)}
            assert not result.timed_out
            assert (result.exit_code == 0) == (name == "valid")
        finally:
            adapter.launcher.destroy(env)
    report["packaged_wrapper_checks"] = wrapper_results
    report["generated_file_substitution_rejected"] = True
    report["generated_file_omission_rejected"] = True
    (directory / "formal.json").write_text(json.dumps(report, indent=2) + "\n")
    print("packaged wrapper passed; bypass and generated-file substitution rejected")


if __name__ == "__main__":
    main()
