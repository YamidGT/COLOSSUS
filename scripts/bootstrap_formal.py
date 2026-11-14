"""Build trusted compiler infrastructure, never an enrolled repository recipe."""

import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path

import httpx

from colossus.sandbox.launcher import SandboxLauncher

SOURCE = "fcb2042d6d043a2634f0854338c08feeaaaf4ae2"
SOURCE_HASH = "94eeeb23d6b11b2cbbdb438d22524ec76dd144fd418f50065f87a30f053757b0"
WHEEL_URL = "https://files.pythonhosted.org/packages/0e/8c/9058d3998fdc2148f3e6d3497e949d5dfc77c66b1cc1cb461554c0bba954/z3_solver-4.13.0.0-py2.py3-none-manylinux2014_aarch64.whl"
WHEEL_HASH = "9d622022a3511c059915c56b2c231c84b5c1be1b82f457d7560dda3d916474fe"


def download(url: str, expected: str) -> bytes:
    response = httpx.get(url, follow_redirects=True, timeout=120)
    response.raise_for_status()
    data = response.content
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Toolchain input digest mismatch")
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", default="colima-colossus")
    args = parser.parse_args()
    launcher = SandboxLauncher(args.context)
    host = launcher.preflight()
    if not host["ready"] or host.get("architecture") not in {"aarch64", "arm64"}:
        raise SystemExit("This locked toolchain bootstrap requires a ready ARM64 lab host")
    root = Path(__file__).resolve().parents[1]
    inputs = {
        "Dockerfile": (root / "tools/formal/Dockerfile").read_bytes(),
        "dafny": (root / "tools/formal/dafny").read_bytes(),
        "dafny-source.tar.gz": download(
            f"https://codeload.github.com/dafny-lang/dafny/tar.gz/{SOURCE}", SOURCE_HASH
        ),
        "z3.whl": download(WHEEL_URL, WHEEL_HASH),
    }
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for name, data in inputs.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
            tar.addfile(entry, io.BytesIO(data))
    result = launcher.docker(
        "build",
        "--progress=plain",
        "-t",
        "colossus-toolchain:dafny-4.11.0-arm64",
        "-",
        stdin=archive.getvalue(),
        timeout=1200,
    )
    logs = root / "artifacts/bootstrap"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "formal-build.log").write_text(result.stdout + result.stderr)
    if result.exit_code or result.timed_out:
        raise SystemExit("Toolchain build failed; inspect artifacts/bootstrap/formal-build.log")
    digest = launcher.checked(
        "image", "inspect", "colossus-toolchain:dafny-4.11.0-arm64", "--format", "{{.Id}}"
    )
    manifest = {
        "image_digest": digest,
        "dafny_commit": SOURCE,
        "dafny_source_release": "4.11.0",
        "solver_version": "4.13.0",
        "architecture": host["architecture"],
        "inputs": {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()},
        "solver_note": "ARM64 4.13.0 calibration; differs from Dafny default Z3 4.12.1",
    }
    environment = launcher.create("formal-toolchain-bootstrap", "verify", image=digest)
    try:
        versions = launcher.execute(
            environment,
            [
                "python",
                "-I",
                "-c",
                "import subprocess,json; print(json.dumps({name:subprocess.check_output([name,'--version'],text=True).strip() for name in ['dafny','z3']}))",
            ],
            30,
            workdir="/work",
        )
        if versions.exit_code or versions.timed_out:
            raise SystemExit("Toolchain cannot run inside gVisor")
        manifest["observed_versions"] = json.loads(versions.stdout)
    finally:
        launcher.destroy(environment)
    (logs / "formal-toolchain.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
