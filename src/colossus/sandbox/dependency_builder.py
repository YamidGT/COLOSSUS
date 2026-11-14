"""Isolated pip installation through a credential-free fixed-origin registry."""

import ipaddress
import json
import socket
from dataclasses import asdict
from importlib.resources import files as resources
from urllib.parse import urlsplit

from packaging.utils import canonicalize_name

from colossus.contracts.core import DomainError, new_id
from colossus.onboarding.dependencies import validate_requirements
from colossus.sandbox.launcher import LABEL
from colossus.sandbox.registry_proxy import FILE


def registry_origins():
    origins = {}
    for host in ("pypi.org", "files.pythonhosted.org"):
        addresses = sorted(
            {
                record[4][0]
                for record in socket.getaddrinfo(
                    host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
                )
            }
        )
        if not addresses or any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise DomainError(
                "registry_resolution", "Registry did not resolve to public addresses", 503
            )
        origins[host] = addresses
    return origins


INVENTORY = """import importlib.metadata,json,platform,sys
from pathlib import Path
packages=sorted([{'ecosystem':'PyPI','name':d.metadata['Name'],'version':d.version} for d in importlib.metadata.distributions(path=['/work/results/vendor'])],key=lambda d:d['name'].lower())
Path('/work/results/inventory.json').write_text(json.dumps({'packages':packages,'scope':'installed wheel inventory','python':sys.version,'machine':platform.machine()}))
"""


def build_dependencies(launcher, project_id: str, requirements: list[str], timeout=600):
    requirements = validate_requirements(requirements)
    if not requirements:
        return {
            "files": {},
            "inventory": {"packages": [], "scope": "stdlib-only runtime"},
            "report": {},
            "logs": {},
            "network": "none",
        }
    if not 1 <= timeout <= 1200:
        raise DomainError("dependency_limit", "Build timeout exceeds the setup budget", 422)
    with launcher._lock:
        private = launcher.network(project_id)
        egress = "colossus-egress-" + new_id()
        proxy = builder = None
        egress_created = False
        try:
            launcher.checked(
                "network",
                "create",
                "--label",
                LABEL + "=true",
                "--label",
                "org.colossus.project=" + project_id,
                egress,
            )
            egress_created = True
            proxy_image = launcher.package(
                {
                    "registry_proxy.py": resources("colossus.sandbox")
                    .joinpath("registry_proxy.py")
                    .read_bytes(),
                    "origins.json": json.dumps(registry_origins()).encode(),
                },
                ["python", "-I", "/app/registry_proxy.py"],
            )
            proxy = launcher.create(
                project_id,
                "registry",
                private,
                memory_mb=512,
                ttl_seconds=timeout + 120,
                image=proxy_image["artifact_digest"],
                application=True,
                start=False,
            )
            launcher.checked("network", "connect", egress, proxy)
            launcher.checked("start", proxy)
            address = launcher.inspect(proxy)["NetworkSettings"]["Networks"][private]["IPAddress"]
            builder = launcher.create(
                project_id, "build", private, memory_mb=2048, ttl_seconds=timeout + 120
            )
            launcher.copy_source(
                builder, {"requirements.txt": ("\n".join(requirements) + "\n").encode()}
            )
            launcher.execute(builder, ["mkdir", "-p", "/work/results"], 10)
            argv = [
                "python",
                "-I",
                "-m",
                "pip",
                "--isolated",
                "install",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-compile",
                "--only-binary=:all:",
                "--ignore-installed",
                "--index-url",
                f"http://{address}:8080/simple/",
                "--trusted-host",
                address,
                "--target",
                "/work/results/vendor",
                "--report",
                "/work/results/install-report.json",
                "-r",
                "requirements.txt",
            ]
            result = launcher.execute(builder, argv, timeout)
            if result.exit_code or result.timed_out or result.truncated:
                raise DomainError(
                    "dependency_build_failed",
                    "Isolated wheel install failed: "
                    + result.stderr[-1500:]
                    + "\n"
                    + result.stdout[-500:],
                    422,
                )
            inventory_result = launcher.execute(builder, ["python", "-I", "-c", INVENTORY], 30)
            if inventory_result.exit_code or inventory_result.timed_out:
                raise DomainError(
                    "dependency_inventory_failed", "Installed dependency inventory failed", 503
                )
            # Shut off registry access before accepting any exported dependency result.
            launcher.destroy(proxy)
            proxy = None
            exported = launcher.export_files(builder, "/work/results", max_bytes=100 * 1024 * 1024)
            inventory = json.loads(exported.pop("inventory.json"))
            report = json.loads(exported.pop("install-report.json"))
            installed = {
                (canonicalize_name(p["name"]), p["version"]) for p in inventory["packages"]
            }
            declared = {
                (canonicalize_name(p["metadata"]["name"]), p["metadata"]["version"])
                for p in report["install"]
            }
            if (
                installed != declared
                or len(installed) > 100
                or len(installed) != len(inventory["packages"])
                or len(declared) != len(report["install"])
            ):
                raise DomainError(
                    "dependency_inventory_mismatch",
                    "Installed packages differ from installer evidence",
                    422,
                )
            vendor = {path: data for path, data in exported.items() if path.startswith("vendor/")}
            for distribution in report["install"]:
                download = distribution.get("download_info", {})
                url = urlsplit(download.get("url", ""))
                path = url.path.removeprefix("/files")
                if (
                    url.scheme != "http"
                    or url.netloc != f"{address}:8080"
                    or url.query
                    or not FILE.fullmatch(path)
                    or not path.endswith(".whl")
                    or not download.get("archive_info", {}).get("hashes", {}).get("sha256")
                ):
                    raise DomainError(
                        "dependency_origin_mismatch",
                        "Installed input did not originate from the fixed wheel registry",
                        422,
                    )
                distribution["registry_origin_url"] = "https://files.pythonhosted.org" + path
            if installed and not vendor:
                raise DomainError(
                    "dependency_inventory_failed",
                    "No installed dependency files were exported",
                    422,
                )
            return {
                "files": vendor,
                "inventory": inventory,
                "report": report,
                "logs": asdict(result),
                "network": "fixed-origin-pypi-wheel-proxy-v1",
                "proxy_artifact": proxy_image["artifact_digest"],
                "requirements": requirements,
            }
        finally:
            for environment in (builder, proxy):
                if environment:
                    launcher.destroy(environment)
            launcher.destroy_network(private, project_id)
            if egress_created:
                launcher.destroy_network(egress, project_id)
