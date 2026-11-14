"""Immutable source intake, isolated startup and positive readiness evidence."""

import asyncio
import base64
import time
from importlib.resources import files as resources

from colossus.contracts.core import DomainError, canonical_json, content_hash, new_id
from colossus.contracts.models import Enrollment, TargetManifest
from colossus.gateway.source import tree_hash
from colossus.onboarding.bundle import assembled_files
from colossus.onboarding.discovery import discover
from colossus.onboarding.plans import gate_untrusted_plans


class Onboarding:
    def __init__(self, store, artifacts, gateway, launcher):
        self.store, self.artifacts, self.gateway, self.launcher = (
            store,
            artifacts,
            gateway,
            launcher,
        )

    def update(self, project_id, **changes):
        with self.store.transaction() as db:
            import json

            row = db.execute(
                "SELECT data FROM records WHERE id=? AND kind='project'", (project_id,)
            ).fetchone()
            if row is None:
                raise DomainError("not_found", "Project not found", 404)
            project = json.loads(row[0])
            return self.store._put(
                db, "project", project_id, project | changes, project_id, project["revision"]
            )

    def evidence(self, project_id, value, *, visibility="internal"):
        key = self.artifacts.put(canonical_json(value))
        self.store.put(
            "artifact",
            content_hash({"project_id": project_id, "artifact_id": key}),
            {"artifact_id": key, "media_type": "application/json", "visibility": visibility},
            project_id,
        )
        return key

    async def run(self, project_id):
        project = self.update(project_id, setup_state="RESOLVING")
        request = Enrollment.model_validate({k: project[k] for k in Enrollment.model_fields})
        source = await self.gateway.call("/source", request.model_dump())
        files = {p: base64.b64decode(v, validate=True) for p, v in source["files"].items()}
        if tree_hash(files) != source["tree_sha256"]:
            raise DomainError(
                "source_hash_mismatch", "Source gateway returned inconsistent bytes", 503
            )
        gate_untrusted_plans(files)
        source_id = self.evidence(project_id, source)
        self.update(project_id, setup_state="DISCOVERING")
        recipe = discover(files)
        self.update(project_id, setup_state="BUILDING")
        runtime = {}
        dependencies = {
            "inventory": {
                "packages": [],
                "scope": "stdlib-only runtime",
                "omitted_optional_dependencies": ["lxml"]
                if recipe.recipe_id == "dsvw-python-v1"
                else [],
            }
        }
        if recipe.requirements:
            if any(p == "vendor" or p.startswith("vendor/") for p in files):
                raise DomainError(
                    "runtime_bundle_collision",
                    "Repository vendor directory requires an explicit dependency layout",
                    422,
                )
            dependencies = await self.launcher.call(
                "/dependencies", {"project_id": project_id, "requirements": recipe.requirements}
            )
            runtime = {
                path: base64.b64decode(data, validate=True)
                for path, data in dependencies.pop("files").items()
            }
        if recipe.runtime_mode != "direct":
            runtime["_colossus_runtime/start.py"] = (
                resources("colossus.onboarding").joinpath("runtime_start.py").read_bytes()
            )
        dependencies_id = self.evidence(project_id, dependencies)
        inventory_hash = self.evidence(project_id, dependencies["inventory"])
        intake_source_id = source_id
        source = source | {
            "runtime_files": {
                path: base64.b64encode(data).decode() for path, data in runtime.items()
            },
            "runtime_tree_sha256": tree_hash(runtime),
            "dependency_inventory_hash": inventory_hash,
            "dependency_evidence_id": dependencies_id,
        }
        source_id = self.evidence(project_id, source)
        package_files = assembled_files(files, runtime)
        image = await self.launcher.call(
            "/package",
            {
                "files": {
                    path: base64.b64encode(data).decode() for path, data in package_files.items()
                },
                "argv": recipe.command,
            },
        )
        if image["tree_sha256"] != tree_hash(package_files):
            raise DomainError(
                "package_hash_mismatch", "Packaged source differs from the resolved snapshot", 503
            )
        self.update(project_id, setup_state="STARTING")
        target = await self.launcher.call(
            "/targets", {"project_id": project_id, "artifact_digest": image["artifact_digest"]}
        )
        self.update(project_id, mirror=target | {"state": "STARTING"})
        try:
            deadline = time.monotonic() + 60
            while True:
                health = await self.launcher.call(
                    "/targets/request",
                    {
                        "project_id": project_id,
                        "environment_id": target["environment_id"],
                        "port": recipe.port,
                        "path": recipe.health_path,
                    },
                )
                if health.get("status") == recipe.expected_status and (
                    recipe.required_body is None or recipe.required_body in health.get("body", "")
                ):
                    break
                if time.monotonic() >= deadline:
                    raise DomainError(
                        "readiness_failed",
                        "Application did not pass its positive readiness probe",
                        503,
                    )
                await asyncio.sleep(1)
            evidence_id = self.evidence(
                project_id, {"health": health, "recipe": recipe.model_dump(), "image": image}
            )
            tool_hash = self.evidence(
                project_id,
                {"base": image["base_digest"], "launcher": await self.launcher.call("/health")},
            )
            manifest = TargetManifest(
                manifest_id=new_id(),
                revision=1,
                project_id=project_id,
                repo_url=project["repo_url"],
                commit=source["commit"],
                tree_sha256=source["tree_sha256"],
                platform=image["platform"],
                target_kind="web",
                recipe_id=recipe.recipe_id,
                recipe_hash=content_hash(recipe.model_dump()),
                artifact_digest=image["artifact_digest"],
                services=[
                    {
                        "service_id": "app",
                        "artifact_digest": image["artifact_digest"],
                        "command_profile_id": recipe.recipe_id,
                        "internal_ports": [recipe.port],
                        "health_check_id": recipe.recipe_id + ":health",
                    }
                ],
                dependency_inventory_id=inventory_hash,
                dependency_inventory_hash=inventory_hash,
                test_profile_ids=recipe.test_profile_ids,
                readiness_profile_id=recipe.recipe_id + ":health",
                data_seed_id="repository-default-v1",
                protected_paths=["colossus-app.json", *recipe.dependency_inputs],
                allowed_patch_paths=[p for p in files if p.endswith(".py")],
                deployment_profile_id=project["deployment_profile_id"],
                policy_hash=content_hash({"policy_id": project["owner_policy_id"]}),
                toolchain_manifest_id=tool_hash,
                setup_provenance=[
                    {
                        "source_id": source_id,
                        "intake_source_id": intake_source_id,
                        "dependency_evidence_id": dependencies_id,
                        "runtime_tree_sha256": source["runtime_tree_sha256"],
                        "readiness_evidence_id": evidence_id,
                        "limitations": recipe.limitations,
                    }
                ],
            )
            manifest_hash = self.evidence(project_id, manifest.model_dump())
            self.store.put("manifest", manifest.manifest_id, manifest.model_dump(), project_id)
            self.update(
                project_id,
                setup_state="READY",
                source={
                    "commit": source["commit"],
                    "tree_sha256": source["tree_sha256"],
                    "source_id": source_id,
                    "manifest_hash": manifest_hash,
                    "manifest_id": manifest.manifest_id,
                },
                mirror=target
                | {
                    "state": "READY",
                    "port": recipe.port,
                    "recipe": recipe.model_dump(),
                    "readiness_evidence_id": evidence_id,
                },
                reason=None,
                reason_code=None,
            )
            return {"manifest_hash": manifest_hash, "readiness_evidence_id": evidence_id}
        except BaseException:
            await self.launcher.call(
                "/targets/stop",
                {k: target[k] for k in ("project_id", "environment_id", "network_id")},
            )
            self.update(project_id, mirror={"state": "STOPPED"})
            raise
