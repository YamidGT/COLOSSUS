"""Read repository configuration as data; never import it to detect a stack."""

import ast
import json
from typing import Literal

from pydantic import Field

from colossus.contracts.core import Contract, DomainError, safe_relative_path
from colossus.onboarding.dependencies import requirements_from_source


class Recipe(Contract):
    recipe_id: str
    command: list[str] = Field(min_length=2, max_length=100)
    port: int = Field(ge=1, le=65535)
    health_path: str = Field(default="/", max_length=2048, pattern=r"^/[A-Za-z0-9_/.-]*$")
    expected_status: int = 200
    required_body: str | None = None
    test_profile_ids: list[str]
    limitations: list[str]
    requirements: list[str] = Field(default_factory=list)
    dependency_inputs: list[str] = Field(default_factory=list)
    runtime_mode: Literal["direct", "flask-script", "bottle-script", "wsgi", "django"] = "direct"


def discover(files: dict[str, bytes]) -> Recipe:
    if any(p.startswith("_colossus_runtime/") or p == "_colossus_runtime" for p in files):
        raise DomainError(
            "reserved_source_path", "Repository collides with trusted runtime files", 422
        )
    if (
        "dsvw.py" in files
        and b"class ReqHandler(" in files["dsvw.py"]
        and b"--host=" in files["dsvw.py"]
    ):
        return Recipe(
            recipe_id="dsvw-python-v1",
            command=["python", "dsvw.py", "--host=0.0.0.0", "--port=65412"],
            port=65412,
            required_body="Damn Small Vulnerable Web",
            test_profile_ids=["dsvw-functional-v1", "dsvw-security-v1"],
            limitations=[
                "Optional lxml is absent: XML/XPath routes are excluded from this runtime profile"
            ],
        )
    # A caller-supplied application manifest is data, not a Dockerfile or shell script.
    if "colossus-app.json" in files:
        try:
            recipe = Recipe.model_validate_json(files["colossus-app.json"])
        except ValueError:
            raise DomainError(
                "needs_configuration", "colossus-app.json does not match the recipe schema", 422
            ) from None
        if recipe.command[:1] != ["python"] or len(recipe.command) < 2:
            raise DomainError(
                "unsupported_stack", "This template requires a Python entrypoint", 422
            )
        if safe_relative_path(recipe.command[1]) not in files or not 1 <= recipe.port <= 65535:
            raise DomainError(
                "needs_configuration", "Recipe entrypoint or internal port is invalid", 422
            )
        if (
            recipe.recipe_id != "declared-python-v1"
            or recipe.test_profile_ids != ["http-readiness-v1"]
            or recipe.runtime_mode != "direct"
        ):
            raise DomainError(
                "recipe_policy",
                "Declared recipes cannot select trusted security or runtime profiles",
                422,
            )
        requirements, inputs = requirements_from_source(files)
        return recipe.model_copy(update={"requirements": requirements, "dependency_inputs": inputs})
    requirements, inputs = requirements_from_source(files)
    candidates = []
    for path, data in sorted(files.items()):
        if (
            not path.endswith(".py")
            or set(path.split("/")) & {"tests", "test", ".venv", "vendor", "node_modules"}
            or len(data) > 512 * 1024
        ):
            continue
        try:
            tree = ast.parse(data)
        except (SyntaxError, ValueError, RecursionError):
            continue
        imports = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module in {"flask", "bottle"}:
                for alias in node.names:
                    imports[alias.asname or alias.name] = (node.module, alias.name)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"flask", "bottle"}:
                        imports[alias.asname or alias.name] = (alias.name, None)
        for node in tree.body:
            if (
                not isinstance(node, ast.Assign)
                or len(node.targets) != 1
                or not isinstance(node.targets[0], ast.Name)
                or not isinstance(node.value, ast.Call)
            ):
                continue
            function = node.value.func
            resolved = (
                imports.get(function.id)
                if isinstance(function, ast.Name)
                else (imports.get(function.value.id, (None, None))[0], function.attr)
                if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name)
                else None
            )
            if resolved not in {("flask", "Flask"), ("bottle", "Bottle")}:
                continue
            variable = node.targets[0].id
            script = any(
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "run"
                and isinstance(child.func.value, ast.Name)
                and child.func.value.id == variable
                for statement in tree.body
                if isinstance(statement, ast.If)
                for child in ast.walk(statement)
            )
            mode = resolved[0] + "-script" if script else "wsgi"
            candidates.append((path, variable, mode, resolved[0]))
    if len(candidates) > 1:
        raise DomainError(
            "needs_configuration",
            "Multiple Python applications found; select a subdirectory or provide an explicit recipe",
            422,
        )
    if candidates:
        entry, variable, mode, framework = candidates[0]
        return Recipe(
            recipe_id="python-" + framework + "-v1",
            command=["python", "-I", "/app/_colossus_runtime/start.py", mode, entry, variable],
            port=5000,
            test_profile_ids=["http-readiness-v1"],
            limitations=[
                "Generic readiness is not a protected security or functional oracle",
                "Synthetic data lives in a disposable scratch copy of the source",
            ],
            requirements=requirements or [framework],
            dependency_inputs=inputs,
            runtime_mode=mode,
        )
    if "manage.py" in files and b"DJANGO_SETTINGS_MODULE" in files["manage.py"]:
        return Recipe(
            recipe_id="python-django-v1",
            command=["python", "-I", "/app/_colossus_runtime/start.py", "django", "manage.py", ""],
            port=8000,
            test_profile_ids=["http-readiness-v1"],
            limitations=[
                "Requires configured local database settings; external services are not mocked",
                "Runs migrations against disposable data; no production credentials",
            ],
            requirements=requirements or ["Django"],
            dependency_inputs=inputs,
            runtime_mode="django",
        )
    # Identify why setup cannot yet execute instead of guessing or running a repo Dockerfile.
    dependencies = any(p in files for p in ("requirements.txt", "pyproject.toml", "Pipfile"))
    if dependencies:
        raise DomainError(
            "unsupported_stack",
            "Python dependencies found but no supported application entrypoint was identified",
            422,
        )
    if "package.json" in files:
        try:
            json.loads(files["package.json"])
        except ValueError:
            raise DomainError("needs_configuration", "Invalid package.json", 422) from None
        raise DomainError("unsupported_stack", "Node runtime adapter is not installed", 422)
    raise DomainError(
        "needs_configuration",
        "No unambiguous supported runtime recipe; supply colossus-app.json or install an adapter",
        422,
    )
