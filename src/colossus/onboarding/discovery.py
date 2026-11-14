"""Read repository configuration as data; never import it to detect a stack."""

import json

from colossus.contracts.core import Contract, DomainError, safe_relative_path


class Recipe(Contract):
    recipe_id: str
    command: list[str]
    port: int
    health_path: str = "/"
    expected_status: int = 200
    required_body: str | None = None
    test_profile_ids: list[str]
    limitations: list[str]


def discover(files: dict[str, bytes]) -> Recipe:
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
        return recipe
    # Identify why setup cannot yet execute instead of guessing or running a repo Dockerfile.
    dependencies = any(p in files for p in ("requirements.txt", "pyproject.toml", "Pipfile"))
    if dependencies:
        raise DomainError(
            "unsupported_stack",
            "Dependency-backed Python setup requires the isolated dependency-builder adapter",
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
