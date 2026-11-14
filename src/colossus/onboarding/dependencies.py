"""Parse static Python requirements without invoking project build metadata."""

import re
import tomllib

from packaging.requirements import InvalidRequirement, Requirement

from colossus.contracts.core import DomainError, safe_relative_path


def validate_requirements(values: list[str]) -> list[str]:
    if not isinstance(values, list) or len(values) > 100:
        raise DomainError("dependency_limit", "At most 100 direct requirements are supported", 422)
    normalized = []
    for value in values:
        if not isinstance(value, str) or len(value) > 2048 or any(c in value for c in "\r\n\x00"):
            raise DomainError("dependency_policy", "Invalid requirement record", 422)
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            raise DomainError("dependency_policy", "Unsupported requirement syntax", 422) from None
        if requirement.url:
            raise DomainError(
                "dependency_policy",
                "Direct URLs, VCS and local dependencies require a separate source profile",
                422,
            )
        normalized.append(str(requirement))
    return sorted(set(normalized))


def requirements_from_source(files: dict[str, bytes]) -> tuple[list[str], list[str]]:
    visited, values = set(), []

    def read(path):
        try:
            path = safe_relative_path(path)
        except ValueError:
            raise DomainError(
                "dependency_policy", "Requirements include escapes the source layout", 422
            ) from None
        if path in visited:
            raise DomainError("dependency_policy", "Recursive requirements include", 422)
        if len(visited) >= 10 or path not in files or len(files[path]) > 256 * 1024:
            raise DomainError("dependency_policy", "Missing or oversized requirements input", 422)
        visited.add(path)
        try:
            text = files[path].decode("utf-8")
        except UnicodeDecodeError:
            raise DomainError("dependency_policy", "Requirements must be UTF-8", 422) from None
        for line in text.splitlines():
            line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r ", "--requirement ")):
                child = line.split(maxsplit=1)[1]
                parent = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
                read(parent + child)
            else:
                values.append(line)

    if "requirements.txt" in files:
        read("requirements.txt")
    elif "pyproject.toml" in files:
        try:
            project = tomllib.loads(files["pyproject.toml"].decode()).get("project", {})
            if not isinstance(project, dict) or not isinstance(project.get("dynamic", []), list):
                raise ValueError("Malformed project metadata")
            if "dependencies" in project.get("dynamic", []):
                raise DomainError(
                    "needs_configuration",
                    "Dynamic project dependencies require an isolated build profile",
                    422,
                )
            values = project.get("dependencies", [])
            visited.add("pyproject.toml")
        except (ValueError, UnicodeDecodeError, AttributeError):
            raise DomainError("dependency_policy", "Invalid Python project metadata", 422) from None
    return validate_requirements(values), sorted(visited)
