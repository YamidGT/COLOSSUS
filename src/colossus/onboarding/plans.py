"""Fail closed on an untrusted Compose-like plan shipped inside a snapshot.

Daniel's stack detector still chooses the runtime recipe. This only rejects a
caller-supplied plan before any build. A valid plan is recorded as checked and
is not executed by this gate.
"""

from __future__ import annotations

import json

from colossus.contracts.core import DomainError
from colossus.sandbox.recipe_validator import validate_recipe

PLAN_NAME = "colossus-compose.json"


def gate_untrusted_plans(files: dict[str, bytes]) -> list[str]:
    if PLAN_NAME not in files:
        return []
    try:
        recipe = json.loads(files[PLAN_NAME])
    except ValueError:
        raise DomainError(
            "hostile_recipe", f"{PLAN_NAME} is not JSON", 422
        ) from None
    violations = validate_recipe(recipe, execution=True)
    if violations:
        detail = "; ".join(f"{item.service}:{item.rule}" for item in violations)
        raise DomainError("hostile_recipe", f"{PLAN_NAME} rejected: {detail}", 422)
    return [PLAN_NAME]
