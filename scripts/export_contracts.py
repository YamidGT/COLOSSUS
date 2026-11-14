"""Export the shared schemas without running any target code."""

import json
from pathlib import Path

from colossus.contracts import models
from colossus.contracts.core import Contract
from colossus.contracts.runtime import RuntimeConfig

out = Path("fixtures/contracts/schemas.json")
schemas = {
    name: cls.model_json_schema()
    for name, cls in vars(models).items()
    if isinstance(cls, type) and issubclass(cls, Contract) and cls is not Contract
}
schemas["RuntimeConfig"] = RuntimeConfig.model_json_schema()
out.write_text(json.dumps(schemas, indent=2) + "\n")
print(f"Exported {len(schemas)} contracts to {out}")
