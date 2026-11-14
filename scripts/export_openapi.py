"""Generate frontend API types from actual routes and shared Pydantic contracts."""

import json
import tempfile
from pathlib import Path

from colossus.contracts import models
from colossus.contracts.core import Contract
from colossus.control.api import create_app
from colossus.control.config import Settings

with tempfile.TemporaryDirectory(prefix="colossus-schema-") as temporary:
    app = create_app(Settings(data_dir=Path(temporary)), execute_tasks=False)
    schema = app.openapi()
    app.state.store.close()
for name, cls in vars(models).items():
    if isinstance(cls, type) and issubclass(cls, Contract) and cls is not Contract:
        value = cls.model_json_schema(ref_template="#/components/schemas/{model}")
        schema["components"]["schemas"].update(value.pop("$defs", {}))
        schema["components"]["schemas"][name] = value
output = Path("fixtures/contracts/openapi.json")
output.write_text(json.dumps(schema, indent=2) + "\n")
print("Exported operator API without starting services or targets")
