"""Export JSON Schema and valid/invalid fixtures for every schema-1.0 object.

Usage: python scripts/export_contracts.py  (writes fixtures/contracts/)
Fixture values are synthetic; they are not evidence of any real run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from colossus.contracts import ALL_TYPES, Envelope, RuntimeConfig  # noqa: E402
from colossus.contracts.fixtures import INVALID, VALID  # noqa: E402

OUT = ROOT / "fixtures" / "contracts"


def dump(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    for name, model in {**ALL_TYPES, "Envelope": Envelope, "RuntimeConfig": RuntimeConfig}.items():
        dump(OUT / "schemas" / f"{name}.schema.json", model.model_json_schema())
    for name, data in VALID.items():
        dump(OUT / "valid" / f"{name}.json", data)
    for name, (why, data) in INVALID.items():
        dump(OUT / "invalid" / f"{name}.json", {"_invalid_because": why, "payload": data})
    print(f"exported {len(ALL_TYPES) + 2} schemas, {len(VALID)} valid and {len(INVALID)} invalid fixtures to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
