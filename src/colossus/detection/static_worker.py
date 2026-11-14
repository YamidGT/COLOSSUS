"""This trusted analysis program runs inside the sandbox, never imports target code."""

import ast
import json
from pathlib import Path

results, failures = [], []
for path in sorted(Path(".").rglob("*.py"))[:2000]:
    if path.name == "_colossus_static_worker.py" or "vendor" in path.parts:
        continue
    if path.stat().st_size > 500_000:
        failures.append({"path": str(path), "reason": "file_limit"})
        continue
    try:
        code = path.read_text()
        tree = ast.parse(code)
    except (SyntaxError, UnicodeError, OSError, RecursionError):
        failures.append({"path": str(path), "reason": "parse_error"})
        continue
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = ast.unparse(node.func)
        rule = None
        if (
            function.endswith((".execute", ".executemany"))
            and node.args
            and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr))
        ):
            rule = ("CWE-89", "Dynamic SQL query construction")
        elif function in ("pickle.loads", "pickle.load"):
            rule = ("CWE-502", "Unsafe deserialization entrypoint")
        elif function.startswith("subprocess.") and any(
            k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
            for k in node.keywords
        ):
            rule = ("CWE-78", "Shell execution with application input")
        if rule:
            results.append(
                {
                    "path": str(path),
                    "line": node.lineno,
                    "symbol": function,
                    "cwe": rule[0],
                    "title": rule[1],
                    "expression": ast.get_source_segment(code, node),
                }
            )
print(
    json.dumps(
        {
            "findings": results,
            "parse_failures": failures,
            "tool": "colossus-ast-v1",
            "scope": "syntactic SQL construction, pickle calls and shell=True; no taint proof",
        }
    )
)
