"""Phase E2 public benchmark adapters (docs/evaluation.md).

Loaders read a locally provided copy of each official dataset; nothing is downloaded.
Selection is deterministic and recorded in a manifest. Scorers consume responses and
verifier/analyzer verdicts supplied by callers; this package never calls a model, never
runs the CyberSecEval analyzer and never invokes Dafny. Absent evidence is ``not_run``.
"""

from colossus.evaluation.benchmarks.common import BenchmarkItem, wilson_interval
from colossus.evaluation.benchmarks.lock import (
    assess_benchmark_lock,
    freeze_manifest,
    result_rows,
)
from colossus.evaluation.benchmarks.selection import build_manifest, select_ids

__all__ = [
    "BenchmarkItem",
    "assess_benchmark_lock",
    "build_manifest",
    "freeze_manifest",
    "result_rows",
    "select_ids",
    "wilson_interval",
]
