# Kiro handoff: Phase E2 benchmark adapters

Branch `wip/benchmarks` (from `kiro/colossus`). Scope: [evaluation.md](../evaluation.md) Phase E2 and [model-strategy.md](../model-strategy.md). This is adapter and scoring code only. **No benchmark has been run, no model was called, no dataset was downloaded, and there are no results.** All tests use synthetic fixtures.

## Location

Package `colossus.evaluation.benchmarks` at `src/colossus/evaluation/benchmarks/`. It sits under `src/colossus` because the wheel only packages that tree, so the module is importable without path hacks. The top-level `evaluation/` directory keeps holding data (`repository-candidates.json`, red-team truth).

| Module | Purpose |
|---|---|
| `common.py` | `BenchmarkItem` (worker view vs evaluator-only gold, content hashes), file hashing with size cap, Wilson intervals |
| `selection.py` | `select_ids` (sorted IDs, `random.Random(seed).sample`, output sorted), `build_manifest` (draft manifest) |
| `lock.py` | `freeze_manifest`, `assess_benchmark_lock`, `result_rows` |
| `ctibench.py` | CTI-RCM / CTI-VSP TSV loaders |
| `cwe.py` | CWE extraction, MITRE CWE CSV hierarchy parser, RCM scorer |
| `cvss.py` | CVSS 3.0/3.1 vector validation, base score, VSP scorer |
| `cyberseceval.py` | Instruct loader, frozen eligibility, `InsecureCodeAnalyzer` port, scorer |
| `dafnybench.py` | Loader, `DafnyVerifier` port, compatibility, upstream edit checks, attempt scorer |

## Obtaining the official datasets (not committed)

Provide each file locally and pass its path. Record the upstream revision and the sha256 the loader computes in the manifest.

| Suite | File | Source | License |
|---|---|---|---|
| CTIBench CTI-RCM | `cti-rcm.tsv` (URL, Description, Prompt, GT) | [HF AI4Sec/cti-bench](https://huggingface.co/datasets/AI4Sec/cti-bench); code [maveryn/cti-bench](https://github.com/maveryn/cti-bench) | CC BY-NC-SA 4.0 (dataset card, repo LICENSE.txt) |
| CTIBench CTI-VSP | `cti-vsp.tsv` (same columns; GT is a CVSS v3.1 vector) | same | same |
| CyberSecEval Instruct | `CybersecurityBenchmarks/datasets/instruct/instruct-v2.json` | [PurpleLlama](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks/datasets/instruct) | MIT (`CybersecurityBenchmarks/LICENSE`) |
| DafnyBench | `test.json` (test_ID, test_file, ground_truth, hints_removed) | [HF wendy-sun/DafnyBench](https://huggingface.co/datasets/wendy-sun/DafnyBench); repo [sun-wendy/DafnyBench](https://github.com/sun-wendy/DafnyBench) | Apache-2.0 |
| CWE hierarchy (optional) | Research view CSV `1000.csv` | [MITRE CWE downloads](https://cwe.mitre.org/data/downloads.html) | MITRE CWE terms of use |

The CTIBench NC-SA license limits redistribution and commercial use. Do not commit the TSVs or derived prompt text.

## Design decisions

- **Worker/gold split.** `worker_view` holds only what a candidate may see: the CTI `Prompt`; for Instruct, `test_case_prompt` and `language` (`origin_code` and `line_text` are answer-bearing and stay in gold); for DafnyBench, the `hints_removed` program. The manifest stores `content_sha256` (view plus gold) and `worker_view_sha256`.
- **IDs.** CTIBench has no id column, so the ID is `cti-rcm:<row:04d>:<CVE>`, stable for a pinned file hash. Instruct uses `prompt_id`. DafnyBench uses `test_ID:test_file`.
- **Selection.** Sorted unique IDs, then `random.Random(seed).sample`; seed 42 output for a 100-id list is pinned in a regression test. If fewer IDs are eligible than requested, all are returned and `actual_size` is reported. `build_manifest` refuses any item that is neither eligible nor in a disclosed exclusion (`hidden_exclusion`).
- **Lock.** This follows `colossus.verify.campaign.assess_campaign`. `candidate_only` is refused with code `candidate_only`, and the repository roster file is also refused. `scored_execution_allowed=True` is refused with code `campaign_not_executed`. Anything other than `frozen` is refused with `campaign_not_frozen`. Freezing requires a dataset sha256, a non-empty selection and 64-hex hashes on every row, and it can recompute row hashes against loaded items. `manifest_sha256` detects tampering. `assess_benchmark_lock` returns `executed: False, scores: None` with every row `not_run`. `result_rows` joins scorer output and keeps unscored rows as `not_run`. It refuses rows that are not in the lock.
- **CTI-RCM.** The answer is the last non-empty line, with markdown emphasis or backticks and a trailing period stripped, and it must fully match `CWE-\d+`. Exact accuracy uses all attempted rows, with invalid outputs counted as wrong. The upstream notebook's valid-only accuracy is reported separately. Hierarchical accuracy means exact or a direct `ChildOf` neighbour (distance 1) in research view 1000, parsed from MITRE's CSV. Upstream `related_dict.pickle` / `alias_dict.pickle` are deliberately not loaded because unpickling is unsafe. Macro-F1 is computed over gold classes.
- **CTI-VSP.** The predicted score is always computed from a spec-validated vector using the FIRST v3.1 formulas and Roundup; v3.0 vectors use ceil rounding. Valid vectors need all eight base metrics exactly once. Temporal and environmental keys are accepted only with legal values. A bare `AV:...` last line gets a `CVSS:3.1/` prefix, as the upstream notebook does, and the row is flagged `prefix_added`. MAD is valid-only and reported alongside the invalid count. Validity and per-component agreement use the attempted denominator.
- **Instruct.** The language list and CWE allowlist must be passed explicitly before sampling; `available_cwes` helps write them. The rate is insecure / analyzed responses. `unavailable` and `error` verdicts are counted and never treated as secure. `UnavailableAnalyzer` is the default, so no rate exists until the upstream ICD is wired behind the sandbox boundary. `PythonParseValidity` uses `ast.parse` only: it does not compile or execute, and it returns unknown for other languages.
- **DafnyBench.** Ground truth must verify under one pinned toolchain before sampling. Missing results are excluded as `ground-truth compatibility not_run`, so the 20-program selection cannot be produced until compatibility has actually run. Attempts are capped at 3 and accepted only when the verifier status is `verified` and the upstream `check_no_cheating` port passes (spec lines preserved, no `{:verify false}` or `assume false`). A stricter `strict_new_assumption` flag for any new `assume` or `{:axiom}` is reported separately. The no-hint baseline is the unchanged `hints_removed` program under the pinned verifier. Upstream `verifies_without_hints` metadata is not used as evidence. `comparable_to_upstream` is always False.

## Dafny runner gap (needs session A / Daniel)

`colossus.verification.dafny.DafnyAdapter.execute` only renders restricted `PolicyProfile` templates. It has no entry point that verifies an arbitrary `.dfy` program. `DafnyRunnerVerifier` wraps an injected `runner(program, timeout) -> {exit_code, stdout, timed_out, truncated}`, matching the shape of `SandboxLauncher.execute`. `classify_output` mirrors `proof_passed` (one summary line, 0 errors, clean exit) plus the DafnyBench "File contains no code" rejection. A general-program sandbox entry point, reusing the same image digest and toolchain label check, has to be agreed as a shared-contract change. Until then `NotWiredDafnyVerifier` returns `not_run`. DafnyBench upstream appends a helper `abs(real)` function and uses a 15 s timeout. Whether to replicate either is an open decision to freeze.

## Commands and outcomes (2026-11-14)

```
export UV_PROJECT_ENVIRONMENT=$PWD/.uvenv; uv sync -q --python 3.12 --all-extras   # ok
uv run pytest -q -p no:cacheprovider --basetemp=$PWD/.pt tests/benchmarks          # 42 passed
uv run pytest -q -p no:cacheprovider -m 'not gvisor' --basetemp=$PWD/.pt           # 338 passed, 20 deselected, 1 warning
uv run ruff check src tests                                                         # All checks passed!
python3 scripts/check_design_docs.py                                                # PASS: 31 required handoff files ...
```

## Remaining work

1. Obtain and pin the official files, then build and freeze CTI-RCM/VSP manifests (50 each, seed 42).
2. Freeze the Instruct Python CWE allowlist from `available_cwes` on the pinned `instruct-v2.json`, then sample up to 30.
3. Wire the PurpleLlama ICD as an `InsecureCodeAnalyzer` running in the sandbox, with its version recorded.
4. Agree the general Dafny entry point, run ground-truth compatibility and the no-hint baseline, then sample 20.
5. Prompt templates, model-profile hash, token/cost and refusal reason codes per row (gateway, session A), and per-attempt cost for DafnyBench.
6. Results export (JSON/CSV) on top of `result_rows`.
7. Scored runs only after Daniel authorizes the campaign.
