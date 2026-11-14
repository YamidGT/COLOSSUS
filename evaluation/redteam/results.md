# Red-team lane: measured results (static tiers, no dynamic probes)

**Teammate-reported legacy experiment.** Imported from `lane-b/redteam` at `8782354`; not rerun by the integration session. The original invocation used a separate provider/budget path and unpinned local snapshots. Its numbers are not current shared-pipeline benchmark results. VAmPI was not run here; the current target-validation limit remains DSVW only. The new evaluator requires source-bound truth, CWE matching and stored findings, so its metrics are not directly comparable to this table.

Model: `deepseek-v4-1-flash-1017` via Mistral. Date: 2026-11-14. **One run per cell.**

| Target | Tier | Recall | Precision vs truth | Reported | Suppressed | Model calls | Cost USD | Seconds | Missed |
|---|---|---|---|---|---|---|---|---|---|
| DSVW | T0 | 0.64 (9/14) | 0.41 | 27 | 0 | 0 | 0.0000 | 1 | xss-v, xpath, dos-size, redirect, format-tmpl |
| DSVW | T1 | 0.64 (9/14) | 1.00 | 11 | 16 | 4 | 0.0113 | 176 | xss-v, xpath, dos-size, redirect, format-tmpl |
| DSVW | T2 | 0.79 (11/14) | 0.88 | 16 | 19 | 6 | 0.0148 | 265 | xss-v, redirect, format-tmpl |
| VAmPI | T0 | 0.25 (2/8) | 0.25 | 8 | 0 | 0 | 0.0000 | 1 | debug-exposure, mass-assignment, user-enum, redos, unauth-password, bola-books |
| VAmPI | T1 | 0.25 (2/8) | 0.50 | 4 | 4 | 1 | 0.0009 | 44 | debug-exposure, mass-assignment, user-enum, redos, unauth-password, bola-books |
| VAmPI | T2 | 0.88 (7/8) | 0.47 | 15 | 17 | 15 | 0.0076 | 650 | redos |

## How to read this
- Ground truth: `truth.json`, written by the contributing lane from reading each target's source; it is not the project's official list, and a reported finding that matches no entry is **unadjudicated**, not a proven false positive. The table's legacy "Precision vs truth" field is a location-match rate. It is not validated precision or a proven lower bound: matching lines without checking the root cause can also produce incorrect matches.
- Matching is by file and line window (1 line for DSVW, 3-4 for multi-line VAmPI items); CWE is not required to match.
- T1 retains raw findings and sets a disposition; T2 adds a model hypothesis pass per file. Hypotheses are `needs_review` until confirmed by a probe.
- **Not done:** dynamic confirmation (Docker engine did not start in this session), repeated runs/variance, the held-out target (Vulpy), and the 12-variant prompt-injection suite (only unit tests with a simulated hostile model exist). No claim of general detection performance follows from two small targets.
- VAmPI `redos` is the one missed item (regex on a multi-line `re.search`).
