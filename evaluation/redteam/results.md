# Red-team lane: measured results (static tiers, no dynamic probes)

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
- Ground truth: `truth.json`, written by us from reading each target's source; it is not the project's official list, and a reported finding that matches no entry is **unadjudicated**, not a proven false positive. "Precision vs truth" is therefore a lower bound on true precision.
- Matching is by file and line window (1 line for DSVW, 3-4 for multi-line VAmPI items); CWE is not required to match.
- T1 retains raw findings and sets a disposition; T2 adds a model hypothesis pass per file. Hypotheses are `needs_review` until confirmed by a probe.
- **Not done:** dynamic confirmation (Docker engine did not start in this session), repeated runs/variance, the held-out target (Vulpy), and the 12-variant prompt-injection suite (only unit tests with a simulated hostile model exist). No claim of general detection performance follows from two small targets.
- VAmPI `redos` is the one missed item (regex on a multi-line `re.search`).
