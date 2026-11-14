# Red-team lane on implementation/full-system: measured results

Integrated pipeline (`detect.redteam.investigate`) driven by the shared `ModelGateway`
(`zai-glm-5-3-flash`, project default). Static tier = Daniel's sandbox rule scanner (the worker
has no Bandit). Date: 2026-11-14. **One run per cell; no dynamic probes.**

| Target | Tier | Recall | Precision vs truth | Reported | Suppressed | Model calls | Cost USD | Seconds | Missed |
|---|---|---|---|---|---|---|---|---|---|
| DSVW | T0 | 0.57 (8/14) | 0.80 | 10 | 0 | 0 | 0.0000 | 1 | xss-v, xpath, dos-size, redirect, format-tmpl, jsonp-xss |
| DSVW | T1 | 0.57 (8/14) | 1.00 | 8 | 2 | 2 | 0.0015 | 14 | xss-v, xpath, dos-size, redirect, format-tmpl, jsonp-xss |
| DSVW | T2 | 0.86 (12/14) | 0.82 | 17 | 3 | 4 | 0.0052 | 50 | xpath, redirect |
| VAmPI | T0 | 0.00 (0/8) | 0.00 | 2 | 0 | 0 | 0.0000 | 0 | debug-exposure, mass-assignment, user-enum, redos, unauth-password, bola-books, sqli-user, weak-jwt-key |
| VAmPI | T1 | 0.00 (0/8) | 0.00 | 1 | 1 | 1 | 0.0001 | 10 | debug-exposure, mass-assignment, user-enum, redos, unauth-password, bola-books, sqli-user, weak-jwt-key |
| VAmPI | T2 | 0.88 (7/8) | 0.33 | 21 | 6 | 15 | 0.0060 | 85 | debug-exposure |

## How to read this
- Ground truth is `truth.json`, written by us from reading each target's source. A reported finding matching no entry is *unadjudicated*, not a proven false positive, so "precision vs truth" is a lower bound.
- Not comparable one-to-one with `results-standalone-deepseek.md`: different model (GLM vs DeepSeek), different T0 (no Bandit here), and the standalone T2 already used the hypothesis step now ported.
- T2 hypotheses stay `needs_review` unless a probe confirms them; the model cannot confirm its own claim.
- **Not done:** dynamic confirmation through the launcher, repeated runs, held-out target (Vulpy), and the 12-variant injection suite.
- Windows note: `tests/security/test_artifacts.py` and `test_launcher_policy.py` (lane A) fail on Windows (POSIX symlink/signal semantics) and `control/` tests need `fcntl`; unrelated to this change.
