# Submission boundary and evidence review

Independent review by the formal-workflow lane, 14 November 2026. Reviewed integrated revision `00003c6` plus the then-uncommitted broker cancellation fix and submission campaign script. This is a bounded review during the submission window, not a complete security audit.

## Checks executed

```bash
uv run pytest tests/security tests/verification tests/deployment tests/control/test_model_accounting.py tests/cli -q
```

Result: **177 passed in 2.96 seconds**. These are platform/fixture tests; no Docker target, provider request or public repository was run by this review. One Starlette/httpx deprecation warning was emitted.

Inspected the formal result adapter, normal DSVW gate construction, required-gate acceptance, broker cancellation handling, deployment artifact/generation binding, authenticated decision/configuration/diff routes, CLI retry and output behavior, source archive handling and the submission campaign's source/static/runtime classifications.

## Findings

- No new release-blocking privilege, credential or proof-acceptance regression was identified in this bounded review. This is not a guarantee that none exists.
- The DSVW path records UNSUPPORTED formal scope and still requires build, functionality, security, static and artifact-binding checks. The separate GLM policy fixture cannot silently satisfy the DSVW proof gate. `formal_required` still rejects missing/unsupported proof.
- A cancelled broker request is now recorded as uncertain with its reservation retained. The new cancellation regression passed; no cancelled request is silently charged zero.
- Repository campaign rows explicitly distinguish source intake, unconfirmed Python patterns, readiness-only checks, unsupported functional/security suites and full-cycle evidence. Do not present those rows as 24 repaired applications or an official public benchmark score.
- Two campaign provenance corrections were sent to its owner: retain the selected subdirectory in enrollment metadata, and validate cached source commit/tree against the frozen report before execution. Raw setup/build evidence should be exported before temporary campaign storage is removed. The owner acknowledged these changes; this review does not claim they were revalidated yet.
- CLI `--watch` waits through `REVIEW_READY` until the deadline unless the case progresses. It is safe to detach, inspect and approve/reject separately, but this is not ideal review-policy usability. Automatic lab-cycle watching is unaffected.

## Claims still excluded

No whole-repository security proof, no guarantee of arbitrary URL setup, no complete public benchmark campaign, no production/cloud deployment acceptance, and no broad recovery/accessibility acceptance are established by this review. The final technical sheet must use the final recorded fresh/replay labels and repository outcome denominators, not assumptions from planned functionality.
