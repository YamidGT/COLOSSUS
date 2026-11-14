# Model-assisted formal verification and mandatory test fallback

The model writes candidate implementation expressions. Deterministic code chooses an eligible registered template, freezes its specification, validates the expression grammar, runs Dafny in gVisor, checks every expected declaration and compiles the exact verified source. Diagnostics return to GLM for at most three attempts within one 180-second loop deadline. The existing shared broker owns credentials, reservations, model-call records and costs; there is no provider client or key in the verifier.

`src/colossus/verification/agent.py` is the workflow. It accepts only a controller-selected profile ID. The present registered profile, `authorization-policy-calibration-v1`, covers four owned policy methods and is a calibration fixture, not approval of any public repository's business policy. The generated expression slots cannot contain statements, imports, assumptions or attributes. Specification and generated implementation hashes must match the verifier response. Provider refusals and unavailable model responses terminate model work; they do not switch providers. Failed proof attempts remain UNKNOWN rather than a fabricated counterexample. Cancellation immediately marks the call and charge uncertain; the conservative reservation continues counting toward the cap until actual billing can be reconciled.

## Normal application flow

The DSVW repair flow now invokes formal applicability and stores its result as operator evidence before existing gate acceptance. Its Python SQL adapter has no matching approved linked proof template, so formal outcome remains UNSUPPORTED. The authorization fixture cannot prove this unrelated SQL patch. Generic supported setup/investigation results also contain the plain testing instructions below. This does not grant generic repair or deployment capability where a protected test oracle is absent.

1. Run registered positive application tests in the candidate sandbox.
2. Reproduce the defect on the baseline and require the protected security check to reject it on the patched candidate.
3. Require build/readiness and static regression checks; preserve failures and timeouts.
4. If the application has no protected functional/security test profile, record unsupported repair and do not promote.
5. Under `tested`, disclose unsupported/unknown proof coverage. Under `formal_required`, missing linked proof still blocks promotion.

Tests run regardless of formal availability. Model-written tests may supplement protected tests; they cannot replace or weaken them. New inferred specifications remain proposals until their requirements and runtime linkage are approved.

## Measured fresh-model calibration

On 14 November 2026, `uv run python scripts/check_formal_agent.py` used the actual shared GLM/Mistral gateway and existing pinned gVisor/Dafny image. One model call generated all four implementations. Dafny proved and compiled them; the loop took **5.496 seconds** including model and proof/compile RPC, excluding the subsequent wrapper packaging checks. Settled model cost: **78 micro-USD ($0.000078)**; no uncertain charge. The packaged wrapper's positive/negative checks passed, a wrapper bypass mutation failed, and generated-file substitution was rejected. The controller audit chain validated. No additional public repository ran in this calibration.

Evidence: [formal-agent.json](../evaluation/submission/formal-agent.json). It records exact source/spec/toolchain hashes, model call ID, diagnostics, wrapper outcomes and costs. `target_proof_outcome` remains UNSUPPORTED because the component fixture is not linked to a public target. `fixture_runtime_linkage=true` means the packaged owned wrapper used the generated component and passed the fixture harness; it is not a universal correspondence proof.

Six focused workflow tests cover unsupported fallback, bounded forbidden edits, diagnostics-based retry, refusal stopping, substituted specification rejection and the distinction between component proof and target correspondence. Existing formal and patch-gate tests also passed: **26 tests** together after the final source-hash strengthening.

## Reproduction

```bash
uv run pytest tests/verification/test_formal_agent.py tests/verification/test_dafny.py tests/verification/test_patch_gates.py -q
uv run python scripts/check_formal_agent.py
```

The live command consumes a small amount of the configured Mistral budget and requires the already calibrated image recorded in `artifacts/bootstrap/formal-toolchain.json`. It preserves a report before asserting calibration success. Do not run it concurrently with another service supervisor on the same state directory.

This division follows Dafny's specification/verification/compiler model: [Dafny reference](https://dafny.org/dafny/DafnyRef/DafnyRef). No claim is made that LLM confidence constitutes proof, that an arbitrary Python translation establishes correspondence, or that this fixture is a DafnyBench result.
