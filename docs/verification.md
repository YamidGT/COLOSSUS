# Verification and formal methods

Owner D. Verification is a set of explicit obligations on actual candidate code. It is not a model's judgment that a patch is secure. Tool versions, command profiles, source, tests, specifications and assumptions are hashed into the evidence.

## Required acceptance gates

Run in this order, stopping expensive work after a decisive failure while preserving required-gate missing statuses:

1. Scope/base: patch applies to exact source; protected inputs unchanged; candidate manifest resolves.
2. Baseline: healthy before testing; original security failure reproduces. A negative-control/no-change case uses its predeclared safe oracle instead.
3. Build/readiness: candidate builds with fixed recipe and starts; compile-only success is insufficient for services.
4. Security: same reproducer no longer violates the security condition, with expected response/state. A crashed or always-denying service does not pass.
5. Functionality: legitimate workflows, classified upstream tests and held-out evaluator checks. In intentionally vulnerable labs such as DSVW, attack-preservation tests are security oracles whose selected expectation must reverse; classify them before patching, separately from positive functionality. Differential comparison excludes intended security changes from equality but retains other behavior. Existing known failures are identified before patching.
6. Static/dependencies: no new in-scope findings under pinned rules; unresolved findings remain visible. LLM suppression cannot override required security gates.
7. Formal: execute declared obligations and evaluate outcomes according to assurance profile.
8. Artifact binding: all gates refer to the exact packaged artifact/source and immutable policy/test/spec versions; generated code and runtime dependencies match.

`tested` requires gates 1–6 and 8 and disclosure of gate 7 coverage. `formal_required` also requires every required formal obligation at the declared evidence kind. Missing/error/timeout on a required gate blocks. `not_applicable` needs a profile-level reason established before execution, not a model's convenience.

## Specification planner

Select existing accepted contracts first, then approved security templates, then owner-approved requirements. Inferred business rules remain unapproved until confirmed and cannot justify automatic formal promotion. The default URL-only lab can use approved general security templates without a clarification for every case.

An obligation declares property, code symbols, spec/harness hashes, environment model, supported backend, bounds, required evidence kind and origin. Check consistency/non-vacuity using reachable positive examples, satisfiable preconditions and the known failing input. Mutation controls test that a known contract violation is rejected; they do not prove the specification complete.

Patcher cannot change obligations, harness assumptions or compiler options. Proof-hint helper may add only permitted proof constructs. Implement parsed/AST-based edit validation or a restrictive insertion grammar with immutable surrounding syntax; a regex blacklist is insufficient. Reject new assume/axiom/extern/trust escapes, verification-disable attributes, arbitrary imports, bodyless methods, weakened preconditions/postconditions and unapproved environment stubs. Existing trusted assumptions are inventoried, not silently removed or endorsed.

## Adapter contracts

`supports(manifest, obligation) -> support/reason`
`prepare(candidate, obligation) -> job_profile + input artifact IDs`
`execute(job) -> raw stdout/stderr/status artifacts`
`interpret(raw, obligation) -> GateResult`

Adapters never accept a model-produced `pass`. Freeze expected declarations/property IDs so zero proofs or skipped targets cannot count. Record tool diagnostics and exit status together; classify timeout/unsupported distinctly.

### Dafny

Use actual Dafny implementations or deliberately integrated compiled components. Pin Dafny and solver versions; verify immutable contracts, permitted hint changes and expected declarations. Explicitly inventory included modules, precompiled libraries and skipped verification scopes; verify all changed dependencies needed by the claim rather than assuming imported files are automatically rechecked. Trusted unchanged libraries are listed as assumptions with hashes. Build generated target-language code from the same verified source using that pinned compiler; hash and package the result. Do not manually modify generated code. Reject any bypass path in candidate builds.

A proof of an AI-translated model is MODEL_ONLY evidence in exclusions; it does not satisfy a linked-code obligation without independently established correspondence. No automated whole-repository translation claim. [Dafny manual](https://dafny.org/latest/DafnyRef/DafnyRef).

The first guided integration is specified in [VAmPI formal plan](vampi-formal-plan.md). Its policy/source migration is separate from ordinary automatic patching and has explicit owner-approved requirements and wrapper assumptions.

### C and C++ with CBMC (extension milestone)

Prefer existing upstream harnesses; otherwise generate a candidate harness that is separately reviewed/frozen as part of the assurance profile. Invoke checks on the actual implementation with a fixed machine model, relevant pointer/bounds/overflow assertions and enabled unwinding assertions. Record every loop bound and stub. A counterexample may indicate a real defect, a bad harness or insufficient unwind; classify with evidence. Passing under finite constraints is BOUNDED_PASS unless the adapter establishes all obligations needed for its stronger claim. Unsupported assembly/syscalls or unmodelled behavior remain exclusions. [CBMC tutorial](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/cbmc-tutorial.md).

### Python with CrossHair

Analyze supported deterministic functions/contracts in a sandbox because analysis executes code. A found counterexample becomes a regression input after confirmation. No counterexample yields UNKNOWN for a proof obligation, with bounded exploration evidence; it does not yield PROVED. [CrossHair limitations](https://crosshair.readthedocs.io/en/latest/limitations.html).

Other languages use tests and an explicit unsupported formal adapter until a real native adapter is added and validated. DafnyBench remains a separate proof-hint benchmark, not proof of non-Dafny application code.

## Incremental coverage

Track named component/property obligations, not a misleading percentage of source lines “proved secure.” Coverage report: required/optional obligations, approved/unapproved, supported/unsupported, attempted/completed and each proof outcome. Invalidation: any change to code dependencies, contract, harness, compiler, environment model or relevant runtime invalidates cached proof; conservatively recheck if dependency impact is unknown. Tests cannot upgrade UNKNOWN to PROVED.

Example: a parser patch is checked for memory bounds under a declared harness; its positive parse tests still pass. This does not prove authentication or deployment correctness. A proven business rule assumes authenticated actor input if authentication is outside the proved component; that assumption is exposed.

## Implementation steps and acceptance

1. Implement obligation registry and immutable-hash policy.
2. Implement gate runner with fake pass/fail/timeout fixtures and exact candidate binding.
3. Integrate Dafny plus one real compiled-call fixture; verify known good/bad/spec-tamper cases.
4. Implement the VAmPI compiled-policy integration and independent wrapper tests; retain explicit unsupported results for the deferred CBMC adapter. On later C/C++ admission, validate it with known-good/bad and insufficient-unwind cases before use.
5. Integrate CrossHair and ensure its no-counterexample outcome never satisfies proof-required gates.
6. Add actual cohort harnesses, incremental invalidation and result aggregation.
7. Run challenge set: spec weakening, test modification, assume insertion, no-op verification, stale proof, artifact substitution, reject-all application, partial-state update, unbounded loop timeout, correct repair. Measure both bad rejection and good acceptance.

Per-call and total proof budgets are in runtime.md. Limits produce UNKNOWN/TIMEOUT; they never waive obligations.
