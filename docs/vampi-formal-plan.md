# VAmPI: formal requirements and implementation linkage

Owner D with C implementing route changes and B supplying fixtures. This is a **proposed guided integration profile**, not a proof already run, not a claim to prove arbitrary Flask, and not a requirement for ordinary URL onboarding. The four REQ IDs below are new VAmPI proposals; the conversation did not provide their definitions. Daniel accepts the semantic policy at M0 before it becomes a required promotion gate. Until then it is unapproved and cannot authorize automatic formal promotion.

## Precisely what is proved

Extract small pure authorization/projection decisions into actual Dafny source, prove them against frozen contracts, compile to Python, and make the real routes invoke that generated code. HTTP parsing, JWT validation, ORM behavior, concurrency, compiler/runtime correctness and the route's use of the result remain explicit trusted assumptions plus integration tests. This is a conditional guarantee about a running component; the whole service is not mathematically verified. [Dafny language/compiler reference](https://dafny.org/latest/DafnyRef/DafnyRef).

```text
HTTP request -> Flask parsing + validated identity + DB lookup   [tested adapter]
                            |
                            v
                 compiled Dafny policy functions                [proved logic]
                            |
                            v
             authorization decision / typed public projection
                            |
                            v
             guarded DB effect / exact response construction   [tested adapter]

Dafny source + frozen spec -> verify -> compile -> hash output -> image digest
       |                                                     |
       +-------- property + tool evidence -------------------+-> gate manifest
```

Do not prove a parallel model and leave the vulnerable Python decision in place. Do not merely call the generated function and discard its result. Reuse the existing proof gate and artifact binding, not a second verifier pipeline.

## Proposed requirements

| ID | Policy over total input domain | Positive behavior to preserve | Scope/exclusions |
|---|---|---|---|
| REQ-1 | `MayChangePassword(authenticated, actor, target, exists)` returns true iff authenticated, target exists and actor equals target | An authenticated existing user changes their own password | Proposed policy rejects mismatched URL identities; upstream safe branch instead selects authenticated subject. Record this deliberate semantic choice. Identity validation and DB writes are outside the proof. |
| REQ-2 | `MayReadBookSecret(authenticated, actor, owner, exists)` returns true iff authenticated, book exists and actor equals owner | Owner retrieves their own book's secret | Book lookup/owner binding and serialization must be tested. Public book metadata need not be hidden. |
| REQ-3 | `RegistrationRole(requestedAdmin)` always returns non-admin for public registration | Valid account creation/login still works | Administrative provisioning is separate; a public request cannot select that path. Proof does not cover authentication or password storage. |
| REQ-4 | `PublicUser(username,email,...)` constructs a typed result containing exactly username and email; output depends only on those inputs | Existing public user listing shape remains useful | Public and debug user-list responses use this result; password/admin fields are excluded. This is field-projection confidentiality, not general noninterference, PII compliance or timing secrecy. |

Define identities with an explicit authenticated flag and canonical strings; missing/invalid token or missing resource cannot become a valid actor. No `requires authenticated` or `requires actor == target` on the decision functions: that would assume the security condition rather than prove rejection. Equality itself is exact; canonicalization/Unicode policy is part of the tested wrapper and must not equate distinct accounts.

For REQ-4 use an immutable output datatype with only the approved fields and a postcondition preserving their values. A two-input lemma can establish equal public fields yield equal public output regardless of secret fields. Do not serialize the original ORM object's entire dictionary after calling the projector. Existing public fields are visible in [user model serialization](https://github.com/erev0s/VAmPI/blob/master/models/user_model.py); the user route checks and registration behavior are in [route source](https://github.com/erev0s/VAmPI/blob/master/api_views/users.py). These sources motivate scope; the table states our proposed security requirements.

## Concrete integration sequence

1. D freezes approved spec/expected declaration IDs and source hashes in the obligation registry. C/B agree route mapping, response/status semantics, canonical identity format and deterministic two-user/book fixtures. Keep gold tests outside model mounts.
2. D creates a small `policy.dfy` with four executable methods and immutable contracts; writable implementation/hint regions are explicitly bounded. Build a correct fixture and engineered wrong candidates (allow everyone, deny everyone, honor requested admin, leak extra fields). These are evaluator controls, not naturally generated findings.
3. D proves the known-good source with a pinned Dafny/solver toolchain and tests that wrong candidates fail. Inventory all imported/trusted declarations and reject axioms, assumptions, skipped verification and empty proof reports.
4. Compile the exact verified source to Python using the pinned supported command, record invocation/tool hash and generated module/runtime hashes. Never hand-edit emitted Python. Confirm generated calls work in a clean target-compatible Python image. If toolchain compatibility fails, report UNSUPPORTED; do not promote a handwritten reimplementation as equivalent.
5. C integrates four narrow wrappers: password effect guarded by REQ-1; secret read guarded by REQ-2; new-user role selected by REQ-3; public/debug lists constructed solely through REQ-4. Wrapper changes are a separately reviewed integration migration, not permission for patchers to rewrite frozen specs or build recipes.
6. D runs positive and negative HTTP/state tests. Verify no cross-user state changes, successful self-service, no secret response on denied paths, no admin assignment, and exact public fields. Include missing/expired token, nonexistent resource and malformed identity cases. Search/call-graph review plus route tests check bypasses, but do not claim this establishes a formal proof of all route coverage.
7. Package generated code and runtime in the candidate image; rerun independently against the packaged artifact. A gate must fail if a generated file is changed, excluded from the image or bypassed by a known test mutation. Rebuild/invalidate when code, spec, compiler or dependency assumptions change.
8. Run normal promotion/health/rollback/refresh and second cycle for this profile. Record actual proof timings and operator integration work separately from standard generated-repair experiments.

## Claims and experiments to keep separate

- Standard VAmPI source repair: tests plus applicable native analysis; no whole-Flask formal claim. Its visible safe branches make it known-reference development.
- Guided VAmPI formal integration: owner-selected policy plus actual compiled replacement. Report the setup intervention and component proof scope. Future repairs to this integrated component must preserve approved obligations.
- Property mutation: corrupt the integrated policy implementation while keeping spec fixed; measure recovery/rejection. Label it an evaluator mutation, not an upstream CVE.
- DafnyBench: separate hint-recovery tasks. Their scores do not validate Flask wrappers or database behavior.

SQL injection, JWT signing strength, rate limiting, password hashing, concurrency and all other unspecified behavior remain outside these four proofs. A certificate lists each outcome/assumption and the exact image; it cannot say “VAmPI is invulnerable.” If the formal integration is unfinished, report that result rather than claiming a detached model proves the deployed service.
