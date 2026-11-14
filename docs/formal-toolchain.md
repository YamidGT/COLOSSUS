# Formal execution and implementation linkage

The adapter in `src/colossus/verification/dafny.py` executes a compiler and solver inside the same gVisor boundary as other untrusted jobs. It never imports candidate code in the controller. Source, immutable specification profile, exact toolchain image, verifier output, declaration-level CSV results and emitted files are retained as evidence.

## Bootstrap

On the current ARM64 lab host:

```sh
uv run python scripts/bootstrap_formal.py
uv run python scripts/check_formal.py
```

The bootstrap builds trusted compiler infrastructure from [Dafny 4.11.0](https://github.com/dafny-lang/dafny/releases/tag/v4.11.0), commit `fcb2042d6d043a2634f0854338c08feeaaaf4ae2`. It checks the downloaded archive and solver wheel against recorded SHA-256 values and uses a digest-pinned .NET SDK base. Only the four explicitly assembled toolchain inputs enter the Docker context; no enrolled repository, credential file or host home enters it. This infrastructure build has network access for official build dependencies. Candidate verification has no network access.

The current ARM64 profile uses Z3 4.13.0, which differs from Dafny's default 4.12.1. It must pass calibration on the actual host before use. The toolchain manifest records this difference and the built image digest. Distribution package resolution is not claimed to produce byte-identical rebuilds; every resulting image is separately identified. AMD64 requires a separately locked and calibrated profile, not ARM emulation by default.

The calibrated source build reports `0.0.0.0` from `dafny --version`; record it as observed metadata together with source release/commit and image digest. Do not label that reported value `4.11.0`. Current measured outcomes are in [implementation status](implementation-status.md).

After successful calibration, set the **nonsecret** `COLOSSUS_FORMAL_TOOLCHAIN_DIGEST` to the manifest's `image_digest` in the controller environment. The supervisor passes it to the launcher. Without it, `/formal/policy` returns `formal_unsupported`. Deployment credentials cannot call this endpoint. A request cannot choose its own image, command, import, solver flag or specification.

## What the current profile measures

`authorization-policy-calibration-v1` is an owned fixture with four total decision/projection methods. It exercises the shape of the proposed VAmPI policy, but is neither a VAmPI run nor approval of VAmPI business requirements. DSVW remains the sole target repository authorized for runtime validation.

Candidate output consists only of expressions for fixed implementation slots. A small parser accepts identifiers from each slot's vocabulary, Boolean operators, grouping and the fixed public projection constructor. It cannot express statements, declarations, imports, attributes, assumptions or contract edits. Dafny then checks typing and the unchanged postconditions. This is intentionally a restricted policy synthesizer; arbitrary DafnyBench hint editing requires a separate adapter.

A pass requires a successful process, a nonempty proof summary and successful CSV entries for every expected declaration. Timeouts, truncated output, missing declarations and zero proofs never pass. The compiler subsequently emits Python from the exact same source; it does not accept handwritten replacements as equivalent. The proof/compile operation shares one deadline.

Calibration includes correct code and four incorrect implementations: allow everyone, deny everyone, honor requested administrator privilege, and expose a secret in the public projection. Failure to prove an incorrect candidate is `UNKNOWN` with the diagnostic, not a claimed concrete counterexample. Wrapper tests are an additional empirical gate.

## Application promotion boundary

An application still needs approved requirements, wrappers that bind real inputs and consume the generated decisions, positive and negative behavior tests, bypass mutations, and hashes binding generated files to the packaged image. Compiled-component evidence alone cannot satisfy that application's `formal_required` policy. No current DSVW SQL repair is upgraded to a Dafny proof. See [verification](verification.md) and [guided VAmPI integration](vampi-formal-plan.md).

The [Dafny language reference](https://dafny.org/latest/DafnyRef/DafnyRef) explains specification and compilation semantics. Tool output and mutation controls check this integration; they do not establish that a specification covers every security property.
