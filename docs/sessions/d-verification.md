# Lane D verification and evaluation

Own `src/colossus/verify`, `evaluation/` adapters/manifests, independent integration/security tests and reports. Implement verification.md, vampi-formal-plan.md, evaluation.md and repository-cohort.md; read model-strategy.md for calibration and scored model freezing. Keep gold solutions/labels outside model-visible workspaces. A owns shared envelope and runtime config; request changes rather than forking them.

Steps:
1. Frozen obligation registry, explicit evidence kinds, protected-contract/harness validation and gate result parser.
2. Real Dafny good/bad proof and compiled-call fixture; VAmPI compiled-policy/wrapper integration (CBMC deferred); CrossHair UNKNOWN semantics.
3. Positive/security/differential checks and artifact linkage, including empty/stale/substituted proof tests.
4. Preflight DSVW/VAmPI with B/C; protect Vulpy/Tiredful gold views from development agents; define exact security/functional oracles before scored calls.
5. Implement CTIBench, Instruct upstream scorer and DafnyBench adapters, fixed subset selection and contamination disclosures.
6. Freeze campaign lock after independent gold controls validate; run paired modes, recurrence, recovery and injection challenges.
7. Produce all denominators/failures/timings/costs and audit claims in the technical sheet.

Acceptance: a useful correct patch can pass and known bad patches fail; unknown/unsupported cannot become proof; all candidate hashes match; benchmark truth remains private; no overall repo-security label; unsupported targets and manual hints remain in report; no ten-repo success claim until each attempted row is observed.
