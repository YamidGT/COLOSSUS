# Public repository evaluation cohort

Owner D; B handles setup and C handles repairs/promotion. Revision 1.1 replaces the former R01-R10 roster with Daniel's Python/API shortlist. Stable U IDs match the [full 24-repository catalog](repository-catalog.md). All ten are candidates; none has passed runtime preflight. Null commit/image/oracle fields in [the machine-readable roster](../evaluation/repository-candidates.json) are intentional and block scored execution.

## Labels and difficulty

A label applies to a snapshot, configuration and named behavior: V = reproduced vulnerable behavior; F = fixed for that behavior; P = named proved property; M = evaluator mutation violating that property; U = unknown. No repository or switch is globally “secure.” D1 means direct/simple setup, D2 contextual authorization or framework setup, D3 multi-service/legacy/heavy compatibility. Difficulty is a planning hypothesis, not a measured ranking of model performance or overall security.

## Ten candidate repositories and initial roles

| ID | Repository | Role / difficulty | Admission condition |
|---|---|---|---|
| U03 | [DSVW](https://github.com/stamparm/DSVW) | Smoke/development, D1 | One bounded SQLi or output-encoding case with positive workflow; classify attack-preservation tests separately |
| U01 | [VAmPI](https://github.com/erev0s/VAmPI) | Main development, D2 | Authorization/data oracles; generated repair under `vulnerable=1`; separate formal integration experiment |
| U02 | [Vulpy](https://github.com/fportantier/vulpy) | Primary heldout, D2 | Runnable `bad/` view and evaluator-only reference; chosen fixed behavior independently reproduced |
| U06 | [Tiredful-API](https://github.com/payatu/Tiredful-API) | Heldout compatibility fallback, D2 | Legacy environment preflight; select before scored model calls, not after Vulpy performance |
| U08 | [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | Optional static-only, D2 | Freeze source findings and policy; no dynamic DoS probes, no full-cycle success credit |
| U05 | [DVPWA](https://github.com/anxolerd/dvpwa) | Deferred multi-service, D3 | aiohttp/database/cache recipe and seeded state fit actual quotas |
| U04 | [Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Deferred legacy, D3 | Resolve actual code layout and interpreter/dependency compatibility; no silent port disguised as automatic setup |
| U07 | [vulnerable-api](https://github.com/mattvaldes/vulnerable-api) | Deferred legacy, D3 | Source rebuild without reliance on old mutable image; exact scenario oracle |
| U09 | [PyGoat](https://github.com/adeyosemanputra/pygoat) | Deferred heavy, D3 | Select one lab and measure setup/resources; no assumed ten-minute build time |
| U18 | [crAPI](https://github.com/OWASP/crAPI) | Deferred heavy, D3 | Resolve required services and optional external/chatbot dependencies; fit resource budget |

Initial full-cycle evaluation uses DSVW and VAmPI for development/calibration, then Vulpy for heldout scoring. Tiredful replaces Vulpy only if preregistered setup/oracle criteria fail before scored exposure. Report that exclusion and replacement. If both fail, report the holdout unavailable. DVGA has a separate static-analysis denominator. The remaining candidates are not automatically scheduled in the hackathon. A ten-repository full-cycle campaign requires explicit admission of every deferred target and changing DVGA's protocol before scoring; the 60-run calculation is an expansion scenario, not the current admitted workload.

## Reference controls and leakage

VAmPI `vulnerable=0` retains some vulnerabilities, including debug behavior. Use it only after validating the selected oracle, and do not accept merely changing that flag as generated source repair. Its source already contains safe branches: development results are **known-reference development**, not blind synthesis. Existing-fix selection is useful but reported separately. [Application source](https://github.com/erev0s/VAmPI/blob/master/app.py).

Vulpy's `good/` is unfinished, so it supplies hypotheses for fixed controls rather than gold truth by name. Its README also does not establish distinct user roles. [Upstream README](https://github.com/fportantier/vulpy).

The evaluator resolves the source then gives repair workers only the runnable target view: no `.git`, gold patches, `good/`, answer-bearing documentation or solution history in heldout-generated mode. Freeze the view/filter manifest and hash; preserve required setup files. Scoring this projected view is distinct from unfiltered URL-only onboarding: report both acquisition/setup and filtered repair conditions. A privileged evaluator can inspect both views without exposing them to agents; do not call the evaluator itself blind. Prior model-training contamination cannot be ruled out.

DSVW upstream regression tests deliberately assert attack success. Freeze a test classification before patching: positive functionality must continue; the selected vulnerability-demonstration oracle must reverse; unrelated known failures remain reported. Never blanket-disable failing tests or ask the patcher to edit expectations. Record lxml availability and skipped features; missing optional dependencies are not successful fixes. [Upstream test description](https://github.com/stamparm/DSVW).

For each target choose exactly one primary root cause and a corresponding F control before the first scored campaign, then document additional independently adjudicated findings separately. This makes the two-variant denominator explicit without pretending to cover every listed vulnerability. The VAmPI REQ-1..4 exercise is a separate guided formal-integration experiment; do not mix its four obligations into the one-defect repair denominator.

## Preflight and freeze procedure

1. Check license and legal local use; store source URL/license. Test only local enrolled copies, never maintainers' public demos.
2. Resolve requested revision to full commit and immutable archive hash; record platform/build inputs. Do not label a moving `main` as a snapshot.
3. Onboard through COLOSSUS using URL-only discovery. Record every manual hint. If a target needs a handcrafted profile, keep it as assisted onboarding, not plug-and-play success.
4. Build the V/M and F/P variants; establish positive functional behavior and the contrasting security/property oracle. The intended V/M must fail and F/P pass on repeated clean seeds.
5. Freeze independent test/harness/seed/recipe hashes, resource profile, expected formal scope and protected paths. Ensure the scorer reads actual behavior, not a model report.
6. Separate all gold fixes, labels and future commits from worker mounts. Commit history and internet solution lookup are unavailable in blind-generated mode. Upstream-update mode explicitly permits official remediation lookup.
7. Write `evaluation/campaign.lock.json`, including every exclusion/failure. Sign off by D and Daniel before any scored model run.
8. If a target is unbuildable or no reliable oracle is obtained, retain an excluded row with reason. Do not substitute another easy target after viewing model performance. A new target requires a preregistered campaign revision.

## Case manifest fields

`case_id, repo_id, repo_url, target_subdir, source_commit, source_archive_sha256, reference_commit_or_mutation_hash, label, difficulty, advisory_id, mode(blind_generated/upstream/negative_control/proof_mutation), platform, recipe_hash, artifact_digest, manifest_hash, seed, oracle_id/hash, positive_test_ids/hashes, obligation_ids, expected_failure, expected_safe_behavior, network_profile, runtime_profile, manual_setup_steps, eligibility_status, exclusion_reason, license, preflight_evidence_ids`.

No scored case can contain unresolved hashes, missing oracle evidence or unrecorded manual setup. The public roster JSON remains explicitly candidate-only until these conditions hold.
