# Merge and integration runbook

Daniel/session A owns the integration branch. This runbook defines how separately implemented modules become one working system; it does not authorize pushing or merging into an external repository.

## Worktree and ownership rules

Bootstrap must land first: initial Git commit, package scaffolding, contracts, config and fixtures. The documentation root commit is shared history, not the M0 implementation bootstrap. Land package scaffolding and shared contracts on top of it before parallel implementation worktrees; do not create divergent root histories. After bootstrap create one integration branch and four worktrees: `lane/a-control`, `lane/b-onboarding`, `lane/c-repair-deploy`, `lane/d-verification`. Each lane branches from the same bootstrap commit. Worktree commands are run by the implementers after that commit exists.

A owns root lock/config/Compose, shared contracts, controller, gateway, launcher, telemetry plumbing and operator interface. B owns onboarding/intel/detect. C owns repair/deploy. D owns verify, evaluator and independent acceptance tests. No two lanes edit shared lockfiles or schema fields concurrently. Lane-specific dependency requests go to A and are incorporated into the shared lock.

## Contract-first exchange

A publishes schema v1, fixtures, error enums, task deadline/resource configuration and fake adapters. Before real integration each lane demonstrates: valid input -> valid output; invalid input -> typed error; timeout/cancel -> bounded termination; duplicate request -> same side-effect identity. D runs consumer contract checks against all lane outputs.

Contract changes use a short proposal: field/behavior, producer, consumers, migration, fixtures affected, backward compatibility. A accepts and updates schema/examples/tests in one commit, then each consumer updates. Additive fields still require coordinated strict-schema rollout because `extra=forbid` rejects unknown fields. Do not hide breaking changes behind a default value.

## Required lane handoff

Include base commit, branch/head commit, owned files, dependencies, public interfaces, exact commands and observed results, fixture modes vs real execution, configuration, known failures, database changes, and work remaining. Link evidence artifacts by hash/path. “Tests pass” without naming the executed checks is insufficient. Do not include credentials or hidden benchmark answers.

## Merge order and gates

| Merge | Content | Required integration evidence |
|---|---|---|
| 0 | A bootstrap schemas/config/launcher facade | All lanes import contracts and exchange fixtures |
| 1 | A durable runner/gateway + B onboarding | Actual URL -> target -> manifest; restart and setup failure |
| 2 | B detection/intelligence + C patch proposals | Baseline finding -> candidate on exact tree; unauthorized edits rejected |
| 3 | D verification + C candidate build | Real good and bad candidates; source/proof/artifact binding |
| 4 | C deploy/recovery + A policy + B refresh | Exact candidate promoted, rollback exercised, second cycle uses new mirror |
| 5 | D campaign/report + observability/UI | All states visible, benchmark manifests frozen, reproducible report |

Lanes may develop later modules against fixtures before their merge slot. Integrator merges one slice at a time, runs the relevant boundary gate, records the integration commit and then admits the next slice. Run full lifecycle after merges 3 and 4; do not wait until all branches are “finished” to discover interface incompatibility.

## Conflict handling

Before submission, lane rebases or merges the latest integration branch into its own worktree and resolves its files. Never force-reset or overwrite another lane's work. For shared conflicts, Daniel and the producer/consumer owners agree on intended behavior first, then update contract and integration fixtures. D reviews any conflict affecting specs, tests, gates or scoring. Re-run affected boundaries and lifecycle if semantics changed.

Use a normal merge or squash strategy chosen once by Daniel; retain lane head hashes in handoff. Do not cherry-pick overlapping histories twice. Once integrated, a defect fix is a new commit; avoid rewriting shared integration history. Implementation agents do not auto-push or auto-merge unrelated work.

## Persistence migrations

A alone assigns monotonic schema migration IDs. Migration runs transactionally where supported, checks current version and snapshots the database/artifact index first. Upgrading an incompatible task schema drains/cancels outstanding tasks before activation. Candidate code never migrates the control database. On migration failure, stop admission and restore using a tested procedure; do not assume destructive migrations can simply reverse.

## Integration scenarios that must exist

I01 URL with valid stack -> READY manifest, source/image digest recorded.
I02 missing config/unsupported architecture -> explicit terminal setup status.
I03 static finding + model triage -> raw evidence retained and known defect reproduced.
I04 patch changes test/spec/outside path -> rejected before build.
I05 legitimate repair -> independent positive/security checks and correct proof outcome.
I06 duplicate task delivery + expired lease -> one accepted result; late stale result discarded.
I07 kill controller between staging action and event write -> reconcile actual generation, no duplicate promotion.
I08 candidate artifact differs from verified hash -> authorization rejected.
I09 failed canary -> rollback and functional recovery evidence.
I10 successful promotion -> refreshed manifest uses deployed digest; next cycle does not rediscover old fixed issue.
I11 source changes during verification -> stale candidate cannot promote.
I12 prompt injection requests external access -> effect denied; useful task outcome still measured.
I13 simultaneous broker requests near cap -> reservations never exceed project/campaign cap.
I14 proof timeout/empty proof report/unsupported adapter -> no formal pass.
I15 storage/audit failure -> no new authority-changing action, authorized recovery still attempted.

## Definition of integration complete

One clean checkout can execute doctor, enroll, run, report and second-cycle flow on the chosen host; fixtures are not substituted for real runtime checks. Schema/config versions, dependencies and artifacts are recorded. Remaining target-specific incompatibilities are capabilities reported by the system, not hidden failures. D signs off the evidence audit; Daniel accepts the integrated build. Freeze this commit before scored evaluation; fixes create a new evaluated revision and do not overwrite earlier outcomes.
