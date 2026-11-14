# Full system architecture

## Objective

A public GitHub URL enrolls software in a managed lab. COLOSSUS discovers its stack, builds and starts an isolated copy, investigates vulnerabilities, applies upstream updates or generates patches, verifies requirements, promotes according to policy, monitors health and repeats against the refreshed mirror. Software can be a web service, a multi-service application or a library with a test harness. Formal assurance grows by component; the product remains the complete lifecycle.

## Logical topology

```text
GitHub URL + optional owner requirements / deployment profile
  |
  v
Onboarding -> pinned source -> validated recipe -> isolated build/readiness
  |                                                    |
  +-------------------- TargetManifest <---------------+
                               |
Repo changes / schedule ------>|
                               v
Feeds -> Intel -> CASE ORCHESTRATOR <-> SQLite tasks/events + evidence files
                       |    |    |
                       |    |    +--> Gateway -> Mistral API (key held here)
                       |    +-------> Policy and resource/budget reservations
                       v
                 Sandbox launcher (sole runtime access)
                       |
            +----------+-----------------------------+
            | ISOLATED CASE                          |
            | baseline -> investigate -> finding     |
            |                       -> patch proposal |
            | fresh candidate -> tests + proof tools |
            +-------------------+--------------------+
                                |
                   manifest-bound acceptance policy
                         |                  |
                   reject/retry      approval or preauthorization
                                            |
                                  Deployment service
                                  staging -> canary -> health
                                            |
                                promote or rollback/reopen
                                            |
                                  refresh mirror/inventory
                                            |
                                        next cycle

Every stage -> OTel traces/metrics/logs -> collector/status/report
Every gate/authority change -> unsampled audit event + retained evidence
```

These boxes describe responsibilities. Process decisions are fixed in [the documentation map](README.md). The controller owns state and authorization, the gateway owns model credentials, the launcher owns runtime access, the deployment service owns destination credentials. Models propose actions; deterministic code controls effects.

## Data and authority boundaries

1. The controller receives an enrolled URL and owner policy. It fetches source through the gateway and never executes source locally.
2. Onboarding emits an immutable TargetManifest after sandboxed setup. Workers consume a manifest hash, not a moving Git branch.
3. Models receive bounded context and named capabilities. They never receive a Docker socket, deployment token, arbitrary host path or a generic internet-fetch tool.
4. A probe worker can reach its target network. The vulnerable target cannot reach management APIs, the gateway, evidence store or another project. Tool output is untrusted data.
5. Candidate source is executable untrusted code. It is built/tested only by isolated workers. No candidate can change protected tests, obligations, policy, build infrastructure or evaluator truth.
6. Verification binds to exact source, test/spec versions and candidate artifact. Promotion consumes that existing artifact; it does not rebuild a mutable branch.
7. Promotion takes a per-project lock and compares the enrolled base/deployment generation. A newer base makes the candidate stale; rebase, build and reverify before proceeding.
8. Evidence export succeeds before teardown. Correlation IDs travel across all components; audit events cannot be suppressed by a model.

## Lifecycle

Enrollment: NEW -> FETCHING -> PLANNING -> BUILDING -> READY, or NEEDS_CONFIGURATION / UNSUPPORTED / SETUP_FAILED.

A cycle captures one project snapshot and one trigger. QUEUED -> PREPARING -> DISCOVERING -> TRIAGING. Each confirmed finding opens a repair case: REPRODUCING -> PATCHING -> VERIFYING -> REVIEW_READY -> AUTHORIZED -> STAGING -> OBSERVING -> PROMOTED -> REFRESHING -> COMPLETE. A cycle can complete without findings; report NO_FINDINGS, not secure. Negative-control cases may complete as NO_CHANGE.

Non-success states: UNCONFIRMED, REJECTED, NEEDS_REVIEW, STALE, TIMEOUT, BUDGET_STOP, INFRA_FAILED, CANCELLED. Deployment recovery has ROLLBACK_PENDING -> ROLLED_BACK or RECOVERY_FAILED. Final statuses retain the last good state and reason. No timeout/error is converted into a pass. A failed probe is not proof of safety.

Several findings may share discovery evidence, but one repair case addresses one root cause. Findings describing the same root cause are grouped. Distinct cases are serialized for promotion; after a promotion, sibling cases are rebased/revalidated against the new deployed version. Deduplicate trigger replay by project/source/advisory revision/policy and findings by source/symbol/CWE/root-cause fingerprint.

## Deployment and assurance profiles

Default URL-only enrollment uses the owned lab and a preconfigured lab policy, permitting automatic stages and promotion if all declared gates pass. It never implies production authorization. A production profile defaults to review for generated source fixes; explicitly preauthorized classes can run automatically. An unconfigured production destination produces NEEDS_CONFIGURATION.

Two assurance profiles are explicit: `tested` requires security/functional gates and reports proof coverage; `formal_required` additionally requires specified linked proof obligations to pass under accepted assumptions/bounds. Scope never changes mid-case. `tested` does not mean formally verified. Every deployment and report carries its assurance profile.

## Component responsibilities and implementation sequence

| Component | Inputs -> outputs | Build steps | Acceptance |
|---|---|---|---|
| Onboarding | URL/policy -> TargetManifest | Detect, plan, validate, build, readiness, inventory | Rebuild from frozen inputs; failures explicit |
| Intel/detection | Snapshot + feeds -> Findings | Fetch/match, static, model review, scoped probes | Evidence reproduces; raw findings retained |
| Patcher | Finding + base -> PatchProposal | Upstream route or source route; apply cleanly | No protected-file edits; candidate tied to base |
| Verifier | Candidate + obligations -> GateResults | Positive/security tests, proof, artifact binding | Bad and good controls distinguished |
| Orchestrator | Events -> durable tasks/decisions | Leases, policy, budget, state recovery | Restart never duplicates promotion |
| Launcher | Validated task profile -> isolated job | Fixed mounts/network/limits, collection, teardown | No cross-case/control reachability |
| Deployment | Manifest + authorization -> running generation | Stage, observe, swap, recover, refresh | Failed rollout restores verified prior state |
| Observability | Events -> trace/report/audit | Correlate, redact, retain, alert | Decision trace recoverable after crash |

Detailed execution contracts and steps live in the linked component documents; do not implement from this diagram alone. The implementation and integration plans preserve every lifecycle stage.
