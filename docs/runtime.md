# Runtime units timing and recurring schedules

Owner A. All durations below are initial engineering budgets/estimates for a 4-CPU, 24-GB host with remote Mistral inference. They are not benchmark measurements or completion guarantees. Setup compatibility, solver difficulty and human waits can dominate.

## Units of work

- Project: enrolled repository/subproject and destination.
- Snapshot: immutable source/image/configuration/dependency/spec state.
- Cycle: one trigger evaluated against one snapshot; owns discovery and zero or more repair cases.
- Finding: one suspected root cause; duplicates are linked.
- Repair case: one root cause and one base snapshot through repair, verification and optional promotion. One case may resolve several duplicate findings.
- Candidate attempt: one proposed patch, fresh build and required checks. Maximum 3 per case, not 3 attempts per individual tool.
- Tool task: one bounded scanner, probe, build, test or proof job.
- Recurrence: a new cycle after a schedule/source/advisory trigger or mirror refresh. It is not an unlimited repair retry.

A complete remediation cycle ends only after successful promotion, observation and mirror refresh. Review-required cases end active computation at REVIEW_READY and remain pending. A no-finding cycle can finish successfully without demonstrating repair. Report these separately.

## Expected wall-clock duration

| Situation | Planning estimate | What it includes |
|---|---|---|
| Warm small target, one successful candidate | 15–40 minutes | Discovery through lab promotion, 5-minute observation and refresh |
| First small target from GitHub URL | 25–60 minutes | Adds source/setup/build/dependency cache preparation |
| Multi-service app or native library with difficult proof | 60–120 minutes | Larger setup/tests/proofs, heavy profile if declared |
| Repeated no-change monitoring scan | 2–10 minutes | Cached inventory/static scan and report; no repair/proof rerun unless invalidated |
| Review-required production action | Above + unbounded human wait | Human approval time is not a computational estimate |

Illustrative standard first cycle: 10 setup + 2 snapshot/readiness + 5 investigation + 2 triage/reproduction + 3 patch + 5 build/tests + 3 proof + 1 policy/stage + 5 observation + 2 refresh = 38 minutes. With a cached setup the same example is 28 minutes. A failed candidate adds another patch/build/verification attempt within the case cap. Hard stage caps do not imply every stage can consume its maximum three times.

The suggestion that DSVW guarantees a complete cold cycle in ten minutes is not adopted. A cached smoke/replay can be shorter, but must report its actual stages and cannot substitute for a fresh URL-to-deployment measurement. The required five-minute observation remains part of a real promotion.

## Standard stage limits

| Stage | Typical planning range | Hard cap | Retry rule |
|---|---|---|---|
| Cold onboarding, dependency setup, readiness | 5–20 min | 20 min | At most 2 recipe revisions, within cap |
| Warm snapshot readiness | 1–3 min | 5 min | 1 restart only for infrastructure failure |
| Red-team investigation, including T0/T1/T2 work | 3–10 min | 15 min total per cycle | Tiers share the slice; no fresh 15 min per model |
| Triage and reproducibility confirmation | 1–3 min | 5 min | At most 2 reproduction executions |
| Patch model and proposal validation | 1–4 min | 6 min per candidate | Count in 3-candidate total |
| Candidate build plus functional/security checks | 3–10 min | 12 min per candidate | Infra retry consumes same stage/case budget |
| Formal checks | 1–5 min | 8 min per candidate | Default 90 seconds per obligation, max 5 obligations; retries fit remaining slice |
| Policy and staging preparation | 1–2 min | 3 min | Idempotent recovery only |
| Health observation | 5 min | 5 min observation + 2 min startup allowance | Failure triggers rollback, not repeated observation to hide failure |
| Mirror refresh and post-promotion scan | 1–3 min | 5 min | 1 idempotent retry within cap |

Standard active case cap: **90 minutes**, including attached cold setup/discovery if this is the first case. The controller also enforces a **120-minute cycle cap** across all cases sharing discovery; it may defer remaining findings to later cycles. Heavy profile: **180-minute case / 240-minute cycle**, onboarding 45 min, investigation 30 min, build/tests 30 min, proof 20 min, observation 10 min. Select profile before execution; no automatic extension to obtain a pass. Human review time and time waiting for initial host dispatch are reported separately; release workers while awaiting review. After dispatch, internal waits/retries count against the active deadline. On resume after human approval, create a new bounded deployment task and recheck artifact freshness/authorization; do not extend the earlier repair deadline or preserve a suspended worker.

For cycles with multiple cases, discovery is charged once to the cycle and attributed without double-counting. Cases have their own active-time limit starting at dispatch; cycle deadline wins if earlier. After each promotion, refresh/rebase remaining cases; never deploy parallel stale patches.

A global scheduler deadline bounds all nested deadlines: `effective_deadline = min(task_deadline, stage_deadline, case_deadline, cycle_deadline)`. On timeout send termination, wait 10 seconds then force stop; do not accept late results from the expired attempt. Reserve up to 5 additional minutes for deterministic emergency rollback, with no model calls. Incomplete recovery is RECOVERY_FAILED, not success.

## Scheduling defaults

| Trigger | Interval or rule |
|---|---|
| Source revision poll | Every 5 min; webhook can replace polling; debounce 60 sec |
| OSV/KEV/advisory refresh | Every 15 min, honor upstream rate limits and cache |
| Inventory/static check | Every changed snapshot and daily reconciliation |
| T1 recurring review | Every 6 hours per enrolled project, staggered |
| T2 deeper review | Daily per project, staggered; also confirmed critical/advisory escalation |
| Post-promotion refresh | Immediately after successful observation |
| Resource reaper | Every 60 sec |
| Health checks during rollout | Every 15 sec |

If a cycle is active, coalesce duplicate triggers; store newer source/advisory revisions for the next snapshot. No overlap per project. Priority: recovery, confirmed exposure, relevant exploited advisory, source change, periodic scan. Age lower-priority jobs to avoid starvation. Stale intel older than twice the intended poll period is visibly flagged; source-specific outage does not imply no exposure. Manual triggers still obey quotas.

## Resource scheduling

One heavy worker at a time, with a host-wide semaphore. Initial allocation: worker up to 2 CPU/6 GiB; target stack aggregate up to 1 CPU/6 GiB; control/gateway/launcher/deployer/collector reserve 1 CPU/3 GiB; leave about 9 GiB for OS/cache/headroom. Candidate and baseline share target-stack allocation; if both cannot fit, run equivalent seeded tests sequentially and report that mode. Heavy profile can use up to 12 GiB worker memory only after target/control allocation check. Enforce actual cgroups and monitor limits; never assume rootless limits took effect.

At most 2 concurrent API requests across lanes; a case allows 20 model requests including retries, within budget. Context defaults: up to 24k input tokens / 4k output; proof/patch profiles may request 32k/8k with reservation. Target HTTP default 2 requests/sec, 200 requests per investigation slice, 64 KiB request body and 1 MiB retained response. Fuzz profiles have their own offline execution budget, not the HTTP cap.

## Money and accounting

$150 total available credit. Automated ceiling $120, leaving $30 contingency not automatically consumed. Per-case cap $2; a higher cap requires a predeclared campaign profile. Reserve worst-case request cost atomically before sending, reconcile actual usage, count retries, retain uncertain charges and stop new calls when the next reservation would exceed a cap. Model profiles and the verified GLM Flash starting-price snapshot are in [model-strategy.md](model-strategy.md); rates are refreshed from the provider/account before admission. Reported 1M TPM is an account observation, not a reason to raise global concurrency or deadlines. [Mistral pricing](https://docs.mistral.ai/inference/pricing).

Suggested $120 allocation: $15 development/capability calibration, $30 public benchmarks, $60 repository campaign including baselines, $15 safety/recovery reruns. These are ceilings, not predicted spend. At $60 for 60 primary runs, average primary-plus-allocated-overhead cost must fit roughly $1/run; a $2 per-case cap alone does not guarantee that. Run pilot accounting before admitting the full campaign.

## Ten-repository campaign duration

Proposed 2 labelled case variants per repo x 3 repetitions = **60 primary runs**. At 20–45 minutes active time each: **20–45 serial host-hours**, plus cold setup roughly 2–6 hours. A second cycle of 10–25 minutes for every primary run adds **10–25 hours**. Baselines add more measured time; paired verifier ablations can reuse candidates rather than regenerate all patches. Thus the primary recurring campaign alone can need **32–76 host-hours**, before separate baseline/benchmark jobs. Not all these runs are full repairs: negative controls may finish faster.

Do not promise ten repos x repeated full cycles within an eight-hour event on one four-core host. The implementation can support the whole campaign while DSVW/VAmPI calibration and a separate Vulpy heldout run are attempted during the event; completion depends on actual build/runtime measurements. Additional local hosts increase throughput only with separate isolated workers and a shared budget ledger; they do not shorten individual proofs. Schedule the expanded campaign after pilot measurements, keeping incomplete rows visible. This is an evaluation budget distinction, not a reduction of the product architecture.

## Calibration implementation

Instrument every stage with queue/start/end times. Run DSVW, VAmPI and the guided VAmPI compiled-policy fixture; preserve Vulpy for heldout scoring and do not calibrate on its results; report cold and warm caches separately. Replace planning estimates with observed median/max once available and retain the original limits in results. Use deterministic fixture replay for fault tests; label it, and never count replay as fresh model latency or new repair success.

## Operator client refresh

Visible active-project UI and CLI watch poll every 2 seconds; idle/list views every 10 seconds. Hidden browser tabs pause polling; transient read failures back off to 30 seconds and show stale state. These are read refreshes, not new investigation cycles and incur no model calls. Server timestamps/deadlines remain authoritative. Small static frontend assets share the controller's existing process/resource reserve; no extra Node server runs in the deployed stack.
