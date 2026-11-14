# Deployment recovery and observability

Owners C for deployment, A for telemetry/audit. Input: EvidenceManifest + artifact-bound Authorization. Output: DeploymentResult + refreshed TargetManifest. The local adapter is required; real production destinations are separate configured adapters.

## Local adapter

For web services, maintain a lab front door with a controller-owned routing configuration and isolated backend slots. Targets cannot modify the router. Deploy candidate into the idle slot, run readiness and a synthetic positive/security smoke suite, then route only synthetic canary traffic while observing. With no real traffic, readiness alone is not a canary: the load generator must exercise the workflows.

For libraries, build a small fixed consumer from the candidate artifact, switch a versioned artifact pointer, run its functional/security workload and retain the previous artifact. Call this consumer-harness promotion, not a production web deployment.

Every operation is under a project promotion lock and expected-generation compare-and-swap. Persist intent before execution. Reconcile observed digest/routing/generation after restart before repeating commands. Consume the exact verified digest; never rebuild during deployment. Expired authorization, stale source, policy/spec changes or evidence mismatch require reauthorization/reverification.

## Autonomy and credentials

`lab_auto`: automatic promotion of candidates meeting the enrolled assurance profile in an owned synthetic destination. `review`: pause at REVIEW_READY until operator approves exact manifest. `production_preapproved`: permit only owner-specified change classes/destinations/limits, with review as fallback. A public URL alone enrolls lab_auto, never third-party production.

Deployment credential is available only to the deployer, scoped to the target destination. Model agents cannot retrieve it. Local deployment uses a runtime action capability mediated by the launcher; it does not share the runtime socket with agents. Remote adapters require their own narrowly scoped credentials and TLS.

## Health and recovery

Default observation is 5 minutes for the standard lab profile, extended to 10 minutes for heavy profile. Check every 15 seconds, generating at least one positive workflow each interval. Required security smoke must pass before any promotion. Fail on any invariant/security-smoke failure, three consecutive readiness failures, or functional failure rate above the predeclared profile threshold. Default synthetic functional threshold: zero unexpected failures. Latency threshold is set from baseline before the candidate, not invented afterward; noisy/baseline-unstable results require review.

Rollback restores prior artifact and routing, then reruns recovery readiness/positive checks. Synthetic isolated evaluation data may reset to its known seed. For a persistent destination, default automatic promotion forbids schema migrations and irreversible side effects; an owner-defined snapshot/forward-recovery plan is required before enabling them. Image rollback is not data rollback.

A failed recovery enters RECOVERY_FAILED, preserves evidence and stops further promotions for that project. Do not claim success because an old image started. Record recovery correctness and elapsed time. Emergency recovery has its own 5-minute budget outside the expired case budget; it makes no new model calls.

If promotion succeeds but mirror refresh fails, keep the actual deployment generation recorded, mark the mirror STALE and block new investigations/promotions until refresh reconciles it. Never falsely record the old version as running. On a first deployment with no prior slot, recovery stops the failed candidate and reports destination unavailable; do not claim rollback without a prior artifact. A retained vulnerable lab baseline may be a recovery target for availability, but its known security findings remain disclosed.

Mirror refresh reads the observed promoted artifact/source manifest, not the latest upstream branch. Upstream source changes create a new generation/case. If an upstream fix arrives while a local patch is staged, mark conflict/stale and reconcile before promotion. Reference tests/specs remain pinned until an explicit profile revision. Second-cycle evaluation proves the new mirror contains the deployed fix and does not reopen the old issue erroneously.

## Observability

Instrument onboarding, builds, tool calls, model calls, verification, authority decisions, queue/lease transitions, deployment and refresh. OpenTelemetry trace IDs correlate with project/cycle/case/task/candidate/deployment IDs. Runtime performance signals: queue age, stage duration, CPU/RAM/disk, model latency/tokens/cost, feed age, failures, retry counts, proof outcomes, denial counts, deployment generation and rollback duration. [OTel signals](https://opentelemetry.io/docs/concepts/signals/).

SQLite audit_events and the outbox are the unsampled decision record. OTel traces may be sampled; sampling must never discard required audit evidence. Audit events include actor/capability, request hash, policy version, decision, reason and evidence IDs. Redact credentials/prompts as appropriate; retain raw bounded tool evidence separately with access controls. Source responses and logs are escaped, truncated and treated as hostile content. A local hash chain helps integrity checks only relative to a separately retained checkpoint; it is not immutable against host compromise.

Required operator UI can be server-rendered status/report pages plus JSON CLI output: project setup state, current/mirror version, active case/stage/deadline, findings and confidence, diff, gate/proof scope, authorization controls, cost, stale feeds and recovery events. No separate SPA or full Prometheus/Grafana/Loki stack is required. Export OTel to a collector and bounded local storage; add external backends through configuration.

Storage defaults: 100 MiB evidence per case, 1 GiB total task scratch per standard job (overridden for builds by resource profile), stop admitting new work below 10 GiB disk free. Keep all benchmark evidence through report completion and export; ordinary lab artifacts retain 7 days plus the current and prior deployment artifacts. Retention deletes only unreferenced case-owned artifacts after digest/index checks. Export evidence before target teardown.

## Implementation steps and acceptance

1. Implement Authorization checks and fake destination adapter.
2. Implement local slots/consumer pointer with generation CAS and durable intents.
3. Implement readiness, positive/security smoke, synthetic traffic and observation windows.
4. Implement rollback and restart reconciliation, then mirror refresh.
5. Instrument traces/events and minimal status/report UI.
6. Test health failure, stale generation, tampered artifact, process crash during swap, authorization expiry, lost audit writer, rollback failure, refresh failure and successful second cycle. No false COMPLETE status is allowed.
