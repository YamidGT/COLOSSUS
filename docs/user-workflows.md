# How operators use COLOSSUS

Owner A; B/C/D supply accurate state and evidence. This is a planned interface, not currently installed software. [CLI](cli.md) and [frontend](frontend.md) are two clients of the same controller. Product and visual decisions live in [PRODUCT.md](../PRODUCT.md) and [DESIGN.md](../DESIGN.md).

## First use

1. An operator installs the future package/locked runtime, configures gateway credentials on the host, and runs `colossus doctor`. It reports setup requirements without exposing keys. `colossus serve` starts the trusted local services and operator endpoint on `127.0.0.1:8787`; it does not enroll or scan a target. Oracle users reach the same endpoint through SSH forwarding.
2. `colossus ui` opens the action center. A short-lived, single-use login code shown in the terminal establishes the local browser session. The CLI uses a separate host operator credential. There is no GitHub OAuth, provider-key entry form or third-party telemetry requirement for v1.
3. On “Add repository,” enter a public GitHub URL. Defaults are local lab destination, `lab_auto` policy and `tested` assurance. Plain copy says the system creates a local isolated copy and may promote passing repairs there. Advanced fields expose revision/subdirectory, review policy and existing approved requirement profile; no arbitrary shell/config editor.
4. Choose “Add repository” (setup only) or “Add and run” (one cycle after READY). The response immediately provides the project ID and link, while setup runs asynchronously. The UI presents actual stages and “Last updated,” not an invented completion percentage.
5. On unsupported stack, missing configuration or failed setup, show a specific cause and permitted remedy. “Retry setup” creates a new attempt against the same intended source revision, under its budget; changed configuration is a versioned update. Neither action erases the earlier failure.

## Daily repository action center

The repository list shows owner/name, setup/current state, decision count, last cycle time and deployed version. Selecting a repository opens its action center. It answers, in order:

- What needs my decision or intervention?
- What is running now, and is its information current?
- What changed and what evidence supports it?
- What is deployed, what can recover it, and when is the next cycle?

Action rows are derived from controller state, not model-generated instructions or a second ticket system. Order recovery failure, configuration/setup blockers, ready patch reviews, stale mirror/budget/feed warnings, then informational outcomes. Each has a stable ID, reason, source case/cycle link, age and an allowed next action. Empty queue: “Nothing needs your attention”; do not equate it with no vulnerabilities.

## Review and promotion

Open “Review patch” to see the reproduced issue, proposed source/dependency change, legitimate tests, security results, formal scope/assumptions, cost, destination and previous version. The server includes whether approval is currently permitted and why. An UNKNOWN formal result remains unknown; required failing gates block approval even if the operator can view the diff.

For `review` policy, “Approve for lab” confirms the exact manifest/digest, destination and expected generation. The server rechecks freshness and all gates on submission; a stale review returns a conflict and reloads the evidence. A clicked button cannot override gate failure. “Reject patch” records a reason, terminates that candidate's review and leaves the current deployment intact. Automated lab policy uses the same acceptance path without a human dialog; its decisions appear in the timeline.

After authorization, show staging, observation, promotion and refresh separately. A candidate is not “deployed” merely because tests passed. A deployment can be healthy while mirror refresh is blocked: show both facts. If recovery fails, surface persistent intervention guidance and stop further promotions. Manual rollback targets the retained prior artifact, displays data-recovery limits and uses a generation-bound action.

## Run, pause and stop

“Run cycle” starts one bounded cycle or returns the existing active cycle according to deduplication rules. “Pause schedule” prevents future automatic/manual admission until resumed; it does not kill an active worker or stop authorized recovery. “Cancel cycle” is a separate action: stop outstanding tasks, preserve evidence and complete required recovery for already staged effects. Cancellation remains pending until termination/reconciliation is observed. Resume permits future admission and coalesces missed periodic triggers; it does not replay every missed timer.

Stopping the local UI or closing the browser never cancels a cycle. An interrupted CLI watcher detaches without cancellation. Stopping the service explicitly drains/cancels work through launcher reconciliation; a process crash recovers from durable state on restart. UI/CLI disconnection cannot grant or revoke authority by itself.

## Evidence and exports

Each completed/failed cycle has a readable report with findings, candidates, gate outcomes, source/model/tool versions, costs, timings, deployments and limitations. Raw evidence is behind a secondary link with byte limits and escaped text. Export is redacted by default; target source, fixtures and provider usage may still be sensitive to the operator. Never expose gold heldout answers through ordinary project endpoints or put provider credentials in an archive.

## Interface acceptance tasks

D tests enrollment-to-report through both clients against the same API. Verify duplicate click/retry returns the same operation, a stale approval cannot promote, pause differs from cancel, offline UI never appears live, keyboard-only review works, and CLI failures return stable exit codes. Test the complete deployment/recovery/second-cycle path with real backend evidence; UI fixtures alone do not establish runtime correctness.
