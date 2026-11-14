# Design audit and implementation readiness

Audited 14 November 2026. This audit checks the documentation, not a running system. No source repositories were built, proof tools executed, agents benchmarked or deployment environment accessed in this documentation task.

## Gaps resolved in this revision

| Previous gap | Resolution |
|---|---|
| Components did not fix transport/persistence choices | Python/FastAPI/Pydantic, single-writer SQLite WAL, typed local RPC and artifact store |
| URL onboarding lacked an executable contract | Versioned TargetManifest, recipe validation, explicit readiness/failure states |
| Timing/iteration unit ambiguous | Project/snapshot/cycle/case/candidate/task units; stage, case and cycle caps |
| Multiple findings could yield stale deployments | Per-project generation CAS and rebase/reverification after each promotion |
| Runtime restart could duplicate actions | Leases/outbox and deploy-intent reconciliation |
| Generic “formal verification” overstated coverage | Per-language adapters, named obligations, bounded/unknown outcomes and linked artifacts |
| Promotion described without precise rollback data semantics | Synthetic reset vs persistent migration/recovery policy; no image-only data guarantee |
| Evaluation lacked fixed labels and negative controls | Up to ten repos, scoped V/F/P/M/U labels, preflight lock and independent oracles |
| Parallel lanes had no merge procedure | Ownership, bootstrap-first worktrees, contract migration and sequential integration gates |
| Plug-and-play could hide manual setup | URL-only and assisted onboarding scored separately |
| Telemetry could be confused with audit | Sampled OTel separated from unsampled authority/evidence record |

## Consistency decisions

Architecture defines the full lifecycle; runtime.md owns numerical budgets and intervals; contracts.md owns states/fields; verification.md owns gate meaning; evaluation.md owns scoring. Other docs reference these rather than authorizing overrides. All examples are illustrative. Repository roster JSON is candidate-only and cannot be used as a frozen scored manifest.

Every implementation component now has steps and acceptance criteria. Four lane briefs map to exclusive source directories. The timing model distinguishes cold/warm, active/queue/human wait, no-change/repair, case/cycle and standard/heavy. Public benchmark components and end-to-end results are never conflated.

## Items requiring actual implementation preflight

1. Oracle architecture, kernel, disk capacity, runtime isolation and cgroup enforcement.
2. A safe untrusted build backend; gVisor on runtime containers alone does not prove Docker builds isolated.
3. Exact compatible package/tool/model versions, account quotas and current price snapshot.
4. All ten cohort revisions, image digests, source hashes, licenses, reproducible oracles and resource needs. Some may fail preflight; keep exclusions visible.
5. Correct source-to-runtime linkage and trusted-dependency inventory for each formal adapter.
6. Actual latency, repair rates, API consumption and human effort; planning estimates are not findings.
7. Local deployment and data recovery behavior under crashes; production adapters need separate destination configuration and authorization.

These are named validation tasks with owners and stop states, not unresolved choices for each lane to reinvent. Documentation is ready to guide implementation; execution readiness remains contingent on the milestone gates.

## Document checks

Run `python3 scripts/check_design_docs.py` after editing. It verifies local links, expected handoff files, candidate roster size/status, illustrative JSON readability and required runtime limits. This is a documentation consistency check, not a test of the cybersecurity system.

Before giving an agent a lane: provide AGENTS.md, docs/README.md and its brief, plus shared contract fixture commit once M0 exists. Before claiming the prototype works: attach M1–M5 evidence. Before claiming ten-repo performance: attach the frozen campaign and every result row.

## Revision 1.1 consistency review

- Original lifecycle retained: URL intake through recurring deployment, rollback and mirror refresh.
- User's 24 repos cataloged; ten candidates use stable U IDs; DSVW/VAmPI development and Vulpy heldout are separate. Legacy R IDs retired.
- Safe-mode/global-security assumptions removed; DSVW attack tests classified separately from protected functional tests.
- VAmPI REQ-1..4 are proposed, scoped policies with actual Dafny compilation and tested wrapper boundaries, not detached-model proof.
- GLM Flash default and provider/account evidence recorded in model-strategy.md; no unsupported quality ranking or automatic refusal evasion.
- Python campaign uses Dafny/CrossHair first; CBMC remains an explicit extension with no fake success.
- Two-page sheet, lane briefs, enrollment example, runtime calibration and benchmark language selection updated together.
- Ready to begin implementation means the handoff is coherent. Host/runtime/model capability and target-oracle preflight remain M0/M1 work, not completed validation.
