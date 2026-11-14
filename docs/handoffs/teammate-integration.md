# Teammate integration record

Remote discovery on 14 November 2026 found `lane-b/redteam` at `615f65f` and the Kiro M0 branches culminating in `kiro/integracion` at `39f4508`. The implementation branch already contained the shared controller/runtime foundation and real gVisor/DSVW evidence. Preserve one contract and one budget authority; do not install a second competing controller from another branch.

## Lane B merge

Merged the red-team branch with integration changes. Retained its Python static rules, grouping, structured triage, injection markers, closed probe profiles and OSV/KEV matching direction. Adaptations are required by the existing architecture:

- Removed direct provider-key loading and the independent in-memory budget counter. Detection now calls the existing controller broker and gateway; no refusal fallback or independent model selection.
- Static target analysis runs through the launcher. Trusted analyzers use Python isolated mode and a protected helper directory so target files cannot shadow analyzer imports. Bandit absence is an explicit coverage gap, not an empty successful result.
- Probes address a project-owned environment through the launcher; callers cannot supply a base URL or resolve arbitrary hosts. SQL errors and raw reflected tags remain signals, not confirmed exploits. Traversal requires a declared synthetic canary; `/etc/passwd` is not mislabeled as one.
- Feed requests run through a fixed-origin gateway adapter, retain bounded raw-response hashes and freshness/error states, distinguish unknown KEV from false, and label package applicability separately from reachability.
- Raw findings survive hostile or invalid triage. Tests exercise that boundary. Injection marker detection is not a measured prompt-injection resistance score.

The original branch's generated contract foundation is already the common ancestor (`8342888`); no duplicate schema tree is imported. This integration adds a T0 rule pass to the current cycle. T1/T2 triage adapters are implemented but not enabled by default until scheduler/budget integration is completed. Feed polling/caching remains a separate controller step.

## Kiro review

Its M0 contracts, launcher and CLI overlap the active implementation and use different field layouts/modules/runtime labels. Do not replace working interfaces wholesale. The reported Docker tests used trusted fixtures under runc on another host; they are useful hardening evidence but not proof of this host's gVisor configuration. The current implementation has its own actual runsc evidence.

The recipe-validator logic, additional hostile fixtures and doctor check vocabulary are useful candidates for selective porting. Their original defaults assume a Linux host and must be adapted to inspect the configured VM/runtime on this macOS machine. The doctor must not become a second reader of provider secrets. Integration is still pending for these pieces; no claim that all Kiro branches have been merged.

## Kiro selective port completed

Ported `sandbox/recipe_validator.py` from `kiro/integracion` (original A-M0-02 work) into the existing package. Hardened named-volume declarations against `driver_opts` host binds, rejected malformed mount/environment shapes, host-variable interpolation, nonpositive/nonfinite CPU and memory limits, and retained digest/privilege/network/credential guards. Added hostile-shape tests. This validator evaluates plan data only; it does not authorize executing an arbitrary repository Dockerfile. The alternative Kiro launcher and contract modules are not installed alongside the current authority.

## Kiro integration based on the implementation branch

Merged `origin/kiro/integracion-fs` after inspection: real host/runtime doctor checks and a second Docker-create policy check, with its regression cases. Retained the already hardened recipe validator from the implementation branch when resolving add/add conflicts. The doctor inspects `.env` metadata only; it does not read provider values (the original proposal did). Added rejection of duplicate authority flags, `--read-only=false`, missing/zero resource bounds and unpinned images. This integration adds explicit private IPC. Observed combined suite: 113 passed. Live doctor detects ARM64 gVisor on `colima-colossus`; overall pipeline remains under construction. The teammate's original handoff describes its own host/results, not evidence from this machine.
