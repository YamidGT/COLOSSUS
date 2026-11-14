# Intelligence and bounded agent behavior

Owners B (intel/discovery) and C (repair). Agents are bounded jobs with shared broker access. No agent chooses its own authority, budget, retry cap or acceptance criteria. Runtime defaults live in runtime.md.

## Threat intelligence

Mandatory sources in v1: OSV for exact dependency matching; GitHub advisories through OSV aliases/full records or direct advisory lookup; CISA KEV for observed exploitation enrichment. CVE/NVD and vendor advisories provide optional detail through the same adapter interface; EPSS is a prioritization enrichment. Do not duplicate alerts from multiple sources. News articles can create hypotheses but cannot establish affected-version facts or authorize a patch.

Pipeline: fetch cache with source/fetched/modified time and content hash -> validate schema -> normalize IDs/aliases -> join resolved dependency ecosystem/name/version -> fetch full advisory -> label affected/not_affected/unknown -> prioritize and emit IntelEvent. OSV batch returns IDs and modification time; fetch complete records before presenting details. [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/).

Version matching uses ecosystem rules, not lexical string comparison. CVE aliases do not imply package equivalence. Presence of a vulnerable package and exploit reachability are distinct facts. KEV absence is not evidence of safety; EPSS probability differs from CVSS severity. Preserve conflicts and missing data. Use official vectors when available; validate predicted vectors and compute scores deterministically. [FIRST EPSS](https://www.first.org/epss/).

Cache snapshots for replay. Conditional requests, rate limits, retries and backoff are adapter-specific, within global deadlines. Intel failure retains cached data with age/stale flag; never invent “no vulnerabilities.” Live polls and historical advisory replay have separate modes and timestamps. Sandbox workers never fetch arbitrary links in advisories.

## Detection stages

T0: inventory/dependency scan, pinned local static rules and existing tests; no model. Use Semgrep for supported languages plus ecosystem-specific tools such as Bandit for Python. Avoid downloading mutable rules during scored runs. License/version availability is checked in preflight.

T1: GLM Flash low-effort triage under the [model strategy](model-strategy.md), deduplication, source-context analysis and closed-profile dynamic reproduction. Retain every raw finding; triage produces a disposition rather than deleting evidence. Review authorization logic and requirements where static checks lack context.

T2: deeper GLM Flash investigation with a calibrated high-reasoning profile, bounded fuzzing and additional hypotheses. Escalate confirmed high-impact issues, failed T1 reasoning or matching high-priority intelligence, within budget. Fixed probes and fuzz harnesses constrain effects; exploratory agent code runs only in the case worker, never the launcher/control plane. Tool execution is authorized by task profile; external targets remain inaccessible.

Finding confirmation requires reproducible evidence in a healthy baseline and a defined failure condition. A tool severity label or model claim alone is not confirmation. An unsuccessful probe leaves UNCONFIRMED, not fixed. Deceptive route names and canaries are not automatically vulnerabilities or negative labels; the evaluator defines expected behavior.

## Repair routes

Upstream: verify the advisory's fixed-version claim, compatibility and provenance; propose a dependency/lock change or known upstream commit. Do not blindly apply shell commands from advisories. Record this route as upstream even if a model selected it.

Generated: provide vulnerable snapshot, finding evidence, permitted files, accepted requirements and bounded tool access. Ask for a minimal structured PatchProposal. Apply exact replacements only if base-file hashes and old content match uniquely; ambiguity is rejected. Default limits: 5 files and 300 changed lines; target profile may override before the run. Protected tests/specs/harnesses/recipes/policy/generated verifier output cannot be changed through this route. New source files need a predeclared allowlisted directory.

Each candidate builds from pristine source. Compiler/tests/proof failures may return bounded diagnostic feedback for at most 3 total candidates. No automatic attempt to repair tests or weaken contracts. A dependency update changes the dependency inventory and manifest revision; all relevant gates rerun. Infrastructure fixes that affect host/cluster policy are separate reviewed configuration proposals, not source patches.

## Broker implementation

Use Mistral `/v1/chat/completions` through httpx with exact model IDs selected by a startup capability probe. Pin temperature/output limits/templates and record requested/returned model. Schema validity does not establish truth. Broker owns API key, validates task capability, assembles system instruction and reserves budget before dispatch. Two transient retries maximum; retries consume deadline and reservations. Fallback only for eligible transport/capability failures to an explicitly pretested model, labelled in results; refusals/policy blocks do not trigger model switching; benchmark runs do not silently mix models.

Treat source/README/tool output as untrusted data, limit context and redact secrets. Delimiters help organization but are not the security boundary. Never include evaluator truth or unrestricted host files. Record redacted prompts/responses or content hashes according to retention policy, provider request ID, usage and price snapshot. Ambiguous provider timeout retains reservation until reconciled; do not assume it was free.

## Implementation steps and acceptance

B: implement source adapters and alias deduplication -> deterministic matching fixtures -> T0 normalized outputs -> T1 triage retaining raw evidence -> probe confirmation -> T2 escalation -> CTIBench adapter. Verify fake/stale/conflicting advisories, unrelated version, no network, injection content and false suppression.

C: implement PatchProposal parser/applier -> known upstream route -> generated route -> isolated build -> bounded retry feedback -> dependency-manifest update -> CyberSecEval Instruct adapter. Verify protected edits/base mismatch are rejected, wrong fixes fail independent tests, valid fixes preserve useful behavior and all calls are charged once.

Do not promise T1/T2 outperform T0. The evaluation measures whether they do and where they fail.
