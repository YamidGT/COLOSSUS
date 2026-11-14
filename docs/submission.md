# COLOSSUS submission and reproduction guide

Updated 14 November 2026. This guide describes the measured prototype and its limitations. The older architecture documents describe the larger intended system; they are not a claim that every adapter or acceptance scenario has been completed.

- [English technical sheet, PDF](../output/pdf/colossus-technical-sheet.pdf): two pages, following the supplied DefAcc template.
- [Technical sheet text](technical-sheet.md).
- [Committed evidence summary](submission-evidence.json): measured values, scope and SHA-256 references to earlier local artifacts.
- [Implementation ledger](implementation-status.md): broader completion status and historical checks.

## What the operator can demonstrate

Give COLOSSUS a public GitHub repository URL. Supported setup produces an isolated local application and immutable source/runtime manifests. The operator can inspect findings and evidence in the CLI or repository action center. A supported repair case uses GLM through the shared Mistral gateway; independent checks decide whether the candidate is eligible for lab deployment. A deployment observes health for five minutes, promotes the existing artifact, refreshes the investigation mirror and supports a subsequent cycle and rollback.

The first complete calibration target is [stamparm/DSVW](https://github.com/stamparm/DSVW), pinned to `9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908`. This is a deliberately vulnerable training application, not a public deployment. Its measured SQL-query repair is a scoped success, not a claim that all DSVW vulnerabilities are fixed.

The [fresh full-cycle result](../evaluation/submission/dsvw-full-cycle.json) completed URL intake, new GLM patch generation, mandatory checks, the 300-second observation, promotion and mirror refresh in **330.690 seconds**. One model call cost **$0.001287**, with no uncertain charge. The second cycle returned `NO_CHANGE` (no additional supported repair, not absence of vulnerabilities). Rollback to the deliberately known-vulnerable retained training baseline took **8.166 seconds**. The audit chain validated and calibration resources were retired. Formal coverage for this SQL adapter remains `UNSUPPORTED`.

## How the formal fallback works

The LLM performs candidate construction and repair. The platform supplies approved templates, immutable specifications, bounded retries, isolated proof tools and recorded diagnostics. The verifier decides proof success. Compiled output must match retained hashes and pass wrapper checks before it can support a claim about running code.

Plain operational instructions:

1. Start with the candidate patch, affected code and registered requirements.
2. If a compatible approved template exists, ask GLM for the permitted implementation fields. Freeze the specification; do not let the model weaken it.
3. Run Dafny in the existing sandbox. Return bounded diagnostics for at most three attempts within the overall deadline.
4. Preserve model-call IDs, source/spec/toolchain hashes, outputs, costs and the exact verified scope.
5. If no compatible template exists, record `UNSUPPORTED`. If verification is inconclusive or times out, record `UNKNOWN` or the failure reason. Do not present either as proof.
6. Run the protected software security and legitimate-behavior checks regardless of optional formal outcome. Under `tested`, passing those required gates can permit deployment with the formal limitation visible. Under `formal_required`, missing or failed required proof blocks deployment.

The owned authorization-policy fixture proves four methods and compiles them to Python. Its wrapper checks do not establish that DSVW or VAmPI uses that policy. DSVW's current SQL repair therefore retains formal `UNSUPPORTED` coverage. New business requirements remain proposals until approved.

## Local use

Use the repository's locked Python environment and the dedicated runtime described in [sandbox setup](onboarding-sandbox.md). The measured host was a local 4-CPU, 8-GiB Linux ARM64 Colima VM running gVisor; the available 24-GB Oracle machine was not the measured host. Do not run vulnerable applications on the management host or substitute a repository Dockerfile for the isolated builder.

Keep provider keys only in the ignored, owner-readable root `.env`. The gateway alone reads them. Groq is disabled by default. Model calls share the existing USD 120 automated ceiling; USD 30 remains reserved.

```bash
uv sync --locked
uv run colossus doctor
uv run colossus serve
```

`doctor` still reports full-product acceptance as incomplete; inspect individual readiness checks. In another terminal:

```bash
uv run colossus ui
uv run colossus enroll https://github.com/stamparm/DSVW \
  --ref 9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908 --run
uv run colossus projects
```

Use the returned project ID with `colossus status PROJECT_ID --watch` and `colossus actions PROJECT_ID`. Use actual case and cycle IDs for `colossus case CASE_ID --diff` and `colossus report CYCLE_ID --output report.json`. HTTP acceptance is not completion; inspect the terminal cycle state, deployment state and mirror digest. Closing a watcher does not cancel work.

## Reproduce the checks

The integrated platform suite passed **220 tests**. Ruff, three targeted frontend intent tests and the frontend production build passed; the initial JavaScript bundle was **89.28 kB gzip**. A separate [live CLI smoke](../evaluation/submission/cli-smoke.json) exercised six commands against the HTTP API, checked diff/report binding and emitted one JSON envelope per command. Its dispatch was disabled; it started no target jobs or model calls. It is interface evidence, not a second lifecycle result.

Platform tests do not launch a campaign against every public repository:

```bash
uv run pytest -q
uv run ruff check src tests scripts
python3 scripts/check_design_docs.py
```

With the configured isolated runtime and previously built Dafny toolchain:

```bash
uv run python scripts/check_formal.py
```

That command exercises the owned policy fixture, four wrong implementations, wrapper behavior and compiled-file binding. It does not call a model or prove a public repository.

The model-assisted version uses the same broker and retained toolchain:

```bash
uv run python scripts/check_formal_agent.py
```

The measured fresh GLM call proved and compiled the four-method owned component in **5.496 seconds**, excluding subsequent wrapper packaging, for **$0.000078**. It passed the packaged wrapper and rejected the bypass mutation. [Full workflow evidence](../evaluation/submission/formal-agent.json) and [workflow details](formal-agent.md) retain scope and assumptions. This is not proof of a public target.

A fresh full DSVW calibration uses:

```bash
uv run python scripts/check_full_cycle.py
```

It makes bounded gateway model calls, includes the real five-minute observation, runs a second cycle, exercises rollback and tears down its local targets. Its historical replay mode is separately labelled. Rollback in this training scenario intentionally restores a retained known-vulnerable baseline; it is a recovery-mechanism test, not security remediation.

## Expanded repository evaluation

Daniel's final instruction authorizes evaluation of all 24 catalogued repositories, superseding the earlier DSVW-only runtime limit. The time-bounded submission campaign records immutable intake and static inspection where supported, then bounded isolated runtime setup for eligible applications. Cloud infrastructure, privileged cluster scenarios and unsupported language/service adapters receive explicit non-execution reasons. No cloud credentials or paid infrastructure are assumed.

The [final per-repository report](../evaluation/submission/README.md) retains all 24 entries: 20 accepted archives and four archive rejections. Eleven repositories had Python text-rule coverage. Final repository-level setup outcomes were three ready rows (DSVW plus two assisted application views), two failed, 15 unsupported and four not run after intake rejection.

The catalog runner made **five runtime attempts: two ready and three failed**. This includes VAmPI's original failed dependency setup and its separately recorded successful compatibility variant. The fresh DSVW lifecycle is an additional integration run, not part of those five attempts. VAmPI's GLM-advised MarkupSafe 2.1.2 to 2.1.5 variant started in **42.994 seconds** and passed **6/6 bounded HTTP checks**. The evaluator-selected PyGoat BOPLA sub-lab started in **18.932 seconds** and passed **7/7 checks**; this is not the full PyGoat application. Both observation cycles returned `NO_CHANGE` with unsupported repair/formal coverage and no promotion. These HTTP checks are limited smoke/authentication checks, not proof that either target is secure. Tiredful-API failed wheel installation for its pinned oauth package; the legacy Flask app failed readiness. Original failures and assisted changes remain in the result rows.

The campaign is a compatibility and capability audit. These development measurements were taken during implementation, not under a single frozen comparative-benchmark revision. It is not 24 full successful repair cycles, a heldout accuracy study, or a ranking of repository security. Failed downloads, setup failures, timeout, unsupported repair and missing proof remain visible. No missing result is counted as a negative finding or a successful patch.

A separate [fresh GLM triage run](../evaluation/submission/model-triage.md) made 11 calls across 11 repositories with eligible Python snippets. It returned 57 valid judgments for 59 selected deduplicated signal groups in 31.366 seconds, costing $0.004014. Ten repository rows were fully reviewed; Tiredful-API returned only one of three requested judgments. These are **unconfirmed model judgments**, not 57 vulnerabilities or an accuracy score. Python helper-script inspection does not establish coverage of C or cloud infrastructure. All 24 requested repositories remain in the accounting.

CTIBench, CyberSecEval and DafnyBench remain **not run** in this submission. The repository preserves their intended evaluation protocols, but the local tests and owned Dafny fixture are not substitutes for those public benchmark scores.

## Evidence and claims

Earlier raw artifacts remain in the ignored local `artifacts/bootstrap/` directory because they include detailed runtime context. The committed evidence summary preserves selected nonsecret measurements and SHA-256 references. New submission campaign results are retained separately with their scope and provenance. Re-running a measurement creates new evidence; it must not silently replace the provenance of the earlier result.

The verified behaviors include scoped DSVW repair checks, an observed local deployment lifecycle, component proof controls and isolation checks. Remaining limits include generic repair adapters, broad stack support, production authorization, complete restart/failure acceptance, full UI accessibility acceptance and the three required public benchmark campaigns. A successful local example does not prove universal setup, model alignment, sandbox invulnerability or production readiness.

## Build the PDF

The PDF generator reads the committed evidence summary and does not call a provider or run targets. In a documentation environment with ReportLab:

```bash
python scripts/build_technical_sheet.py
```

Re-render and inspect both pages after changing results. The final PDF must remain at most two pages and 10 MB; shorten text instead of shrinking the body font. Team identities and contact details not supplied by the team have not been invented.
