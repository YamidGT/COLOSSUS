# Submission repository preflight

Generated: 2026-11-14T21:45:15.032247Z

All 24 catalog entries are retained. This is a compatibility/static pilot, not a security certification or a scored benchmark.

| ID | Repository | Source | Python signals | Setup | Software tests |
|---|---|---|---:|---|---|
| U01 | [erev0s/VAmPI](https://github.com/erev0s/VAmPI) | accepted | 2 | failed original pin; ready modified pin (assisted) | 6/6 bounded HTTP checks |
| U02 | [fportantier/vulpy](https://github.com/fportantier/vulpy) | rejected | — | not_run | not_run |
| U03 | [stamparm/DSVW](https://github.com/stamparm/DSVW) | accepted | 14 | ready (fresh full cycle) | protected_repair_gates_passed |
| U04 | [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | accepted | 8 | failed | not_run |
| U05 | [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) | accepted | 2 | unsupported | not_run |
| U06 | [payatu/Tiredful-API](https://github.com/payatu/Tiredful-API) | accepted | 4 | failed (assisted entrypoint/view) | not_run |
| U07 | [mattvaldes/vulnerable-api](https://github.com/mattvaldes/vulnerable-api) | accepted | 14 | unsupported | not_run |
| U08 | [dolevf/Damn-Vulnerable-GraphQL-Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | accepted | 3 | unsupported | not_run |
| U09 | [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) | accepted | 40 | ready (one BOPLA lab; assisted) | 7/7 bounded HTTP checks |
| U10 | [digininja/DVWA](https://github.com/digininja/DVWA) | accepted | — | unsupported | not_run |
| U11 | [webpwnized/mutillidae-docker](https://github.com/webpwnized/mutillidae-docker) | accepted | — | unsupported | not_run |
| U12 | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | accepted | — | unsupported | not_run |
| U13 | [appsecco/dvna](https://github.com/appsecco/dvna) | accepted | — | unsupported | not_run |
| U14 | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | accepted | — | unsupported | not_run |
| U15 | [OWASP/railsgoat](https://github.com/OWASP/railsgoat) | accepted | — | unsupported | not_run |
| U16 | [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof) | accepted | — | unsupported | not_run |
| U17 | [globocom/secDevLabs](https://github.com/globocom/secDevLabs) | rejected | — | not_run | not_run |
| U18 | [OWASP/crAPI](https://github.com/OWASP/crAPI) | accepted | 15 | unsupported | not_run |
| U19 | [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) | accepted | — | unsupported | not_run |
| U20 | [madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat) | rejected | — | not_run | not_run |
| U21 | [RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) | accepted | 96 | unsupported | not_run |
| U22 | [vulhub/vulhub](https://github.com/vulhub/vulhub) | rejected | — | not_run | not_run |
| U23 | [sudo-project/sudo](https://github.com/sudo-project/sudo) | accepted | 1 | unsupported | not_run |
| U24 | [tukaani-project/xz](https://github.com/tukaani-project/xz) | accepted | — | unsupported | not_run |

## Interpretation

- One source preflight per repository, with explicitly retained assisted runtime attempts; no gold adjudication or security score.
- Runner instrumentation evolved during this exploratory campaign; this is not a frozen performance benchmark. Source commits and per-attempt input hashes are retained.
- Python text-pattern signals are unconfirmed, not distinct proven vulnerabilities.
- No CTIBench, CyberSecEval or DafnyBench benchmark score is produced by this campaign.
- Fresh-inference DSVW full-cycle evidence is a separate integration run, linked in dsvw-full-cycle.json; other rows are compatibility preflights.

Static counts concern the original admitted source view. Assisted runtime subdirectories and dependency changes have separate hashes; PyGoat's runtime checks cover one lab only. Model rationales are unverified suggestions, not compatibility evidence; the observed build/tests decide outcomes.

Each JSON row retains the resolved commit, source hash where available, scope, failure reason, stage timing and plain fallback-testing instructions. Source intake failures remain in the denominator. `unsupported` does not mean secure.

## Observed execution and cleanup

Source intake: 24/24 entries recorded; {'accepted': 20, 'rejected': 4}. Python rule coverage: 11 repositories.
Catalog runtime attempts: 5; outcomes {'failed': 3, 'ready': 2}. The separately linked fresh DSVW lifecycle is additional. Original failed attempts remain in each row's runtime_attempts.
The commands below were executed on 14 November 2026. Ruff and Python compilation checks passed for the runner. Final cleanup inventory is in [cleanup.json](cleanup.json); only the pre-existing DSVW mirror was retained.

## Related measured experiments

- [Fresh DSVW full cycle](dsvw-full-cycle.json): separate integration-lane fresh inference, promotion, second cycle and rollback.
- [GLM triage](model-triage.json): separate bounded model review of static signals; not dynamic confirmation.
- [VAmPI setup advice](vampi-setup-advice.json): separately accounted model dependency proposal, when available.

## Reproduction

```bash
uv run python scripts/run_submission_campaign.py intake
uv run python scripts/run_submission_campaign.py runtime --assisted --ids U09 U01 U06 U04 U02 U03 U05 U07 U08 U10 U11 U12 U13 U14 U15 U16 U17 U18 U19 U20 U21 U22 U23 U24
uv run python scripts/run_submission_campaign.py runtime --assisted --vampi-compatible-wheels --ids U01 --seconds 120
```

Runtime uses the existing gVisor launcher; it never executes repository Dockerfiles or package hooks on the host. Cloud/Kubernetes/C targets are not deployed by this runner.
