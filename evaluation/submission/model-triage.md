# Fresh GLM catalog triage

Measured: 2026-11-14T21:39:19.066872Z

Model calls: 11; settled cost: $0.004014; uncertain reservation: 0 micro-USD.

| ID | Repository | Outcome | Selected / available groups | Valid model judgments |
|---|---|---|---:|---:|
| U01 | erev0s/VAmPI | reviewed | 2 / 2 | 2 |
| U02 | fportantier/vulpy | unsupported | 0 / 0 | 0 |
| U03 | stamparm/DSVW | reviewed | 8 / 10 | 8 |
| U04 | we45/Vulnerable-Flask-App | reviewed | 8 / 8 | 8 |
| U05 | anxolerd/dvpwa | reviewed | 2 / 2 | 2 |
| U06 | payatu/Tiredful-API | partial_or_invalid_output | 3 / 3 | 1 |
| U07 | mattvaldes/vulnerable-api | reviewed | 8 / 14 | 8 |
| U08 | dolevf/Damn-Vulnerable-GraphQL-Application | reviewed | 3 / 3 | 3 |
| U09 | adeyosemanputra/pygoat | reviewed | 8 / 40 | 8 |
| U10 | digininja/DVWA | no_eligible_signals | 0 / 0 | 0 |
| U11 | webpwnized/mutillidae-docker | no_eligible_signals | 0 / 0 | 0 |
| U12 | juice-shop/juice-shop | no_eligible_signals | 0 / 0 | 0 |
| U13 | appsecco/dvna | no_eligible_signals | 0 / 0 | 0 |
| U14 | OWASP/NodeGoat | no_eligible_signals | 0 / 0 | 0 |
| U15 | OWASP/railsgoat | no_eligible_signals | 0 / 0 | 0 |
| U16 | snyk-labs/nodejs-goof | no_eligible_signals | 0 / 0 | 0 |
| U17 | globocom/secDevLabs | unsupported | 0 / 0 | 0 |
| U18 | OWASP/crAPI | reviewed | 8 / 15 | 8 |
| U19 | bridgecrewio/terragoat | no_eligible_signals | 0 / 0 | 0 |
| U20 | madhuakula/kubernetes-goat | unsupported | 0 / 0 | 0 |
| U21 | RhinoSecurityLabs/cloudgoat | reviewed | 8 / 94 | 8 |
| U22 | vulhub/vulhub | unsupported | 0 / 0 | 0 |
| U23 | sudo-project/sudo | reviewed | 1 / 1 | 1 |
| U24 | tukaani-project/xz | no_eligible_signals | 0 / 0 | 0 |

- One serial T1 request per eligible repository, at most eight deduplicated static signals.
- Only Python snippets were reviewed; helper scripts do not establish coverage of the repository's main language.
- Model judgments are unconfirmed; suggested probes are recorded but never executed.
- No gold adjudication, precision, recall, repair, formal proof or deployment score is claimed.
- No second provider or refusal bypass; incomplete outcomes stay in the denominator.

Reproduce while the normal local gateway is running:

```bash
uv run python scripts/check_catalog_triage.py --seconds 90
```

Exact commits, source/snippet hashes, call IDs, token accounting references and bounded verdicts are retained in [model-triage.json](model-triage.json).
