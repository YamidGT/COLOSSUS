# Full repository catalog and evidence status

Stable IDs follow Daniel's original 24-item list, not the reordered difficulty table. This preserves the supplied context without treating AI-generated vulnerability inventories as verified findings. All links below are upstream repository entry points. **No target has been executed or locally preflighted.** “Documented” means upstream documentation/source was inspected, not that a defect was reproduced. Rows marked “supplied” preserve user hypotheses; verify their current stack, license, scenario and revision before admission.

## Python/API candidates

| ID / repository | Supplied stack and scenario inventory | Evidence / disposition |
|---|---|---|
| U01 [VAmPI](https://github.com/erev0s/VAmPI) | Flask API; SQLi, unauthorized password changes, BOLA, mass assignment, debug data exposure, enumeration, ReDoS, missing limits, weak JWT secret | README and selected source inspected. Development target. `vulnerable=0` still has unsafe behaviors; scope each control. |
| U02 [Vulpy](https://github.com/fportantier/vulpy) | Flask/SQLite; XSS, SQLi, CSRF, session impersonation, unsafe deserialization, login brute force, auth bypass | README documents categories and unfinished `good/`. Primary heldout; `bad/` runnable view, reference withheld. No role hierarchy assumed. |
| U03 [DSVW](https://github.com/stamparm/DSVW) | Small Python server with Docker; XSS, SQLi including time-based, local/remote XXE, blind XPath | README inspected: Python 3, XML scenarios depend on lxml, upstream tests preserve attacks. Smoke target; choose a bounded non-DoS case. |
| U04 [Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Claimed single Flask app/11 routes: SQLi, unsafe YAML, SSTI, disabled JWT checks, secrets, MD5/plaintext passwords, IDOR, card exposure, unauthenticated registration, credential logs, uploads/possible XXE, error leakage | Repository located; detailed code inventory and Python-2-era compatibility claim remain supplied/unverified. Deferred legacy preflight. |
| U05 [DVPWA](https://github.com/anxolerd/dvpwa) | Supplied aiohttp/Postgres/Redis; fixation, SQLi, stored XSS, unsalted MD5, CSRF, authorization, cookie/debug/input/brute-force weaknesses | Repository located; per-defect source validation pending. Deferred multi-service Python candidate. |
| U06 [Tiredful-API](https://github.com/payatu/Tiredful-API) | Django REST; information leakage, IDOR/access control, throttling, SQLi, XSS | README inspected; legacy dependency risk and upstream-linked newer forks. Holdout compatibility fallback, selected before scored exposure. |
| U07 [vulnerable-api](https://github.com/mattvaldes/vulnerable-api) | Bottle/Docker; TLS, enumeration, headers, auth bypass, input/errors, SQLi, sessions/crypto, command injection, ReDoS | README inspected; old tooling references. Scenario details and buildability require validation. Deferred legacy candidate. |
| U08 [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | Flask/Graphene; schema exposure, batching/depth/alias DoS, SSRF, commands, stored XSS, HTML/log injection, SQLi, JWT, denylist bypass, path/file writes | README inspected; use this canonical URL, not guessed `dolevf/DVGA`. Optional static-only. Count neither DoS probes nor full-cycle repair success. Exposure is policy-dependent. |
| U09 [PyGoat](https://github.com/adeyosemanputra/pygoat) | Django OWASP labs: injection, auth/access, XXE, XSS, deserialization, SSRF, crypto, SSTI, components, logging/integrity | Broad training-project purpose documented; supplied exact lab counts/build >10 minutes unmeasured. Deferred heavy candidate. |
| U18 [crAPI](https://github.com/OWASP/crAPI) | Multi-service API: BOLA/BFLA, auth, excess data, missing limits, mass assignment, SSRF, NoSQLi/SQLi, JWT; supplied optional LLM chatbot/injections | Broad training-project purpose documented; exact challenge count and chatbot topology require snapshot verification. Deferred heavy candidate. |

Primary sources for corrections: [VAmPI application switch](https://github.com/erev0s/VAmPI/blob/master/app.py), [user serialization](https://github.com/erev0s/VAmPI/blob/master/models/user_model.py), [Vulpy README](https://github.com/fportantier/vulpy), [DSVW requirements/tests](https://github.com/stamparm/DSVW), [Tiredful README](https://github.com/payatu/Tiredful-API), [DVGA README](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application). Date inspected: 14 November 2026. Moving branch URLs are source pointers; frozen evidence must retain exact commits.

## Other language applications: deferred, supplied inventory

These are useful future adapter/evaluation candidates; their presence is not a requirement to implement every language during the initial campaign. Exact scenario counts and current build stacks below are not independently validated here.

| ID / repository | Supplied context |
|---|---|
| U10 [DVWA](https://github.com/digininja/DVWA) | PHP/MySQL; low/medium/high/impossible modes. Brute force, commands, CSRF, file inclusion/upload, CAPTCHA, SQLi/blind SQLi, weak sessions, DOM/reflected/stored XSS, CSP bypass, redirect, crypto and authorization. Modes are not universal safety labels. |
| U11 [Mutillidae Docker](https://github.com/webpwnized/mutillidae-docker), [application](https://github.com/webpwnized/mutillidae) | PHP/MySQL Compose; supplied 40+ scenarios including SQLi, XSS, CSRF, commands, file inclusion, XXE, auth/session and redirects. |
| U12 [Juice Shop](https://github.com/juice-shop/juice-shop) | Node/Express/Angular; supplied 100+ challenges across SQLi/NoSQLi, XSS, authorization, JWT, XXE, SSRF, deserialization, data, crypto and dependencies. |
| U13 [DVNA](https://github.com/appsecco/dvna) | Node/Express; OWASP 2017 injection, auth, exposure, XXE, access, configuration, XSS, deserialization, components and logging. |
| U14 [NodeGoat](https://github.com/OWASP/NodeGoat) | Node/Express/MongoDB; server-side JS/NoSQL injection, auth/session, XSS, object references, config, data, CSRF, components, redirects and ReDoS. |
| U15 [RailsGoat](https://github.com/OWASP/railsgoat) | Ruby/Rails; SQLi/commands, XSS, CSRF, auth, mass assignment, object references, config and redirects. |
| U16 [Goof](https://github.com/snyk-labs/nodejs-goof) | Node/Express/MongoDB; vulnerable dependencies, NoSQLi, XSS, prototype pollution, ReDoS, commands and traversal. |
| U17 [secDevLabs](https://github.com/globocom/secDevLabs) | Multiple languages/labs; supplied Python, Go, PHP, Node and Java with Docker. Select one app, never treat the whole collection as one runnable service. |

## Infrastructure/cloud: distinct experiment, deferred

| ID / repository | Supplied context and boundary |
|---|---|
| U19 [TerraGoat](https://github.com/bridgecrewio/terragoat) | Terraform AWS/Azure/GCP misconfigurations: exposure, encryption, network permissions, secrets, logging. Static IaC evaluation is distinct from web exploitation and runtime patching. |
| U20 [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | Kubernetes labs: image secrets, escapes, RBAC, metadata SSRF, privileged pods, network policies. Requires a separately isolated cluster threat model. |
| U21 [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) | Real AWS/Terraform scenarios: IAM escalation, storage, Lambda/EC2 and credentials. No cloud deployment, costs or real cloud credentials authorized by inclusion here. |
| U22 [Vulhub](https://github.com/vulhub/vulhub) | Per-CVE Docker Compose environments for popular software. Each selected environment requires its own pinned snapshot, oracle, resource and isolation preflight; not a single target. |

## Historical motivation only

| ID / repository | Supplied incident context and use |
|---|---|
| U23 [sudo](https://github.com/sudo-project/sudo) | CVE-2021-3156 (Baron Samedit), C heap overflow/privilege escalation. Not a current target and no exploit execution planned. |
| U24 [XZ Utils](https://github.com/tukaani-project/xz) | CVE-2024-3094 supply-chain backdoor. Do not pitch it as an ordinary code bug our patcher has demonstrated fixing; trusted provenance/restoration is a different response. |

Verify original advisories before placing incident details or impact figures in the pitch. No benchmark evidence may be inferred from this catalog.

## Admission steps

B checks setup metadata and architecture; D checks license, selected behavior and evaluator feasibility; A checks resource/isolation profile; C confirms deploy/rollback support. Use [cohort freeze procedure](repository-cohort.md). Expanding target scope requires a manifest revision before scored runs. Preserve rejected/excluded candidates with reasons; never select only repositories on which the model already succeeded.
