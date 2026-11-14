# Illustrative contract inputs

`enrollment.json` shows a URL/ref enrollment request. `runtime-config.json` records the documented default limits in seconds and micro-USD. These are examples for implementing the schema/config loader, not installed commands or evidence of an executed run. M0 must validate them with the actual shared Pydantic contracts.

The roster at `evaluation/repository-candidates.json` contains unvalidated candidates with null commit/image/oracle fields. The scored runner must reject it. The preflight procedure creates the separate frozen campaign lock only after real validation; do not fill missing hashes with fabricated values.
