# Submission freeze

The measured submission includes the bounded shared-broker GLM formal workflow,
mandatory test fallback, fresh DSVW lifecycle, 24-repository compatibility campaign,
model triage, operator CLI/action center and the English two-page technical sheet.
The reports distinguish original snapshots, assisted variants, partial coverage,
failed setup and unsupported profiles. No official public-benchmark score is claimed.

The final remote review also found Kiro `3f03284`, containing additional benchmark,
CrossHair, fault, observability, safety and accessibility work, and red-team metrics
`cfc3029`, containing scanner/ranking changes. These remain available on their
remote branches. They were not blindly merged into the measured submission at the
last minute; they need integration review and affected runtime validation. Earlier
compatible CLI/red-team/runtime work is already integrated and attributed in the
teammate handoff. No teammate branch was deleted or rewritten.

Release validation: 220 Python platform tests, three frontend mutation-identity
tests, Ruff, documentation links, TypeScript/Vite production build, live CLI checks,
fresh full-cycle evidence, campaign artifact bindings and rendered PDF pages.
See docs/submission.md and evaluation/submission/README.md for actual outcomes.
