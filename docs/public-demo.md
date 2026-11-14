# Public recorded demo

Public URL: https://colossus-defence-demo.netlify.app (deployment verified separately).

This static React/Tailwind walkthrough displays the actual committed DSVW repeat-cycle evidence, candidate gate outcomes, separate formal-component experiment and 24-repository compatibility campaign. It is an interactive record of completed runs, not a hosted executor. The authenticated local operator application remains unchanged.

The public page cannot enroll repositories, run probes, call a model or deploy a target. It contains no backend, provider keys or execution endpoint. Its content-security policy disables network connections and embedding. Evidence downloads are copies of already committed submission artifacts; no local runtime database, target source archive or provider response body is packaged.

## Rebuild

From `frontend/`, using the locked project Node dependencies:

```sh
npm ci
npx tsc --project tsconfig.demo.json
npx vite build --config vite.demo.config.ts
```

Publish only `frontend/dist-demo/` to static hosting. Never upload the repository root, `.env`, `.colossus`, node_modules or the running operator API. The demo uses its own HTML entry and does not import the operator API client. No hosting environment variables are required.

The data snapshot in `frontend/demo/data.json` is an allowlisted projection of `evaluation/submission/dsvw-repeat-cycle.json`, `dsvw-repeat-evidence.json`, `results.json` and `docs/submission-evidence.json`. The public files preserve the corresponding committed reports and current two-page PDF. Refresh both the projection and downloads if measurements change; do not relabel recorded results as live execution.

## Presentation

1. Start with “First patch blocked” and its failed security gate.
2. Select “Corrected patch” to compare actual gate outcomes.
3. Show observed deployment, recurrence and the explicitly known-vulnerable rollback baseline.
4. Open Formal verification: component proof succeeded; DSVW proof remains unsupported.
5. Open Repository campaign to inspect all 24 outcomes without implying 24 repairs.

Scope: only the recorded DSVW SQL id-query repair completed the end-to-end cycle. Unsupported, failed and assisted setups remain visible. The three public benchmark campaigns remain unrun. The local application instructions are in [submission.md](submission.md).

## Implementation handoff

Base revision: `17faf61`. Branch: `demo/public-evidence`. Owned changes: the independent `frontend/demo/` entry, demo Vite/TypeScript configuration, ignore rules and this runbook. No shared API contracts, runtime policy, provider client or authenticated operator page changed.

Validation: `tsc --project tsconfig.demo.json` passed; `vite build --config vite.demo.config.ts` passed (75.80 kB gzipped JavaScript). Data checks confirmed 24 repository rows, the first candidate's security failure, seven passing required gates on the accepted candidate, and preserved unsupported proof. PDF/JSON downloads matched the committed source artifacts byte-for-byte. A bounded output scan found no provider-key-shaped values. No target code, model calls or target jobs ran for this demo build. Browser/public-deployment verification is performed by the integrator.
