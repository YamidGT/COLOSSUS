# Repository action center: frontend implementation plan

Owner A. Scope is documentation only until implementation begins. Build the operator experience in [PRODUCT.md](../PRODUCT.md) with [DESIGN.md](../DESIGN.md), [user workflows](user-workflows.md) and [CLI parity](cli.md). This replaces the earlier optional server-rendered status-page proposal with one small Tailwind frontend.

## Stack and serving

[React](https://react.dev/learn/build-a-react-app-from-scratch) + TypeScript + Vite, Tailwind CSS v4 through `@tailwindcss/vite`, and React Router for the three page routes. Pin compatible exact versions/Node runtime at M0. [Tailwind's Vite integration](https://tailwindcss.com/docs/installation/using-vite) is the setup reference. Use semantic CSS variables and Tailwind utilities, not a second component styling framework. Use a small accessible dialog primitive if native `<dialog>` is insufficient after testing; no full dashboard template or heavyweight component suite.

Directory: `frontend/` with its own package/lockfile, `src/app`, `pages`, `components`, `api`, `styles.css`. A owns it and all root configuration. Generate TypeScript API types from the frozen FastAPI OpenAPI contract; generated output is not hand-edited. Fetch with one small typed client and bounded polling; no Redux, WebSocket server, Next.js server or separate frontend database. Production assets are built once and served by FastAPI at `/`; operator APIs are mounted at `/api/v1`. Vite development proxy forwards `/api/v1` to the loopback API. Existing bare API paths in diagrams denote paths under that prefix.

The browser never contains provider/deployment/runtime credentials. No `VITE_*` provider secret variables, root `.env` imports, `envDir` pointing to the repository root, target-volume mounts or browser-side provider calls. Configure Vite with `frontend/` as its env root. Static assets and the redacted authenticated API are the entire browser boundary.

## Three page routes

| Route | Purpose and contents |
|---|---|
| `/` | Repositories: compact rows, attention count, setup/run state, last cycle, deployed revision; “Add repository” form/dialog |
| `/projects/:projectId` | Repository action center: attention queue, current cycle, findings, recent runs, deployment/mirror, budget and intel freshness |
| `/projects/:projectId/cases/:caseId` | Case review: issue/evidence, source diff, gate list, formal scope/assumptions, destination and permitted decision |

Project configuration is a small dialog/panel; runs and evidence expand inline or use a query-selected detail view. Keep shareable filters/selected run in URL query parameters. Do not add multiple dashboard tabs to hide essential state. Browser refresh on a nested route works through the static fallback; unknown API paths still return JSON 404, not the HTML shell.

## Layout wireframe

```text
COLOSSUS     Repositories                           Connected   Operator
------------------------------------------------------------------------
erev0s / VAmPI                                      [Run cycle] [More]
main @ abc1234    Local lab    Automatic after checks

Needs attention (1)                           Deployment
------------------------------------------    --------------------------
Review patch: book ownership                  Running  abc1234
Security + functionality passed               Mirror   current
Formal: 1 proved property [View scope]         Recovery previous available
[Review patch]                                 [View history]

Current cycle                                 Resources
------------------------------------------    --------------------------
Detect > Repair > Verify > Observe > Refresh   $0.06 used / $2.00 case cap
Verifying | 8m elapsed | Updated 2s ago        OSV/KEV updated 6m ago
[View steps] [Cancel cycle]

Findings                       Confirmed 2 | Unconfirmed 1
------------------------------------------------------------------------
Issue                      Evidence       Candidate          Outcome
Book access control        Reproduced     Patch ready        Review
Input validation           Unconfirmed    None               Investigating

Recent runs
------------------------------------------------------------------------
Started           Outcome                Deployed version    Cost
...               ...                    ...                 ...
```

All values are illustrative. “Automatic” projects normally promote passing candidates without review; the review row appears only if a configured policy exception/requirement actually demands it. Do not fabricate pending decisions to populate the layout. One current-cycle strip shows real stages; failed/rejected stages remain visible rather than always drawing a completed green sequence.

## State and actions

The controller returns a ProjectSnapshot and ActionItems with permitted action IDs and disabled reasons. The frontend renders these; it does not reimplement eligibility, assurance or cost rules. The backend revalidates every action despite earlier UI permission. No optimistic success for approval, promotion, cancellation or rollback: show pending until server state confirms the result.

`Needs attention` rows resolve from state transitions, not a local dismiss button. Informational events move to history; unconfirmed findings remain visible without forcing a review. Include setup pending/failure, no findings, active repair, budget stopped, needs review, rejected, proof unknown, stale evidence, observation failure, rollback failure, mirror stale, paused and disconnected states. Blank data is shown as “Not available,” never zero or green.

Polling: every 2 seconds for a visible active project; 10 seconds for idle project/list; pause when tab hidden. Use an ETag/state revision to avoid redundant payloads. Back off failed polls up to 30 seconds; show disconnect/stale status after a failed poll and last successful update time. Disable authority-changing controls until a fresh snapshot is retrieved. Refresh on tab focus and after mutations. Show duration from server timestamps with a local display clock; the server owns deadlines. Do not reorder the focused action row on every poll; provide a stable focus anchor and announce new items gently.

Case diff defaults to unified text, readable at narrow widths. Lazy-load a bounded diff and raw logs only on request. No Monaco/terminal emulator is required. File changes list path, added/removed counts and protected-file gate status. Formal rows show property, outcome, assumptions and linked runtime scope; aggregate green “verified” must never hide UNKNOWN or UNSUPPORTED.

## Authentication and untrusted content

V1 is a single trusted operator over localhost/SSH tunnel; no anonymous read APIs. `colossus ui` requests a login code with the CLI's host credential, displays it only to the operator, and opens the login page. Code is random, stored hashed, one-use, expires after 60 seconds, and has a bounded exchange attempt rate. Exchange creates a server-side session cookie: HttpOnly, SameSite=Strict, host-only, eight-hour absolute expiry, Secure when served over TLS. Loopback HTTP is the explicit local-only exception. Session logout/revocation invalidate server state. Never use query-string tokens or browser localStorage for auth.

Check Host against loopback/explicit tunnel hosts, validate Origin on mutations, require session-bound CSRF tokens for cookie-auth writes, and allow no wildcard CORS. CLI bearer authentication is separately scoped and auditable; no CSRF token is needed for non-cookie bearer requests. Bind every resource to the selected project and validate access server-side. Production remote hosting requires a separate TLS/auth design before public binding.

Escape repository names, findings, code, logs and advisories; render text rather than unsanitized HTML/Markdown. Do not load target-generated images, embedded links or frames. External source links are deliberate clicks with safe schemes and `noopener noreferrer`. Downloaded evidence has a safe filename/content-disposition and byte limits. Use a restrictive CSP: same-origin scripts/styles/connections, no object/frame embeddings or inline script; keep the operator origin separate from sandbox target ports. Report exports cannot include provider secrets or evaluator-only answers.

## Implementation slices and checks

1. M0: A freezes ProjectSnapshot/ActionItem/operation APIs and typed fixtures; initialize frontend build, semantic tokens and reusable primitives. Add PRODUCT/DESIGN context to frontend agent brief.
2. M1: implement repository list/enrollment/setup, against real controller state. Empty/error/loading designs precede decorative polish.
3. M2/M3: add current cycle, attention queue, findings and full case/diff/gate review; lazy-load evidence. C/D supply decision/gate fixtures.
4. M4: wire approval/rejection, observation, rollback, pause/cancel and mirror freshness. Validate stale/duplicate actions through CLI and browser.
5. M5: add bounded report download/history; run Impeccable critique/simplify/audit/polish or equivalent manual review; inspect screenshots and keyboard flow. Keep any tool install pinned and development-only.

Acceptance: typecheck/production build, keyboard-only add/review/decision, 375px and 1280px screenshots, 200% zoom, automated accessibility scan plus manual focus/contrast checks, escape tests on hostile repo text, session/CSRF/Host tests, and an integrated CLI/UI parity flow. Use focused interaction tests for consequential behavior; do not snapshot every Tailwind class. Target initial JS budget <=200 KiB gzip excluding lazy evidence tools, no external fonts, no needless chart library; measure and document exceptions. No frontend claim of a successful remediation may come only from mock data.
