# Kiro a11y lane handoff (branch `wip/a11y`, from `kiro/colossus` @ 908850e)

Scope: accessibility acceptance tests and small, additive fixes to Daniel's action center in `frontend/`. No file moves, no rewrites, no Python changes. All fixtures are synthetic UI fixtures; nothing here is controller or benchmark evidence.

## Test setup (new)

- Pinned devDependencies: vitest 5.1.0, jsdom 31.0.1, @testing-library/react 16.3.3, @testing-library/dom 10.4.2, @testing-library/user-event 14.6.10, @testing-library/jest-dom 7.0.1, axe-core 4.14.0. Script: `npm test` (`vitest run`).
- `frontend/vitest.config.ts` merges `vite.config.ts`; tests live in `frontend/tests/` (outside the `tsc --noEmit` build include, so the production build is unaffected).
- `frontend/tests/setup.ts` shims `HTMLDialogElement.showModal/close` because jsdom 31 does not implement them. The shim only toggles `open`; native top-layer inertness is not tested in jsdom.
- `frontend/src/main.tsx` now exports `App` and only calls `createRoot` when `#root` exists (so tests can render it).

## What the tests cover (`frontend/tests/a11y.test.tsx`, 40 tests)

- Keyboard-only flow, Tab/Enter/Space only: login code (autofocused, Enter submits), then the repository list, project, "Review case", "Approve for lab" (Space), Escape closes the dialog, then "Reject patch" (Enter), type a reason, and confirm. It asserts focus order (Add repository comes before the repo link), focus moving into dialogs, the Tab/Shift+Tab trap, focus restored to the invoking button after Escape and after submission, and the POST body of the reject request.
- Visible focus: a CSS-source assertion that `:focus-visible` has a 2px outline, that no `outline: none/0` exists, and that a reduced-motion block exists. This is a source check because jsdom has no layout or focus-visible engine.
- Dialogs: each one is labelled (unique `useId` title), described (`aria-describedby`), focuses its first field, traps focus, restores focus, and passes axe inside the open dialog.
- Disabled actions: the server `disabled_reason` is wired to Run cycle, Roll back and Approve/Reject through `aria-describedby`, and for Run cycle it is also asserted as visible text.
- Hostile text: `<img onerror>`/`<script>` in the repo name, finding title, CWE, tool, location, case title, gate scope and reason is rendered as text, with no element injected. Hostile evidence IDs are percent-encoded in the download href.
- Proof outcomes: UNKNOWN, UNSUPPORTED, incomplete, not_proved and uncertain are styled warn. COUNTEREXAMPLE, fail, timeout and error are styled bad. A formal gate whose `proof_outcome` is null renders "Unknown", never "Pass".
- Stale/disconnected: after a successful poll, a failed poll shows `role="alert"` with the cause and "disabled until reconnection", Run cycle/Approve become disabled, Approve's description says why, and a polite `role="status"` "Connection status" region reads "Stale …".
- axe-core (jsdom, `color-contrast` rule disabled because jsdom has no layout): 0 violations on the login, repositories, project and case pages and the open add-repository dialog.
- Token contrast: computed WCAG ratios for the DESIGN.md token pairs (text at least 4.5:1, input boundary and focus ring at least 3:1). All pass.

## Fixes made (the tests failed before them; 15 of 40 failed on the first run)

- `Status` tone (`frontend/src/components/ui.tsx`): `fail`, `timeout` and `COUNTEREXAMPLE` were neutral, and `incomplete`/`not_proved` could match the success regex. Inconclusive words are now checked before success words. The function is exported as `tone`.
- Case evidence list (`frontend/src/pages/Case.tsx`): a formal gate with a null `proof_outcome` fell back to `status` ("Pass", green). It now shows UNKNOWN.
- Disabled reasons: Run cycle, Roll back and Retry setup used a `title` tooltip only. All of them, plus Approve/Reject, now show visible reason text linked with `aria-describedby`. When the view is stale, the reason says the action is disabled until refresh, instead of showing a server reason that is no longer current.
- Dialog (`ui.tsx`): it had a fixed `id="dialog-title"` and no description. It now uses a unique id and an optional `description` prop wired to `aria-describedby`, moves focus to the first field (or Close) on open, traps Tab/Shift+Tab, and keeps the existing focus restore. The callers pass their existing first paragraph as `description`, with the same copy and classes.
- Focus after login or navigation (`frontend/src/main.tsx`, `FocusHeading`): focus used to drop to `<body>`. It now moves to the new page's `h1` (`tabIndex=-1`) once that heading renders, and never steals focus the user has placed elsewhere.
- Connection live region (`Connection` in `ui.tsx`, used on the Project and Case pages): its text changes only on connected/stale transitions, so polling is not re-announced.
- Case stale alert now adds "Decisions are disabled until the case refreshes."
- CSS (`frontend/src/styles.css`): dialog action rows wrap (`flex-wrap`). Dialogs are centred (`margin: auto`; Tailwind preflight had pinned them top-left, as seen in the Chromium screenshot). A `max-width: 400px` block lets button labels wrap, gives dialogs 16px padding, wraps `.detail` rows, and stops `.status` labels from shrinking. Reduced motion now also covers pseudo-elements and `scroll-behavior`.

## Commands and outputs (Node v22.22.3, npm 10.9.8)

- `npm ci`: `found 0 vulnerabilities`
- `npm run build`: `tsc --noEmit && vite build`. Output: `dist/assets/index-*.css 14.55 kB │ gzip: 4.02 kB`, `dist/assets/index-*.js 287.54 kB │ gzip: 90.05 kB`, `✓ built`. The earlier checkpoint was 89.17 kB gzip; this branch adds about 0.9 kB, within the 200 KiB budget.
- `npm test`: `Test Files 1 passed (1)`, `Tests 40 passed (40)`. It also prints one harmless jsdom note from axe: `HTMLCanvasElement's getContext() … not implemented`.
- Layout probe (`frontend/tests/layout-probe.mjs`, not part of `npm test`): headless `/usr/bin/chromium` through puppeteer-core 24 against the built `dist`, with synthetic fixtures (very long unbroken repo name, 100 findings, UNKNOWN/null formal gates, disabled retry setup). It measured document horizontal overflow and controls/headings exceeding the viewport or their own box, outside the table/diff scrollers, at 360, 375 and 1280px, with the add-repository, rollback and approve dialogs open. It also ran a 640px CSS viewport at 2x DPR (the same reflow width as 1280px at 200% zoom). Final result: `docOverflow=0 issues=0` for every one of the 20 page/width combinations. The first run found 11–12px overflow on Case at 360/375 (status labels shrinking in `.gate`), fixed above. Screenshots were inspected locally from the scratch directory and are not committed.

## Not verified

- Real screen-reader output (NVDA, VoiceOver), real-browser `:focus-visible` rendering, and native `<dialog>` inertness. jsdom uses a shim, and Chromium was used only for layout, not for keyboard testing.
- Rendered contrast of final combinations in a browser (only the token pairs were computed), and axe `color-contrast`.
- Integration with the real FastAPI controller, session/CSRF/Host behaviour, CLI/UI parity, and the approval stale-revision race.
- Real browser zoom (only the DPR approximation above was tested), and touch target size at 44px on real devices. The probe asserted at least 40px.

## Remaining work / notes for Daniel

- The findings table scrolls horizontally inside `.table-wrap` on mobile (`td:first-child` has a 180px minimum width). DESIGN.md allows horizontal scrolling only in code/diff regions; consider a stacked row layout under 760px.
- Repositories: the footer "Updated … · Connected/Stale" is not a live region (the alert covers disconnects). A top-bar connection indicator from DESIGN.md is still absent.
- `vitest.config.ts` imports `./vite.config.ts`. If `vite.config.ts` changes plugins, tests inherit the change.
- The touched files are small hunks in `main.tsx`, `ui.tsx`, the three page files and `styles.css`. Expect easy merges, but check for conflicts with Daniel's ongoing edits.
