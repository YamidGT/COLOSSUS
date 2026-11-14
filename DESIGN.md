# COLOSSUS visual and interaction specification

Status: intended design, not an implemented interface. Read [PRODUCT.md](PRODUCT.md) and [frontend plan](docs/frontend.md). Design direction: a calm technical workbench with strong typography, precise alignment and a short action queue. Beauty comes from useful hierarchy and careful spacing.

## References and design workflow

Use [Impeccable](https://impeccable.style/#language) and its [design-system/command documentation](https://impeccable.style/docs/) as implementation-time helpers. Its project/design context workflow and critique, simplify, audit and polish passes fit this project. These files supply project-specific decisions; do not copy a generic generated dashboard. No Impeccable package or hook has been installed during this documentation task. The implementer may install a reviewed, pinned release and record it in the development tooling manifest. If unavailable, perform the checklist below manually; do not block product implementation on a design plugin.

Suggested passes: establish layout from PRODUCT/DESIGN -> critique hierarchy -> simplify -> audit accessibility/states -> polish spacing/typography. Use actual screenshots at desktop and mobile widths after implementation, not only code inspection. Do not auto-enable third-party hooks without inspecting their behavior. Helpers never require provider keys or target/evaluator secrets.

## Visual tokens

Use Tailwind CSS v4 semantic theme variables in `frontend/src/styles.css`; keep values in one place. Light theme only for initial delivery. Use the browser/system sans-serif stack and system monospace for code/hashes; no font download is necessary.

| Token | Initial value / intent |
|---|---|
| Canvas / surface | `#F6F7F9` / `#FFFFFF` |
| Main / muted text | `#17212B` / `#52606D` |
| Divider | `#DCE1E7`; decorative separators only |
| Input boundary | `#7B8794`; verify control-boundary contrast |
| Accent / focus | `#174EA6`; one restrained blue |
| Success text / tint | `#166534` / `#F0FDF4` |
| Warning text / tint | `#854D0E` / `#FEFCE8` |
| Failure text / tint | `#B42318` / `#FFF1F0` |
| Body / metadata / heading | 15px/22px, 13px/18px, 24px/30px |
| Code | 13px/20px; tabular digits for time/cost |
| Spacing | 4, 8, 12, 16, 24, 32, 48px |
| Radius | 6px controls; 8px panels/dialogs |
| Width | 1200px max shell, 24px desktop / 16px mobile gutters |
| Motion | 120–160ms opacity/color; disable nonessential motion for reduced-motion preference |

These values are design proposals; measure contrast against final rendered combinations. Aim for WCAG 2.2 AA, body-text contrast at least 4.5:1 and visible focus/control boundaries. Status always has a word/icon in addition to color. Buttons have at least 40px height, 44px on touch layouts; do not confuse this product choice with WCAG's 24px minimum and spacing exceptions. [W3C target sizing](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html).

## Composition

A 56px top bar contains COLOSSUS, “Repositories,” connection status and the operator menu. The repository screen begins with owner/name, branch/commit, environment and policy in subdued metadata. The main area starts with “Needs attention,” then current activity and recent outcomes. Use thin row separators, not a card around every field. A narrow secondary column shows deployment, budget and feed freshness. On mobile it moves below the action list.

Case review is a full page so diffs and evidence have room. On desktop, diff/evidence occupy two-thirds and a decision summary occupies one-third. On mobile the summary comes before the diff and the decision controls remain reachable without overlaying text. Use a modal only for a concise consequential confirmation, not the entire review workflow.

## Components and copy

Build only reusable `Button`, `Field`, `StatusLabel`, `Section`, `DataTable`, `ActionRow`, `EmptyState`, `ErrorNotice`, `ConfirmDialog`, `GateList`, `DiffView` and `Timeline`. Prefer native HTML semantics. Use small consistent outline icons where recognition improves; include visible text on action buttons. Keep source filenames and hashes selectable/copyable; show shortened hashes with a way to inspect the full value.

Good labels: “Run cycle,” “Review patch,” “Approve for lab,” “Reject patch,” “Pause schedule,” “Retry setup,” “Download report.” State copy explains cause and next action: “Build stopped: Python version unsupported. View setup details.” Do not show “Something went wrong” without a reason/correlation ID, “AI is thinking,” fake progress percentages or “Your repository is secure.” No stream of model reasoning is shown; evidence and bounded decision rationale are enough.

One primary button per decision context. Buttons do not move when loading; a pending state retains its label and announces progress. Inline field errors use visible labels and describe how to correct input. Toasts are optional acknowledgments; important failures and pending decisions persist on the page. Empty states distinguish no repositories, no findings, no decisions and no data yet.

## Avoid generic generated styling

No gradients, glass effects, neon cyber visuals, decorative blobs, oversized hero titles, sparkle icons, filler KPI cards, donut security scores, nested-card grids or animated counting totals. No all-dark “hacker terminal” theme. Avoid excessive pills, all-caps microcopy, low-contrast gray and tooltip-only actions. Meaningful counts are permitted when they answer a user question, such as “2 patches need review.”

## Accessibility and review gate

Keyboard navigation reaches every action in logical order; visible focus never disappears. Dialogs manage/restore focus, trap it while open, support Escape where cancellation is safe, and expose name/description according to [W3C dialog guidance](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/). Use semantic tables with headers and real links for navigation. Do not announce every polling update; announce stage changes with a polite live region and critical failures once.

Review at 375px and 1280px, 200% zoom, long repo names, 100 findings, empty states, unknown proof, stale connection, error and pending approval. Page content must reflow; only code/diff regions may scroll horizontally. Reject clipped labels, overlapping actions, misleading success colors and inaccessible contrast. Record screenshots and accessibility findings in the frontend handoff.
