import { useEffect, useId, useRef } from 'react'
import type { ButtonHTMLAttributes, KeyboardEvent, ReactNode } from 'react'
import { label } from '../api/client'

export function Button({ primary = false, danger = false, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { primary?: boolean; danger?: boolean }) {
  return <button {...props} className={`button ${primary ? 'button-primary' : ''} ${danger ? 'button-danger' : ''} ${props.className ?? ''}`}>{children}</button>
}
// Order matters: anything failed/refuted is bad, anything inconclusive is warn, and only then can a value read as good.
// Inconclusive words (incomplete, not proved, unknown) are tested before "complete|pass|proved" so they can never look like success.
export function tone(value: string) {
  return /fail|error|rejected|cancelled|counterexample|timeout|timed.?out/i.test(value) ? 'bad'
    : /incomplete|not.?proved|unproved|unverified|review|stale|unknown|unsupported|uncertain|paused|unconfirmed|suspected/i.test(value) ? 'warn'
    : /complete|ready|promoted|pass|proved/i.test(value) ? 'good' : 'neutral'
}
export function Status({ value }: { value: string }) {
  return <span className={`status status-${tone(value)}`}><span className="status-dot" aria-hidden="true" />{label(value)}</span>
}
export function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  return <section className="section"><div className="section-heading"><h2>{title}</h2>{aside}</div>{children}</section>
}
export function Notice({ children, error = false }: { children: ReactNode; error?: boolean }) { return <div role={error ? 'alert' : 'status'} className={`notice ${error ? 'notice-error' : ''}`}>{children}</div> }
export function Empty({ title, children }: { title: string; children: ReactNode }) { return <div className="empty"><h3>{title}</h3><p>{children}</p></div> }
/** Polite live region whose text changes only on connected/stale transitions, so polling is not re-announced. */
export function Connection({ fresh, updated }: { fresh: boolean; updated: Date | null }) {
  return <p role="status" aria-label="Connection status" className="meta">{fresh ? 'Connected' : updated ? `Stale: connection lost. Showing data from ${updated.toLocaleTimeString()}.` : 'Not connected'}</p>
}
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'
export function Dialog({ open, title, description, descriptionClassName = 'mt-5', children, onClose }: { open: boolean; title: string; description?: ReactNode; descriptionClassName?: string; children: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  const prior = useRef<HTMLElement | null>(null)
  const id = useId()
  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    if (open) {
      prior.current = document.activeElement as HTMLElement
      if (!dialog.open) dialog.showModal()
      // Prefer the first form field; otherwise the first control (Close), never a destructive confirm.
      const target = dialog.querySelector<HTMLElement>('input:not([disabled]), select:not([disabled]), textarea:not([disabled])') ?? dialog.querySelector<HTMLElement>(FOCUSABLE)
      target?.focus()
    } else if (dialog.open) { dialog.close(); prior.current?.focus() }
  }, [open])
  // Native modal dialogs make the page inert, but Tab can still escape to browser chrome; keep it cycling inside.
  function trap(event: KeyboardEvent<HTMLDialogElement>) {
    if (event.key !== 'Tab' || !ref.current) return
    const items = [...ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)]
    if (!items.length) return
    const first = items[0], last = items[items.length - 1]
    if (event.shiftKey && (document.activeElement === first || !ref.current.contains(document.activeElement))) { event.preventDefault(); last.focus() }
    else if (!event.shiftKey && (document.activeElement === last || !ref.current.contains(document.activeElement))) { event.preventDefault(); first.focus() }
  }
  return <dialog ref={ref} className="dialog" aria-labelledby={`${id}-title`} aria-describedby={description ? `${id}-desc` : undefined} onKeyDown={trap} onCancel={event => { event.preventDefault(); onClose() }} onClose={onClose}>
    <div className="flex items-center justify-between gap-4"><h2 id={`${id}-title`}>{title}</h2><Button onClick={onClose} aria-label="Close dialog">Close</Button></div>{description && <p id={`${id}-desc`} className={descriptionClassName}>{description}</p>}{children}
  </dialog>
}
export function Hash({ value }: { value: string }) { return <span className="hash" title={value}>{value.startsWith('sha256:') ? value.slice(7, 19) : value.slice(0, 12)}</span> }
