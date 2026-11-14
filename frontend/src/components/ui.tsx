import { useEffect, useRef } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { label } from '../api/client'

export function Button({ primary = false, danger = false, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { primary?: boolean; danger?: boolean }) {
  return <button {...props} className={`button ${primary ? 'button-primary' : ''} ${danger ? 'button-danger' : ''} ${props.className ?? ''}`}>{children}</button>
}
export function Status({ value }: { value: string }) {
  const tone = /failed|error|rejected|cancelled/i.test(value) ? 'bad' : /review|stale|unknown|unsupported|paused/i.test(value) ? 'warn' : /complete|ready|promoted|pass|proved/i.test(value) ? 'good' : 'neutral'
  return <span className={`status status-${tone}`}><span className="status-dot" aria-hidden="true" />{label(value)}</span>
}
export function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  return <section className="section"><div className="section-heading"><h2>{title}</h2>{aside}</div>{children}</section>
}
export function Notice({ children, error = false }: { children: ReactNode; error?: boolean }) { return <div role={error ? 'alert' : 'status'} className={`notice ${error ? 'notice-error' : ''}`}>{children}</div> }
export function Empty({ title, children }: { title: string; children: ReactNode }) { return <div className="empty"><h3>{title}</h3><p>{children}</p></div> }
export function Dialog({ open, title, children, onClose }: { open: boolean; title: string; children: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  const prior = useRef<HTMLElement | null>(null)
  useEffect(() => {
    if (open) { prior.current = document.activeElement as HTMLElement; ref.current?.showModal() }
    else if (ref.current?.open) { ref.current.close(); prior.current?.focus() }
  }, [open])
  return <dialog ref={ref} className="dialog" aria-labelledby="dialog-title" onCancel={event => { event.preventDefault(); onClose() }} onClose={onClose}>
    <div className="flex items-center justify-between gap-4"><h2 id="dialog-title">{title}</h2><Button onClick={onClose} aria-label="Close dialog">Close</Button></div>{children}
  </dialog>
}
export function Hash({ value }: { value: string }) { return <span className="hash" title={value}>{value.startsWith('sha256:') ? value.slice(7, 19) : value.slice(0, 12)}</span> }
