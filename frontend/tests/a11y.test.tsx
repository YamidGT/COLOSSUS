import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import axe from 'axe-core'
import { describe, expect, it } from 'vitest'
import { App } from '../src/main'
import { Status } from '../src/components/ui'
import { caseReview, HOSTILE, mockApi, project, standardRoutes } from './fixtures'

type User = ReturnType<typeof userEvent.setup>

function name(el: Element | null) {
  if (!el || el === document.body) return '(body)'
  return (el.getAttribute('aria-label') ?? el.textContent ?? '').trim() || el.tagName
}

/** Press Tab until `target` matches the focused element; returns the names visited (focus order). */
async function tabTo(user: User, target: (el: Element) => boolean, max = 40) {
  const visited: string[] = []
  for (let i = 0; i < max; i++) {
    await user.tab()
    const el = document.activeElement!
    visited.push(name(el))
    if (target(el)) return visited
  }
  throw new Error('Focus never reached target. Visited: ' + visited.join(' | '))
}

async function axeViolations(root: Element = document.body) {
  // color-contrast cannot be computed in jsdom (no layout); tokens are checked separately below.
  const result = await axe.run(root, { rules: { 'color-contrast': { enabled: false } } })
  return result.violations.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`)
}

describe('keyboard-only decision flow', () => {
  it('reaches login -> repositories -> project -> case -> decision with Tab/Enter/Space', async () => {
    const calls = mockApi([
      { path: '/session', status: 401, body: { error: { code: 'unauthenticated', message: 'Sign in required.' } } },
      ...standardRoutes(),
      { method: 'POST', path: '/sessions/exchange', body: { csrf_token: 'csrf-test' } },
      { method: 'POST', path: '/cases/c1/reject', body: { operation_id: 'op-12345678', status: 'accepted', resource_ids: {} } },
    ])
    const user = userEvent.setup()
    render(<App />)

    const code = await screen.findByLabelText('Login code')
    expect(code).toHaveFocus()
    await user.keyboard('ABCD-1234{Enter}')

    const repoLink = await screen.findByRole('link', { name: 'owner/repo' })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Add repository' })).toBeEnabled())
    // After login, focus lands on the page heading instead of being lost on <body>.
    expect(document.activeElement).toBe(screen.getByRole('heading', { level: 1, name: 'Repositories' }))
    const order = await tabTo(user, el => el === repoLink)
    expect(order.indexOf('Add repository')).toBeLessThan(order.indexOf('owner/repo'))
    await user.keyboard('{Enter}')

    const review = await screen.findByRole('link', { name: 'Review case' })
    await tabTo(user, el => el === review)
    await user.keyboard('{Enter}')

    await screen.findByRole('heading', { level: 1, name: 'Book ownership check' })
    const approve = screen.getByRole('button', { name: 'Approve for lab' })
    await waitFor(() => expect(approve).toBeEnabled())
    await tabTo(user, el => el === approve)
    await user.keyboard(' ')

    const dialog = await screen.findByRole('dialog', { name: 'Approve this exact artifact?' })
    expect(dialog).toHaveAccessibleDescription(/server will recheck the evidence/i)
    expect(dialog.contains(document.activeElement)).toBe(true)
    // Focus is trapped: many Tabs never leave the dialog.
    for (let i = 0; i < 8; i++) { await user.tab(); expect(dialog.contains(document.activeElement)).toBe(true) }
    await user.tab({ shift: true }); expect(dialog.contains(document.activeElement)).toBe(true)
    // Escape (native `cancel`) closes and restores focus to the invoking button.
    fireEvent(dialog, new Event('cancel', { cancelable: true }))
    await waitFor(() => expect(dialog).not.toHaveAttribute('open'))
    expect(approve).toHaveFocus()

    const reject = screen.getByRole('button', { name: 'Reject patch' })
    await user.tab(); expect(reject).toHaveFocus()
    await user.keyboard('{Enter}')
    const rejectDialog = await screen.findByRole('dialog', { name: 'Reject this patch?' })
    const reason = within(rejectDialog).getByLabelText(/Reason/)
    expect(reason).toHaveFocus()
    await user.keyboard('Breaks login flow')
    const confirm = within(rejectDialog).getByRole('button', { name: 'Reject patch' })
    await tabTo(user, el => el === confirm)
    await user.keyboard('{Enter}')
    await screen.findByText(/Decision accepted/)
    expect(calls.find(c => c.method === 'POST' && c.path === '/cases/c1/reject')?.body).toMatchObject({ reason: 'Breaks login flow', expected_revision: 7 })
    expect(reject).toHaveFocus()
  })

  it('declares a visible focus indicator that is never removed', () => {
    const css = readFileSync(resolve(process.cwd(), 'src/styles.css'), 'utf8')
    expect(css).toMatch(/:focus-visible\s*\{[^}]*outline:\s*2px solid/)
    expect(css).not.toMatch(/outline:\s*(none|0)\b/)
    expect(css).toMatch(/prefers-reduced-motion:\s*reduce/)
  })
})

describe('dialogs', () => {
  it('add-repository dialog is labelled, focuses its first field, traps and restores focus', async () => {
    mockApi(standardRoutes())
    const user = userEvent.setup()
    render(<App />)
    const add = await screen.findByRole('button', { name: 'Add repository' })
    await waitFor(() => expect(add).toBeEnabled())
    add.focus()
    await user.keyboard('{Enter}')
    const dialog = await screen.findByRole('dialog', { name: 'Add a repository' })
    expect(dialog).toHaveAccessibleDescription(/local isolated copy/i)
    expect(screen.getByLabelText('Public GitHub URL')).toHaveFocus()
    for (let i = 0; i < 10; i++) { await user.tab(); expect(dialog.contains(document.activeElement)).toBe(true) }
    expect(await axeViolations(dialog)).toEqual([])
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(dialog).not.toHaveAttribute('open'))
    expect(add).toHaveFocus()
  })
})

describe('disabled actions expose their server reason', () => {
  it('project actions', async () => {
    mockApi(standardRoutes())
    render(<App />)
    window.history.replaceState(null, '', '/')
    const run = await screen.findByRole('link', { name: 'owner/repo' })
    await userEvent.setup().click(run)
    const button = await screen.findByRole('button', { name: 'Run cycle' })
    expect(button).toBeDisabled()
    expect(button).toHaveAccessibleDescription('A cycle is already queued for this project.')
    const rollback = screen.getByRole('button', { name: 'Roll back' })
    expect(rollback).toHaveAccessibleDescription('Rollback requires an observed previous artifact.')
    expect(screen.getByText('A cycle is already queued for this project.')).toBeVisible()
  })

  it('case decision', async () => {
    window.history.replaceState(null, '', '/projects/p1/cases/c1')
    mockApi(standardRoutes([], { kase: { allowed_actions: [
      { action: 'approve', eligible: false, disabled_reason: 'Evidence manifest is stale; rerun verification.' },
      { action: 'reject', eligible: false, disabled_reason: 'Case is already closed.' },
    ] } }))
    render(<App />)
    const approve = await screen.findByRole('button', { name: 'Approve for lab' })
    expect(approve).toBeDisabled()
    expect(approve).toHaveAccessibleDescription('Evidence manifest is stale; rerun verification.')
    expect(screen.getByRole('button', { name: 'Reject patch' })).toHaveAccessibleDescription('Case is already closed.')
  })
})

describe('untrusted text', () => {
  it('renders hostile repository, finding, case and evidence text escaped', async () => {
    window.history.replaceState(null, '', '/projects/p1')
    const routes = standardRoutes([
      { path: '/projects/p1/findings', body: { items: [{ finding_id: 'f1', title: HOSTILE, status: 'confirmed', cwe: HOSTILE, source_tools: [HOSTILE], location: { file: HOSTILE, line: 1 } }] } },
    ], { project: { display_name: HOSTILE, reason: HOSTILE } })
    mockApi(routes)
    const { container } = render(<App />)
    await screen.findByRole('heading', { level: 1, name: HOSTILE })
    await screen.findAllByText(HOSTILE)
    expect(container.querySelector('img, script')).toBeNull()
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined()
  })

  it('encodes hostile identifiers in evidence links', async () => {
    window.history.replaceState(null, '', '/projects/p1/cases/c1')
    mockApi(standardRoutes([], { kase: { title: HOSTILE, gate_results: [
      { gate_id: 'g1', case_id: 'c1', candidate_id: 'cand1', candidate_hash: 'h', check_profile_id: 'security-v1', category: 'security', status: 'pass', proof_outcome: null, scope: [HOSTILE], reason: HOSTILE, tool_version: '1', command_profile_hash: 'x', exit_code: 0, started_at: '', finished_at: '', evidence_ids: ['../../session?x=1#'] },
    ] } }))
    const { container } = render(<App />)
    const link = await screen.findByRole('link', { name: 'Evidence 1' })
    expect(link.getAttribute('href')).toBe('/api/v1/artifacts/..%2F..%2Fsession%3Fx%3D1%23/download?project_id=p1')
    expect(container.querySelector('img, script')).toBeNull()
  })
})

describe('proof outcomes', () => {
  it.each([
    ['UNKNOWN', 'warn'], ['UNSUPPORTED', 'warn'], ['COUNTEREXAMPLE', 'bad'], ['fail', 'bad'], ['timeout', 'bad'], ['error', 'bad'],
    ['PROVED', 'good'], ['BOUNDED_PASS', 'good'], ['pass', 'good'], ['incomplete', 'warn'], ['not_proved', 'warn'], ['uncertain', 'warn'],
  ])('%s is styled %s', (value, tone) => {
    const { container } = render(<Status value={value} />)
    expect(container.querySelector('.status')).toHaveClass(`status-${tone}`)
  })

  it('formal gate with no proof outcome is shown as Unknown, never Pass', async () => {
    window.history.replaceState(null, '', '/projects/p1/cases/c1')
    mockApi(standardRoutes())
    render(<App />)
    await screen.findByRole('heading', { level: 1, name: 'Book ownership check' })
    const formal = screen.getByRole('heading', { level: 3, name: /formal ownership/i }).closest('.gate')!
    expect(within(formal as HTMLElement).queryByText('Pass')).toBeNull()
    const unknown = within(formal as HTMLElement).getByText('Unknown').closest('.status')
    expect(unknown).toHaveClass('status-warn')
    expect(document.querySelectorAll('.status-good').length).toBe(1) // only the non-formal security gate
  })
})

describe('stale and disconnected states', () => {
  const down = { status: 503, body: { error: { code: 'unavailable', message: 'Controller unreachable.' } } }
  it('announces a lost connection and disables authority-changing controls', async () => {
    window.history.replaceState(null, '', '/projects/p1')
    let n = 0
    mockApi(standardRoutes([
      { path: '/projects/p1/status', reply: () => (n++ === 0 ? { status: 200, body: project({ allowed_actions: [{ action: 'run', eligible: true, disabled_reason: null }] }) } : down) },
    ]))
    render(<App />)
    const run = await screen.findByRole('button', { name: 'Run cycle' })
    await waitFor(() => expect(run).toBeEnabled())
    await act(async () => { window.dispatchEvent(new Event('focus')) })
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/Controller unreachable/)
    expect(alert).toHaveTextContent(/disabled until reconnection/)
    expect(run).toBeDisabled()
    expect(screen.getByRole('status', { name: /connection/i })).toHaveTextContent(/Stale/i)
  })

  it('case review announces stale evidence and explains why decisions are disabled', async () => {
    window.history.replaceState(null, '', '/projects/p1/cases/c1')
    let n = 0
    mockApi(standardRoutes([{ path: '/cases/c1', reply: () => (n++ === 0 ? { status: 200, body: caseReview() } : down) }]))
    render(<App />)
    const approve = await screen.findByRole('button', { name: 'Approve for lab' })
    await waitFor(() => expect(approve).toBeEnabled())
    await act(async () => { window.dispatchEvent(new Event('focus')) })
    expect(await screen.findByRole('alert')).toHaveTextContent(/Controller unreachable/)
    expect(approve).toBeDisabled()
    expect(approve).toHaveAccessibleDescription(/disabled until the case refreshes/i)
  })
})

describe('automated axe scan (jsdom, structure/ARIA rules only)', () => {
  it.each([
    ['login', '/', false],
    ['repositories', '/', true],
    ['project', '/projects/p1', true],
    ['case', '/projects/p1/cases/c1', true],
  ])('%s has no axe violations', async (_label, path, signedIn) => {
    window.history.replaceState(null, '', path)
    mockApi(signedIn ? standardRoutes() : [{ path: '/session', status: 401, body: { error: { code: 'unauthenticated', message: 'Sign in required.' } } }])
    render(<App />)
    await screen.findByRole('heading', { level: 1 })
    if (signedIn) await waitFor(() => expect(document.querySelector('.notice')?.textContent ?? '').not.toMatch(/Loading/))
    expect(await axeViolations()).toEqual([])
  })
})

describe('design tokens meet WCAG AA contrast', () => {
  const lum = (hex: string) => {
    const c = hex.replace('#', '').match(/../g)!.map(x => parseInt(x, 16) / 255).map(v => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
  }
  const ratio = (a: string, b: string) => { const [x, y] = [lum(a), lum(b)].sort((m, n) => n - m); return (x + 0.05) / (y + 0.05) }
  it.each([
    ['ink on canvas', '#17212b', '#f6f7f9', 4.5], ['muted on canvas', '#52606d', '#f6f7f9', 4.5], ['muted on surface', '#52606d', '#ffffff', 4.5],
    ['accent link on canvas', '#174ea6', '#f6f7f9', 4.5], ['white on accent button', '#ffffff', '#174ea6', 4.5],
    ['success', '#166534', '#ffffff', 4.5], ['warning', '#854d0e', '#ffffff', 4.5], ['failure', '#b42318', '#ffffff', 4.5],
    ['error notice text', '#8b1d14', '#fff1f0', 4.5], ['diff add', '#166534', '#f0fdf4', 4.5], ['diff remove', '#9e2016', '#fff1f0', 4.5],
    ['notice text on tint', '#17212b', '#f0f4fa', 4.5], ['input boundary on surface (non-text 3:1)', '#7b8794', '#ffffff', 3],
    ['focus ring on canvas (non-text 3:1)', '#174ea6', '#f6f7f9', 3],
  ])('%s', (_n, fg, bg, min) => { expect(ratio(fg, bg)).toBeGreaterThanOrEqual(min) })
})
