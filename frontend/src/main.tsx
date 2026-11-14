import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import { api, setCsrf } from './api/client'
import { Button, Notice } from './components/ui'
import Repositories from './pages/Repositories'
import Project from './pages/Project'
import Case from './pages/Case'
import './styles.css'

// After sign-in or a route change, move focus to the new page's heading once it renders, so keyboard and
// screen-reader users are not left on <body>. Never steal focus the user has already placed somewhere.
function FocusHeading({ enabled }: { enabled: boolean }) {
  const { pathname } = useLocation()
  useEffect(() => {
    if (!enabled) return
    let tries = 0
    let timer: ReturnType<typeof setTimeout>
    const attempt = () => {
      const active = document.activeElement
      if (active && active !== document.body) return
      const heading = document.querySelector<HTMLElement>('#main h1')
      if (heading) { heading.tabIndex = -1; heading.focus(); return }
      if (tries++ < 100) timer = setTimeout(attempt, 50)
    }
    attempt()
    return () => clearTimeout(timer)
  }, [pathname, enabled])
  return null
}

export function App() {
  const [ready, setReady] = useState(false)
  const [checking, setChecking] = useState(true)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => { api<{ csrf_token: string }>('/session').then(s => { setCsrf(s.csrf_token); setReady(true) }).catch(() => setReady(false)).finally(() => setChecking(false)) }, [])
  useEffect(() => {
    const expired = () => { setCsrf(''); setReady(false); setError('Your session expired. Run colossus ui for a new code.') }
    window.addEventListener('colossus:session-expired', expired)
    return () => window.removeEventListener('colossus:session-expired', expired)
  }, [])
  async function login(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(null)
    try { const session = await api<{ csrf_token: string }>('/sessions/exchange', { method: 'POST', body: { code: code.trim() } }); setCsrf(session.csrf_token); setCode(''); setReady(true) }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'Could not establish a session.') }
    finally { setBusy(false) }
  }
  async function logout() { try { await api('/session', { method: 'DELETE' }); setCsrf(''); setReady(false) } catch { setError('Could not sign out. Check the connection and try again.') } }
  return <BrowserRouter><FocusHeading enabled={ready} /><a href="#main" className="skip">Skip to content</a><header className="topbar"><div className="topbar-inner"><Link className="brand" to="/"><span className="brand-mark" aria-hidden="true">C</span>COLOSSUS</Link>{ready && <Link className="text-[13px] desktop-only" to="/">Repositories</Link>}<div className="ml-auto flex items-center gap-5 topbar-menu"><span className="meta desktop-only">Local operator</span>{ready && <Button onClick={logout}>Sign out</Button>}</div></div></header>
    <main id="main" className="shell">
      {checking ? <Notice>Checking the local session…</Notice> : !ready ? <div className="max-w-[430px] mx-auto mt-12"><h1>Open your workbench</h1><p className="meta mt-3">Use the one-time code from your terminal. Provider keys stay in the gateway.</p><form className="panel mt-6" onSubmit={login}><p className="text-sm">Run <code className="hash">colossus ui</code> to get a code.</p><label className="field">Login code<input value={code} onChange={e => setCode(e.target.value)} autoComplete="off" spellCheck={false} required autoFocus /></label>{error && <Notice error>{error}</Notice>}<Button primary type="submit" className="w-full mt-6" disabled={busy}>{busy ? 'Opening session…' : 'Open workbench'}</Button><p className="meta mt-4">Codes expire after 60 seconds and can be used once.</p></form></div> : <Routes><Route path="/" element={<Repositories />} /><Route path="/projects/:projectId" element={<Project />} /><Route path="/projects/:projectId/cases/:caseId" element={<Case />} /><Route path="*" element={<Notice>This page does not exist. <Link to="/">Return to repositories.</Link></Notice>} /></Routes>}
    </main></BrowserRouter>
}

const root = document.getElementById('root')
if (root) createRoot(root).render(<StrictMode><App /></StrictMode>)
