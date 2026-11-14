import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, ApiError, label } from '../api/client'
import type { Project, Receipt } from '../api/client'
import { usePoll } from '../api/usePoll'
import { Button, Dialog, Empty, Hash, Notice, Status } from '../components/ui'

export default function Repositories() {
  const state = usePoll<{ items: Project[]; next_cursor: string | null }>('/projects?limit=100')
  const [open, setOpen] = useState(false)
  const [url, setUrl] = useState('')
  const [policy, setPolicy] = useState('lab-auto-v1')
  const [start, setStart] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  async function enroll(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(null)
    try {
      const result = await api<Receipt>('/projects', { method: 'POST', body: { repo_url: url, owner_policy_id: policy, start_cycle: start } })
      navigate('/projects/' + result.resource_ids.project_id)
    } catch (failure) { setError(failure instanceof ApiError ? failure.message : 'Could not reach the controller. The repository may still have been accepted; refresh before retrying.') }
    finally { setBusy(false) }
  }
  return <>
    <div className="page-head"><div><h1>Repositories</h1><p className="meta mt-2">Follow the work. Review the evidence. Control what runs.</p></div><Button primary onClick={() => setOpen(true)} disabled={!state.fresh}>Add repository</Button></div>
    {state.error && <Notice error>Connection interrupted: {state.error} Changes are disabled until this view refreshes.</Notice>}
    {!state.data ? <Notice>Loading repositories…</Notice> : state.data.items.length === 0 ? <div className="panel"><Empty title="Your first repository starts here">Add a public GitHub URL. COLOSSUS will prepare an isolated copy and show what it can verify.</Empty><Button primary onClick={() => setOpen(true)}>Add repository</Button></div> : <>
      <div className="flex justify-between pb-3 border-b border-line meta"><span>{state.data.items.length} repositories</span><span>Latest activity first</span></div>
      {state.data.items.map(project => <div className="row" key={project.project_id}>
        <div className="min-w-0"><Link className="repo-name" to={'/projects/' + project.project_id}>{project.display_name}</Link><div className="meta mt-2 flex flex-wrap gap-x-4 gap-y-1"><span>Local isolated lab</span><span>{project.owner_policy_id === 'review-v1' ? 'Review before promotion' : 'Automatic after checks'}</span>{typeof project.source_summary.commit === 'string' && <Hash value={project.source_summary.commit} />}</div></div>
        <div className="flex flex-wrap items-center gap-5"><Status value={project.active_cycle ? String(project.active_cycle.status) : project.setup_state} />{project.attention_count > 0 && <Link className="text-[13px]" to={'/projects/' + project.project_id}>{project.attention_count} need attention</Link>}<Link className="text-[13px] font-semibold" to={'/projects/' + project.project_id}>Open <span aria-hidden="true">→</span></Link></div>
      </div>)}
      {state.data.next_cursor && <Notice>Showing the first 100 repositories. Use the CLI for the remaining pages.</Notice>}
    </>}
    <Dialog open={open} title="Add a repository" onClose={() => { if (!busy) setOpen(false) }} descriptionClassName="meta mt-4" description="Create a local isolated copy. Automatic promotion applies only to your lab environment."><form onSubmit={enroll}>
      <label className="field">Public GitHub URL<input required type="url" autoFocus placeholder="https://github.com/owner/repository" value={url} onChange={e => setUrl(e.target.value)} autoComplete="off" /></label>
      <label className="field">Promotion policy<select value={policy} onChange={e => setPolicy(e.target.value)}><option value="lab-auto-v1">Automatically promote passing repairs to the lab</option><option value="review-v1">Ask me to review each patch</option></select></label>
      <label className="flex gap-3 mt-5 items-start text-sm"><input className="mt-1" type="checkbox" checked={start} onChange={e => setStart(e.target.checked)} /><span>Run one cycle after setup completes</span></label>
      {error && <Notice error>{error}</Notice>}<div className="flex flex-wrap justify-end gap-3 mt-6"><Button type="button" onClick={() => setOpen(false)} disabled={busy}>Cancel</Button><Button primary type="submit" disabled={busy}>{busy ? 'Adding repository…' : start ? 'Add and run' : 'Add repository'}</Button></div>
    </form></Dialog>
    {state.updated && <p className="meta mt-6">Updated {state.updated.toLocaleTimeString()} · {state.fresh ? 'Connected' : label('stale')}</p>}
  </>
}
