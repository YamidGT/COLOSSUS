import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, label, money, text } from '../api/client'
import type { Action, Finding, Project as ProjectType, Receipt } from '../api/client'
import { usePoll } from '../api/usePoll'
import { Button, Dialog, Empty, Hash, Notice, Section, Status } from '../components/ui'

type Cycle = { cycle_id: string; status: string; created_at: string; reason: string | null; case_ids: string[] }
export default function Project() {
  const { projectId = '' } = useParams()
  const state = usePoll<ProjectType>(`/projects/${projectId}/status`, 2000)
  const actions = usePoll<{ items: Action[] }>(`/projects/${projectId}/actions`, 2000)
  const findings = usePoll<{ items: Finding[] }>(`/projects/${projectId}/findings`, 10000)
  const cycles = usePoll<{ items: Cycle[] }>(`/projects/${projectId}/cycles`, 10000)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<'cancel' | 'rollback' | null>(null)
  const p = state.data
  async function mutate(path: string, body: unknown = {}) {
    setBusy(true); setError(null); setNotice(null)
    try { const result = await api<Receipt>(path, { method: 'POST', body }); setNotice(`Request accepted · ${result.operation_id.slice(0, 8)}. Progress will appear here.`); state.refresh(); actions.refresh(); cycles.refresh(); setConfirm(null) }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'The operation could not be submitted.'); state.refresh() }
    finally { setBusy(false) }
  }
  if (!p || p.project_id !== projectId) return <Notice>{state.error ?? 'Loading repository…'}</Notice>
  const run = p.allowed_actions.find(a => a.action === 'run')
  const rollback = p.allowed_actions.find(a => a.action === 'rollback')
  const activeId = p.active_cycle ? text(p.active_cycle, 'cycle_id', '') : ''
  const canAct = state.fresh && !busy
  const deploymentId = text(p.deployment_summary, 'deployment_id', '')
  return <>
    <div className="breadcrumb"><Link to="/">Repositories</Link> <span aria-hidden="true">/</span> Repository</div>
    <div className="page-head"><div><h1>{p.display_name}</h1><div className="meta mt-3 flex flex-wrap items-center gap-4"><span>Local isolated lab</span><span>{p.owner_policy_id === 'review-v1' ? 'Review before promotion' : 'Automatic after checks'}</span>{typeof p.source_summary.commit === 'string' && <Hash value={p.source_summary.commit} />}</div></div><div className="flex flex-wrap gap-2"><Button primary disabled={!canAct || !run?.eligible} title={run?.disabled_reason ?? undefined} onClick={() => mutate(`/projects/${projectId}/cycles`)}>Run cycle</Button><Button disabled={!canAct} onClick={() => mutate(`/projects/${projectId}/${p.admission_state === 'paused' ? 'resume' : 'pause'}`)}>{p.admission_state === 'paused' ? 'Resume schedule' : 'Pause schedule'}</Button></div></div>
    {(error || state.error) && <Notice error>{error ?? state.error} {state.error && 'Authority-changing controls are disabled until reconnection.'}</Notice>}{notice && <Notice>{notice}</Notice>}
    <div className="split"><div className="min-w-0">
      <Section title="Needs attention" aside={<span className="meta">{p.attention_count} items</span>}>
        {actions.error ? <Notice error>{actions.error}</Notice> : actions.data?.items.length === 0 ? <Empty title="Nothing needs your attention">This queue tracks decisions and failures. It is not a statement that the repository is secure.</Empty> : actions.data?.items.map(action => <div className="row" key={action.action_id}><div><h3>{action.title}</h3><p className="meta mt-1">{action.reason}</p></div>{action.case_id ? <Link className="button" to={`/projects/${projectId}/cases/${action.case_id}`}>Review case</Link> : <Button disabled={!canAct || !(action.allowed_actions ?? []).some(a => a.action === 'retry_setup' && a.eligible)} onClick={() => mutate(`/projects/${projectId}/retry-setup`)}>Retry setup</Button>}</div>)}
      </Section>
      <Section title={p.setup_state === 'READY' ? 'Current activity' : 'Repository setup'}>
        <div className="py-5"><div className="flex items-center justify-between gap-4" aria-live="polite"><Status value={p.active_cycle ? text(p.active_cycle, 'status') : p.setup_state} />{activeId && <Button disabled={!canAct} onClick={() => setConfirm('cancel')}>Cancel cycle</Button>}</div><p className="meta mt-3">{p.reason ?? (p.active_cycle ? text(p.active_cycle, 'reason', 'The controller is working through the bounded cycle.') : p.setup_state === 'READY' ? 'Ready for the next cycle. No active work.' : 'Resolving, packaging and checking the isolated application.')}</p></div>
      </Section>
      <Section title="Findings" aside={<span className="meta">{findings.data?.items.length ?? '—'} recorded</span>}>
        {findings.error ? <Notice error>{findings.error}</Notice> : !findings.data?.items.length ? <Empty title="No findings recorded yet">Findings appear after investigation. Coverage and unresolved signals remain visible in each case.</Empty> : <div className="table-wrap"><table><thead><tr><th scope="col">Finding</th><th scope="col">Evidence</th><th scope="col">Location</th></tr></thead><tbody>{findings.data.items.map(f => <tr key={f.finding_id}><td><div className="font-medium">{f.title}</div><div className="meta mt-1">{f.cwe ?? 'Unclassified'} · {f.source_tools.join(', ')}</div></td><td><Status value={f.status} /></td><td className="break-all">{String(f.location.file ?? '')}:{String(f.location.line ?? '')}</td></tr>)}</tbody></table></div>}
      </Section>
      <Section title="Recent cycles">{!cycles.data?.items.length ? <Empty title="No cycles yet">Start a cycle after setup reaches ready.</Empty> : cycles.data.items.map(c => <div className="row" key={c.cycle_id}><div><Status value={c.status} /><div className="meta mt-2">{new Date(c.created_at).toLocaleString()}</div>{c.reason && <p className="meta mt-1">{c.reason}</p>}</div><div className="flex flex-wrap gap-3">{c.case_ids[0] && <Link className="text-[13px]" to={`/projects/${projectId}/cases/${c.case_ids[0]}`}>View case</Link>}<a className="text-[13px]" href={`/api/v1/reports/${c.cycle_id}`} download={`colossus-${c.cycle_id}.json`}>Download report</a></div></div>)}</Section>
    </div><aside>
      <Section title="Deployment"><dl className="detail"><div><dt>Destination</dt><dd>Local lab</dd></div><div><dt>State</dt><dd>{text(p.deployment_summary, 'status', 'Not deployed')}</dd></div><div><dt>Artifact</dt><dd>{typeof p.deployment_summary.artifact_digest === 'string' ? <Hash value={p.deployment_summary.artifact_digest} /> : 'Not available'}</dd></div><div><dt>Generation</dt><dd>{text(p.deployment_summary, 'generation', '—')}</dd></div><div><dt>Mirror</dt><dd>{text(p.mirror_summary, 'state', 'Not prepared')}</dd></div></dl>{p.deployment_summary.known_vulnerable_baseline === true && <Notice>Known vulnerable baseline. Retained for recovery testing.</Notice>}{deploymentId && Boolean(p.deployment_summary.previous_digest) && <Button className="mt-5" disabled={!canAct || !rollback?.eligible} title={rollback?.disabled_reason ?? undefined} onClick={() => setConfirm('rollback')}>Roll back</Button>}</Section>
      <Section title="Resources"><dl className="detail"><div><dt>Platform spend</dt><dd>{money(p.cost_summary.committed_micro_usd)}</dd></div><div><dt>Automation ceiling</dt><dd>{money(p.cost_summary.ceiling)}</dd></div><div><dt>Model calls</dt><dd>{text(p.cost_summary, 'calls', '—')}</dd></div><div><dt>Schedule</dt><dd>{label(p.admission_state)}</dd></div></dl></Section>
      <Section title="Threat intelligence">{p.feed_freshness.length ? p.feed_freshness.map((feed, i) => <div className="py-3" key={i}><h3>{text(feed, 'source')}</h3><p className="meta">{text(feed, 'status')} · {text(feed, 'fetched_at')}</p></div>) : <p className="meta py-4">No feed refresh recorded. Dependency intelligence coverage is not available yet.</p>}</Section>
      <p className="meta">Last successful update<br />{state.updated?.toLocaleTimeString() ?? 'Not available'}</p>
    </aside></div>
    <Dialog open={confirm !== null} title={confirm === 'rollback' ? 'Restore the previous artifact?' : 'Cancel this cycle?'} onClose={() => { if (!busy) setConfirm(null) }}><p className="mt-5">{confirm === 'rollback' ? 'COLOSSUS will restore the retained image, check its workflows and refresh the mirror. Restoring an image does not restore persistent data.' : 'The controller will stop outstanding jobs, preserve evidence and reconcile staged changes.'}</p>{confirm === 'rollback' && <p className="meta mt-3 break-all">Restore: {text(p.deployment_summary, 'previous_digest')}</p>}<div className="flex justify-end gap-3 mt-6"><Button onClick={() => setConfirm(null)} disabled={busy}>Keep current state</Button><Button danger disabled={busy || !state.fresh} onClick={() => confirm === 'rollback' ? mutate(`/deployments/${deploymentId}/rollback`, { expected_generation: p.deployment_summary.generation }) : mutate(`/cycles/${activeId}/cancel`)}>{busy ? 'Submitting…' : confirm === 'rollback' ? 'Restore artifact' : 'Cancel cycle'}</Button></div></Dialog>
  </>
}
