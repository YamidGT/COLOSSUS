import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, artifact, label } from '../api/client'
import type { Case as CaseType, Receipt } from '../api/client'
import { usePoll } from '../api/usePoll'
import { Button, Dialog, Hash, Notice, Section, Status } from '../components/ui'

export default function Case() {
  const { projectId = '', caseId = '' } = useParams()
  const state = usePoll<CaseType>(`/cases/${caseId}`, 2000)
  const [diff, setDiff] = useState<string | null>(null)
  const [diffError, setDiffError] = useState<string | null>(null)
  const [decision, setDecision] = useState<'approve' | 'reject' | null>(null)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const c = state.data
  useEffect(() => { setDiff(null); setDiffError(null) }, [caseId, c?.candidate_id])
  async function loadDiff() {
    if (!c?.diff_ref) return
    try { setDiff(await artifact(c.diff_ref, projectId)) } catch (failure) { setDiffError(failure instanceof Error ? failure.message : 'Could not load the diff.') }
  }
  async function submit() {
    if (!c) return
    setBusy(true); setError(null)
    const body = decision === 'approve' ? { candidate_id: c.candidate_id, evidence_manifest_hash: c.evidence_manifest_hash, expected_revision: c.revision, expected_deployment_generation: c.expected_deployment_generation } : { candidate_id: c.candidate_id, expected_revision: c.revision, reason }
    try { const receipt = await api<Receipt>(`/cases/${caseId}/${decision}`, { method: 'POST', body }); setNotice(`Decision accepted · ${receipt.operation_id.slice(0, 8)}. Deployment is complete only after observation and mirror refresh.`); setDecision(null); state.refresh() }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'Decision could not be submitted.'); state.refresh() }
    finally { setBusy(false) }
  }
  if (!c || c.case_id !== caseId || c.project_id !== projectId) return <Notice>{state.error ?? 'Loading case evidence…'}</Notice>
  const eligible = (action: string) => state.fresh && !busy && c.allowed_actions.some(a => a.action === action && a.eligible)
  return <>
    <div className="breadcrumb"><Link to="/">Repositories</Link> / <Link to={'/projects/' + projectId}>Repository</Link> / Case</div>
    <div className="page-head"><div><h1>{c.title}</h1><div className="flex flex-wrap items-center gap-4 mt-3"><Status value={c.status} /><span className="meta">Case <Hash value={caseId} /></span></div></div><a className="button" href={`/api/v1/reports/${c.cycle_id}`} download={`colossus-${c.cycle_id}.json`}>Download report</a></div>
    {(error || state.error) && <Notice error>{error ?? state.error}</Notice>}{notice && <Notice>{notice}</Notice>}
    <div className="split"><div className="min-w-0">
      <Section title="Proposed change" aside={c.diff_ref && <Hash value={c.diff_ref} />}>
        <p className="meta my-4">{c.reason ?? 'Review the source change and its independent acceptance checks.'}</p>
        {!c.diff_ref ? <Notice>No candidate diff is available.</Notice> : diff === null ? <Button onClick={loadDiff}>Load source diff</Button> : <pre className="diff" aria-label="Unified source diff">{diff.split('\n').map((line, index) => <span key={index} className={`diff-line ${line.startsWith('+') && !line.startsWith('+++') ? 'diff-add' : line.startsWith('-') && !line.startsWith('---') ? 'diff-remove' : ''}`}>{line || ' '}{'\n'}</span>)}</pre>}
        {diffError && <Notice error>{diffError}</Notice>}
      </Section>
      <Section title="Verification evidence">{c.gate_results.length === 0 ? <Notice>No verification gates have completed.</Notice> : c.gate_results.map(g => <div className="gate" key={g.gate_id}><div className="min-w-0"><h3>{label(g.check_profile_id.replace(/-v\d+$/, '').replaceAll('-', ' '))}</h3><p className="meta">{g.reason}</p><p className="meta">Scope: {g.scope.join('; ')}</p>{(g.assumptions ?? []).length > 0 && <details className="meta mt-2"><summary>Assumptions</summary><ul className="list-disc pl-5 mt-2">{(g.assumptions ?? []).map(a => <li key={a}>{a}</li>)}</ul></details>}<div className="flex flex-wrap gap-3 mt-2">{g.evidence_ids.map((id, i) => <a className="text-[12px]" key={id} href={`/api/v1/artifacts/${id}/download?project_id=${projectId}`} download>Evidence {i + 1}</a>)}</div></div><Status value={g.proof_outcome ?? g.status} /></div>)}</Section>
    </div><aside className="review-summary">
      <Section title="Decision"><dl className="detail"><div><dt>Destination</dt><dd>Local isolated lab</dd></div><div><dt>Expected generation</dt><dd>{c.expected_deployment_generation}</dd></div><div><dt>Candidate</dt><dd>{c.candidate_id ? <Hash value={c.candidate_id} /> : 'Not available'}</dd></div><div><dt>Evidence manifest</dt><dd>{c.evidence_manifest_hash ? <Hash value={c.evidence_manifest_hash} /> : 'Not issued'}</dd></div></dl>
        <Notice>Passing tests support the declared checks. They do not establish that the whole repository is invulnerable.</Notice>
        {c.gate_results.filter(g => g.category === 'formal').map(g => <div className="py-2" key={g.gate_id}><Status value={g.proof_outcome ?? 'UNKNOWN'} /><p className="meta mt-2">{g.reason}</p></div>)}
        {c.generation_mode === 'replayed_proposal' && <p className="meta mt-3">Replay: a previously generated proposal was reverified. No fresh generation result is claimed.</p>}
        <div className="flex flex-wrap gap-2 mt-6"><Button primary disabled={!eligible('approve')} onClick={() => setDecision('approve')}>Approve for lab</Button><Button disabled={!eligible('reject')} onClick={() => setDecision('reject')}>Reject patch</Button></div>
        {!eligible('approve') && <p className="meta mt-3">{c.allowed_actions.find(a => a.action === 'approve')?.disabled_reason ?? 'Approval is unavailable for this case state.'}</p>}
      </Section>
    </aside></div>
    <Dialog open={decision !== null} title={decision === 'approve' ? 'Approve this exact artifact?' : 'Reject this patch?'} onClose={() => { if (!busy) setDecision(null) }}>
      <p className="mt-5">{decision === 'approve' ? 'The server will recheck the evidence, destination generation and required gates before promotion. Approval cannot override a failed gate.' : 'The current running artifact will remain in place. Your reason will be recorded with this case.'}</p>
      {decision === 'approve' ? <p className="meta mt-4 break-all">Evidence: {c.evidence_manifest_hash}<br />Destination: {c.destination_id} · generation {c.expected_deployment_generation}</p> : <label className="field">Reason<textarea rows={3} maxLength={2000} value={reason} onChange={e => setReason(e.target.value)} required /></label>}
      <div className="flex gap-3 justify-end mt-6"><Button onClick={() => setDecision(null)} disabled={busy}>Cancel</Button><Button primary={decision === 'approve'} danger={decision === 'reject'} disabled={busy || !state.fresh || (decision === 'reject' && !reason.trim())} onClick={submit}>{busy ? 'Submitting…' : decision === 'approve' ? 'Approve for lab' : 'Reject patch'}</Button></div>
    </Dialog>
  </>
}
