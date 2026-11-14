// Synthetic UI test fixtures. These are NOT controller results and prove nothing about a real repository.
import { vi } from 'vitest'

export const HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>'

export function project(overrides: Record<string, unknown> = {}) {
  return {
    project_id: 'p1', display_name: 'owner/repo', owner_policy_id: 'review-v1', setup_state: 'READY', admission_state: 'active',
    attention_count: 1, active_cycle: null, reason: null, source_summary: { commit: 'abc1234def5678' },
    deployment_summary: { deployment_id: 'd1', status: 'running', generation: 3, previous_digest: 'sha256:prev', artifact_digest: 'sha256:cur' },
    mirror_summary: { state: 'current' }, cost_summary: { committed_micro_usd: 60000, ceiling: 2000000 }, feed_freshness: [],
    allowed_actions: [
      { action: 'run', eligible: false, disabled_reason: 'A cycle is already queued for this project.' },
      { action: 'rollback', eligible: false, disabled_reason: 'Rollback requires an observed previous artifact.' },
    ],
    ...overrides,
  }
}

export function caseReview(overrides: Record<string, unknown> = {}) {
  return {
    title: 'Book ownership check', status: 'needs_review', cycle_id: 'cy1', created_at: '2026-11-14T10:00:00Z', reason: null,
    generation_mode: 'fresh_inference', case_id: 'c1', project_id: 'p1', revision: 7, finding_refs: [], candidate_id: 'cand1',
    diff_ref: null, assurance_summary: {}, evidence_manifest_hash: 'sha256:manifest0000000', destination_id: 'lab', expected_deployment_generation: 3,
    gate_results: [
      { gate_id: 'g1', case_id: 'c1', candidate_id: 'cand1', candidate_hash: 'h', check_profile_id: 'security-replay-v1', category: 'security', status: 'pass', proof_outcome: null, scope: ['GET /books'], tool_version: '1', command_profile_hash: 'x', exit_code: 0, started_at: '', finished_at: '', evidence_ids: ['ev1'] },
      { gate_id: 'g2', case_id: 'c1', candidate_id: 'cand1', candidate_hash: 'h', check_profile_id: 'formal-ownership-v1', category: 'formal', status: 'pass', proof_outcome: null, scope: ['ownership'], tool_version: '1', command_profile_hash: 'x', exit_code: 0, started_at: '', finished_at: '', evidence_ids: [], reason: 'Solver returned no verdict within the bound.' },
    ],
    allowed_actions: [
      { action: 'approve', eligible: true, disabled_reason: null },
      { action: 'reject', eligible: true, disabled_reason: null },
    ],
    ...overrides,
  }
}

type Route = { method?: string; path: string | RegExp; status?: number; body?: unknown; reply?: () => { status: number; body: unknown } }

/** Installs a fetch mock answering routes under /api/v1. Unmatched requests fail loudly. */
export function mockApi(routes: Route[]) {
  const calls: { method: string; path: string; body: unknown }[] = []
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://127.0.0.1')
    const path = url.pathname.replace(/^\/api\/v1/, '') + url.search
    const method = init?.method ?? 'GET'
    calls.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : undefined })
    const route = routes.find(r => (r.method ?? 'GET') === method && (typeof r.path === 'string' ? r.path === path : r.path.test(path)))
    if (!route) return new Response(JSON.stringify({ error: { code: 'not_found', message: `Unmocked ${method} ${path}` } }), { status: 404 })
    const { status, body } = route.reply ? route.reply() : { status: route.status ?? 200, body: route.body }
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fn)
  return calls
}

export function standardRoutes(extra: Route[] = [], opts: { project?: Record<string, unknown>; kase?: Record<string, unknown> } = {}): Route[] {
  return [
    ...extra,
    { path: '/session', body: { csrf_token: 'csrf-test' } },
    { path: '/projects?limit=100', body: { items: [project(opts.project)], next_cursor: null } },
    { path: '/projects/p1/status', body: project(opts.project) },
    { path: '/projects/p1/actions', body: { items: [{ action_id: 'a1', title: 'Review patch: book ownership', reason: 'Policy requires review.', case_id: 'c1', allowed_actions: [] }] } },
    { path: '/projects/p1/findings', body: { items: [] } },
    { path: '/projects/p1/cycles', body: { items: [] } },
    { path: '/cases/c1', body: caseReview(opts.kase) },
  ]
}
