// Layout probe: serves the built frontend with synthetic API fixtures on loopback and measures clipping in headless Chromium.
// Not part of `npm test`. Copy into a scratch dir where `npm i puppeteer-core@24` was run (ESM resolves imports from the
// script location), set a short TMPDIR (Chromium socket-path limit), then: node layout-probe.mjs <abs frontend/dist> <screenshot dir>
// Uses /usr/bin/chromium; fixtures are synthetic and prove layout only, not controller behaviour.
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import puppeteer from 'puppeteer-core'

const DIST = process.argv[2]
const OUT = process.argv[3]
const long = 'very-long-organisation-name-without-breaks/another-extremely-long-repository-name-for-wrapping-tests'
const project = { project_id: 'p1', display_name: long, owner_policy_id: 'review-v1', setup_state: 'READY', admission_state: 'active', attention_count: 1, active_cycle: { cycle_id: 'cy1', status: 'verifying', reason: 'Verifying candidate.' }, reason: null, source_summary: { commit: 'abc1234def5678' }, deployment_summary: { deployment_id: 'd1', status: 'running', generation: 3, previous_digest: 'sha256:prevprevprevprevprev', artifact_digest: 'sha256:curcurcurcurcur' }, mirror_summary: { state: 'current' }, cost_summary: { committed_micro_usd: 60000, ceiling: 2000000 }, feed_freshness: [{ source: 'OSV', status: 'current', fetched_at: '2026-11-14T10:00:00Z' }], allowed_actions: [{ action: 'run', eligible: false, disabled_reason: 'A cycle is already running for this repository.' }, { action: 'rollback', eligible: true, disabled_reason: null }] }
const gate = (i, cat, outcome) => ({ gate_id: 'g' + i, case_id: 'c1', candidate_id: 'cand1', candidate_hash: 'h', check_profile_id: `${cat}-check-${i}-v1`, category: cat, status: 'pass', proof_outcome: outcome, scope: ['GET /books/{id}', 'ownership invariant'], assumptions: ['Single tenant'], reason: 'Gate reason text that is reasonably long to exercise wrapping on narrow screens.', tool_version: '1', command_profile_hash: 'x', exit_code: 0, started_at: '', finished_at: '', evidence_ids: ['ev1', 'ev2'] })
const kase = { title: 'Review patch: ' + long, status: 'needs_review', cycle_id: 'cy1', created_at: '2026-11-14T10:00:00Z', reason: null, generation_mode: 'fresh_inference', case_id: 'c1', project_id: 'p1', revision: 7, finding_refs: [], candidate_id: 'cand1', diff_ref: null, assurance_summary: {}, evidence_manifest_hash: 'sha256:' + 'f'.repeat(64), destination_id: 'local-lab-destination', expected_deployment_generation: 3, gate_results: [gate(1, 'security', null), gate(2, 'formal', 'UNKNOWN'), gate(3, 'formal', null)], allowed_actions: [{ action: 'approve', eligible: true }, { action: 'reject', eligible: true }] }
const findings = Array.from({ length: 100 }, (_, i) => ({ finding_id: 'f' + i, title: `Finding ${i} ` + long, status: i % 3 ? 'unconfirmed' : 'confirmed', cwe: 'CWE-639', source_tools: ['semgrep'], location: { file: 'src/some/deeply/nested/path/module_' + i + '.py', line: i } }))
const api = { '/session': { csrf_token: 't' }, '/projects?limit=100': { items: [project], next_cursor: null }, '/projects/p1/status': project, '/projects/p1/actions': { items: [{ action_id: 'a1', title: 'Review patch: book ownership', reason: 'Policy requires review.', case_id: 'c1' }, { action_id: 'a2', title: 'Setup failed: unsupported Python', reason: 'Build stopped.', case_id: null, allowed_actions: [{ action: 'retry_setup', eligible: false, disabled_reason: 'Fix the declared runtime first.' }] }] }, '/projects/p1/findings': { items: findings }, '/projects/p1/cycles': { items: [{ cycle_id: 'cy1', status: 'verifying', created_at: '2026-11-14T10:00:00Z', reason: null, case_ids: ['c1'] }] }, '/cases/c1': kase }

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x')
  if (url.pathname.startsWith('/api/v1')) {
    const key = url.pathname.slice(7) + url.search
    const body = api[key]
    res.writeHead(body ? 200 : 404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body ?? { error: { message: 'nf' } })); return
  }
  let file = path.join(DIST, url.pathname)
  if (!file.startsWith(DIST) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(DIST, 'index.html')
  res.writeHead(200, { 'Content-Type': file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html' }); fs.createReadStream(file).pipe(res)
})
await new Promise(r => server.listen(0, '127.0.0.1', r))
const base = `http://127.0.0.1:${server.address().port}`
const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] })
const measure = () => {
  const vw = document.documentElement.clientWidth
  const bad = []
  for (const el of document.querySelectorAll('button, a.button, input, select, textarea, label, h1, h2, h3')) {
    const r = el.getBoundingClientRect()
    if (!r.width) continue
    const scroller = el.closest('.table-wrap, .diff')
    if (scroller) continue
    if (r.right > vw + 1 || r.left < -1 || el.scrollWidth > el.clientWidth + 1) bad.push(`${el.tagName} "${(el.textContent || '').trim().slice(0, 40)}" left=${r.left|0} right=${r.right|0} sw=${el.scrollWidth} cw=${el.clientWidth}`)
    if ((el.tagName === 'BUTTON' || el.classList.contains('button')) && r.height < 40) bad.push(`small target ${el.textContent.trim()} h=${r.height}`)
  }
  return { vw, docOverflow: document.documentElement.scrollWidth - vw, bad }
}
const results = []
for (const [w, h] of [[360, 900], [375, 900], [1280, 900]]) {
  const page = await browser.newPage()
  await page.setViewport({ width: w, height: h })
  for (const [name, route, open] of [['repos', '/', null], ['repos-dialog', '/', 'Add repository'], ['project', '/projects/p1', null], ['project-rollback', '/projects/p1', 'Roll back'], ['case', '/projects/p1/cases/c1', null], ['case-approve', '/projects/p1/cases/c1', 'Approve for lab']]) {
    await page.goto(base + route, { waitUntil: 'networkidle0' })
    await page.waitForSelector('#main h1')
    if (open) {
      await page.evaluate(label => [...document.querySelectorAll('button')].find(b => b.textContent.trim() === label && !b.disabled)?.click(), open)
      await page.waitForSelector('dialog[open]')
    }
    const m = await page.evaluate(measure)
    await page.screenshot({ path: `${OUT}/${name}-${w}.png`, fullPage: !open })
    results.push({ w, name, ...m })
  }
  await page.close()
}
// 200% zoom approximation: 640px CSS viewport at deviceScaleFactor 2 (equivalent reflow width of a 1280px window at 200%).
const zp = await browser.newPage(); await zp.setViewport({ width: 640, height: 450, deviceScaleFactor: 2 })
for (const [name, route] of [['zoom200-project', '/projects/p1'], ['zoom200-case', '/projects/p1/cases/c1']]) {
  await zp.goto(base + route, { waitUntil: 'networkidle0' }); await zp.waitForSelector('#main h1')
  results.push({ w: '640@2x', name, ...(await zp.evaluate(measure)) }); await zp.screenshot({ path: `${OUT}/${name}.png` })
}
await browser.close(); server.close()
for (const r of results) console.log(`${String(r.w).padEnd(6)} ${r.name.padEnd(18)} docOverflow=${r.docOverflow} issues=${r.bad.length}${r.bad.length ? '\n   ' + r.bad.join('\n   ') : ''}`)
