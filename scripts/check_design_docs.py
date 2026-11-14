"""Check handoff structure and examples; does not validate the product."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = [
    'README.md', 'AGENTS.md', 'PRODUCT.md', 'DESIGN.md',
    'docs/user-workflows.md', 'docs/cli.md', 'docs/frontend.md', 'docs/secrets-configuration.md', 'docs/README.md', 'docs/architecture.md',
    'docs/contracts.md', 'docs/onboarding-sandbox.md', 'docs/agents-intelligence.md',
    'docs/verification.md', 'docs/deployment-observability.md', 'docs/runtime.md',
    'docs/implementation.md', 'docs/integration.md', 'docs/evaluation.md',
    'docs/repository-cohort.md', 'docs/value-assessment.md', 'docs/design-audit.md',
    'docs/project-context.md', 'docs/repository-catalog.md', 'docs/model-strategy.md',
    'docs/vampi-formal-plan.md',
    'docs/sessions/README.md', 'docs/sessions/a-control.md',
    'docs/sessions/b-onboarding.md', 'docs/sessions/c-repair-deploy.md',
    'docs/sessions/d-verification.md',
]
errors=[]
for name in required:
    if not (ROOT/name).is_file(): errors.append('Missing: '+name)
for p in [ROOT/'README.md', ROOT/'AGENTS.md', ROOT/'PRODUCT.md', ROOT/'DESIGN.md', *sorted((ROOT/'docs').rglob('*.md'))]:
    if not p.exists(): continue
    text=p.read_text()
    if text.count('```') % 2: errors.append('Unclosed code fence: '+str(p.relative_to(ROOT)))
    for link in re.findall(r'\]\(([^)]+)\)',text):
        if link.startswith(('https://','http://','#','mailto:')): continue
        target=(p.parent/link.split('#')[0]).resolve()
        if not target.exists(): errors.append(f'Broken link {p.relative_to(ROOT)} -> {link}')
for p in sorted((ROOT/'docs/examples').glob('*.json')):
    json.loads(p.read_text())
cohort=json.loads((ROOT/'evaluation/repository-candidates.json').read_text())
assert cohort['status']=='candidate_only' and cohort['scored_execution_allowed'] is False
rows=cohort['repositories']
assert len(rows)==10 and len({r['repo_id'] for r in rows})==10
assert all(r['eligibility_status']=='not_preflighted' and r['source_commit'] is None for r in rows)
assert {x['repo_id'] for x in rows} == {'U01','U02','U03','U04','U05','U06','U07','U08','U09','U18'}
by_id={x['repo_id']:x for x in rows}
assert by_id['U02']['phase_role']=='primary_holdout'
assert by_id['U08']['evaluation_mode']=='static_only'
catalog=(ROOT/'docs/repository-catalog.md').read_text()
assert set(re.findall(r'\| (U\d{2}) \[',catalog)) == {f'U{i:02}' for i in range(1,25)}
assert 'zai-glm-5-3-flash' in (ROOT/'docs/model-strategy.md').read_text()
r=json.loads((ROOT/'docs/examples/runtime-config.json').read_text())
assert r['standard']['case_seconds']==90*60 and r['standard']['cycle_seconds']==120*60
assert r['heavy']['case_seconds']==180*60 and r['heavy']['cycle_seconds']==240*60
assert r['standard']['max_candidates']==3
b=r['budget']
assert b['automatic_ceiling_micro_usd']+b['contingency_micro_usd']==b['total_credit_micro_usd']
example=(ROOT/'.env.example').read_text()
assert 'MISTRAL_API_KEY=\n' in example and 'GROQ_API_KEY=\n' in example
assert all(not line.split('=',1)[1].strip() for line in example.splitlines() if line.startswith(('MISTRAL_API_KEY=','GROQ_API_KEY=')))
if errors:
    raise SystemExit('\n'.join(errors))
print(f'PASS: {len(required)} required handoff files, local links/code fences, JSON examples, 10 candidate records and runtime accounting.')
print('This check validates documents only; it does not execute or validate implementation, sandboxes or benchmarks.')
