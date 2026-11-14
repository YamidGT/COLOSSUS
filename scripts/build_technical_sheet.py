"""Generate the English two-page design-stage technical sheet (ReportLab)."""
from pathlib import Path
from html import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, PageBreak
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors

ROOT=Path(__file__).resolve().parents[1]
pages=[[
('title','COLOSSUS'),
('subtitle','Recurring automated cyberdefence from a GitHub repository'),
('small','Track 3 | Daniel and three collaborators | Design specification v1.2 | 14 November 2026'),
('body','Status: implementation handoff prepared. Product execution, repository preflight and empirical results are pending. The system described below is the intended implementation, not a claim of measured performance.'),
('heading','Objective and risk'),
('body','COLOSSUS is designed to reduce the interval between a software exposure and a healthy remediated deployment. It combines recurring threat intelligence and security investigation with patch generation, explicit verification, controlled promotion and recovery. It also constrains the risk that a defensive agent follows hostile repository content, changes its own acceptance criteria or deploys a faulty repair.'),
('heading','Plug and play onboarding'),
('body','A public GitHub URL starts source inspection and immutable snapshot creation. The system identifies the stack, validates an existing container recipe or proposes one, builds in an isolated worker, provisions synthetic dependencies and checks readiness. A versioned TargetManifest binds source, images, dependencies, configuration, tests, security policy and proof obligations. Unsupported stacks and missing configuration are explicit outcomes. Libraries use a consumer/test harness; services use isolated application stacks.'),
('heading','Complete recurring lifecycle'),
('body','Source changes, scheduled reviews and relevant advisories trigger a deterministic orchestrator. The investigation agent combines static tools, dependency matching, scoped probes and bounded fuzzing. Confirmed findings lead to an official upstream update or an agent-generated source repair. Each candidate is built from pristine inputs and checked against security, functional and formal obligations. Accepted artifacts pass an autonomy policy, staging and observation. Success refreshes the mirror; failure triggers recovery and reopens investigation.'),
('heading','Architecture and authority'),
('body','Operators use a Typer CLI or a minimal React/Tailwind repository action center for setup, patch review, proof scope, approvals and recovery. Both share the Python API, SQLite durable tasks/events and content-addressed evidence. A gateway alone holds the Mistral key; a sandbox launcher alone controls runtime actions; a deployment service alone holds destination credentials. Target workers cannot reach management networks or other projects. Code, build hooks and proof tools execute only in isolated environments. Resource quotas, deadlines, capability checks and protected test/specification paths constrain effects independently of model compliance.'),
('heading','Formal methods and assurance'),
('body','The initial formal integration compiles verified Dafny policy functions into VAmPI: password ownership, book-secret access, registration privileges and public user fields. Flask/JWT/database wrappers remain tested assumptions. CrossHair explores Python counterexamples; CBMC is a later C/C++ adapter. A detached model does not prove the running application. Outcomes distinguish proof, bounded pass, counterexample, unknown and unsupported. Required proofs block on failure or missing evidence; patchers cannot weaken specifications.'),
], [
('title','Evaluation and delivery'),
('heading','Repository campaign'),
('body','Use DSVW for smoke testing and VAmPI for development; reserve Vulpy for heldout scoring, with Tiredful-API as a predeclared setup fallback. DVGA is optional static-only. Five further Python/API candidates remain deferred in a ten-repository roster; all 24 user suggestions are cataloged. VAmPI safe mode and Vulpy good/ are not globally secure references. Freeze commits, images, scoped oracles and positive workflows; disclose manual setup and known-reference access.'),
('body','Calibrate on development targets before the holdout. Two scoped variants and three repetitions across three full-cycle targets yield up to 18 primary runs, with development and heldout results separate. A second cycle checks mirror freshness and continued operation. Compare tools-only discovery and baseline repair; rescore identical candidates with gates removed offline. Add rollout failures, prompt injections and good/bad candidate controls.'),
('heading','Three public benchmark families'),
('body','CTIBench: 50 root-cause mapping and 50 severity-prediction examples, measuring CWE accuracy and CVSS error/validity. CyberSecEval Instruct: up to 30 eligible examples, measuring generated insecure code with the upstream analyzer. DafnyBench: 20 compatible programs, up to three attempts, measuring verifier acceptance and improvement over a no-hint baseline. These are fixed-subset pilots, not full-suite certification. Local patch checks inspired by AutoPatchBench are labelled separately from official benchmark results.'),
('heading','Metrics and observable evidence'),
('body','Report onboarding completion, labelled precision/recall, correct repair and healthy deployment rates, regressions, per-property proof outcomes, incorrect and correct candidate acceptance, rollback correctness/time, unauthorized effects and useful task completion under attack. Include latency, all model costs, operator interventions, exclusions and failed runs. OpenTelemetry traces/metrics/logs provide operational visibility; unsampled audit decisions retain policy and artifact provenance. No empirical values are claimed yet.'),
('heading','Resources timing and implementation'),
('body','Resources: 4 CPU, 24 GB Oracle host, local workers and USD 150 Mistral credit. Default model: zai-glm-5-3-flash; published input/output rates USD 0.15/0.50 per million tokens. Account throughput is user-reported, not measured here. One heavy worker; USD 120 automated ceiling plus USD 30 reserve. Planning estimates: 15-40 minutes for a small warm cycle; 25-60 minutes for first URL setup and cycle. Standard active case cap: 90 minutes. These estimates require calibration. A repeated ten-repository campaign with second cycles may require 32-76 serial host-hours before additional baselines/benchmarks.'),
('body','Four lanes implement shared contracts first: A/Daniel owns control, gateway, sandbox and integration; B owns onboarding, intelligence and investigation; C owns repairs, deployment and recovery; D owns verification and evaluation. Integration proceeds through a real URL-to-target path, candidate checks, promotion/rollback and a second cycle. The merging runbook requires ownership boundaries, versioned interfaces, CLI/UI parity, restart tests and evidence. Product/design briefs define Impeccable-guided visual and accessibility review.'),
('heading','Limits and research basis'),
('body','Formal guarantees remain conditional on properties, assumptions and trusted tools. Small samples, historical public data and synthetic mutations limit generalization. An image rollback does not automatically reverse data changes. Model alignment and absolute sandbox security are not proved. Production deployment needs separately configured owner authorization. The research basis includes DARPA AIxCC, CodeMender, CTIBench, CyberSecEval, DafnyBench and AgentDojo; full source links and protocols are in the repository documentation.'),
]]
styles={
 'title':ParagraphStyle('title',fontName='Helvetica-Bold',fontSize=22,leading=26,spaceAfter=9),
 'subtitle':ParagraphStyle('subtitle',fontName='Helvetica-Bold',fontSize=12,leading=16,spaceAfter=8),
 'heading':ParagraphStyle('heading',fontName='Helvetica-Bold',fontSize=11,leading=14,spaceBefore=8,spaceAfter=4),
 'body':ParagraphStyle('body',fontName='Helvetica',fontSize=9.7,leading=12.8,spaceAfter=6),
 'small':ParagraphStyle('small',fontName='Helvetica',fontSize=8,leading=11,spaceAfter=8),
}
flow=[]; md=[]
for index,items in enumerate(pages):
 if index: flow.append(PageBreak()); md.append('\n<!-- Page 2 in the PDF -->\n')
 for kind,text in items:
  flow.append(Paragraph(escape(text),styles[kind]))
  prefix='# ' if kind=='title' else '## ' if kind in ('subtitle','heading') else ''
  md.append(prefix+text+'\n')
def footer(canvas,doc):
 canvas.setFont('Helvetica',8); canvas.setFillColor(colors.HexColor('#555555'))
 canvas.drawString(42,24,'COLOSSUS | Design-stage technical sheet')
 canvas.drawRightString(553,24,str(doc.page))
out=ROOT/'output/pdf/colossus-technical-sheet.pdf'; out.parent.mkdir(parents=True,exist_ok=True)
SimpleDocTemplate(str(out),pagesize=(595,842),leftMargin=42,rightMargin=42,topMargin=33,bottomMargin=38).build(flow,onFirstPage=footer,onLaterPages=footer)
(ROOT/'docs/technical-sheet.md').write_text('\n'.join(md))
print(out)
