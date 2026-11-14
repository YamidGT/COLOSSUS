"""Build the two-page English submission from committed, measured evidence.

Run with a documentation environment containing ReportLab. This does not execute
repositories, call models, or replace the evaluation runner.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = json.loads((ROOT / "docs/submission-evidence.json").read_text())
BASE = EVIDENCE["baseline"]
REPAIR = BASE["dsvw_fresh_repair"]
REPLAY = BASE["dsvw_replayed_lifecycle"]
FORMAL = BASE["formal_component_calibration"]
NEW = EVIDENCE["new_runs"]
INK = colors.HexColor("#17212B")
MUTED = colors.HexColor("#52606D")
ACCENT = colors.HexColor("#174EA6")
LINE = colors.HexColor("#DCE1E7")
PALE = colors.HexColor("#F6F7F9")
WIDTH = 511

STYLES = {
    "title": ParagraphStyle(
        "title", fontName="Helvetica-Bold", fontSize=27, leading=30, textColor=INK, spaceAfter=6
    ),
    "subtitle": ParagraphStyle(
        "subtitle", fontName="Helvetica", fontSize=14, leading=18, textColor=INK, spaceAfter=9
    ),
    "heading": ParagraphStyle(
        "heading",
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=15,
        textColor=ACCENT,
        spaceBefore=12,
        spaceAfter=5,
    ),
    "body": ParagraphStyle(
        "body", fontName="Helvetica", fontSize=10.5, leading=14.3, textColor=INK, spaceAfter=7
    ),
    "meta": ParagraphStyle(
        "meta", fontName="Helvetica", fontSize=8.7, leading=12, textColor=MUTED, spaceAfter=8
    ),
    "caption": ParagraphStyle(
        "caption",
        fontName="Helvetica",
        fontSize=8.8,
        leading=12,
        textColor=MUTED,
        spaceBefore=5,
        spaceAfter=5,
    ),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=9.4, leading=12.2, textColor=INK),
    "headcell": ParagraphStyle(
        "headcell", fontName="Helvetica-Bold", fontSize=9.4, leading=12.2, textColor=INK
    ),
    "reference": ParagraphStyle(
        "reference", fontName="Helvetica", fontSize=8, leading=10.8, textColor=MUTED, spaceAfter=4
    ),
}


class Architecture(Flowable):
    """Small vector diagram; arrows encode execution and the recurring loop."""

    def __init__(self):
        Flowable.__init__(self)
        self.width, self.height = WIDTH, 139

    def draw(self):
        c = self.canv
        c.setLineWidth(0.7)
        boxes = [
            (0, 92, 116, 37, ["CLI / action center", "GitHub URL + policy"]),
            (133, 92, 178, 37, ["Deterministic controller", "Queue, budget, audit, evidence"]),
            (
                328,
                92,
                183,
                37,
                ["GLM gateway + threat feeds", "Proposals; no deployment authority"],
            ),
            (0, 27, 155, 41, ["Isolated copy", "Inspect, reproduce, patch"]),
            (174, 27, 165, 41, ["Verification", "Mandatory tests + applicable proof"]),
            (358, 27, 153, 41, ["Lab deployment", "Observe, recover, refresh"]),
        ]
        for x, y, w, h, labels in boxes:
            c.setFillColor(PALE)
            c.setStrokeColor(LINE)
            c.roundRect(x, y, w, h, 4, stroke=1, fill=1)
            c.setFillColor(INK)
            c.setFont("Helvetica-Bold", 9)
            c.drawCentredString(x + w / 2, y + h - 13, labels[0])
            c.setFont("Helvetica", 7.8)
            c.drawCentredString(x + w / 2, y + 9, labels[1])
        c.setStrokeColor(ACCENT)
        c.setFillColor(ACCENT)

        def arrow(x1, y1, x2, y2):
            c.line(x1, y1, x2, y2)
            if x2 > x1:
                p = c.beginPath()
                p.moveTo(x2, y2)
                p.lineTo(x2 - 4, y2 + 2)
                p.lineTo(x2 - 4, y2 - 2)
                p.close()
            elif y2 < y1:
                p = c.beginPath()
                p.moveTo(x2, y2)
                p.lineTo(x2 - 2, y2 + 4)
                p.lineTo(x2 + 2, y2 + 4)
                p.close()
            else:
                p = c.beginPath()
                p.moveTo(x2, y2)
                p.lineTo(x2 + 4, y2 + 2)
                p.lineTo(x2 + 4, y2 - 2)
                p.close()
            c.drawPath(p, stroke=0, fill=1)

        arrow(116, 110, 133, 110)
        arrow(311, 110, 328, 110)
        c.line(222, 92, 222, 80)
        c.line(222, 80, 77, 80)
        arrow(77, 80, 77, 68)
        arrow(155, 47, 174, 47)
        arrow(339, 47, 358, 47)
        c.line(435, 27, 435, 10)
        c.line(435, 10, 77, 10)
        c.line(77, 10, 77, 27)
        c.setFont("Helvetica", 7.8)
        c.setFillColor(MUTED)
        c.drawCentredString(255, 0, "Refresh the tested mirror; next bounded cycle")


def p(text, kind="body"):
    return Paragraph(escape(text), STYLES[kind])


fresh = NEW.get("dsvw_fresh_lifecycle", {})
formal_agent = NEW.get("formal_agent", {})
campaign = NEW.get("repository_campaign", {})
fresh_ok = fresh.get("status") == "COMPLETE"
if fresh_ok:
    result_sentence = (
        f"A fresh DSVW run completed repair, lab promotion and mirror refresh in {fresh['elapsed_seconds']:.1f} seconds, "
        "including five minutes of health observation."
    )
else:
    result_sentence = (
        f"A fresh DSVW repair passed its checks in {REPAIR['elapsed_seconds']:.1f} seconds; "
        f"a separate replay completed promotion and mirror refresh in {REPLAY['first_cycle_seconds']:.1f} seconds, "
        "including five minutes of observation."
    )
abstract = (
    "AI can accelerate vulnerability discovery, but an autonomous defender can also ship a broken patch or follow hostile instructions. "
    "COLOSSUS accepts a GitHub URL, investigates an isolated copy, generates repairs with GLM, and gates lab deployment on recorded tests and applicable proofs. "
    + result_sentence
)
threat = (
    "Faster vulnerability discovery is useful only if defenders can safely remediate what they find. "
    "An automated patch may break legitimate behavior; a repository comment or tool response may redirect the agent. "
    "Developers need an auditable path from evidence to a running repair, with independent checks and recovery. "
    "COLOSSUS treats repository content and model proposals as untrusted inputs, consistent with agent-security research [1]."
)
build = (
    "An operator enrolls a repository through a Typer CLI or React/Tailwind action center. "
    "The controller pins source, builds a supported Python application in gVisor, and records readiness and dependencies. "
    "Scheduled reviews and OSV/CISA intelligence feed bounded investigations. GLM, accessed through Mistral, proposes patches; deterministic code controls edits, budgets and deployment. "
    "Every repair requires protected security and legitimate-behavior tests. For the registered policy fixture, GLM proposes implementations inside a frozen Dafny template, receives verifier diagnostics and retries within a fixed budget [2]. "
    "Unknown or unsupported proof falls back to mandatory testing under the tested policy; required proofs still block deployment. "
    "Compiled components require artifact and wrapper checks. Accepted artifacts undergo lab observation, promotion and mirror refresh. A retained previous image supports recovery. "
    "Credentials remain outside target containers."
)
evaluation = (
    "We evaluated two fresh runs of one DSVW SQL-query repair through protected tests, deployment, recurrence and rollback. "
    "An owned four-method policy fixture exercises proof, compilation and wrong implementations. "
    "A 24-repository compatibility pilot accepted 20 archives; five additional runtime attempts yielded two assisted starts and three failures. "
    "GLM triaged Python snippets in 11 repositories; judgments remain unconfirmed. "
    "Metrics are scope, completion, latency and cost, not security accuracy. CTIBench, CyberSecEval and DafnyBench remain unrun [3-5]."
)

results_text = (
    "The complete deployment path is demonstrated for one scoped DSVW repair; component proofs are separate evidence. "
    "Unsupported verification never becomes a proof pass. Earlier fresh lifecycle attempts stopped on invalid model output and HTTP 429; a successful replay does not establish fresh-model reliability."
)
if fresh_ok:
    results_text = (
        "The fresh DSVW cycle demonstrates repair through healthy lab deployment and mirror refresh. "
        "Component proofs remain separate evidence. Earlier attempts stopped on invalid model output and HTTP 429; one successful run does not establish reliability across repositories."
    )
repeat = NEW.get("dsvw_fresh_repetition", {})
if repeat.get("status") == "COMPLETE":
    results_text = (
        "Two fresh DSVW cycles completed deployment and mirror refresh. In the repetition, the security gate blocked the first generated patch; "
        "GLM used failure feedback and the second candidate passed. Both next cycles returned NO_CHANGE. "
        "Component proofs remain separate; earlier provider errors and narrow scope prevent general reliability claims."
    )
limits = (
    "This is a constrained lab prototype, not a production security guarantee. Generic repair coverage and stack compatibility remain limited. "
    "Proofs cover named components under fixed contracts and toolchain assumptions; they do not prove an entire Python application secure. "
    "Public training repositories and small calibration samples limit generalization. Detection and patch generation are dual-use: execution is confined to enrolled local copies with quotas, restricted networking and no model-held deployment credentials. "
    "No live public target or cloud attack scenario was exercised."
)
refs = [
    ("[1] Debenedetti et al. (2024). AgentDojo. NeurIPS.", "https://arxiv.org/abs/2406.13352"),
    (
        "[2] Dafny contributors. Dafny Reference Manual.",
        "https://dafny.org/dafny/DafnyRef/DafnyRef",
    ),
    (
        "[3] Alam et al. (2024). CTIBench. NeurIPS.",
        "https://arxiv.org/abs/2406.07599",
    ),
    (
        "[4] Bhatt et al. (2023). Purple Llama CyberSecEval.",
        "https://arxiv.org/abs/2312.04724",
    ),
    ("[5] Loughridge et al. (2024). DafnyBench.", "https://arxiv.org/abs/2406.08467"),
]
rows = [
    ["Measurement", "Scope / baseline", "Observed result"],
    [
        "DSVW repair checks",
        "One original vs patched query",
        "7 required gates passed; formal unsupported",
    ],
    [
        "Fresh repair generation",
        "One call; no deployment",
        f"{REPAIR['elapsed_seconds']:.1f} s; ${REPAIR['cost_micro_usd'] / 1_000_000:.6f}",
    ],
    [
        "Deployment + refresh",
        "Fresh inference" if fresh_ok else "Replayed proposal; 300 s observation",
        f"{fresh['elapsed_seconds'] if fresh_ok else REPLAY['first_cycle_seconds']:.1f} s; complete",
    ],
    ["Formal component", "Owned policy; not DSVW", "4 methods proved; 39 wrapper checks passed"],
    [
        "Incorrect controls",
        "4 policy mutants + wrapper bypass",
        "All rejected; substituted files rejected",
    ],
]
if fresh_ok:
    rows[2] = [
        "Fresh full cycle",
        "1 new call; 300 s observation",
        f"{fresh['elapsed_seconds']:.1f} s; ${fresh['settled_micro_usd'] / 1_000_000:.6f}",
    ]
    rows[3] = [
        "Repeat / recovery",
        "Second cycle; retained training image",
        f"NO_CHANGE; rollback {fresh['rollback_seconds']:.1f} s",
    ]
if repeat.get("status") == "COMPLETE":
    rows[3] = [
        "Fresh repetition",
        "2 calls; first candidate blocked",
        f"{repeat['elapsed_seconds']:.1f} s; ${repeat['settled_micro_usd'] / 1_000_000:.6f}",
    ]
if formal_agent.get("status") not in (None, "pending"):
    rows[4] = [
        "GLM formal component",
        "Owned: 4 methods; 39 wrapper checks",
        formal_agent.get("display", formal_agent["status"]),
    ]
triage = NEW.get("catalog_triage", {})
if triage.get("status") == "measured":
    rows.append(
        [
            "GLM signal triage",
            "11 repos; unconfirmed judgments",
            f"{triage['valid_verdicts']} / {triage['selected_groups']} returned; ${triage['settled_micro_usd'] / 1_000_000:.6f}",
        ]
    )
if campaign.get("status") == "completed_capability_audit":
    rows.append(
        [
            "Application smoke tests",
            "VAmPI modified pin; PyGoat sub-lab",
            "6/6 + 7/7 HTTP checks; no repair",
        ]
    )
if campaign.get("status") not in (None, "pending"):
    rows.append(
        [
            "Repository campaign",
            "24 requested; mixed coverage",
            campaign.get("display", campaign["status"]),
        ]
    )
else:
    rows.append(
        ["Repository campaign", "24 requested", "Results pending; not counted as successes"]
    )

flow = [
    p("COLOSSUS", "title"),
    p("Recurring cyberdefence from a GitHub repository", "subtitle"),
    p(
        "Hackathon DefAcc 2026 | Track 3: Automated cyberdefence | COLOSSUS team (four contributors); lead: Daniel",
        "meta",
    ),
    Paragraph(
        '<link href="https://github.com/YamidGT/COLOSSUS" color="#174EA6">Repository and run instructions: github.com/YamidGT/COLOSSUS</link>',
        STYLES["meta"],
    ),
    p("Abstract", "heading"),
    p(abstract),
    p("1. The threat", "heading"),
    p(threat),
    p("2. What we built", "heading"),
    p(build),
    Spacer(1, 6),
    Architecture(),
    p(
        "Figure 1. Models propose repairs and proof candidates; deterministic gates control isolated execution and lab deployment.",
        "caption",
    ),
    PageBreak(),
    p("Evaluation and results", "title"),
    p("3. How we evaluated", "heading"),
    p(evaluation),
    p("4. Results", "heading"),
]
table_data = [
    [p(value, "headcell" if i == 0 else "cell") for value in row] for i, row in enumerate(rows)
]
table = Table(table_data, colWidths=[130, 177, 204], hAlign="LEFT")
table.setStyle(
    TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), PALE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, LINE),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]
    )
)
flow += [
    table,
    p(
        "Table 1. Development and component-calibration results; no overall security score or benchmark certification.",
        "caption",
    ),
    p(results_text),
    p("5. Limits and dual-use risk", "heading"),
    p(limits),
    p("References", "heading"),
]
for label, url in refs:
    flow.append(
        Paragraph(
            f'{escape(label)} <link href="{escape(url)}" color="#174EA6">Source</link>',
            STYLES["reference"],
        )
    )


def footer(canvas, doc):
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(42, 23, "COLOSSUS | Measured prototype submission | 14 November 2026")
    canvas.drawRightString(553, 23, f"{doc.page} / 2")


out = ROOT / "output/pdf/colossus-technical-sheet.pdf"
out.parent.mkdir(parents=True, exist_ok=True)
document = SimpleDocTemplate(
    str(out),
    pagesize=(595, 842),
    leftMargin=42,
    rightMargin=42,
    topMargin=32,
    bottomMargin=38,
    title="COLOSSUS: recurring automated cyberdefence",
    author="COLOSSUS team",
)
document.build(flow, onFirstPage=footer, onLaterPages=footer)
if document.page != 2:
    raise ValueError(f"Expected two pages; rendered {document.page}")
md = [
    "# COLOSSUS",
    "Recurring cyberdefence from a GitHub repository",
    "Hackathon DefAcc 2026 | Track 3: Automated cyberdefence | 14 November 2026",
    "Team: four contributors; lead Daniel. [Repository and run instructions](https://github.com/YamidGT/COLOSSUS).",
    "## Abstract",
    abstract,
    "## 1. The threat",
    threat,
    "## 2. What we built",
    build,
    "```text\nCLI / action center --> Controller <--> GLM gateway + feeds\n                             |\nIsolated copy --> Mandatory tests + applicable proof --> Lab deployment\n      ^                                                    |\n      +---------------- Mirror refresh --------------------+\n```",
    "Figure 1. Models propose; deterministic gates control effects.",
    "## 3. How we evaluated",
    evaluation,
    "## 4. Results",
]
table_lines = ["| " + " | ".join(rows[0]) + " |", "|---|---|---|"]
table_lines += ["| " + " | ".join(row) + " |" for row in rows[1:]]
md.append("\n".join(table_lines))
md += [results_text, "## 5. Limits and dual-use risk", limits, "## References"]
md += [f"- {label} [Source]({url})" for label, url in refs]
md += [
    "\nEvidence: [committed summary](submission-evidence.json), [submission runbook](submission.md)."
]
(ROOT / "docs/technical-sheet.md").write_text("\n\n".join(md) + "\n")
print(out)
print(
    "Section word counts:",
    {
        name: len(text.split())
        for name, text in [
            ("abstract", abstract),
            ("threat", threat),
            ("build", build),
            ("evaluation", evaluation),
            ("results", results_text),
            ("limits", limits),
        ]
    },
)
