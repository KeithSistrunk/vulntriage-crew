"""The PDF triage report.

Same rule as every other renderer in this project: **everything on the page comes
from `PipelineState`'s structured findings.** The agents' narrative is not
rendered here at all -- not summarized, not quoted. A PDF is the artifact that
gets forwarded to someone who was not in the room, and the one thing it must
never do is put a model's prose where a reader will take it for fact. The
markdown report is where narrative belongs, clearly attributed and guard-checked.

Layout only. The byte-level PDF mechanics are in `pdfwriter.py`.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .pdfwriter import (
    HELVETICA,
    HELVETICA_BOLD,
    PdfCanvas,
    columns,
    text_width,
    wrap,
)
from .models import ScoredFinding
from .remediation import remediation_for
from .scoring import PRIORITY_BANDS
from .state import PipelineState

PRIORITY_SLA = {priority: sla for _, priority, sla in PRIORITY_BANDS}

# Priority owns the colour in this document; nothing else is coloured, so a
# reader's eye goes to severity rather than to decoration.
PRIORITY_COLORS = {
    "P1": (0.698, 0.149, 0.118),
    "P2": (0.776, 0.420, 0.051),
    "P3": (0.129, 0.349, 0.620),
    "P4": (0.400, 0.420, 0.450),
}
INK = (0.10, 0.11, 0.13)
MUTED = (0.42, 0.44, 0.47)
FAINT = (0.93, 0.94, 0.95)
RULE = (0.85, 0.86, 0.88)

# #, Pri, CVE, CVSS, Risk, Host, Exploit -- 504pt, the content width at 54pt margins.
TABLE_WIDTHS = [24.0, 32.0, 96.0, 40.0, 40.0, 152.0, 120.0]
TABLE_HEADS = ["#", "Pri", "CVE", "CVSS", "Risk", "Host", "Exploit"]


def _fit(text: str, font: str, size: float, width: float) -> str:
    """Truncate with an ellipsis so a cell can never bleed into its neighbour."""
    text = str(text)
    if text_width(text, font, size) <= width:
        return text
    while text and text_width(text + "…", font, size) > width:
        text = text[:-1]
    return text + "…"


def _target(finding: ScoredFinding) -> str:
    port = f"{finding.port}/{finding.protocol}" if finding.port else "host-level"
    return f"{finding.hostname} ({port})"


def _exploit(finding: ScoredFinding) -> str:
    if finding.intel.kev:
        return "KEV + ransomware" if finding.intel.ransomware_campaign_use else "KEV"
    if not finding.intel.known_cve:
        return "unknown"
    return finding.intel.exploit_maturity or "none known"


def _header(canvas: PdfCanvas, state: PipelineState, scored: list[ScoredFinding]) -> None:
    report = state.normalization_report
    generated = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")

    canvas.text("Vulnerability Triage Report", font=HELVETICA_BOLD, size=19, color=INK)
    canvas.space(4)
    canvas.text(f"Generated {generated}", size=9, color=MUTED)
    canvas.space(8)
    canvas.rule(RULE)
    canvas.space(6)

    if report:
        canvas.paragraph(
            f"Source: {report.source_file} ({report.source_format.upper()}) · "
            f"{report.raw_rows} raw rows · {len(scored)} findings triaged · "
            f"{len({f.hostname for f in scored})} host(s) affected",
            size=9,
            color=MUTED,
        )
    canvas.space(2)
    canvas.paragraph(
        "Every figure in this document is computed from the pipeline's structured "
        "data — scanner output, CVE intelligence and the asset inventory. No agent "
        "narrative is reproduced here.",
        size=8.5,
        color=MUTED,
    )
    canvas.space(12)


def _summary(canvas: PdfCanvas, scored: list[ScoredFinding]) -> None:
    counts = Counter(finding.priority for finding in scored)

    canvas.text("Summary", font=HELVETICA_BOLD, size=12, color=INK)
    canvas.space(8)

    # One row of four chips: priority, count, SLA. The SLA wraps rather than
    # truncating -- "Emergency change - remedi…" tells a reader nothing, and the
    # SLA is the reason the priority band exists.
    chip_width = (canvas.content_width - 3 * 10) / 4
    chip_height = 50.0
    top = canvas.y
    for index, (_, priority, sla) in enumerate(PRIORITY_BANDS):
        x = canvas.margin + index * (chip_width + 10)
        canvas.rect(x, top - chip_height + 10, chip_width, chip_height, FAINT)
        canvas.rect(x, top - chip_height + 10, 3.0, chip_height, PRIORITY_COLORS[priority])

        canvas.y = top
        canvas.text(priority, x=x + 12, font=HELVETICA_BOLD, size=10,
                    color=PRIORITY_COLORS[priority], leading=12)
        canvas.text(str(counts.get(priority, 0)), x=x + 12, font=HELVETICA_BOLD,
                    size=15, color=INK, leading=17)
        for line in wrap(sla, HELVETICA, 7, chip_width - 20)[:2]:
            canvas.text(line, x=x + 12, size=7, color=MUTED, leading=8.5)
    canvas.y = top - chip_height + 10
    canvas.space(18)

    kev = sum(1 for finding in scored if finding.intel.kev)
    ransomware = sum(1 for finding in scored if finding.intel.ransomware_campaign_use)
    exposed = sum(1 for finding in scored if finding.asset.internet_facing)
    canvas.paragraph(
        f"{kev} of {len(scored)} findings are on the CISA KEV list (confirmed exploited "
        f"in the wild), {ransomware} have been used in ransomware campaigns, and "
        f"{exposed} sit on an internet-facing host.",
        size=9,
        color=INK,
    )
    canvas.space(14)


def _table_head(canvas: PdfCanvas) -> None:
    """The column header band. Repeated whenever the table crosses a page."""
    canvas.rect(canvas.margin, canvas.y - 4, canvas.content_width, 15, (0.16, 0.18, 0.22))
    edges = columns(TABLE_WIDTHS, canvas.margin)
    row = canvas.y
    for index, head in enumerate(TABLE_HEADS):
        canvas.y = row
        canvas.text(head, x=edges[index], font=HELVETICA_BOLD, size=8,
                    color=(1.0, 1.0, 1.0))
    canvas.y = row - 15


def _table(canvas: PdfCanvas, scored: list[ScoredFinding]) -> None:
    canvas.text("Ranked findings", font=HELVETICA_BOLD, size=12, color=INK)
    canvas.space(8)
    _table_head(canvas)

    for index, finding in enumerate(scored):
        # A row that would land in the footer moves to the next page, and the
        # header repeats there -- a bare continuation of a table is unreadable.
        if canvas.ensure(16):
            _table_head(canvas)

        if index % 2:
            canvas.rect(canvas.margin, canvas.y - 3.5, canvas.content_width, 14, FAINT)

        edges = columns(TABLE_WIDTHS, canvas.margin)
        row = canvas.y
        cells = [
            (str(finding.rank), HELVETICA, INK),
            (None, None, None),  # the priority badge, drawn separately
            (finding.cve, HELVETICA_BOLD, INK),
            (f"{finding.effective_cvss:g}", HELVETICA, INK),
            (f"{finding.risk_score:g}", HELVETICA_BOLD, INK),
            (_target(finding), HELVETICA, INK),
            (_exploit(finding), HELVETICA, MUTED),
        ]
        for column, (value, font, color) in enumerate(cells):
            if value is None:
                continue
            canvas.y = row
            canvas.text(
                _fit(value, font, 8.5, TABLE_WIDTHS[column] - 6),
                x=edges[column],
                font=font,
                size=8.5,
                color=color,
            )
        canvas.y = row
        canvas.badge(
            finding.priority,
            x=edges[1],
            width=TABLE_WIDTHS[1] - 6,
            fill=PRIORITY_COLORS[finding.priority],
            size=7.5,
        )
        canvas.y = row - 14

    canvas.space(4)
    canvas.rule(RULE)
    canvas.space(2)
    canvas.paragraph(
        "Risk score weighs CVSS by asset criticality, exploit availability and network "
        "exposure, so this order is not the CVSS order.",
        size=8,
        color=MUTED,
    )


def _detail(canvas: PdfCanvas, scored: list[ScoredFinding]) -> None:
    canvas.new_page()
    canvas.text("Findings and remediation", font=HELVETICA_BOLD, size=12, color=INK)
    canvas.space(4)
    canvas.paragraph(
        f"All {len(scored)} findings in rank order. Remediation guidance is drawn from "
        "the CVE intelligence database and the asset's recorded constraints.",
        size=8.5,
        color=MUTED,
    )
    canvas.space(12)

    for finding in scored:
        _finding_block(canvas, finding)


def _finding_block(canvas: PdfCanvas, finding: ScoredFinding) -> None:
    plan = remediation_for(finding)
    color = PRIORITY_COLORS[finding.priority]

    # Keep the heading with at least the first lines of its body. A finding whose
    # title sits alone at the foot of a page reads as though it has no fix.
    canvas.ensure(72)
    canvas.space(4)

    top = canvas.y
    canvas.badge(finding.priority, x=canvas.margin, width=26, fill=color, size=7.5)
    title = f"{finding.rank}. {finding.cve}"
    name = finding.intel.name or finding.plugin_name
    canvas.y = top
    canvas.text(title, x=canvas.margin + 32, font=HELVETICA_BOLD, size=11, color=INK)
    if name:
        canvas.y = top
        canvas.text(
            _fit(name, HELVETICA, 9, canvas.content_width - 40
                 - text_width(title, HELVETICA_BOLD, 11)),
            x=canvas.margin + 38 + text_width(title, HELVETICA_BOLD, 11),
            size=9,
            color=MUTED,
        )
    canvas.y = top - 15

    canvas.paragraph(
        f"Host {_target(finding)} · CVSS {finding.effective_cvss:g} "
        f"({finding.intel.cvss_severity or 'unrated'}) · risk {finding.risk_score:g}/100 "
        f"({finding.priority}, {PRIORITY_SLA.get(finding.priority, '')}) · "
        f"exploit: {_exploit(finding)}",
        x=canvas.margin + 32,
        width=canvas.content_width - 32,
        size=8.5,
        color=INK,
    )
    owner = finding.asset.owner or "owner unknown"
    canvas.paragraph(
        f"{finding.asset.role or 'unclassified asset'} · {finding.asset.criticality} "
        f"criticality · {owner}"
        + (" · internet-facing" if finding.asset.internet_facing else ""),
        x=canvas.margin + 32,
        width=canvas.content_width - 32,
        size=8.5,
        color=MUTED,
    )
    canvas.space(5)

    canvas.paragraph(
        f"Fix: {plan['summary']}",
        x=canvas.margin + 32,
        width=canvas.content_width - 32,
        font=HELVETICA_BOLD,
        size=8.5,
        color=INK,
    )
    for number, step in enumerate(plan["steps"], start=1):
        canvas.paragraph(
            f"{number}. {step}",
            x=canvas.margin + 32,
            width=canvas.content_width - 32,
            size=8.5,
            color=INK,
            indent=12,
        )

    facts = [
        f"Effort: {plan['effort']} ({plan['effort_hours']})",
        f"Change risk: {plan['change_risk']}",
    ]
    if plan["requires_reboot"]:
        facts.append("reboot required")
    if plan["requires_downtime"]:
        facts.append("downtime required")
    if plan["window"]:
        facts.append(f"window: {plan['window']}")
    canvas.space(2)
    canvas.paragraph(
        " · ".join(facts),
        x=canvas.margin + 32,
        width=canvas.content_width - 32,
        size=8.5,
        color=MUTED,
    )
    for constraint in plan["constraints"]:
        canvas.paragraph(
            f"Constraint: {constraint}",
            x=canvas.margin + 32,
            width=canvas.content_width - 32,
            size=8.5,
            color=PRIORITY_COLORS["P2"],
            indent=12,
        )

    canvas.space(6)
    canvas.rule(RULE)
    canvas.space(2)


def build_pdf(state: PipelineState, top_n: int = 5) -> bytes:
    """Render the triage report to PDF bytes.

    `top_n` is accepted for symmetry with the other renderers but deliberately
    unused: a PDF is read away from the terminal that produced it, so it carries
    the remediation for every finding rather than the console's top slice.
    """
    scored = state.require_scored()
    canvas = PdfCanvas(
        footer="VulnTriage — machine-proposed, analyst-approved. Nothing here is applied "
               "automatically."
    )
    _header(canvas, state, scored)
    _summary(canvas, scored)
    _table(canvas, scored)
    _detail(canvas, scored)
    return canvas.to_bytes()


def write_pdf(state: PipelineState, path: str | Path, top_n: int = 5) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_pdf(state, top_n))
    return path
