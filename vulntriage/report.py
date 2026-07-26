"""Report builder: the ranked, actionable triage report.

The tables and numbers are assembled deterministically from `PipelineState`, so
the report always reconciles with the input file. The agents' narrative sections
are dropped in alongside them -- clearly attributed, never load-bearing for the
data itself.

Four artifacts per run: markdown to read, JSON to machine-consume, CSV for the
spreadsheet, and a PDF to forward (`report_pdf.py` -- structured data only, no
narrative, because a PDF travels furthest from the run that produced it).
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, NamedTuple

from .guard import GuardReport, check_narratives
from .models import ScoredFinding
from .remediation import effort_summary, group_by_change, remediation_for
from .scoring import MAX_RAW_SCORE, PRIORITY_BANDS, ranking_divergences
from .state import PipelineState

PRIORITY_SLA = {p: sla for _, p, sla in PRIORITY_BANDS}

# Failure modes seen from small local models: a refusal, an empty answer, or a raw
# tool-call blob emitted as the final answer. None of it belongs in a report an
# analyst is meant to act on.
_REFUSAL_MARKERS = (
    "i can't help",
    "i cannot help",
    "i can't assist",
    "i cannot assist",
    "i'm unable to",
    "as an ai",
)


def usable_note(text: str | None) -> str | None:
    """Return the agent's narrative, or None if it is not fit to publish.

    The data in this report never depends on the model. When an agent produces a
    refusal or a malformed tool call instead of analysis, the honest move is to
    say the stage produced no narrative -- not to paste the artifact into the
    report and let the reader assume it means something.
    """
    if not text:
        return None
    stripped = text.strip()
    if len(stripped) < 80:
        return None
    lowered = stripped.lower()
    if any(lowered.startswith(m) for m in _REFUSAL_MARKERS):
        return None
    # A JSON object with a "name"/"parameters" or "tool" key is a leaked tool call.
    if stripped.startswith("{") and ('"parameters"' in stripped or '"tool' in lowered):
        return None
    return stripped


def _fmt_target(f: ScoredFinding) -> str:
    port = f"{f.port}/{f.protocol}" if f.port else "host-level"
    return f"`{f.hostname}` ({port})"


def _kev_flag(f: ScoredFinding) -> str:
    if f.intel.kev:
        return "KEV" + (" + ransomware" if f.intel.ransomware_campaign_use else "")
    if not f.intel.known_cve:
        return "unknown"
    return f.intel.exploit_maturity


def build_markdown(
    state: PipelineState, top_n: int = 5, guard: GuardReport | None = None
) -> str:
    scored = state.require_scored()
    report = state.normalization_report
    notes = state.agent_notes
    guard = guard if guard is not None else check_narratives(state, top_n)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    counts = Counter(f.priority for f in scored)
    efforts = effort_summary(scored)
    lines: list[str] = []
    add = lines.append

    # ---- header ----------------------------------------------------------
    add("# Vulnerability Triage Report")
    add("")
    add(f"*Generated {generated} by the VulnTriage crew (4 agents, sequential).*")
    add("")
    if report:
        meta = report.scan_metadata or {}
        add(f"- **Source:** `{report.source_file}` ({report.source_format.upper()})")
        if meta.get("name"):
            add(f"- **Scan:** {meta.get('name')} — {meta.get('scanner', 'unknown scanner')}")
        if meta.get("completed_at"):
            add(f"- **Scan completed:** {meta['completed_at']}")
        add(f"- **Raw rows in:** {report.raw_rows} → **findings triaged:** {len(scored)}")
        hosts = sorted({f.hostname for f in scored})
        add(f"- **Hosts affected:** {len(hosts)} ({', '.join(hosts)})")
    add("")
    add("> Machine-proposed, analyst-approved. Nothing here is applied automatically.")
    add("")

    # ---- executive summary ----------------------------------------------
    add("## Executive summary")
    add("")
    add("| Priority | SLA | Count |")
    add("|---|---|---|")
    for _, priority, sla in PRIORITY_BANDS:
        add(f"| **{priority}** | {sla} | {counts.get(priority, 0)} |")
    add("")
    kev_count = sum(1 for f in scored if f.intel.kev)
    ransom_count = sum(1 for f in scored if f.intel.ransomware_campaign_use)
    internet_count = sum(1 for f in scored if f.asset.internet_facing)
    add(
        f"{kev_count} of {len(scored)} findings are on the CISA KEV list "
        f"(confirmed exploited in the wild), {ransom_count} have been used in ransomware "
        f"campaigns, and {internet_count} sit on an internet-facing host."
    )
    add("")
    add(
        f"Remediation effort across all findings: "
        f"{efforts['low']} low, {efforts['medium']} medium, {efforts['high']} high"
        + (f", {efforts['unknown']} unscoped" if efforts["unknown"] else "")
        + "."
    )
    add("")

    # ---- why this differs from CVSS -------------------------------------
    divergences = ranking_divergences(scored)
    if divergences:
        add("## Why this ranking is not the CVSS ranking")
        add("")
        add(
            "Risk score = CVSS × asset criticality × exploit availability × exposure. "
            "The findings that moved furthest against a raw-CVSS sort:"
        )
        add("")
        for line in divergences:
            add(f"- {line}")
        add("")

    # ---- ranked table ----------------------------------------------------
    add("## Ranked findings")
    add("")
    add("| # | Risk | Pri | CVE | Target | CVSS | Asset | Exploit | Δ vs CVSS rank |")
    add("|---:|---:|---|---|---|---:|---|---|---:|")
    for f in scored:
        delta = f.rank_delta or 0
        delta_str = f"+{delta}" if delta > 0 else (str(delta) if delta else "—")
        crit = f.asset.criticality + ("" if f.asset.known_asset else " (unmanaged)")
        add(
            f"| {f.rank} | **{f.risk_score}** | {f.priority} | {f.cve} | {_fmt_target(f)} "
            f"| {f.effective_cvss} | {crit}{' / internet' if f.asset.internet_facing else ''} "
            f"| {_kev_flag(f)} | {delta_str} |"
        )
    add("")
    add(
        f"*Risk score is the raw product normalized against the worst possible case "
        f"({MAX_RAW_SCORE:.2f}). Δ is how many places risk scoring moved the finding "
        f"versus ranking on CVSS alone.*"
    )
    add("")

    # ---- remediation plan ------------------------------------------------
    top = scored[:top_n]
    add(f"## Remediation plan — top {len(top)}")
    add("")
    for f in top:
        rem = remediation_for(f)
        title = f.intel.name or f.plugin_name or f.cve
        add(f"### {f.rank}. {f.cve} — {title}")
        add("")
        add(
            f"**{_fmt_target(f)}** · risk **{f.risk_score}/100** ({f.priority}) · "
            f"CVSS {f.effective_cvss} · owner: {f.asset.owner or 'unknown'}"
        )
        add("")
        if f.asset.role:
            add(f"- **Asset:** {f.asset.role} — {f.asset.criticality} criticality, "
                f"{f.asset.environment or 'unknown env'}"
                + (f", {'/'.join(f.asset.compliance_scope)} scope" if f.asset.compliance_scope else "")
                + (", internet-facing" if f.asset.internet_facing else ""))
        if f.intel.description:
            add(f"- **Vulnerability:** {f.intel.description}")
        if f.intel.exploit_notes:
            add(f"- **Exploit status:** {f.intel.exploit_notes}")
        add(f"- **Why it ranks here:** {f.rationale}")
        add("")
        add(f"**Fix:** {rem['summary']}")
        add("")
        for i, step in enumerate(rem["steps"], start=1):
            add(f"{i}. {step}")
        add("")
        bits = [
            f"**Effort:** {rem['effort']} ({rem['effort_hours']})",
            f"**Change risk:** {rem['change_risk']}",
        ]
        if rem["requires_reboot"]:
            bits.append("**Reboot required**")
        if rem["requires_downtime"]:
            bits.append("**Downtime required**")
        if rem["window"]:
            bits.append(f"**Window:** {rem['window']}")
        add(" · ".join(bits))
        add("")
        if rem["constraints"]:
            add("**Constraints:**")
            for c in rem["constraints"]:
                add(f"- {c}")
            add("")

    # ---- change grouping -------------------------------------------------
    groups = group_by_change(top)
    if len(groups) < len(top):
        add("### Suggested change tickets")
        add("")
        add("Findings that share a host should share a maintenance window:")
        add("")
        for host, items in groups.items():
            cves = ", ".join(f.cve for f in sorted(items, key=lambda x: x.rank))
            window = items[0].asset.maintenance_window or "window not set in CMDB"
            add(f"- **{host}** — {cves} ({len(items)} findings, one window: {window})")
        add("")

    # ---- agent narrative -------------------------------------------------
    stage_titles = {
        "discovery": "Discovery agent — normalization review",
        "enrichment": "Enrichment agent — intelligence assessment",
        "prioritization": "Prioritization agent — ranking rationale",
        "remediation": "Remediation agent — remediation strategy",
    }
    usable = {k: usable_note(notes.get(k)) for k in stage_titles}
    if any(usable.values()):
        add("## Agent analysis")
        add("")
        add(
            "*Narrative from each agent. The data above does not depend on it — "
            "tables and scores are computed deterministically.*"
        )
        add("")
        add(f"*{guard.summary()}*")
        add("")
        for key, title in stage_titles.items():
            if not notes.get(key):
                continue
            add(f"### {title}")
            add("")
            flagged = guard.for_stage(key)
            if flagged:
                # Next to the prose, not in an appendix — an analyst reading this
                # paragraph is the person who needs to know it is unsupported.
                add(
                    f"> **⚠ Grounding guard: {len(flagged)} claim"
                    f"{'s' if len(flagged) != 1 else ''} contradict the structured data.** "
                    f"The findings, scores and remediation steps above are unaffected."
                )
                add(">")
                for violation in flagged:
                    add(f"> - {violation.render()}")
                    if violation.excerpt:
                        add(f">   <br>*“{violation.excerpt}”*")
                add("")
            if usable[key]:
                add(usable[key])
            else:
                add(
                    "*This agent did not return usable analysis (a refusal, an empty "
                    "answer, or a malformed tool call). The stage's data was produced "
                    "correctly regardless. A larger model usually fixes this — see the "
                    "model guidance in the README.*"
                )
            add("")

    # ---- appendix --------------------------------------------------------
    if report:
        add("## Appendix A — normalization audit")
        add("")
        add(f"- Raw rows read: **{report.raw_rows}**")
        add(f"- Findings after normalization: **{report.normalized_findings}**")
        add(f"- Informational rows dropped: {report.dropped_informational}")
        add(f"- Rows dropped for having no CVE: {report.dropped_no_cve}")
        add(f"- Rows dropped as already remediated: {report.dropped_not_open}")
        add(f"- Duplicate findings collapsed: {report.duplicates_collapsed}")
        add(f"- Multi-CVE rows split: {report.multi_cve_rows_split}")
        add(f"- CVE ids recovered from plugin names: {report.cve_recovered_from_plugin_name}")
        add("")
        if report.anomalies:
            add("**Anomalies:**")
            add("")
            for a in report.anomalies:
                add(f"- {a}")
            add("")

    gaps = sorted({
        *(f"{f.cve}: not in the local CVE intel database — scored on scanner CVSS "
          f"with a neutral exploit weight. Verify against NVD and CISA KEV."
          for f in scored if not f.intel.known_cve),
        *(f"{f.hostname}: no CMDB record — criticality assumed medium. Identify the owner."
          for f in scored if not f.asset.known_asset),
    })
    if gaps:
        add("## Appendix B — intelligence gaps")
        add("")
        add("These findings were scored on incomplete data. Treat their rank as provisional:")
        add("")
        for gap in gaps:
            add(f"- {gap}")
        add("")

    add("---")
    add("")
    add(
        "*VulnTriage POC — mock CVE intel and mock asset inventory. "
        "Swap in live NVD, CISA KEV, and Tenable feeds per FUTURE_ADDONS.md.*"
    )
    add("")
    return "\n".join(lines)


def build_json(
    state: PipelineState, top_n: int = 5, guard: GuardReport | None = None
) -> dict:
    scored = state.require_scored()
    guard = guard if guard is not None else check_narratives(state, top_n)
    counts = Counter(f.priority for f in scored)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": state.source_file,
        "normalization": (
            state.normalization_report.model_dump() if state.normalization_report else None
        ),
        "summary": {
            "findings": len(scored),
            "by_priority": {p: counts.get(p, 0) for _, p, _ in PRIORITY_BANDS},
            "kev_listed": sum(1 for f in scored if f.intel.kev),
            "internet_facing": sum(1 for f in scored if f.asset.internet_facing),
            "effort": effort_summary(scored),
        },
        "divergences": ranking_divergences(scored),
        "findings": [
            {**f.model_dump(), "remediation_plan": remediation_for(f)} for f in scored
        ],
        "top_n": top_n,
        "agent_notes": state.agent_notes,
        "narrative_guard": guard.model_dump(),
    }


# --------------------------------------------------------------------------- #
# CSV — one row per finding, for spreadsheets and ticket imports
# --------------------------------------------------------------------------- #

CSV_COLUMNS: list[str] = [
    # what an analyst sorts and filters on first
    "rank", "risk_score", "priority", "sla",
    "cve", "cve_name", "cvss", "cvss_severity",
    "hostname", "asset_criticality", "asset_owner", "asset_role",
    # the risk model, so the score can be audited in the spreadsheet
    "cvss_rank", "rank_delta", "asset_weight", "exploit_weight", "exposure_weight",
    "raw_score", "max_raw_score", "cvss_source",
    # exposure and threat context
    "internet_facing", "environment", "data_classification", "compliance_scope",
    "exploit_maturity", "kev", "kev_date_added", "ransomware_campaign_use",
    # where it lives
    "fqdn", "ip", "port", "protocol", "service", "maintenance_window",
    # remediation
    "remediation_summary", "remediation_type", "remediation_steps",
    "effort", "effort_hours", "change_risk", "requires_reboot", "requires_downtime",
    "constraints",
    # provenance and data quality
    "finding_id", "plugin_id", "plugin_name", "scanner_severity", "scanner_cvss",
    "first_found", "last_found", "source_rows",
    "known_cve", "known_asset", "intel_gap", "rationale",
]

# Excel and Sheets execute a cell that starts with one of these. A triage export is
# exactly the kind of file that gets opened without thinking, and the CVE text here
# is attacker-influenced in a real deployment -- so neutralize it on the way out.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> str:
    """Flatten a value to a spreadsheet-safe single-line string."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        text = " | ".join(str(v) for v in value)
    else:
        text = str(value)
    text = " ".join(text.split())  # collapse newlines/tabs so a row stays a row
    if text.startswith(_FORMULA_PREFIXES):
        text = "'" + text
    return text


def build_csv_rows(state: PipelineState) -> list[dict[str, str]]:
    """One dict per finding, in rank order, keyed by `CSV_COLUMNS`."""
    rows: list[dict[str, str]] = []
    for f in state.require_scored():
        rem = remediation_for(f)
        b = f.breakdown
        raw = {
            "rank": f.rank,
            "risk_score": f.risk_score,
            "priority": f.priority,
            "sla": PRIORITY_SLA.get(f.priority, ""),
            "cve": f.cve,
            "cve_name": f.intel.name,
            "cvss": f.effective_cvss,
            "cvss_severity": f.intel.cvss_severity,
            "hostname": f.hostname,
            "asset_criticality": f.asset.criticality,
            "asset_owner": f.asset.owner,
            "asset_role": f.asset.role,
            "cvss_rank": f.cvss_rank,
            "rank_delta": f.rank_delta,
            "asset_weight": b.asset_weight,
            "exploit_weight": b.exploit_weight,
            "exposure_weight": b.exposure_weight,
            "raw_score": b.raw_score,
            "max_raw_score": b.max_raw_score,
            "cvss_source": f.cvss_source,
            "internet_facing": f.asset.internet_facing,
            "environment": f.asset.environment,
            "data_classification": f.asset.data_classification,
            "compliance_scope": f.asset.compliance_scope,
            "exploit_maturity": f.intel.exploit_maturity,
            "kev": f.intel.kev,
            "kev_date_added": f.intel.kev_date_added,
            "ransomware_campaign_use": f.intel.ransomware_campaign_use,
            "fqdn": f.fqdn,
            "ip": f.ip,
            "port": f.port if f.port is not None else "host-level",
            "protocol": f.protocol,
            "service": f.service,
            "maintenance_window": f.asset.maintenance_window,
            "remediation_summary": rem["summary"],
            "remediation_type": rem["type"],
            "remediation_steps": [f"{i}. {s}" for i, s in enumerate(rem["steps"], start=1)],
            "effort": rem["effort"],
            "effort_hours": rem["effort_hours"],
            "change_risk": rem["change_risk"],
            "requires_reboot": rem["requires_reboot"],
            "requires_downtime": rem["requires_downtime"],
            "constraints": rem["constraints"],
            "finding_id": f.finding_id,
            "plugin_id": f.plugin_id,
            "plugin_name": f.plugin_name,
            "scanner_severity": f.scanner_severity_name,
            "scanner_cvss": f.scanner_cvss,
            "first_found": f.first_found,
            "last_found": f.last_found,
            "source_rows": f.source_rows,
            "known_cve": f.intel.known_cve,
            "known_asset": f.asset.known_asset,
            "intel_gap": f.intel_gap,
            "rationale": f.rationale,
        }
        rows.append({col: _csv_safe(raw.get(col)) for col in CSV_COLUMNS})
    return rows


def write_csv(state: PipelineState, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig so Excel on Windows renders the em-dashes instead of mojibake;
    # newline="" so the writer does not double up line endings.
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(build_csv_rows(state))
    return path


class ReportOutputs(NamedTuple):
    markdown: Path
    json: Path
    csv: Path
    pdf: Path
    warnings: list[str]
    guard: GuardReport


def write_with_fallback(path: Path, write: Callable[[Path], None]) -> tuple[Path, str | None]:
    """Write `path`, falling back to a timestamped sibling if it is locked.

    A CSV left open in Excel holds a write lock on Windows. Losing a completed
    crew run -- twenty minutes of local inference -- because the last of three
    files could not be opened is not an acceptable failure mode. Write beside it
    and say so instead.
    """
    try:
        write(path)
        return path, None
    except PermissionError:
        alt = path.with_name(f"{path.stem}-{datetime.now():%Y%m%d-%H%M%S}{path.suffix}")
        write(alt)
        return alt, (
            f"{path.name} is locked by another process (usually an open spreadsheet "
            f"or editor). Wrote {alt.name} instead — close the file and re-run to "
            f"refresh the original."
        )


def write_reports(
    state: PipelineState, output_dir: str | Path, top_n: int = 5
) -> ReportOutputs:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []

    # One evaluation, shared by both renderers, so the markdown and the JSON can
    # never disagree about what was flagged.
    guard = check_narratives(state, top_n)

    def _record(path: Path, write: Callable[[Path], None]) -> Path:
        resolved, warning = write_with_fallback(path, write)
        if warning:
            warnings.append(warning)
        return resolved

    md_path = _record(
        out / "triage_report.md",
        lambda p: p.write_text(build_markdown(state, top_n, guard), encoding="utf-8"),
    )
    json_path = _record(
        out / "triage_report.json",
        lambda p: p.write_text(
            json.dumps(build_json(state, top_n, guard), indent=2), encoding="utf-8"
        ),
    )
    csv_path = _record(out / "triage_report.csv", lambda p: write_csv(state, p))
    # Imported here rather than at module scope: the PDF renderer pulls in the
    # page-layout machinery, and nothing else in this module needs it.
    from .report_pdf import write_pdf

    pdf_path = _record(out / "triage_report.pdf", lambda p: write_pdf(state, p, top_n))

    return ReportOutputs(md_path, json_path, csv_path, pdf_path, warnings, guard)
