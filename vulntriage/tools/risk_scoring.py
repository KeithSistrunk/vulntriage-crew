"""Prioritization + Remediation agent tools: the risk model and the ranked queue."""

from __future__ import annotations

from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from ..pipeline import run_prioritization
from ..remediation import (
    EFFORT_HOURS,
    effort_total,
    patch_is_not_enough,
    remediation_for,
)
from ..scoring import (
    ASSET_WEIGHTS,
    EXPLOIT_WEIGHTS,
    INTERNET_FACING_WEIGHT,
    MAX_RAW_SCORE,
    ranking_divergences,
)
from ..state import STATE


class ScoreAndRankInput(BaseModel):
    """No arguments — the tool scores every enriched finding in the pipeline."""


class ScoreAndRankTool(BaseTool):
    name: str = "score_and_rank_findings"
    description: str = (
        "Score and rank every enriched finding using the risk model: "
        "CVSS x asset criticality x exploit availability x exposure, normalized to 0-100 "
        "and banded into P1-P4. Takes no arguments. "
        "Returns the ranked queue, the full multiplier breakdown for each finding, and — "
        "most importantly — which findings moved furthest against a raw-CVSS ranking. "
        "Call this exactly once."
    )
    args_schema: Type[BaseModel] = ScoreAndRankInput

    def _run(self, **_: object) -> str:
        try:
            scored = run_prioritization(STATE)
        except RuntimeError as exc:
            return f"ERROR: {exc}"

        counts: dict[str, int] = {}
        for f in scored:
            counts[f.priority] = counts.get(f.priority, 0) + 1

        lines = [
            f"Scored and ranked {len(scored)} findings.",
            "",
            "RISK MODEL",
            f"- asset criticality: {', '.join(f'{k} x{v}' for k, v in ASSET_WEIGHTS.items())}",
            f"- exploit maturity: {', '.join(f'{k} x{v}' for k, v in EXPLOIT_WEIGHTS.items())}"
            "  (CISA KEV membership floors this at the weaponized weight)",
            f"- exposure: internet-facing x{INTERNET_FACING_WEIGHT}, internal x1.0",
            f"- normalized against the worst case ({MAX_RAW_SCORE:.2f}) to a 0-100 score",
            "- bands: P1 >= 75, P2 >= 55, P3 >= 35, P4 below 35",
            "",
            "BANDS: " + ", ".join(f"{p}={counts.get(p, 0)}" for p in ("P1", "P2", "P3", "P4")),
            "",
            "TOP OF THE QUEUE",
        ]
        for f in scored[:5]:
            lines.append(
                f"- #{f.rank} {f.cve} on {f.hostname} — risk {f.risk_score} ({f.priority}), "
                f"CVSS {f.effective_cvss}, {f.asset.criticality} asset, "
                f"{'KEV-listed' if f.intel.kev else f.intel.exploit_maturity}"
                + (", internet-facing" if f.asset.internet_facing else "")
            )

        lines += ["", "BOTTOM OF THE QUEUE"]
        for f in scored[-3:]:
            lines.append(
                f"- #{f.rank} {f.cve} on {f.hostname} — risk {f.risk_score} ({f.priority}), "
                f"CVSS {f.effective_cvss}, {f.asset.criticality} asset, "
                f"{'KEV-listed' if f.intel.kev else f.intel.exploit_maturity}"
            )

        divergences = ranking_divergences(scored)
        lines += ["", "WHERE RISK RANKING DISAGREES MOST WITH RAW CVSS"]
        lines += [f"- {d}" for d in divergences] or ["- the two rankings agree"]
        return "\n".join(lines)


class RankedFindingsInput(BaseModel):
    top_n: int = Field(
        5, description="How many of the highest-risk findings to return. Use 5 unless told otherwise."
    )


class RankedFindingsTool(BaseTool):
    name: str = "get_ranked_findings"
    description: str = (
        "Retrieve the top N findings from the ranked queue with everything needed to write a "
        "remediation plan: risk score and priority, asset role/owner/criticality, maintenance "
        "window, compliance scope, exploit status, the baseline vendor fix with its steps and "
        "effort estimate, and the operational constraints that limit when the fix can land."
    )
    args_schema: Type[BaseModel] = RankedFindingsInput

    def _run(self, top_n: int = 5, **_: object) -> str:
        """Return the facts for the top N findings, and nothing else.

        This output carries no instructions. It used to: the roster announced
        itself as "a closed set — any other pairing is wrong", every finding said
        "(do not attribute <CVE> to any other host)", and the effort block said
        "quote these, do not re-derive". The agent duly quoted all of it into the
        report -- guardrail text and all -- because the directives were sitting
        inside the data it had been told to work from, indistinguishable from it.

        Facts here, behaviour in the task prompt (`vulntriage/tasks.py`). Anything
        the agent is told to *do* belongs there, where echoing it is not a way of
        answering. Keeping the two apart is what makes the transcription failure
        structurally impossible rather than merely discouraged.
        """
        try:
            findings = STATE.top(int(top_n))
        except (RuntimeError, ValueError, TypeError) as exc:
            return f"ERROR: {exc}"
        if not findings:
            return "ERROR: the ranked queue is empty. Run score_and_rank_findings first."

        # The valid CVE->host pairings, stated once. This is data, not an
        # instruction: the task prompt is what tells the agent to check against it.
        index = ["CVE / HOST INDEX"]
        index += [f"  {f.cve}  {f.hostname}" for f in findings]

        blocks: list[str] = []
        for f in findings:
            rem = remediation_for(f)
            block = [
                f"FINDING #{f.rank} — {f.cve} ({f.intel.name or f.plugin_name})",
                f"  host: {f.hostname}",
                f"  risk: {f.risk_score}/100 ({f.priority})",
                f"  target: {f.hostname}:{f.port or 'host-level'} ({f.service or 'n/a'})",
                f"  asset: {f.asset.role or 'unknown role'} | owner {f.asset.owner or 'unknown'} | "
                f"{f.asset.criticality} criticality | {f.asset.environment or 'unknown env'}"
                + (" | internet-facing" if f.asset.internet_facing else "")
                + (f" | scope: {'/'.join(f.asset.compliance_scope)}" if f.asset.compliance_scope else ""),
                f"  window: {f.asset.maintenance_window or 'not set in CMDB'}",
                f"  exploit: {'CISA KEV listed' if f.intel.kev else f.intel.exploit_maturity}"
                + (", used in ransomware campaigns" if f.intel.ransomware_campaign_use else ""),
                f"  ranking basis: {f.rationale}",
                f"  fix: {rem['summary']}",
                f"  fix profile: {rem['type']}, effort {rem['effort']} ({rem['effort_hours']}), "
                f"change risk {rem['change_risk']}, reboot {rem['requires_reboot']}, "
                f"downtime {rem['requires_downtime']}",
            ]
            block.append("  steps:")
            block += [f"    {i}. {s}" for i, s in enumerate(rem["steps"], start=1)]
            if rem["constraints"]:
                block.append("  constraints:")
                block += [f"    - {c}" for c in rem["constraints"]]
            blocks.append("\n".join(block))

        hosts: dict[str, list[str]] = {}
        for f in findings:
            hosts.setdefault(f.hostname, []).append(f.cve)
        shared = {h: c for h, c in hosts.items() if len(c) > 1}

        footer = ["", "SHARED HOSTS"]
        if shared:
            footer += [f"  {h}: {', '.join(cves)}" for h, cves in shared.items()]
        else:
            footer.append("  none — each of these findings is on a different host")

        # Precomputed because asking a model to add up effort bands is asking it
        # to fabricate one: an earlier run flattened five findings into "medium x 5".
        totals = effort_total(findings)
        footer += ["", "EFFORT TOTAL (computed)"]
        footer += [
            f"  {n} finding(s) at {band} effort ({EFFORT_HOURS.get(band, 'unknown')})"
            for band, n in totals["counts"].items()
            if n
        ]
        footer.append(f"  combined: {totals['range']}")
        if totals["unscoped"]:
            footer.append(f"  {totals['unscoped']} finding(s) unscoped, excluded from that range")

        needs_more = patch_is_not_enough(findings)
        footer += ["", "FINDINGS NOT CLOSED BY PATCHING ALONE"]
        if needs_more:
            footer += [f"  {f.cve} on {f.hostname}" for f in needs_more]
        else:
            footer.append("  none")

        return (
            f"TOP {len(findings)} FINDINGS BY RISK\n\n"
            + "\n".join(index)
            + "\n\n"
            + "\n\n".join(blocks)
            + "\n"
            + "\n".join(footer)
        )
