"""Enrichment agent tool: join every finding against CVE intel and the CMDB."""

from __future__ import annotations

from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel

from ..intel import intel_gaps
from ..pipeline import run_enrichment
from ..state import STATE


class EnrichFindingsInput(BaseModel):
    """No arguments — the tool operates on every finding discovery produced."""


class EnrichFindingsTool(BaseTool):
    name: str = "enrich_findings"
    description: str = (
        "Enrich every normalized finding in the pipeline at once: attach CVE intelligence "
        "(CVSS, exploit maturity, CISA KEV status, ransomware usage) and asset context "
        "(criticality, owner, internet exposure, compliance scope), reconcile hosts the "
        "scanner identified only by IP against the CMDB, and settle an effective CVSS for "
        "findings the scanner left blank. Takes no arguments. "
        "Returns the enriched inventory plus an explicit list of intelligence gaps. "
        "Call this exactly once, then use lookup_cve / lookup_asset to dig into specifics."
    )
    args_schema: Type[BaseModel] = EnrichFindingsInput

    def _run(self, **_: object) -> str:
        try:
            count = run_enrichment(STATE)
        except RuntimeError as exc:
            return f"ERROR: {exc}"

        findings = STATE.enriched
        kev = [f for f in findings if f.intel.kev]
        ransomware = [f for f in findings if f.intel.ransomware_campaign_use]
        internet = [f for f in findings if f.asset.internet_facing]

        lines = [
            f"Enriched {count} findings.",
            "",
            "EXPLOIT PICTURE",
            f"- on the CISA KEV list (confirmed exploited in the wild): {len(kev)} of {count}",
            f"- tied to known ransomware campaigns: {len(ransomware)}"
            + (f" ({', '.join(sorted({f.cve for f in ransomware}))})" if ransomware else ""),
            f"- on an internet-facing host: {len(internet)}"
            + (f" ({', '.join(sorted({f.hostname for f in internet}))})" if internet else ""),
            f"- no public exploit or PoC only: {sum(1 for f in findings if not f.intel.kev)}",
        ]

        # Only the findings where context changes the story are worth the agent's
        # attention. The full enriched set lives in the pipeline, not in this prompt.
        notable: list[str] = []
        for f in findings:
            crit = f.asset.criticality
            if f.effective_cvss >= 8.5 and crit in ("low", "unknown") and not f.intel.kev:
                notable.append(
                    f"- {f.cve} on {f.hostname}: CVSS {f.effective_cvss} but a {crit}-criticality "
                    f"host and no confirmed in-the-wild exploitation "
                    f"({f.intel.exploit_maturity}). High score, low real risk."
                )
            elif (
                f.effective_cvss < 6.0
                and (f.asset.internet_facing or crit == "critical")
                # A low score with no exploit at all is just scanner noise, not a
                # buried risk. Do not hand the agent a talking point it cannot defend.
                and f.intel.exploit_maturity not in ("none", "unknown")
            ):
                notable.append(
                    f"- {f.cve} on {f.hostname}: only CVSS {f.effective_cvss}, but "
                    f"{'internet-facing' if f.asset.internet_facing else 'a critical asset'} "
                    f"with a {f.intel.exploit_maturity} exploit. Low score, real exposure."
                )
            elif f.intel.ransomware_campaign_use and crit == "critical":
                notable.append(
                    f"- {f.cve} on {f.hostname}: ransomware-campaign CVE on a "
                    f"{crit} asset ({f.asset.role or 'role unknown'})."
                )
        lines += ["", "WHERE CONTEXT CHANGES THE STORY"]
        lines += notable[:6] or ["- nothing stands out against its CVSS score"]

        lines += ["", "INTELLIGENCE GAPS"]
        lines += [f"- {gap}" for gap in intel_gaps(findings)] or ["- none"]
        lines += [
            "",
            "Write your assessment from the above. Use lookup_cve / lookup_asset to check "
            "specifics — do not reproduce this output.",
        ]
        return "\n".join(lines)
