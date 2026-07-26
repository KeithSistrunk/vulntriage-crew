"""The mock CVE lookup tool.

Backed by `data/cve_db.json` — a hand-curated snapshot standing in for NVD plus
the CISA KEV catalogue. `vulntriage.intel.lookup_cve` is the single seam a live
feed replaces later; this tool only formats what it returns.
"""

from __future__ import annotations

from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from ..intel import lookup_cve
from ..remediation import EFFORT_HOURS


class CVELookupInput(BaseModel):
    cve_id: str = Field(..., description="A CVE identifier, e.g. 'CVE-2021-44228'.")


class CVELookupTool(BaseTool):
    name: str = "lookup_cve"
    description: str = (
        "Look up one CVE in the threat intelligence database. Returns the description, "
        "CVSS v3 score and vector, exploit maturity, whether it is on the CISA KEV list "
        "(confirmed exploited in the wild), whether it has appeared in ransomware campaigns, "
        "and analyst notes on how real the exploit actually is. "
        "Use this to check a specific CVE you want to comment on. Unknown CVEs return a "
        "clearly-marked 'not found' rather than an error."
    )
    args_schema: Type[BaseModel] = CVELookupInput

    def _run(self, cve_id: str, **_: object) -> str:
        intel = lookup_cve(cve_id)
        if not intel.known_cve:
            return (
                f"{intel.cve}: NOT FOUND in the local intel database.\n"
                f"{intel.notes}\n"
                "Do not assume it is harmless — assume it is unverified."
            )

        exploit = "on the CISA KEV list (confirmed exploited in the wild)" if intel.kev else (
            f"exploit maturity: {intel.exploit_maturity}"
        )
        lines = [
            f"{intel.cve} — {intel.name} (published {intel.published})",
            f"CVSS v3: {intel.cvss} ({intel.cvss_severity}) {intel.cvss_vector}",
            f"Exploit: {exploit}"
            + (f", added to KEV {intel.kev_date_added}" if intel.kev_date_added else "")
            + (", used in known ransomware campaigns" if intel.ransomware_campaign_use else ""),
            f"Description: {intel.description}",
        ]
        if intel.exploit_notes:
            lines.append(f"Analyst note: {intel.exploit_notes}")
        return "\n".join(lines)


class CVERemediationInput(BaseModel):
    cve_id: str = Field(..., description="A CVE identifier, e.g. 'CVE-2021-44228'.")


class CVERemediationTool(BaseTool):
    name: str = "lookup_remediation"
    description: str = (
        "Get the vendor-guidance remediation for one CVE: the fix summary, ordered steps, "
        "effort level, change risk, and whether it needs a reboot or downtime. "
        "Use this when writing the remediation plan for a specific finding."
    )
    args_schema: Type[BaseModel] = CVERemediationInput

    def _run(self, cve_id: str, **_: object) -> str:
        intel = lookup_cve(cve_id)
        rem = intel.remediation
        if not intel.known_cve or not rem:
            return (
                f"{intel.cve}: no remediation guidance on file. "
                "Pull the vendor advisory manually, identify the fixed version, and scope "
                "the change from there. Treat effort as unknown until that is done."
            )

        effort = rem.get("effort", "unknown")
        lines = [
            f"{intel.cve} — {intel.name}",
            f"Fix: {rem.get('summary', '')}",
            f"Type: {rem.get('type', 'patch')} | Effort: {effort} ({EFFORT_HOURS.get(effort, 'unknown')}) "
            f"| Change risk: {rem.get('change_risk', 'unknown')}",
            f"Reboot required: {bool(rem.get('requires_reboot'))} | "
            f"Downtime required: {bool(rem.get('requires_downtime'))}",
            "Steps:",
        ]
        lines += [f"  {i}. {step}" for i, step in enumerate(rem.get("steps", []), start=1)]
        return "\n".join(lines)
