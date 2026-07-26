"""Remediation stage: turn a ranked finding into a proposed fix + effort estimate.

This module produces the *baseline* plan straight from the intel database. The
Remediation agent's job is the part a lookup table cannot do: grouping fixes into
sensible change tickets, spotting where one action closes several findings, and
calling out the operational constraints (a POS terminal at a branch cannot reboot
mid-shift; a domain controller change is high-blast-radius).

The crew proposes. The analyst approves. See FUTURE_ADDONS.md item 4.
"""

from __future__ import annotations

from collections import defaultdict

from .models import ScoredFinding

EFFORT_HOURS = {"low": "0.5-2h", "medium": "2-8h", "high": "1-3 days"}
EFFORT_RANK = {"low": 1, "medium": 2, "high": 3}


def remediation_for(finding: ScoredFinding) -> dict:
    """Baseline remediation plan for one finding, drawn from the intel DB."""
    rem = finding.intel.remediation or {}
    effort = rem.get("effort", "unknown")

    if not rem:
        return {
            "summary": (
                f"No vendor guidance on file for {finding.cve}. Look it up in NVD and the "
                f"vendor advisory, then patch {finding.plugin_name or 'the affected component'} "
                f"on {finding.hostname}."
            ),
            "steps": [
                f"Confirm {finding.cve} applies to the installed version on {finding.hostname}.",
                "Pull the vendor advisory and identify the fixed version.",
                "Schedule the update through normal change management.",
                "Re-scan to confirm the plugin no longer fires.",
            ],
            "type": "investigate",
            "effort": "unknown",
            "effort_hours": "unknown - scope after the advisory review",
            "requires_reboot": None,
            "requires_downtime": None,
            "change_risk": "unknown",
            "window": finding.asset.maintenance_window,
            "constraints": _constraints(finding),
        }

    return {
        "summary": rem.get("summary", ""),
        "steps": list(rem.get("steps", [])),
        "type": rem.get("type", "patch"),
        "effort": effort,
        "effort_hours": EFFORT_HOURS.get(effort, "unknown"),
        "requires_reboot": rem.get("requires_reboot"),
        "requires_downtime": rem.get("requires_downtime"),
        "change_risk": rem.get("change_risk", "unknown"),
        "window": finding.asset.maintenance_window,
        "constraints": _constraints(finding),
    }


def _constraints(finding: ScoredFinding) -> list[str]:
    """Operational realities that shape *when* and *how* the fix can land."""
    notes: list[str] = []
    rem = finding.intel.remediation or {}
    asset = finding.asset

    if rem.get("requires_reboot") and asset.criticality in ("critical", "high"):
        notes.append(
            f"Reboot required on a {asset.criticality}-criticality host - "
            f"must land in the approved window ({asset.maintenance_window or 'window not set in CMDB'})."
        )
    if rem.get("requires_downtime") and asset.environment == "production":
        notes.append("Service interruption in production - needs a change record and a rollback plan.")
    if rem.get("change_risk") == "high":
        notes.append("High change risk - stage in a lower environment first if one exists.")
    if "PCI-DSS" in asset.compliance_scope:
        notes.append("PCI-DSS in scope - the fix and its evidence belong in the quarterly ASV record.")
    if asset.internet_facing:
        notes.append("Internet-facing - assume opportunistic scanning; treat the clock as already running.")
    if not asset.known_asset:
        notes.append("No CMDB owner - identify who owns this host before any change is scheduled.")
    if not finding.intel.known_cve:
        notes.append("CVE not in the local intel DB - verify severity and exploit status against NVD/KEV first.")
    if asset.role and "point-of-sale" in (asset.role or "").lower():
        notes.append("POS terminal - branch cannot take an outage during trading hours.")
    if finding.intel.name == "Heartbleed":
        notes.append("Patching alone is not sufficient - key and credential rotation is part of the fix.")
    return notes


def group_by_change(findings: list[ScoredFinding]) -> dict[str, list[ScoredFinding]]:
    """Group findings into candidate change tickets: one host, one maintenance window."""
    groups: dict[str, list[ScoredFinding]] = defaultdict(list)
    for finding in findings:
        groups[finding.hostname].append(finding)
    return dict(
        sorted(groups.items(), key=lambda kv: min(f.rank for f in kv[1]))
    )


# Working-hour ranges behind the effort labels, for totalling a batch.
EFFORT_HOUR_RANGE = {"low": (0.5, 2.0), "medium": (2.0, 8.0), "high": (8.0, 24.0)}


def effort_total(findings: list[ScoredFinding]) -> dict:
    """Deterministic effort roll-up for a set of findings.

    Handed to the Remediation agent precomputed. Asking a model to add up five
    effort bands is asking it to fabricate one -- in a previous run it flattened a
    high-effort finding into 'medium x 5'.
    """
    counts = effort_summary(findings)
    low = sum(EFFORT_HOUR_RANGE[e][0] * n for e, n in counts.items() if e in EFFORT_HOUR_RANGE)
    high = sum(EFFORT_HOUR_RANGE[e][1] * n for e, n in counts.items() if e in EFFORT_HOUR_RANGE)
    return {
        "counts": counts,
        "low_hours": round(low, 1),
        "high_hours": round(high, 1),
        "range": f"{low:g}-{high:g} engineer-hours",
        "unscoped": counts.get("unknown", 0),
    }


def patch_is_not_enough(findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """Findings whose own constraints say a patch does not close them."""
    return [
        f for f in findings
        if any("patching alone is not sufficient" in c.lower() for c in _constraints(f))
    ]


def effort_summary(findings: list[ScoredFinding]) -> dict[str, int]:
    counts = {"low": 0, "medium": 0, "high": 0, "unknown": 0}
    for finding in findings:
        effort = (finding.intel.remediation or {}).get("effort", "unknown")
        counts[effort if effort in counts else "unknown"] += 1
    return counts
