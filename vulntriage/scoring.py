"""Prioritization stage: the risk model.

    risk = CVSS  x  asset weight  x  exploit weight  x  exposure weight

CVSS answers "how bad is this bug in the abstract". The three multipliers answer
"how bad is it *here*" -- what the host is worth, whether anyone can actually
exploit it, and whether it is reachable. That is the whole thesis of the project:
a medium CVE on a crown-jewel asset with a working public exploit outranks a high
CVE on a nightly-rebuilt lab box.

The weights are deliberately blunt and every one is recorded in `ScoreBreakdown`,
so an analyst can see exactly why a finding sits where it does and argue with the
number instead of guessing at it.
"""

from __future__ import annotations

from .models import EnrichedFinding, Priority, ScoreBreakdown, ScoredFinding

# How much the business cares about the host.
ASSET_WEIGHTS: dict[str, float] = {
    "critical": 1.50,
    "high": 1.25,
    "medium": 1.00,
    "low": 0.70,
    "unknown": 1.00,
}

# How real the exploit is. KEV membership floors this at "weaponized" -- CISA only
# lists CVEs with confirmed in-the-wild exploitation.
EXPLOIT_WEIGHTS: dict[str, float] = {
    "weaponized": 1.60,
    "functional": 1.45,
    "poc": 1.30,
    "none": 1.00,
    "unknown": 1.00,
}

INTERNET_FACING_WEIGHT = 1.25
INTERNAL_WEIGHT = 1.00

# Worst possible case: 10.0 CVSS, critical asset, weaponized, internet-facing.
MAX_RAW_SCORE = 10.0 * max(ASSET_WEIGHTS.values()) * max(EXPLOIT_WEIGHTS.values()) * INTERNET_FACING_WEIGHT

# Score bands -> priority, with the SLA an analyst would actually attach.
PRIORITY_BANDS: list[tuple[float, Priority, str]] = [
    (75.0, "P1", "Emergency change - remediate within 24-48 hours"),
    (55.0, "P2", "Expedited - remediate within 7 days"),
    (35.0, "P3", "Scheduled - next monthly patch cycle"),
    (0.0, "P4", "Backlog - bundle with routine hardening"),
]


def priority_for(score: float) -> tuple[Priority, str]:
    for threshold, priority, sla in PRIORITY_BANDS:
        if score >= threshold:
            return priority, sla
    return "P4", PRIORITY_BANDS[-1][2]


def _asset_weight(finding: EnrichedFinding) -> tuple[float, str]:
    crit = finding.asset.criticality
    weight = ASSET_WEIGHTS.get(crit, 1.0)
    if not finding.asset.known_asset:
        return weight, "unmanaged host with no CMDB record - assumed medium (x1.00)"
    detail = f"{crit} criticality"
    if finding.asset.compliance_scope:
        detail += f", in scope for {'/'.join(finding.asset.compliance_scope)}"
    if finding.asset.environment:
        detail += f", {finding.asset.environment} environment"
    return weight, f"{detail} (x{weight:.2f})"


def _exploit_weight(finding: EnrichedFinding) -> tuple[float, str]:
    intel = finding.intel
    maturity = intel.exploit_maturity
    weight = EXPLOIT_WEIGHTS.get(maturity, 1.0)

    if intel.kev:
        weight = max(weight, EXPLOIT_WEIGHTS["weaponized"])
        reason = "on the CISA KEV list - confirmed exploited in the wild"
        if intel.ransomware_campaign_use:
            reason += ", used in known ransomware campaigns"
        return weight, f"{reason} (x{weight:.2f})"

    reasons = {
        "weaponized": "reliable public exploit available",
        "functional": "functional public exploit available",
        "poc": "proof-of-concept published, no weaponized exploit observed",
        "none": "no public exploit - theoretical or research-grade only",
        "unknown": "exploit status unknown (CVE not in the local intel DB)",
    }
    return weight, f"{reasons.get(maturity, 'exploit status unclear')} (x{weight:.2f})"


def _exposure_weight(finding: EnrichedFinding) -> tuple[float, str]:
    if finding.asset.internet_facing:
        return INTERNET_FACING_WEIGHT, f"internet-facing host (x{INTERNET_FACING_WEIGHT:.2f})"
    return INTERNAL_WEIGHT, f"internal-only host (x{INTERNAL_WEIGHT:.2f})"


def score_finding(finding: EnrichedFinding) -> ScoredFinding:
    """Score one enriched finding. Rank is filled in later by `score_all`."""
    base = finding.effective_cvss
    asset_w, asset_reason = _asset_weight(finding)
    exploit_w, exploit_reason = _exploit_weight(finding)
    exposure_w, exposure_reason = _exposure_weight(finding)

    raw = base * asset_w * exploit_w * exposure_w
    normalized = round(min(100.0, raw / MAX_RAW_SCORE * 100.0), 1)
    priority, sla = priority_for(normalized)

    breakdown = ScoreBreakdown(
        base_cvss=base,
        asset_weight=asset_w,
        asset_reason=asset_reason,
        exploit_weight=exploit_w,
        exploit_reason=exploit_reason,
        exposure_weight=exposure_w,
        exposure_reason=exposure_reason,
        raw_score=round(raw, 2),
        max_raw_score=round(MAX_RAW_SCORE, 2),
    )

    rationale = (
        f"CVSS {base} ({finding.cvss_source}) x {asset_w:.2f} [{asset_reason}] "
        f"x {exploit_w:.2f} [{exploit_reason}] x {exposure_w:.2f} [{exposure_reason}] "
        f"= {raw:.2f}/{MAX_RAW_SCORE:.2f} -> {normalized}/100. {priority}: {sla}."
    )

    return ScoredFinding(
        **finding.model_dump(),
        risk_score=normalized,
        priority=priority,
        rank=0,
        breakdown=breakdown,
        rationale=rationale,
    )


def score_all(findings: list[EnrichedFinding]) -> list[ScoredFinding]:
    """Score, rank, and record how far each finding moved against a raw-CVSS ranking."""
    scored = [score_finding(f) for f in findings]

    # Rank by risk. Ties break on CVSS, then KEV, then host for stability.
    scored.sort(
        key=lambda f: (-f.risk_score, -f.effective_cvss, not f.intel.kev, f.hostname, f.cve)
    )
    for i, finding in enumerate(scored, start=1):
        finding.rank = i

    # Where each finding *would* have landed if we ranked on CVSS alone.
    cvss_order = sorted(scored, key=lambda f: (-f.effective_cvss, f.hostname, f.cve))
    cvss_rank = {f.finding_id: i for i, f in enumerate(cvss_order, start=1)}
    for finding in scored:
        finding.cvss_rank = cvss_rank[finding.finding_id]
        finding.rank_delta = finding.cvss_rank - finding.rank

    return scored


def ranking_divergences(scored: list[ScoredFinding], limit: int = 5) -> list[str]:
    """The headline output: where risk ranking disagrees most with raw CVSS."""
    movers = sorted(scored, key=lambda f: -abs(f.rank_delta or 0))[:limit]
    lines: list[str] = []
    for f in movers:
        if not f.rank_delta:
            continue
        direction = "promoted" if f.rank_delta > 0 else "demoted"
        lines.append(
            f"{f.cve} on {f.hostname} {direction} {abs(f.rank_delta)} place(s) "
            f"(CVSS rank #{f.cvss_rank} -> risk rank #{f.rank}): "
            f"CVSS {f.effective_cvss}, {f.asset.criticality} asset, "
            f"{'KEV-listed' if f.intel.kev else f.intel.exploit_maturity + ' exploit'}, "
            f"{'internet-facing' if f.asset.internet_facing else 'internal'}."
        )
    return lines
