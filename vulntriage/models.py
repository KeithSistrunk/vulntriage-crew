"""Data models for the triage pipeline.

One model per pipeline stage. Each stage adds fields rather than replacing the
previous shape, so the final scored finding still carries everything discovery
saw in the raw scanner row.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Criticality = Literal["low", "medium", "high", "critical", "unknown"]
ExploitMaturity = Literal["none", "poc", "functional", "weaponized", "unknown"]
Priority = Literal["P1", "P2", "P3", "P4"]


class NormalizedFinding(BaseModel):
    """Output of the Discovery stage: one host + one port + one CVE."""

    finding_id: str = Field(..., description="Stable id: <host>:<port>:<cve>")
    hostname: str
    fqdn: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = Field(None, description="None means a host-level finding")
    protocol: Optional[str] = None
    service: Optional[str] = None
    cve: str
    plugin_id: str
    plugin_name: str
    scanner_severity: int = Field(..., ge=0, le=4, description="Nessus 0-4 scale")
    scanner_severity_name: str
    scanner_cvss: Optional[float] = None
    first_found: Optional[str] = None
    last_found: Optional[str] = None
    evidence: Optional[str] = None
    solution: Optional[str] = Field(
        None,
        description=(
            "The scanner's own remediation text, when the export carries one. "
            "Vendor guidance as reported, not vetted advice - the intel database "
            "wins wherever it has an entry."
        ),
    )
    source_rows: int = Field(1, description="How many raw rows collapsed into this finding")


class AssetContext(BaseModel):
    """CMDB context for the host a finding lives on."""

    hostname: str
    fqdn: Optional[str] = None
    known_asset: bool = True
    role: Optional[str] = None
    owner: Optional[str] = None
    os: Optional[str] = None
    criticality: Criticality = "unknown"
    internet_facing: bool = False
    environment: Optional[str] = None
    data_classification: Optional[str] = None
    compliance_scope: list[str] = Field(default_factory=list)
    maintenance_window: Optional[str] = None
    notes: Optional[str] = None


class CVEContext(BaseModel):
    """Threat intel for the CVE a finding refers to."""

    cve: str
    known_cve: bool = True
    name: Optional[str] = None
    description: Optional[str] = None
    published: Optional[str] = None
    cvss: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    exploit_maturity: ExploitMaturity = "unknown"
    kev: bool = False
    kev_date_added: Optional[str] = None
    ransomware_campaign_use: bool = False
    exploit_notes: Optional[str] = None
    remediation: dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None

    # -- live intel (empty on the mock path) --------------------------------
    epss_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="FIRST EPSS: probability of exploitation in the next 30 days",
    )
    epss_percentile: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Where that probability sits against all CVEs"
    )
    cwe: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    intel_sources: list[str] = Field(
        default_factory=list,
        description="Which live feeds answered for this CVE. Empty means the local DB only.",
    )


class EnrichedFinding(NormalizedFinding):
    """Output of the Enrichment stage: normalized finding + asset + CVE context."""

    asset: AssetContext
    intel: CVEContext
    effective_cvss: float = Field(
        ..., description="Intel CVSS if known, else the scanner's, else derived from severity"
    )
    cvss_source: str
    intel_gap: bool = False


class ScoreBreakdown(BaseModel):
    """Every multiplier that went into the risk score, so the number is auditable."""

    base_cvss: float
    asset_weight: float
    asset_reason: str
    exploit_weight: float
    exploit_reason: str
    exposure_weight: float
    exposure_reason: str
    raw_score: float
    max_raw_score: float


class ScoredFinding(EnrichedFinding):
    """Output of the Prioritization stage."""

    risk_score: float = Field(..., description="0-100, normalized")
    priority: Priority
    rank: int
    breakdown: ScoreBreakdown
    rationale: str
    cvss_rank: Optional[int] = Field(
        None, description="Where this finding would sit if ranked by raw CVSS alone"
    )
    rank_delta: Optional[int] = Field(
        None, description="cvss_rank - rank. Positive means risk scoring promoted it."
    )


class NormalizationReport(BaseModel):
    """What Discovery did to the raw file, so the numbers can be reconciled."""

    source_file: str
    source_format: str
    raw_rows: int
    normalized_findings: int
    dropped_informational: int = 0
    dropped_no_cve: int = 0
    dropped_not_open: int = 0
    duplicates_collapsed: int = 0
    multi_cve_rows_split: int = 0
    cve_recovered_from_plugin_name: int = 0
    hosts: list[str] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    scan_metadata: dict[str, Any] = Field(default_factory=dict)
