"""Enrichment stage: join findings against CVE intel and the asset inventory.

Both sources are local JSON for the POC. The lookup functions are the seam where
a live NVD / CISA KEV feed and a real CMDB drop in later -- callers only ever see
`CVEContext` and `AssetContext`, so swapping the backing store does not ripple.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import AssetContext, CVEContext, EnrichedFinding, NormalizedFinding
from .normalize import SEVERITY_TO_CVSS

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CVE_DB_PATH = DATA_DIR / "cve_db.json"
ASSET_DB_PATH = DATA_DIR / "asset_inventory.json"


@lru_cache(maxsize=1)
def _cve_db(path: str = str(CVE_DB_PATH)) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8")).get("cves", {})


@lru_cache(maxsize=1)
def _asset_db(path: str = str(ASSET_DB_PATH)) -> dict[str, dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    index: dict[str, dict[str, Any]] = {}
    for asset in payload.get("assets", []):
        for key in (asset.get("hostname"), asset.get("fqdn"), asset.get("ip")):
            if key:
                index[str(key).lower()] = asset
    return index


def reload_databases() -> None:
    """Drop the cached copies (used by tests and after editing the mock data)."""
    _cve_db.cache_clear()
    _asset_db.cache_clear()


# --------------------------------------------------------------------------- #
# lookups
# --------------------------------------------------------------------------- #

def lookup_cve(cve_id: str) -> CVEContext:
    """Look up one CVE. Unknown CVEs come back flagged, never raise."""
    cve_id = (cve_id or "").strip().upper()
    record = _cve_db().get(cve_id)
    if not record:
        return CVEContext(
            cve=cve_id,
            known_cve=False,
            exploit_maturity="unknown",
            notes=(
                "No entry in the local intel database. Exploit status is unknown, not absent - "
                "scoring falls back to the scanner's CVSS with a neutral exploit weight and the "
                "finding is flagged for a manual NVD/KEV check."
            ),
        )

    cvss = record.get("cvss_v3", {}) or {}
    exploit = record.get("exploit", {}) or {}
    return CVEContext(
        cve=cve_id,
        known_cve=True,
        name=record.get("name"),
        description=record.get("description"),
        published=record.get("published"),
        cvss=cvss.get("score"),
        cvss_severity=cvss.get("severity"),
        cvss_vector=cvss.get("vector"),
        exploit_maturity=exploit.get("maturity", "unknown"),
        kev=bool(exploit.get("kev")),
        kev_date_added=exploit.get("kev_date_added"),
        ransomware_campaign_use=bool(exploit.get("ransomware_campaign_use")),
        exploit_notes=exploit.get("notes"),
        remediation=record.get("remediation", {}) or {},
    )


def lookup_asset(host: str) -> AssetContext:
    """Look up a host by short name, FQDN, or IP. Unknown hosts come back flagged."""
    record = _asset_db().get((host or "").strip().lower())
    if not record:
        return AssetContext(
            hostname=host,
            known_asset=False,
            criticality="unknown",
            notes=(
                "No CMDB record. Treated as medium criticality for scoring, but an unmanaged "
                "host on a production subnet is itself a finding - confirm ownership before "
                "any remediation is scheduled."
            ),
        )

    return AssetContext(
        hostname=record.get("hostname", host),
        fqdn=record.get("fqdn"),
        known_asset=True,
        role=record.get("role"),
        owner=record.get("owner"),
        os=record.get("os"),
        criticality=record.get("criticality", "unknown"),
        internet_facing=bool(record.get("internet_facing")),
        environment=record.get("environment"),
        data_classification=record.get("data_classification"),
        compliance_scope=list(record.get("compliance_scope") or []),
        maintenance_window=record.get("maintenance_window"),
    )


# --------------------------------------------------------------------------- #
# enrichment
# --------------------------------------------------------------------------- #

def enrich(finding: NormalizedFinding, live=None) -> EnrichedFinding:
    """Attach CVE intel and asset context to a single normalized finding.

    `live` is an optional `vulntriage.live.LiveIntel`. When present, its feeds
    overlay the local database; when absent, this is exactly the POC path.
    """
    intel = lookup_cve(finding.cve)
    if live is not None:
        intel = live.apply(intel)
    asset = lookup_asset(finding.fqdn or finding.hostname)
    if not asset.known_asset and finding.ip:
        asset = lookup_asset(finding.ip)
    if not asset.known_asset:
        asset.hostname = finding.hostname

    data = finding.model_dump()
    if asset.known_asset and asset.hostname != finding.hostname:
        # The scanner identified this host by IP or by an alias. Reconcile it to
        # the CMDB name so per-host grouping and change tickets do not fragment.
        asset.notes = (
            f"Scanner reported this host as '{finding.hostname}'; "
            f"reconciled to CMDB name '{asset.hostname}'."
        )
        data["hostname"] = asset.hostname
        data["fqdn"] = asset.fqdn or finding.fqdn
        data["finding_id"] = f"{asset.hostname}:{finding.port or 'host'}:{finding.cve}"

    if intel.cvss is not None:
        effective_cvss, source = intel.cvss, "intel database (NVD CVSS v3.x)"
    elif finding.scanner_cvss is not None:
        effective_cvss, source = finding.scanner_cvss, "scanner-reported CVSS"
    else:
        effective_cvss = SEVERITY_TO_CVSS.get(finding.scanner_severity, 5.0)
        source = f"derived from scanner severity '{finding.scanner_severity_name}'"

    return EnrichedFinding(
        **data,
        asset=asset,
        intel=intel,
        effective_cvss=effective_cvss,
        cvss_source=source,
        intel_gap=not intel.known_cve or not asset.known_asset,
    )


def enrich_all(findings: list[NormalizedFinding], live=None) -> list[EnrichedFinding]:
    """Enrich every finding, collapsing duplicates that only host reconciliation reveals.

    Discovery cannot tell that `10.20.4.11` and `prod-db-01` are the same box --
    that join only exists in the CMDB. So a second dedupe pass belongs here.

    When `live` is supplied its feeds are primed once for the whole CVE set --
    one KEV download and batched EPSS beats per-finding lookups by an order of
    magnitude, and NVD's rate limit makes it the difference between seconds and
    minutes.
    """
    if live is not None:
        live.prime(f.cve for f in findings)

    enriched: dict[str, EnrichedFinding] = {}
    for finding in findings:
        result = enrich(finding, live=live)
        existing = enriched.get(result.finding_id)
        if existing:
            existing.source_rows += result.source_rows
            continue
        enriched[result.finding_id] = result
    return list(enriched.values())


def intel_gaps(findings: list[EnrichedFinding]) -> list[str]:
    """Human-readable list of everything enrichment could not resolve."""
    gaps: list[str] = []
    for f in findings:
        if not f.intel.known_cve:
            gaps.append(
                f"{f.cve} on {f.hostname}: not in the local CVE database - "
                f"scored on the scanner's CVSS ({f.effective_cvss}) with a neutral exploit weight. "
                "Verify against NVD and CISA KEV before closing."
            )
        if not f.asset.known_asset:
            gaps.append(
                f"{f.hostname}: no CMDB record - business criticality assumed medium. "
                "Identify the owner before scheduling remediation."
            )
    return sorted(set(gaps))
