"""Discovery stage: raw scanner export -> clean, deduplicated findings.

Real scanner exports are messy in predictable ways, and every one of those ways
is represented in `data/sample_findings.json`:

  * host identity is inconsistent (FQDN, short name, uppercase, IP-only)
  * one row can carry several CVEs
  * the same exposure is reported by several plugins
  * informational and already-remediated rows ship in the same export
  * the CVE is sometimes only in the plugin name, not the CVE field
  * severity and CVSS arrive as ints, strings, or nulls

This module is deterministic on purpose. Parsing is not a judgment call, so it
does not belong in a prompt; the Discovery *agent* reviews and reports on what
this produced (see `vulntriage/agents.py`).
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .models import NormalizationReport, NormalizedFinding

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SEVERITY_NAMES = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
RISK_TO_SEVERITY = {
    "info": 0,
    "informational": 0,
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
# Fallback CVSS when neither the scanner nor the intel DB gives us a number.
SEVERITY_TO_CVSS = {0: 0.0, 1: 2.0, 2: 5.0, 3: 7.5, 4: 9.5}

OPEN_STATES = {"open", "new", "reopened", "active", ""}


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #

def load_raw(path: str | Path) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """Return (raw rows, scan metadata, format) for a JSON or CSV export."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Findings file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return payload, {}, "json"
        rows = payload.get("vulnerabilities") or payload.get("findings") or []
        return rows, payload.get("scan", {}), "json"

    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            rows = [_csv_row_to_dict(row) for row in csv.DictReader(handle)]
        return rows, {"scanner": "CSV export", "name": path.name}, "csv"

    raise ValueError(f"Unsupported findings format '{suffix}'. Use .json or .csv.")


def _csv_row_to_dict(row: dict[str, str]) -> dict[str, Any]:
    """Map Tenable's CSV column names onto the JSON export's field names."""
    get = lambda *names: next(  # noqa: E731 - terse on purpose, local helper
        (row[n] for n in names if row.get(n) not in (None, "")), ""
    )
    risk = get("Risk", "Severity").strip().lower()
    return {
        "plugin_id": get("Plugin ID", "Plugin"),
        "plugin_name": get("Name", "Plugin Name"),
        "severity": RISK_TO_SEVERITY.get(risk, 0),
        "severity_name": risk.title() or "Info",
        "host": get("Host", "DNS Name", "IP Address"),
        "ip": get("IP Address", "Host"),
        "port": get("Port"),
        "protocol": get("Protocol"),
        "svc_name": get("Service", "Protocol"),
        "cve": [c.strip() for c in get("CVE").split(",") if c.strip()],
        "cvss3_base_score": get("CVSS v3.0 Base Score", "CVSS v3 Base Score", "CVSS"),
        "state": get("State") or "open",
        "plugin_output": get("Plugin Output", "Description", "Synopsis"),
    }


# --------------------------------------------------------------------------- #
# field coercion
# --------------------------------------------------------------------------- #

def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _to_float(value: Any) -> float | None:
    if value in (None, "", "n/a"):
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _to_port(value: Any) -> int | None:
    port = _to_int(value, default=0)
    # Tenable uses port 0 for host-level (non-service) findings.
    return port if port > 0 else None


def _split_host(row: dict[str, Any]) -> tuple[str, str | None, str | None]:
    """Return (short hostname, fqdn, ip) from whatever identity fields exist."""
    raw_host = str(row.get("host") or "").strip()
    ip = str(row.get("ip") or "").strip() or None

    is_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", raw_host))
    if is_ip:
        return raw_host, None, raw_host

    fqdn = raw_host.lower() or None
    hostname = fqdn.split(".")[0] if fqdn else (ip or "unknown-host")
    if fqdn and "." not in fqdn:
        fqdn = None
    return hostname, fqdn, ip


def _extract_cves(row: dict[str, Any]) -> tuple[list[str], bool]:
    """Pull CVE ids from the CVE field, falling back to the plugin name/output."""
    field = row.get("cve") or row.get("cves") or []
    if isinstance(field, str):
        field = [c for c in re.split(r"[,\s]+", field) if c]
    cves = {c.upper() for c in field if CVE_RE.fullmatch(str(c).strip())}
    if cves:
        return sorted(cves), False

    haystack = f"{row.get('plugin_name', '')} {row.get('plugin_output', '')}"
    recovered = sorted({m.upper() for m in CVE_RE.findall(haystack)})
    return recovered, bool(recovered)


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #

def normalize(
    raw_rows: Iterable[dict[str, Any]],
    scan_meta: dict[str, Any] | None = None,
    source_file: str = "<memory>",
    source_format: str = "json",
) -> tuple[list[NormalizedFinding], NormalizationReport]:
    """Normalize raw scanner rows into one finding per (host, port, CVE)."""
    raw_rows = list(raw_rows)
    report = NormalizationReport(
        source_file=source_file,
        source_format=source_format,
        raw_rows=len(raw_rows),
        normalized_findings=0,
        scan_metadata=scan_meta or {},
    )

    by_id: dict[str, NormalizedFinding] = {}

    for row in raw_rows:
        state = str(row.get("state") or "open").strip().lower()
        if state not in OPEN_STATES:
            report.dropped_not_open += 1
            report.anomalies.append(
                f"Dropped plugin {row.get('plugin_id')} on {row.get('host')}: "
                f"state '{state}' (already remediated in the source system)."
            )
            continue

        severity = _to_int(row.get("severity"))
        cves, recovered = _extract_cves(row)

        if severity == 0 and not cves:
            report.dropped_informational += 1
            continue
        if not cves:
            report.dropped_no_cve += 1
            report.anomalies.append(
                f"Dropped plugin {row.get('plugin_id')} "
                f"('{row.get('plugin_name')}') on {row.get('host')}: no CVE reference. "
                "Configuration/hygiene finding - route to the hardening backlog, not CVE triage."
            )
            continue

        if recovered:
            report.cve_recovered_from_plugin_name += 1
            report.anomalies.append(
                f"Plugin {row.get('plugin_id')} had an empty CVE field; recovered "
                f"{', '.join(cves)} from the plugin name."
            )
        if len(cves) > 1:
            report.multi_cve_rows_split += 1
            report.anomalies.append(
                f"Plugin {row.get('plugin_id')} on {row.get('host')} bundled "
                f"{len(cves)} CVEs ({', '.join(cves)}); split into separate findings "
                "so each can be scored on its own merits."
            )

        hostname, fqdn, ip = _split_host(row)
        port = _to_port(row.get("port"))
        protocol = (str(row.get("protocol") or "").strip().lower() or None)
        service = (str(row.get("svc_name") or row.get("service") or "").strip().lower() or None)

        for cve in cves:
            finding_id = f"{hostname}:{port or 'host'}:{cve}"
            if finding_id in by_id:
                existing = by_id[finding_id]
                existing.source_rows += 1
                report.duplicates_collapsed += 1
                report.anomalies.append(
                    f"Collapsed duplicate {cve} on {hostname}:{port or 'host'} "
                    f"(plugins {existing.plugin_id} and {row.get('plugin_id')})."
                )
                # Keep the richest evidence and the earliest first_found.
                if len(str(row.get("plugin_output") or "")) > len(existing.evidence or ""):
                    existing.evidence = str(row.get("plugin_output") or "").strip() or None
                first = str(row.get("first_found") or "")
                if first and (not existing.first_found or first < existing.first_found):
                    existing.first_found = first
                continue

            by_id[finding_id] = NormalizedFinding(
                finding_id=finding_id,
                hostname=hostname,
                fqdn=fqdn,
                ip=ip,
                port=port,
                protocol=protocol,
                service=service,
                cve=cve,
                plugin_id=str(row.get("plugin_id") or "unknown"),
                plugin_name=str(row.get("plugin_name") or "").strip(),
                scanner_severity=severity,
                scanner_severity_name=str(
                    row.get("severity_name") or SEVERITY_NAMES.get(severity, "Info")
                ),
                scanner_cvss=_to_float(row.get("cvss3_base_score") or row.get("cvss")),
                first_found=str(row.get("first_found") or "") or None,
                last_found=str(row.get("last_found") or "") or None,
                evidence=str(row.get("plugin_output") or "").strip() or None,
            )

    findings = sorted(by_id.values(), key=lambda f: (f.hostname, f.port or 0, f.cve))
    report.normalized_findings = len(findings)
    report.hosts = sorted({f.hostname for f in findings})

    missing_cvss = [f.finding_id for f in findings if f.scanner_cvss is None]
    if missing_cvss:
        report.anomalies.append(
            f"{len(missing_cvss)} finding(s) arrived without a CVSS score "
            f"({', '.join(missing_cvss)}); enrichment must supply one."
        )

    return findings, report


def normalize_file(path: str | Path) -> tuple[list[NormalizedFinding], NormalizationReport]:
    """Convenience wrapper: load a file and normalize it in one call."""
    rows, meta, fmt = load_raw(path)
    return normalize(rows, meta, source_file=str(path), source_format=fmt)
