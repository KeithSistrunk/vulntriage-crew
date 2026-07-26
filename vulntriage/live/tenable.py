"""Tenable.io / Tenable.sc -- the findings themselves.

The spec leaves the variant open ("confirm which one"), so both are supported
and selected by `TENABLE_FLAVOR`. Tenable.io is the default because that is what
the documented endpoints belong to.

The contract this module has to honour is narrow and important: it returns *raw
row dicts in the same shape `normalize()` already parses*, not finished models.
Everything the normalizer does for the mock export -- collapsing duplicate
plugins, splitting multi-CVE rows, recovering CVE ids from plugin names,
reconciling host naming -- is exactly as necessary against live data, and none
of it should be reimplemented here.

Auth is the documented header form:
    X-ApiKeys: accessKey=<KEY>; secretKey=<SECRET>
Keys come from the environment. They are never logged or written to state.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from .http import LiveFetchError, get_json

log = logging.getLogger("vulntriage.live")

TENABLE_IO_URL = "https://cloud.tenable.com"

# Tenable severity ids line up with the Nessus 0-4 scale the normalizer expects.
SEVERITY_NAMES = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
SEVERITY_IDS = {name.lower(): value for value, name in SEVERITY_NAMES.items()}


class TenableAuthError(RuntimeError):
    """Credentials are absent or malformed. Distinct from a feed being down."""


class TenableClient:
    """Pulls findings from Tenable and hands back raw rows for the normalizer."""

    def __init__(
        self,
        base_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        flavor: str | None = None,
        fetch=get_json,
    ) -> None:
        self.base_url = (base_url or os.getenv("TENABLE_URL") or TENABLE_IO_URL).rstrip("/")
        # None means "read the environment"; "" means "explicitly unconfigured",
        # which is what tests need in order not to pick up real credentials.
        if access_key is None:
            access_key = os.getenv("TENABLE_ACCESS_KEY")
        if secret_key is None:
            secret_key = os.getenv("TENABLE_SECRET_KEY")
        self.access_key = access_key or None
        self.secret_key = secret_key or None
        self.flavor = (flavor or os.getenv("TENABLE_FLAVOR") or "io").strip().lower()
        self._fetch = fetch
        self.error: str | None = None

    # -- auth ---------------------------------------------------------------
    @property
    def configured(self) -> bool:
        return bool(self.access_key and self.secret_key)

    def _headers(self) -> dict[str, str]:
        if not self.configured:
            raise TenableAuthError(
                "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY are not set. Copy .env.example "
                "to .env and fill them in, or run with --source mock."
            )
        return {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
        }

    # -- pulls --------------------------------------------------------------
    def fetch_assets(self) -> dict[str, dict[str, Any]]:
        """Asset context keyed by asset id, for the host/criticality join."""
        payload = self._fetch(
            f"{self.base_url}/workbenches/assets", headers=self._headers()
        )
        assets: dict[str, dict[str, Any]] = {}
        for asset in (payload or {}).get("assets", []) or []:
            asset_id = asset.get("id")
            if asset_id:
                assets[str(asset_id)] = asset
        return assets

    def fetch_vulnerabilities(self) -> list[dict[str, Any]]:
        """The vulnerability workbench, one row per plugin/asset pair."""
        payload = self._fetch(
            f"{self.base_url}/workbenches/vulnerabilities",
            headers=self._headers(),
            params={"date_range": 30},
        )
        return list((payload or {}).get("vulnerabilities", []) or [])

    def fetch_vulnerability_outputs(self, plugin_id: Any) -> list[dict[str, Any]]:
        """Per-plugin detail -- this is where host, port and state actually live."""
        payload = self._fetch(
            f"{self.base_url}/workbenches/vulnerabilities/{plugin_id}/outputs",
            headers=self._headers(),
        )
        return list(payload or [])

    # -- normalization ------------------------------------------------------
    def fetch_findings(self) -> list[dict[str, Any]]:
        """Every open finding, as raw rows in the mock export's shape.

        The workbench summary gives one row per plugin; the per-plugin outputs
        give the hosts and ports it fired on. One finding is one host + one port
        + one CVE, so the outputs are what actually get expanded.
        """
        assets = self._safe_assets()
        rows: list[dict[str, Any]] = []

        for vuln in self.fetch_vulnerabilities():
            plugin = vuln.get("plugin_id") or (vuln.get("plugin") or {}).get("id")
            if plugin is None:
                continue
            try:
                outputs = self.fetch_vulnerability_outputs(plugin)
            except LiveFetchError as exc:
                # One noisy plugin must not cost the whole pull.
                log.warning("Tenable: no outputs for plugin %s (%s)", plugin, exc)
                continue
            rows.extend(self._rows_for_plugin(vuln, plugin, outputs, assets))

        log.info("Tenable: %d raw finding row(s)", len(rows))
        return rows

    def _safe_assets(self) -> dict[str, dict[str, Any]]:
        try:
            return self.fetch_assets()
        except LiveFetchError as exc:
            # Asset context is a bonus here; the CMDB join still happens in intel.py.
            log.warning("Tenable asset workbench unavailable (%s); continuing", exc)
            self.error = str(exc)
            return {}

    def _rows_for_plugin(
        self,
        vuln: dict[str, Any],
        plugin_id: Any,
        outputs: list[dict[str, Any]],
        assets: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        plugin_name = vuln.get("plugin_name") or (vuln.get("plugin") or {}).get("name") or ""
        severity = _severity_id(vuln.get("severity"))
        cves = _cve_list(vuln)
        cvss = _first_float(
            vuln.get("cvss3_base_score"),
            vuln.get("cvss_base_score"),
            (vuln.get("plugin") or {}).get("cvss3_base_score"),
        )

        rows: list[dict[str, Any]] = []
        for output in outputs:
            for state_block in output.get("states") or []:
                state = str(state_block.get("name") or "open").lower()
                for result in state_block.get("results") or []:
                    for host in result.get("hosts") or []:
                        rows.append(
                            self._row(
                                host=host,
                                assets=assets,
                                plugin_id=plugin_id,
                                plugin_name=plugin_name,
                                severity=severity,
                                cves=cves,
                                cvss=cvss,
                                port=result.get("port"),
                                protocol=result.get("protocol"),
                                service=result.get("service"),
                                state=state,
                                evidence=output.get("plugin_output"),
                                first_found=state_block.get("first_found") or result.get("first_found"),
                                last_found=state_block.get("last_found") or result.get("last_found"),
                            )
                        )
        return rows

    @staticmethod
    def _row(
        host: dict[str, Any],
        assets: dict[str, dict[str, Any]],
        plugin_id: Any,
        plugin_name: str,
        severity: int,
        cves: list[str],
        cvss: float | None,
        port: Any,
        protocol: Any,
        service: Any,
        state: str,
        evidence: Any,
        first_found: Any,
        last_found: Any,
    ) -> dict[str, Any]:
        asset = assets.get(str(host.get("id") or ""), {})
        # `host` is the key the normalizer's `_split_host` actually reads, and it
        # prefers an FQDN there because that is what reconciles against the CMDB.
        # Emitting `hostname` instead silently drops every finding back to being
        # identified by IP.
        identity = (
            _first(asset.get("fqdn"))
            or host.get("hostname")
            or _first(asset.get("netbios_name"))
            or host.get("ip")
            or _first(asset.get("ipv4"))
            or ""
        )
        ip = host.get("ip") or _first(asset.get("ipv4"))

        return {
            "host": identity,
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "svc_name": service,
            "cve": cves,
            "plugin_id": str(plugin_id),
            "plugin_name": plugin_name,
            "severity": severity,
            "severity_name": SEVERITY_NAMES.get(severity, "Info"),
            "cvss3_base_score": cvss,
            "state": state,
            "first_found": first_found,
            "last_found": last_found,
            "plugin_output": evidence,
        }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _first(value: Any) -> Any:
    """Tenable returns several asset attributes as single-element lists."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _first_float(*values: Any) -> float | None:
    for value in values:
        try:
            if value is not None:
                return float(value)
        except (TypeError, ValueError):
            continue
    return None


def _severity_id(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    return SEVERITY_IDS.get(str(value or "").strip().lower(), 0)


def _cve_list(vuln: dict[str, Any]) -> list[str]:
    raw = vuln.get("cve") or vuln.get("cves") or (vuln.get("plugin") or {}).get("cve") or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        text = str(item or "").strip().upper()
        if text:
            out.append(text if text.startswith("CVE-") else f"CVE-{text}")
    return list(dict.fromkeys(out))
