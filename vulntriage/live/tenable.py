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

from ..models import AssetContext
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
        self.plugins_seen = 0
        self.plugins_without_cve = 0

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

    def fetch_asset_contexts(self) -> dict[str, AssetContext]:
        """Build the host -> criticality index the risk model needs.

        Without this the whole thesis of the project goes inert against live
        data: the mock CMDB knows none of the real estate, so every finding
        scores at the neutral asset weight and the ranking collapses back to
        something close to a CVSS sort.

        Tenable's Asset Criticality Rating is the "asset data / tags" the spec's
        formula refers to. It is a 1-10 scale, banded here the way Tenable's own
        documentation describes it.
        """
        try:
            raw = self.fetch_assets()
        except (LiveFetchError, TenableAuthError) as exc:
            log.warning("Tenable asset workbench unavailable (%s); continuing", exc)
            self.error = str(exc)
            return {}

        index: dict[str, AssetContext] = {}
        for asset in raw.values():
            hostname = _first(asset.get("hostname")) or _first(asset.get("netbios_name"))
            fqdn = _first(asset.get("fqdn"))
            ipv4 = _first(asset.get("ipv4"))
            name = hostname or (fqdn.split(".")[0] if fqdn else None) or ipv4
            if not name:
                continue

            acr = asset.get("acr_score")
            context = AssetContext(
                hostname=name,
                fqdn=fqdn,
                known_asset=True,
                os=_first(asset.get("operating_system")),
                criticality=acr_to_criticality(acr),
                # Tenable's workbench does not say whether a host is reachable
                # from the internet, so this stays False rather than guessing.
                # Getting it wrong in either direction moves the score.
                internet_facing=False,
                notes=(
                    f"Tenable asset (ACR {acr})" if acr is not None
                    else "Tenable asset with no ACR - criticality assumed medium"
                ),
            )
            for key in (hostname, fqdn, ipv4, name):
                if key:
                    index[str(key).strip().lower()] = context
        log.info("Tenable: asset criticality for %d identities", len(index))
        return index

    def fetch_vulnerabilities(self) -> list[dict[str, Any]]:
        """The vulnerability workbench, one row per plugin/asset pair."""
        payload = self._fetch(
            f"{self.base_url}/workbenches/vulnerabilities",
            headers=self._headers(),
            params={"date_range": 30},
        )
        return list((payload or {}).get("vulnerabilities", []) or [])

    def fetch_vulnerability_outputs(self, plugin_id: Any) -> list[dict[str, Any]]:
        """Per-plugin detail -- this is where host, port and state actually live.

        The endpoint returns `{"outputs": [...]}`, not a bare list. Treating the
        payload as a list yields the dict's *keys* -- a list of strings -- which
        fails later with a confusing "'str' object has no attribute 'get'".
        """
        payload = self._fetch(
            f"{self.base_url}/workbenches/vulnerabilities/{plugin_id}/outputs",
            headers=self._headers(),
        )
        if isinstance(payload, dict):
            return list(payload.get("outputs") or [])
        return list(payload or [])

    def fetch_vulnerability_info(self, plugin_id: Any) -> dict[str, Any]:
        """Plugin metadata -- and the only place the CVE ids actually appear.

        The vulnerability workbench summary carries plugin id, name, severity and
        a CVSS score but *no* CVE reference at all, so this second call is not
        optional: without it every finding would be dropped for having no CVE.
        """
        payload = self._fetch(
            f"{self.base_url}/workbenches/vulnerabilities/{plugin_id}/info",
            headers=self._headers(),
        )
        return dict((payload or {}).get("info") or {})

    # -- normalization ------------------------------------------------------
    def fetch_findings(self, progress=None) -> list[dict[str, Any]]:
        """Every open finding, as raw rows in the mock export's shape.

        Three calls per plugin would be wasteful, so the order matters: the
        workbench summary lists the plugins, `/info` supplies the CVEs, and
        `/outputs` supplies the hosts and ports. A plugin whose `/info` carries
        no CVE is skipped before its outputs are ever requested -- the normalizer
        drops CVE-less rows anyway, and on a real estate that is most of them.
        """
        summary = self.fetch_vulnerabilities()
        rows: list[dict[str, Any]] = []
        skipped_no_cve = 0

        for index, vuln in enumerate(summary, start=1):
            plugin = vuln.get("plugin_id") or (vuln.get("plugin") or {}).get("id")
            if plugin is None:
                continue
            if progress:
                progress(index, len(summary), vuln.get("plugin_name") or str(plugin))

            try:
                info = self.fetch_vulnerability_info(plugin)
            except LiveFetchError as exc:
                log.warning("Tenable: no info for plugin %s (%s)", plugin, exc)
                continue

            cves = _cves_from_info(info) or _cve_list(vuln)
            if not cves:
                skipped_no_cve += 1
                continue

            try:
                outputs = self.fetch_vulnerability_outputs(plugin)
            except LiveFetchError as exc:
                # One noisy plugin must not cost the whole pull.
                log.warning("Tenable: no outputs for plugin %s (%s)", plugin, exc)
                continue

            rows.extend(self._rows_for_plugin(vuln, plugin, cves, info, outputs))

        self.plugins_seen = len(summary)
        self.plugins_without_cve = skipped_no_cve
        log.info(
            "Tenable: %d plugin(s), %d without a CVE, %d raw finding row(s)",
            len(summary), skipped_no_cve, len(rows),
        )
        return rows

    def _rows_for_plugin(
        self,
        vuln: dict[str, Any],
        plugin_id: Any,
        cves: list[str],
        info: dict[str, Any],
        outputs: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        plugin_name = (
            vuln.get("plugin_name")
            or ((info.get("plugin_details") or {}).get("name"))
            or ""
        )
        severity = _severity_id(vuln.get("severity", info.get("severity")))
        risk = info.get("risk_information") or {}
        cvss = _first_float(
            risk.get("cvss3_base_score"),
            vuln.get("cvss3_base_score"),
            risk.get("cvss_base_score"),
            vuln.get("cvss_base_score"),
        )

        rows: list[dict[str, Any]] = []
        for output in outputs:
            evidence = output.get("plugin_output")
            for state_block in output.get("states") or []:
                state = str(state_block.get("name") or "open").lower()
                for result in state_block.get("results") or []:
                    port = result.get("port")
                    protocol = result.get("transport_protocol") or result.get("protocol")
                    service = result.get("application_protocol") or result.get("service")
                    # Real payloads key this `assets`; the docs say `hosts`.
                    for asset in result.get("assets") or result.get("hosts") or []:
                        rows.append(
                            self._row(
                                asset=asset,
                                plugin_id=plugin_id,
                                plugin_name=plugin_name,
                                severity=severity,
                                cves=cves,
                                cvss=cvss,
                                port=port,
                                protocol=protocol,
                                service=service,
                                state=state,
                                evidence=evidence,
                            )
                        )
        return rows

    @staticmethod
    def _row(
        asset: dict[str, Any],
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
    ) -> dict[str, Any]:
        # `host` is the key the normalizer's `_split_host` actually reads, and it
        # prefers an FQDN there because that is what reconciles against the CMDB.
        # Emitting `hostname` instead silently drops every finding back to being
        # identified by IP.
        identity = (
            _first(asset.get("fqdn"))
            or _first(asset.get("hostname"))
            or _first(asset.get("netbios_name"))
            or _first(asset.get("ipv4"))
            or _first(asset.get("ip"))
            or ""
        )
        ip = _first(asset.get("ipv4")) or _first(asset.get("ip"))

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
            "first_found": asset.get("first_seen"),
            "last_found": asset.get("last_seen"),
            "plugin_output": evidence,
        }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def acr_to_criticality(acr: Any) -> str:
    """Tenable's 1-10 Asset Criticality Rating -> the model's criticality band.

    Bands follow Tenable's own documentation. An asset with no ACR comes back
    "unknown", which the risk model already treats as a neutral x1.00 rather
    than inventing a criticality for it.
    """
    try:
        score = float(acr)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


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


def _cves_from_info(info: dict[str, Any]) -> list[str]:
    """Pull CVE ids out of a plugin's reference block.

    Shape is a list of named reference groups, only one of which is CVEs:
        [{"name": "cve", "values": ["CVE-2025-53783"]}, {"name": "iava", ...}]
    """
    out: list[str] = []
    for group in info.get("reference_information") or []:
        if str(group.get("name") or "").strip().lower() != "cve":
            continue
        for value in group.get("values") or []:
            text = str(value or "").strip().upper()
            if text.startswith("CVE-"):
                out.append(text)
    return list(dict.fromkeys(out))


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
