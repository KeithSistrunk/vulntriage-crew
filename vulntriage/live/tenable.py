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

A live pull is also capped (`limit`, default 20, `--limit` on the CLI). A real
estate has thousands of findings and every one of them costs an NVD lookup during
enrichment, so the cap is applied here -- at the pull -- rather than downstream:
rows beyond the cap are never produced, and the plugins behind them are never
requested at all.

*What* the cap keeps matters as much as the cap itself. The workbench comes back
in plugin order, so taking the first 20 rows off it returned 20 hosts carrying the
same CVE-1999-0524 ICMP timestamp disclosure -- 1 of 105 plugins, every finding
P4. A capped pull is therefore sampled, not truncated:

    1. drop anything below `min_cvss` (default 7.0)
    2. keep each CVE once, at the highest-severity plugin reporting it
    3. walk the workbench in severity order
    4. stop at `limit`

which yields up to 20 *distinct* high-severity CVEs. The dedupe is part of the
sampling and so applies only when a cap is in force; `min_cvss` is its own flag
and applies either way.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ..models import AssetContext
# The severity -> CVSS fallback belongs to the normalizer; importing it keeps the
# sampling filter and the downstream scoring reading the same table.
from ..normalize import SEVERITY_TO_CVSS
from .http import LiveFetchError, get_json

log = logging.getLogger("vulntriage.live")

TENABLE_IO_URL = "https://cloud.tenable.com"

# How many findings one live pull may return. Small on purpose: this is a POC and
# the enrichment stage makes a rate-limited NVD call per CVE. `--limit 0` lifts it.
DEFAULT_FINDING_LIMIT = 20

# The sampling floor. 7.0 is the CVSS v3 "High" boundary, so the default keeps
# High and Critical. `--min-cvss` lowers it when too little survives.
DEFAULT_MIN_CVSS = 7.0

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
        limit: int | None = DEFAULT_FINDING_LIMIT,
        min_cvss: float | None = DEFAULT_MIN_CVSS,
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
        # None means uncapped. Anything <= 0 is read as "no cap" so `--limit 0`
        # is an escape hatch rather than a pull that returns nothing.
        self.limit = _coerce_limit(limit)
        # 0 means "no floor", so `--min-cvss 0` pulls informational findings too.
        self.min_cvss = _coerce_min_cvss(min_cvss)
        self._fetch = fetch
        self.error: str | None = None
        self.plugins_seen = 0
        self.plugins_examined = 0
        self.plugins_without_cve = 0
        self.plugins_below_min_cvss = 0
        self.duplicate_cves_skipped = 0
        self.hosts_not_sampled = 0
        self.truncated = False

    @property
    def sampling(self) -> bool:
        """True when the cap is in force, and with it the one-host-per-CVE dedupe."""
        return self.limit is not None

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
        """Open findings, as raw rows in the mock export's shape.

        Three calls per plugin would be wasteful, so the order matters: the
        workbench summary lists the plugins, `/info` supplies the CVEs and the v3
        score, and `/outputs` supplies the hosts and ports. A plugin that is
        skipped -- no CVE, below `min_cvss`, or reporting only CVEs already
        sampled -- never costs an `/outputs` call, and on a real estate that is
        most of them.

        The sampling is enforced inside this loop rather than by filtering the
        result, for the same reason the cap is: a capped pull against a large
        estate should cost a handful of calls, not thousands. Walking the
        workbench in severity order is what makes stopping early safe -- the first
        plugin to claim a CVE is by construction the highest-severity one
        reporting it, which is the instance the cap is meant to keep.
        """
        summary = self.fetch_vulnerabilities()
        candidates = _by_severity(summary)
        rows: list[dict[str, Any]] = []
        claimed: set[str] = set()
        skipped_no_cve = below_floor = duplicates = crowded_out = examined = 0
        self.truncated = False

        for index, vuln in enumerate(candidates, start=1):
            if self.sampling and len(claimed) >= self.limit:
                self.truncated = True
                break

            plugin = vuln.get("plugin_id") or (vuln.get("plugin") or {}).get("id")
            if plugin is None:
                continue
            if progress:
                progress(index, len(candidates), vuln.get("plugin_name") or str(plugin))
            examined += 1

            try:
                info = self.fetch_vulnerability_info(plugin)
            except LiveFetchError as exc:
                log.warning("Tenable: no info for plugin %s (%s)", plugin, exc)
                continue

            cves = _cves_from_info(info) or _cve_list(vuln)
            if not cves:
                skipped_no_cve += 1
                continue

            severity = _severity_id(vuln.get("severity", info.get("severity")))
            cvss = _effective_cvss(vuln, info)
            if not self._meets_floor(cvss, severity):
                below_floor += 1
                continue

            # Each CVE is kept once. Because the walk is severity-ordered, a CVE
            # already claimed was claimed by a plugin at least this severe, so
            # there is nothing better here -- and no reason to spend an
            # `/outputs` call finding that out.
            wanted = [c for c in cves if c not in claimed] if self.sampling else list(cves)
            duplicates += len(cves) - len(wanted)
            if not wanted:
                continue

            try:
                outputs = self.fetch_vulnerability_outputs(plugin)
            except LiveFetchError as exc:
                # One noisy plugin must not cost the whole pull.
                log.warning("Tenable: no outputs for plugin %s (%s)", plugin, exc)
                continue

            for cve in wanted:
                if self.sampling and len(claimed) >= self.limit:
                    self.truncated = True
                    break

                found = self._rows_for_plugin(vuln, plugin, cve, info, outputs)
                if not found:
                    continue
                if self.sampling:
                    # Every host here reports the same CVE at the same severity,
                    # so the pick is deterministic rather than meaningful -- and
                    # the hosts it drops are counted, because "1 of 89 affected
                    # hosts" is the sort of thing a report must not hide.
                    found.sort(key=lambda row: str(row.get("host") or ""))
                    crowded_out += len(found) - 1
                    found = found[:1]
                    claimed.add(cve)
                rows.extend(found)

        self.plugins_seen = len(summary)
        self.plugins_examined = examined
        self.plugins_without_cve = skipped_no_cve
        self.plugins_below_min_cvss = below_floor
        self.duplicate_cves_skipped = duplicates
        self.hosts_not_sampled = crowded_out
        log.info(
            "Tenable: %d plugin(s), %d examined, %d without a CVE, %d below CVSS %.1f, "
            "%d duplicate CVE(s), %d row(s)%s",
            len(summary), examined, skipped_no_cve, self.min_cvss, duplicates, len(rows),
            f" (sampled to {self.limit})" if self.truncated else "",
        )
        return rows

    def _meets_floor(self, cvss: float | None, severity: int) -> bool:
        """Is this plugin severe enough to sample?

        A plugin with no CVSS at all falls back to the band its severity implies
        -- the same table the normalizer uses downstream. Dropping unscored rows
        instead would quietly discard Criticals for the crime of missing a field.
        """
        if not self.min_cvss:
            return True
        if cvss is None:
            cvss = SEVERITY_TO_CVSS.get(severity, 0.0)
        return cvss >= self.min_cvss

    def _rows_for_plugin(
        self,
        vuln: dict[str, Any],
        plugin_id: Any,
        cve: str,
        info: dict[str, Any],
        outputs: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """One row per affected host, for a single CVE.

        Emitting one CVE per row rather than the plugin's whole list is what makes
        the cap mean what it says: the normalizer splits a multi-CVE row into one
        finding per CVE, so a 20-row cap on multi-CVE rows would have handed
        enrichment 80 lookups.
        """
        plugin_name = (
            vuln.get("plugin_name")
            or ((info.get("plugin_details") or {}).get("name"))
            or ""
        )
        severity = _severity_id(vuln.get("severity", info.get("severity")))
        cvss = _effective_cvss(vuln, info)

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
                                cves=[cve],
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


def _by_severity(summary: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The workbench, most severe first.

    Tenable returns it in plugin order, which is why an unsorted cap kept 20 hosts
    carrying one ICMP timestamp disclosure. Ties break on the summary's CVSS and
    then on plugin id, so the sample is reproducible run to run -- a demo that
    reshuffles its findings between runs is not a demo of anything.
    """
    return sorted(
        summary,
        key=lambda vuln: (
            -_severity_id(vuln.get("severity")),
            -(_first_float(vuln.get("cvss3_base_score"), vuln.get("cvss_base_score")) or 0.0),
            str(vuln.get("plugin_id") or ""),
        ),
    )


def _effective_cvss(vuln: dict[str, Any], info: dict[str, Any]) -> float | None:
    """The best CVSS available, v3 before v2 and `/info` before the summary."""
    risk = info.get("risk_information") or {}
    return _first_float(
        risk.get("cvss3_base_score"),
        vuln.get("cvss3_base_score"),
        risk.get("cvss_base_score"),
        vuln.get("cvss_base_score"),
    )


def _coerce_limit(value: Any) -> int | None:
    """Normalize a cap: a positive int, or None for "no cap".

    0, a negative number and anything unparseable all mean uncapped, so a bad
    value can never turn a live pull into a silent zero-finding run.
    """
    if value is None:
        return None
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return None
    return limit if limit > 0 else None


def _coerce_min_cvss(value: Any) -> float:
    """Normalize the sampling floor: 0.0 means no floor.

    An unparseable value falls back to the default rather than to 0.0 -- a typo
    should not silently pull the whole informational tail of the workbench.
    """
    if value is None:
        return 0.0
    try:
        floor = float(value)
    except (TypeError, ValueError):
        return DEFAULT_MIN_CVSS
    return max(0.0, floor)


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
