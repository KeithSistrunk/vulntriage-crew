"""Tenable CSV export -- the same findings, from a file instead of the API.

`--source csv` exists because a Tenable CSV export is what people actually have.
Handing over an export costs nobody an API key, and it is the only way to triage
an estate you can no longer reach: an old scan, a customer's export, a scan run
by someone else entirely.

Why this subclasses `TenableClient` rather than parsing into findings directly:
the value of `--source tenable` is not the HTTP, it is the *sampling* -- drop
everything under the CVSS floor, keep each CVE once at the most severe plugin
reporting it, one host per CVE, stop at the cap. Reimplementing that here would
mean two copies of the rule that decides what a report covers, and they would
drift. So this class overrides only the three seams the sampling loop reads --
which plugins exist, what a plugin's CVEs and score are, which hosts report it --
and inherits the loop itself. A CSV pull is sampled by the same code, in the same
order, with the same counters, as a live one.

Nothing here is live and nothing here is HTTP, which makes `live/` an odd home
for it. It sits beside `tenable.py` anyway, because the thing it is coupled to is
that file's sampling loop, and `live/` imports no CrewAI -- so `--offline` still
runs on nothing but pydantic.

The columns read are the ones the API client already normalizes, under whichever
of Tenable's several spellings the export happens to use:

    CVE, CVSS3 Base Score, Risk, Host, FQDN, Name, Solution

plus the identity and evidence fields the normalizer needs downstream (IP, port,
protocol, service, plugin output, state, first/last found).
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import AssetContext
# One CVE pattern and one risk table for the whole project. A source that is
# stricter than the normalizer about what counts as a CVE drops findings the
# normalizer would have kept, with nothing anywhere to show for it.
from ..normalize import CVE_RE, RISK_TO_SEVERITY
from .http import LiveFetchError
from .tenable import (
    DEFAULT_FINDING_LIMIT,
    DEFAULT_MIN_CVSS,
    SEVERITY_NAMES,
    TenableClient,
    # Private to that module, imported rather than copied on purpose: both files
    # decide whether a name is really an address, and two copies of that rule
    # would eventually disagree about which findings are identified by IP.
    _looks_like_ip,
)

log = logging.getLogger("vulntriage.live")


class CsvSourceError(LiveFetchError):
    """The export could not be read.

    A `LiveFetchError` subclass so that `main.py` -- which already treats a
    findings source failing as fatal, and an intel feed failing as not -- catches
    it without learning about a new exception type.
    """


# Tenable spells its columns differently depending on which product and which
# export dialog produced the file. Every alias seen in the wild is listed; the
# first one present in the row wins.
COLUMNS: dict[str, tuple[str, ...]] = {
    "plugin_id": ("Plugin ID", "Plugin", "PluginID"),
    "plugin_name": ("Name", "Plugin Name", "Synopsis"),
    "cve": ("CVE", "CVEs", "CVE ID"),
    "cvss3": (
        "CVSS3 Base Score", "CVSS v3.0 Base Score", "CVSS v3 Base Score",
        "CVSS V3 Base Score", "CVSS3", "CVSS3 Score",
    ),
    "cvss2": ("CVSS", "CVSS Base Score", "CVSS v2.0 Base Score", "CVSS2 Base Score"),
    "risk": ("Risk", "Risk Factor"),
    "severity": ("Severity",),
    "host": ("Host", "DNS Name", "Asset Name", "NetBios"),
    "fqdn": ("FQDN", "DNS Name"),
    "netbios": ("NetBios", "NetBIOS", "NetBIOS Name"),
    "ip": ("IP Address", "IP", "Host IP", "IPv4 Address"),
    "port": ("Port",),
    "protocol": ("Protocol",),
    "service": ("Service", "Service Name", "Application Protocol"),
    "solution": ("Solution", "Steps to Remediate"),
    "output": ("Plugin Output", "Output"),
    "state": ("Vulnerability State", "State", "Status"),
    "first_found": ("First Found", "First Seen", "First Discovered"),
    "last_found": ("Last Found", "Last Seen", "Last Observed"),
    "os": ("OS", "Operating System"),
}

# Tenable's vulnerability-state vocabulary mapped onto the normalizer's, which is
# the Nessus one. Only the mapping matters, not the spelling: "Resurfaced" is an
# open finding and must not be read as remediated, and "Fixed" must not be read
# as open. Anything unrecognized passes through unchanged, so the normalizer
# records the drop and names the state rather than this file guessing.
STATES = {
    "new": "new",
    "active": "active",
    "resurfaced": "reopened",
    "reopened": "reopened",
    "open": "open",
    "fixed": "fixed",
    "closed": "fixed",
    "remediated": "fixed",
}


@dataclass
class _Row:
    """One CSV row, parsed into the fields the pipeline actually reads."""

    plugin_id: str
    plugin_name: str
    severity: int
    cves: list[str]
    cvss3: float | None
    cvss2: float | None
    solution: str | None
    asset: dict[str, Any]
    port: Any
    protocol: str | None
    service: str | None
    state: str
    evidence: str | None


@dataclass
class _Plugin:
    """Every row a plugin produced, plus the summary the sampling loop reads.

    The aggregate takes the *worst* severity and the *highest* score across the
    plugin's rows. An export that disagrees with itself between two rows of the
    same plugin should be sampled on the more severe reading, never the milder.
    """

    plugin_id: str
    plugin_name: str = ""
    severity: int = 0
    cvss3: float | None = None
    cvss2: float | None = None
    solution: str | None = None
    cves: list[str] = field(default_factory=list)
    rows: list[_Row] = field(default_factory=list)

    def add(self, row: _Row) -> None:
        self.plugin_name = self.plugin_name or row.plugin_name
        self.severity = max(self.severity, row.severity)
        self.cvss3 = _max_score(self.cvss3, row.cvss3)
        self.cvss2 = _max_score(self.cvss2, row.cvss2)
        self.solution = self.solution or row.solution
        for cve in row.cves:
            if cve not in self.cves:
                self.cves.append(cve)
        self.rows.append(row)

    @property
    def hosts(self) -> int:
        return len({str(r.asset.get("key") or "") for r in self.rows})

    def summary(self) -> dict[str, Any]:
        """The plugin as the sampling loop expects to see it.

        Deliberately the workbench's summary shape, not a shape of its own: the
        loop sorts on `severity` and `cvss3_base_score`, and `_by_severity` is
        what makes stopping at the cap safe.
        """
        return {
            "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name,
            "severity": self.severity,
            "severity_name": SEVERITY_NAMES.get(self.severity, "Info"),
            "cvss3_base_score": self.cvss3,
            "cvss_base_score": self.cvss2,
            "cve": list(self.cves),
            "count": self.hosts,
        }

    def info(self) -> dict[str, Any]:
        """The plugin detail, in the `/info` shape `_cves_from_info` parses."""
        return {
            "severity": self.severity,
            "plugin_details": {"name": self.plugin_name},
            "reference_information": [{"name": "cve", "values": list(self.cves)}],
            "risk_information": {
                "cvss3_base_score": self.cvss3,
                "cvss_base_score": self.cvss2,
            },
        }

    def outputs(self) -> list[dict[str, Any]]:
        """The plugin's rows, in the `/outputs` shape `_rows_for_plugin` walks.

        One output per *instance* -- host, port, state -- not per CSV row. A
        Tenable export writes one row per (plugin, CVE), so a plugin reporting
        four CVEs on one host is four rows describing one instance. Left as four
        outputs, `_rows_for_plugin` would build four identical rows for every CVE
        and the sampling would report three affected hosts that do not exist.

        The workbench's own `/outputs` is already grouped this way -- an output
        carries hosts and ports, never CVEs -- so collapsing here is what makes
        the two sources the same shape, not a special case for this one.
        """
        instances: dict[tuple, _Row] = {}
        for row in self.rows:
            key = (row.asset.get("key"), row.port, row.protocol, row.service, row.state)
            seen = instances.get(key)
            # Same instance seen twice: keep whichever row explains it best.
            if seen is None or len(row.evidence or "") > len(seen.evidence or ""):
                instances[key] = row

        return [
            {
                "plugin_output": row.evidence,
                "states": [
                    {
                        "name": row.state,
                        "results": [
                            {
                                "port": row.port,
                                "transport_protocol": row.protocol,
                                "application_protocol": row.service,
                                "assets": [row.asset],
                            }
                        ],
                    }
                ],
            }
            for row in instances.values()
        ]


class TenableCsvClient(TenableClient):
    """A Tenable CSV export, sampled exactly as a live pull is.

    Everything the base class does with three HTTP calls per plugin, this does
    with one pass over the file. The three seams are overridden; the sampling
    loop, the row shape, the normalizer and the risk model are untouched.
    """

    def __init__(
        self,
        path: str | Path,
        limit: int | None = DEFAULT_FINDING_LIMIT,
        min_cvss: float | None = DEFAULT_MIN_CVSS,
    ) -> None:
        # Credentials are explicitly empty rather than read from the environment:
        # a file source must not authenticate, and a stray TENABLE_ACCESS_KEY in
        # the shell must not make it look as though it had.
        super().__init__(
            access_key="",
            secret_key="",
            limit=limit,
            min_cvss=min_cvss,
            scan_id=None,
            fetch=_no_network,
        )
        self.path = Path(path)
        self.flavor = "csv"
        self._plugins: dict[str, _Plugin] | None = None
        self._rows_read = 0

    # -- identity -----------------------------------------------------------
    @property
    def configured(self) -> bool:
        """A readable file is this source's whole credential."""
        return self.path.is_file()

    @property
    def pool(self) -> str:
        return f"export {self.path.name}"

    @property
    def source_label(self) -> str:
        return str(self.path)

    @property
    def source_format(self) -> str:
        return "csv"

    # -- parsing ------------------------------------------------------------
    def _load(self) -> dict[str, _Plugin]:
        """Parse the export once, grouped by plugin. Raises `CsvSourceError`.

        Grouping by plugin is not an optimization -- it is what makes this file a
        drop-in for the API client. The sampling loop is written against a plugin
        summary, and a CSV row is a plugin *instance*, so the two have to be
        folded back together before the loop can see them.
        """
        if self._plugins is not None:
            return self._plugins

        if not self.path.is_file():
            raise CsvSourceError(f"CSV export not found: {self.path}")

        try:
            with self.path.open(newline="", encoding="utf-8-sig") as handle:
                reader = csv.DictReader(handle)
                headers = reader.fieldnames or []
                if not _looks_like_tenable(headers):
                    raise CsvSourceError(
                        f"{self.path.name} does not look like a Tenable export: no "
                        f"'Plugin ID' or 'CVE' column. Columns found: "
                        f"{', '.join(headers[:8]) or 'none'}."
                    )
                raw_rows = list(reader)
        except OSError as exc:
            raise CsvSourceError(f"Could not read {self.path}: {exc}") from exc
        except csv.Error as exc:
            raise CsvSourceError(f"Malformed CSV in {self.path}: {exc}") from exc

        plugins: dict[str, _Plugin] = {}
        for raw in raw_rows:
            row = _parse_row(raw)
            if row is None:
                continue
            plugins.setdefault(row.plugin_id, _Plugin(row.plugin_id)).add(row)

        self._rows_read = len(raw_rows)
        self._plugins = plugins
        log.info(
            "Tenable CSV %s: %d row(s), %d plugin(s)",
            self.path.name, len(raw_rows), len(plugins),
        )
        return plugins

    # -- source dispatch ----------------------------------------------------
    #
    # The same three seams scan mode overrides. Answering them from the file is
    # the entire integration; everything else is inherited.

    def _plugin_summary(self) -> list[dict[str, Any]]:
        return [plugin.summary() for plugin in self._load().values()]

    def _plugin_info(self, plugin_id: Any) -> dict[str, Any]:
        plugin = self._load().get(str(plugin_id))
        return plugin.info() if plugin else {}

    def _plugin_outputs(self, plugin_id: Any) -> list[dict[str, Any]]:
        plugin = self._load().get(str(plugin_id))
        return plugin.outputs() if plugin else []

    # -- findings -----------------------------------------------------------
    def fetch_findings(self, progress=None) -> list[dict[str, Any]]:
        """The sampled rows, with the export's own remediation text attached.

        `Solution` has no home in the API client's row -- the workbench does not
        return one -- so it is folded in here rather than by widening a shape two
        sources share. The normalizer carries it through to the report, where it
        stands in for vendor guidance the local intel database does not have.
        """
        rows = super().fetch_findings(progress)
        plugins = self._load()
        for row in rows:
            plugin = plugins.get(str(row.get("plugin_id")))
            if plugin and plugin.solution:
                row["solution"] = plugin.solution
        return rows

    # -- assets -------------------------------------------------------------
    def fetch_asset_contexts(self) -> dict[str, AssetContext]:
        """Host identity from the export, indexed the way enrichment looks it up.

        A CSV export carries no Asset Criticality Rating, so unlike the API path
        this cannot supply criticality -- and it does not pretend to.
        `known_asset` stays False so the finding is still flagged as an intel gap
        and remediation still says "identify the owner first", which is the
        truth: the scanner seeing a host is not the same as the business knowing
        who owns it. What it does supply is identity and OS, so findings still
        reconcile across FQDN, NetBIOS name and IP.
        """
        try:
            plugins = self._load()
        except CsvSourceError as exc:
            log.warning("Tenable CSV asset context unavailable (%s); continuing", exc)
            self.error = str(exc)
            return {}

        index: dict[str, AssetContext] = {}
        for plugin in plugins.values():
            for row in plugin.rows:
                asset = row.asset
                fqdn = asset.get("fqdn")
                hostname = asset.get("hostname") or (fqdn.split(".")[0] if fqdn else None)
                ip = asset.get("ipv4")
                name = hostname or fqdn or ip
                if not name:
                    continue
                context = AssetContext(
                    hostname=str(name),
                    fqdn=fqdn,
                    known_asset=False,
                    os=asset.get("os"),
                    criticality="unknown",
                    internet_facing=False,
                    notes=(
                        "Seen in a Tenable CSV export, which carries no asset criticality "
                        "rating and no ownership. Scored at the neutral asset weight; "
                        "confirm the owner and business criticality before scheduling work."
                    ),
                )
                for key in (fqdn, hostname, ip, name):
                    if key:
                        index.setdefault(str(key).strip().lower(), context)
        return index

    # -- reporting ----------------------------------------------------------
    @property
    def rows_read(self) -> int:
        """Raw rows in the export, for the run summary. 0 until it is parsed."""
        return self._rows_read


# --------------------------------------------------------------------------- #
# parsing helpers
# --------------------------------------------------------------------------- #

def _no_network(*args: Any, **kwargs: Any) -> Any:
    """The fetch a file-backed client must never call.

    Injected instead of the real `get_json` so that a missed override fails
    loudly here rather than quietly reaching for the network with no credentials.
    """
    raise CsvSourceError(
        "A CSV export source must not make HTTP calls. This is a bug: a plugin "
        "lookup fell through to the live Tenable client."
    )


def _looks_like_tenable(headers: list[str]) -> bool:
    """Cheap sanity check, so a wrong file fails with a sentence not a stack."""
    present = {h.strip().lower() for h in headers if h}
    return bool(present & {"plugin id", "plugin"}) or "cve" in present


def _cell(row: dict[str, Any], key: str) -> str:
    """The first populated column among that field's known spellings."""
    for name in COLUMNS.get(key, ()):
        value = row.get(name)
        if value not in (None, ""):
            text = str(value).strip()
            if text:
                return text
    return ""


def _parse_row(raw: dict[str, Any]) -> _Row | None:
    """One CSV row -> `_Row`, or None if there is no plugin to hang it on."""
    plugin_id = _cell(raw, "plugin_id")
    if not plugin_id:
        return None

    risk = _cell(raw, "risk")
    fqdn = _cell(raw, "fqdn") or None
    host = _cell(raw, "host") or None
    netbios = _cell(raw, "netbios") or None
    ip = _cell(raw, "ip") or None

    # `host` in a Tenable export is whatever the scan targeted -- an FQDN, a
    # NetBIOS name or an address. It is only promoted to FQDN when it actually
    # looks like one, because `_split_host` downstream reads a dotted name as a
    # domain and an address as an address.
    if not fqdn and host and "." in host and not _looks_like_ip(host):
        fqdn = host
    if not ip and host and _looks_like_ip(host):
        ip = host
    hostname = netbios or (host if host and not _looks_like_ip(host) else None)

    asset = {
        "fqdn": fqdn,
        "hostname": hostname,
        "ipv4": ip,
        "os": _cell(raw, "os") or None,
        "first_seen": _cell(raw, "first_found") or None,
        "last_seen": _cell(raw, "last_found") or None,
        # Identity for the per-plugin host count. Not read by `_row`.
        "key": (fqdn or hostname or ip or "").strip().lower(),
    }

    state = _cell(raw, "state").strip().lower()
    return _Row(
        plugin_id=plugin_id,
        plugin_name=_cell(raw, "plugin_name"),
        severity=_severity(raw, risk),
        cves=_cves(_cell(raw, "cve")),
        cvss3=_to_float(_cell(raw, "cvss3")),
        cvss2=_to_float(_cell(raw, "cvss2")),
        solution=_cell(raw, "solution") or None,
        asset=asset,
        port=_cell(raw, "port") or None,
        protocol=_cell(raw, "protocol") or None,
        service=_cell(raw, "service") or None,
        state=STATES.get(state, state or "open"),
        evidence=_cell(raw, "output") or None,
    )


def _severity(raw: dict[str, Any], risk: str) -> int:
    """The Nessus 0-4 severity, from whichever column carries it.

    `Severity` is numeric in a Tenable.io export and a word in others, and `Risk`
    is a word in both. Both are read, the numeric one first, so neither dialect
    silently lands every finding at Info.
    """
    severity = _cell(raw, "severity")
    if severity:
        try:
            return max(0, min(4, int(float(severity))))
        except (TypeError, ValueError):
            band = RISK_TO_SEVERITY.get(severity.strip().lower())
            if band is not None:
                return band
    return RISK_TO_SEVERITY.get(risk.strip().lower(), 0)


def _cves(cell: str) -> list[str]:
    """Every CVE id in the cell. One row can carry several, comma separated."""
    return list(dict.fromkeys(match.upper() for match in CVE_RE.findall(cell or "")))


def _to_float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _max_score(current: float | None, candidate: float | None) -> float | None:
    if candidate is None:
        return current
    if current is None:
        return candidate
    return max(current, candidate)
