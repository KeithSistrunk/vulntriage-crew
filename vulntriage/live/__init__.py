"""Live intel clients: CISA KEV, FIRST EPSS, NVD, and Tenable.

Why this is `vulntriage/live/` and not `vulntriage/tools/`, which is where the
integration spec puts these files: `tools/__init__.py` imports CrewAI, and
`pipeline.py` guarantees that the deterministic `--offline` path never does.
Putting an HTTP client in that package would make `import vulntriage.pipeline`
drag in CrewAI through the back door and break the offline promise. `tools/` is
for the agents' hands; this is infrastructure the pipeline calls directly.

The architecture rule from the spec holds: everything here fetches into the
state layer and is normalized there. Raw API JSON never reaches the LLM -- the
agents still only ever see `CVEContext`, `AssetContext` and the compact tool
summaries built from them.

Every client degrades rather than raising. A feed being down costs context, not
the run.
"""

from __future__ import annotations

import logging
from typing import Iterable

from ..models import CVEContext
from .cache import Cache
from .epss import EpssClient, EpssScore
from .http import LiveFetchError
from .kev import KevClient
from .nvd import NvdClient, NvdRecord
from .tenable import TenableAuthError, TenableClient

__all__ = [
    "Cache",
    "EpssClient",
    "EpssScore",
    "LiveFetchError",
    "KevClient",
    "LiveIntel",
    "NvdClient",
    "NvdRecord",
    "TenableAuthError",
    "TenableClient",
]

log = logging.getLogger("vulntriage.live")


class LiveIntel:
    """The three enrichment feeds behind one interface.

    `intel.py` calls `apply()` on each `CVEContext` it builds from the mock
    database. Live data overlays the mock rather than replacing it wholesale:
    NVD wins on CVSS and description because it is authoritative, KEV wins on
    exploited-in-the-wild because it is the only source that knows, and the
    mock's curated remediation guidance survives because no public feed carries
    "a POS terminal cannot reboot during trading hours".
    """

    def __init__(
        self,
        kev: KevClient | None = None,
        epss: EpssClient | None = None,
        nvd: NvdClient | None = None,
    ) -> None:
        """Takes clients, never builds them.

        `None` means *disabled*, not "construct a default". An earlier version
        auto-created the missing clients, which meant `LiveIntel(kev=stub)` in a
        test quietly built real EPSS and NVD clients and called out to the
        internet -- exactly what the spec forbids. Use `from_env()` to build the
        standard set.
        """
        self.kev = kev
        self.epss = epss
        self.nvd = nvd
        self.warnings: list[str] = []

    @classmethod
    def from_env(
        cls,
        use_kev: bool = True,
        use_epss: bool = True,
        use_nvd: bool = True,
        cache_enabled: bool = True,
    ) -> "LiveIntel":
        """The standard three clients, configured from environment variables."""
        from .epss import EPSS_TTL_SECONDS
        from .kev import KEV_TTL_SECONDS
        from .nvd import NVD_TTL_SECONDS

        def cache(name: str, ttl: int) -> Cache:
            return Cache(name, ttl_seconds=ttl, enabled=cache_enabled)

        return cls(
            kev=KevClient(cache=cache("kev", KEV_TTL_SECONDS)) if use_kev else None,
            epss=EpssClient(cache=cache("epss", EPSS_TTL_SECONDS)) if use_epss else None,
            nvd=NvdClient(cache=cache("nvd", NVD_TTL_SECONDS)) if use_nvd else None,
        )

    # -- lifecycle ----------------------------------------------------------
    def prime(self, cve_ids: Iterable[str]) -> None:
        """Do the batched work up front: one KEV download, batched EPSS, NVD per CVE."""
        ids = [c for c in dict.fromkeys((c or "").strip().upper() for c in cve_ids) if c]
        if not ids:
            return

        # `is not None` throughout, never truthiness: KevClient defines __len__,
        # so an empty catalogue makes `if self.kev` false and silently skips the
        # whole feed instead of clearing stale flags.
        if self.kev is not None:
            if self.kev.load():
                log.info("KEV catalogue: %d entries", len(self.kev))
            else:
                self._warn(f"CISA KEV unavailable ({self.kev.error}); KEV flags fall back to the local DB.")

        if self.epss is not None:
            self.epss.fetch_many(ids)
            if self.epss.error:
                self._warn(f"FIRST EPSS unavailable ({self.epss.error}); findings scored without EPSS.")

        if self.nvd is not None:
            self.nvd.fetch_many(ids)
            if self.nvd.error:
                self._warn(f"NVD unavailable ({self.nvd.error}); CVE detail falls back to the local DB.")
            elif not self.nvd.has_key:
                self._warn(
                    "NVD_API_KEY is not set - throttled to 5 requests/30s. Request a free key "
                    "at nvd.nist.gov to raise it to 50."
                )

    def _warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)
            log.warning(message)

    # -- overlay ------------------------------------------------------------
    def apply(self, intel: CVEContext) -> CVEContext:
        """Return `intel` with whatever live data is available folded in."""
        cve = intel.cve
        sources: list[str] = list(intel.intel_sources)

        record = self.nvd.fetch(cve) if self.nvd is not None else None
        if record:
            sources.append("NVD")
            # NVD is authoritative on the vulnerability itself.
            if record.cvss is not None:
                intel.cvss = record.cvss
                intel.cvss_severity = record.cvss_severity
                intel.cvss_vector = record.cvss_vector
            intel.description = record.description or intel.description
            intel.published = record.published or intel.published
            intel.cwe = record.cwe or intel.cwe
            intel.references = record.references or intel.references
            # A CVE NVD knows about is not an intel gap, even if our DB missed it.
            intel.known_cve = True

        entry = self.kev.entry(cve) if self.kev is not None else None
        if self.kev is not None and self.kev.available:
            sources.append("CISA KEV")
            # Authoritative in both directions: presence *and* absence.
            intel.kev = entry is not None
            if entry:
                intel.kev_date_added = entry.date_added or intel.kev_date_added
                intel.ransomware_campaign_use = entry.ransomware
                if intel.exploit_maturity in ("unknown", "none"):
                    intel.exploit_maturity = "weaponized"

        score = self.epss.get(cve) if self.epss is not None else None
        if score:
            sources.append("FIRST EPSS")
            intel.epss_score = score.score
            intel.epss_percentile = score.percentile

        intel.intel_sources = list(dict.fromkeys(sources))
        if intel.intel_sources and not intel.known_cve:
            # Something answered for this CVE, so it is no longer a total blank.
            intel.notes = (intel.notes or "") + " Live feeds returned partial data."
        return intel

    def summary(self) -> str:
        bits: list[str] = []
        if self.kev is not None:
            bits.append(f"KEV {len(self.kev)} entries" if self.kev.available else "KEV unavailable")
        if self.epss is not None:
            bits.append("EPSS unavailable" if self.epss.error else f"EPSS {self.epss.count} scored")
        if self.nvd is not None:
            bits.append(f"NVD {self.nvd.requests_made} request(s)")
        return ", ".join(bits) or "no live feeds enabled"
