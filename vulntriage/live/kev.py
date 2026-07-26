"""CISA Known Exploited Vulnerabilities.

One public JSON file, no auth, no rate limit -- the cheapest high-value feed on
the list, which is why the spec builds it first.

KEV membership is the strongest single signal in the risk model: CISA only lists
CVEs with *confirmed* in-the-wild exploitation, so it floors the exploit weight
rather than averaging into it. The feed also carries the ransomware-campaign
flag and the date CISA added the CVE, both of which the report already renders.
"""

from __future__ import annotations

import logging
from typing import Any

from .cache import Cache
from .http import LiveFetchError, get_json

log = logging.getLogger("vulntriage.live")

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# The catalogue is republished daily; a few hours of staleness is harmless.
KEV_TTL_SECONDS = 12 * 60 * 60


class KevEntry:
    """One KEV catalogue row, reduced to the fields the risk model uses."""

    __slots__ = ("cve", "date_added", "ransomware", "name", "due_date")

    def __init__(self, cve: str, date_added: str | None, ransomware: bool,
                 name: str | None = None, due_date: str | None = None) -> None:
        self.cve = cve
        self.date_added = date_added
        self.ransomware = ransomware
        self.name = name
        self.due_date = due_date

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "date_added": self.date_added,
            "ransomware": self.ransomware,
            "name": self.name,
            "due_date": self.due_date,
        }


class KevClient:
    """Downloads the KEV catalogue once and answers membership questions."""

    def __init__(
        self,
        url: str = KEV_FEED_URL,
        cache: Cache | None = None,
        fetch=get_json,
    ) -> None:
        self.url = url
        self.cache = cache if cache is not None else Cache("kev", ttl_seconds=KEV_TTL_SECONDS)
        self._fetch = fetch
        self._entries: dict[str, KevEntry] | None = None
        self.available = False
        self.error: str | None = None

    # -- loading ------------------------------------------------------------
    def load(self) -> bool:
        """Fetch (or read from cache) the catalogue. Returns whether it is usable."""
        if self._entries is not None:
            return self.available

        cached = self.cache.get("catalog")
        if cached:
            self._entries = {
                cve: KevEntry(**row) for cve, row in cached.items()
            }
            self.available = True
            log.info("KEV: %d entries from cache", len(self._entries))
            return True

        try:
            payload = self._fetch(self.url)
        except LiveFetchError as exc:
            # Degrade: no KEV data means findings keep whatever the mock DB said.
            self._entries = {}
            self.available = False
            self.error = str(exc)
            log.warning("KEV unavailable, continuing without it: %s", exc)
            return False

        self._entries = self._parse(payload)
        self.available = True
        self.cache.set("catalog", {cve: e.as_dict() for cve, e in self._entries.items()})
        self.cache.save()
        log.info("KEV: %d entries from %s", len(self._entries), self.url)
        return True

    @staticmethod
    def _parse(payload: Any) -> dict[str, KevEntry]:
        entries: dict[str, KevEntry] = {}
        for row in (payload or {}).get("vulnerabilities", []) or []:
            cve = str(row.get("cveID") or "").strip().upper()
            if not cve:
                continue
            raw_ransomware = str(row.get("knownRansomwareCampaignUse") or "").strip().lower()
            entries[cve] = KevEntry(
                cve=cve,
                date_added=row.get("dateAdded"),
                # The feed uses the strings "Known" / "Unknown", not a boolean.
                ransomware=raw_ransomware == "known",
                name=row.get("vulnerabilityName"),
                due_date=row.get("dueDate"),
            )
        return entries

    # -- queries ------------------------------------------------------------
    def is_known_exploited(self, cve_id: str) -> bool:
        self.load()
        return (cve_id or "").strip().upper() in (self._entries or {})

    def entry(self, cve_id: str) -> KevEntry | None:
        self.load()
        return (self._entries or {}).get((cve_id or "").strip().upper())

    def __len__(self) -> int:
        self.load()
        return len(self._entries or {})
