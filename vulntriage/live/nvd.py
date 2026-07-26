"""NVD 2.0 -- authoritative CVE detail.

The rate limit is the whole design constraint here: 5 requests per 30 seconds
without an API key, 50 with one. That is 6 seconds between calls unkeyed, so an
18-finding run takes nearly two minutes of pure waiting if nothing is cached.

Hence: cache first, sleep only when a request is actually going out, and read
the key from the environment. A run over findings already seen costs nothing.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from .cache import Cache
from .http import LiveFetchError, get_json

log = logging.getLogger("vulntriage.live")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVE records change rarely; a week is comfortably safe and saves a lot of calls.
NVD_TTL_SECONDS = 7 * 24 * 60 * 60

# Published limits are 5/30s unkeyed and 50/30s keyed. Leave headroom on both --
# NVD returns 403s rather than 429s when it thinks you are abusing it.
DELAY_WITHOUT_KEY = 6.5
DELAY_WITH_KEY = 0.7


NVD_SOURCE = "nvd@nist.gov"


def _preferred_metric(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick which CVSS reading to believe when NVD returns several.

    A CVE can carry a score from its CNA *and* one from NVD's own analysts, and
    they can disagree sharply. CVE-2020-1472 (Zerologon) is the case that forced
    this: Microsoft scores it 5.5, NVD scores it 10.0, and Microsoft's entry is
    returned first. Taking the first one halves Zerologon's risk score and drops
    it from second in the queue to fifteenth -- the single most dangerous
    finding in the sample set, reported as mid-tier.

    So: prefer NVD's own analysis, then anything marked Primary, then whatever
    is there. Note that NVD's entry is not always flagged Primary (it is
    Secondary for Zerologon), so the source check has to come first.
    """
    scored = [e for e in entries if (e.get("cvssData") or {}).get("baseScore") is not None]
    if not scored:
        return None
    for entry in scored:
        if (entry.get("source") or "").lower() == NVD_SOURCE:
            return entry
    for entry in scored:
        if (entry.get("type") or "").lower() == "primary":
            return entry
    return scored[0]


class NvdRecord:
    """One CVE, reduced to the fields enrichment consumes."""

    __slots__ = (
        "cve", "description", "cvss", "cvss_severity", "cvss_vector",
        "cwe", "published", "modified", "references",
    )

    def __init__(
        self,
        cve: str,
        description: str | None = None,
        cvss: float | None = None,
        cvss_severity: str | None = None,
        cvss_vector: str | None = None,
        cwe: str | None = None,
        published: str | None = None,
        modified: str | None = None,
        references: list[str] | None = None,
    ) -> None:
        self.cve = cve
        self.description = description
        self.cvss = cvss
        self.cvss_severity = cvss_severity
        self.cvss_vector = cvss_vector
        self.cwe = cwe
        self.published = published
        self.modified = modified
        self.references = references or []

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "description": self.description,
            "cvss": self.cvss,
            "cvss_severity": self.cvss_severity,
            "cvss_vector": self.cvss_vector,
            "cwe": self.cwe,
            "published": self.published,
            "modified": self.modified,
            "references": self.references,
        }


class NvdClient:
    """Per-CVE NVD lookup with caching and rate-limit pacing."""

    def __init__(
        self,
        url: str = NVD_API_URL,
        api_key: str | None = None,
        cache: Cache | None = None,
        fetch=get_json,
        sleep=time.sleep,
    ) -> None:
        self.url = url
        # None means "read the environment"; "" means "explicitly unkeyed", so a
        # test for the throttled path cannot accidentally use a real key.
        if api_key is None:
            api_key = os.getenv("NVD_API_KEY")
        self.api_key = api_key or None
        self.cache = cache if cache is not None else Cache("nvd", ttl_seconds=NVD_TTL_SECONDS)
        self._fetch = fetch
        self._sleep = sleep
        self.delay = DELAY_WITH_KEY if self.api_key else DELAY_WITHOUT_KEY
        self._records: dict[str, NvdRecord] = {}
        self._last_call: float | None = None
        self.requests_made = 0
        self.error: str | None = None

    @property
    def has_key(self) -> bool:
        return bool(self.api_key)

    def _pace(self) -> None:
        """Sleep only as long as the rate limit actually requires."""
        if self._last_call is None:
            return
        elapsed = time.monotonic() - self._last_call
        remaining = self.delay - elapsed
        if remaining > 0:
            self._sleep(remaining)

    def fetch(self, cve_id: str) -> NvdRecord | None:
        cve = (cve_id or "").strip().upper()
        if not cve:
            return None
        if cve in self._records:
            return self._records[cve]

        cached = self.cache.get(cve)
        if cached is not None:
            if not cached:
                return None  # cached miss
            record = NvdRecord(**cached)
            self._records[cve] = record
            return record

        headers = {"apiKey": self.api_key} if self.api_key else {}
        self._pace()
        try:
            payload = self._fetch(self.url, headers=headers, params={"cveId": cve})
        except LiveFetchError as exc:
            self.error = str(exc)
            log.warning("NVD lookup failed for %s, continuing without: %s", cve, exc)
            return None
        finally:
            self._last_call = time.monotonic()
            self.requests_made += 1

        record = self._parse(cve, payload)
        if record is None:
            self.cache.set(cve, {})
            return None
        self._records[cve] = record
        self.cache.set(cve, record.as_dict())
        return record

    def fetch_many(self, cve_ids: Any) -> dict[str, NvdRecord]:
        out: dict[str, NvdRecord] = {}
        for cve in dict.fromkeys(c.strip().upper() for c in cve_ids if c and c.strip()):
            record = self.fetch(cve)
            if record:
                out[cve] = record
        self.cache.save()
        return out

    @staticmethod
    def _parse(cve: str, payload: Any) -> NvdRecord | None:
        vulns = (payload or {}).get("vulnerabilities") or []
        if not vulns:
            return None
        item = (vulns[0] or {}).get("cve") or {}

        description = None
        for entry in item.get("descriptions") or []:
            if entry.get("lang") == "en":
                description = entry.get("value")
                break

        # Prefer v3.1, fall back to v3.0. v2 is left alone: mixing scoring
        # systems in one column is how a "CVSS 7.5" stops meaning anything.
        cvss = cvss_severity = cvss_vector = None
        metrics = item.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30"):
            metric = _preferred_metric(metrics.get(key) or [])
            if metric is None:
                continue
            data = metric.get("cvssData") or {}
            cvss = float(data["baseScore"])
            cvss_severity = (data.get("baseSeverity") or "").title() or None
            cvss_vector = data.get("vectorString")
            break

        cwe = None
        for weakness in item.get("weaknesses") or []:
            for entry in weakness.get("description") or []:
                value = entry.get("value") or ""
                if value.startswith("CWE-"):
                    cwe = value
                    break
            if cwe:
                break

        references = [
            ref.get("url") for ref in (item.get("references") or []) if ref.get("url")
        ][:8]

        return NvdRecord(
            cve=cve,
            description=description,
            cvss=cvss,
            cvss_severity=cvss_severity,
            cvss_vector=cvss_vector,
            cwe=cwe,
            published=item.get("published"),
            modified=item.get("lastModified"),
            references=references,
        )
