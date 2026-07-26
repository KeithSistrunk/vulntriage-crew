"""FIRST EPSS -- probability a CVE will be exploited in the next 30 days.

Public, no auth, and it batches: one call takes a comma-separated list of CVEs,
so the whole finding set costs a handful of requests rather than one per CVE.

EPSS is a *probability*, not a severity, and the two must not be conflated. A
0.97 EPSS on a CVSS 4.3 does not make it a critical vulnerability; it makes it
one that is about to be attacked. The curve that turns a probability into a
multiplier lives in `scoring.py`, deliberately, where the rest of the risk model
can be read alongside it.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from .cache import Cache
from .http import LiveFetchError, get_json

log = logging.getLogger("vulntriage.live")

EPSS_API_URL = "https://api.first.org/data/v1/epss"

# EPSS is recomputed daily.
EPSS_TTL_SECONDS = 12 * 60 * 60

# The API accepts a comma-separated list; keep the URL a sane length.
EPSS_BATCH_SIZE = 50


class EpssScore:
    """One EPSS reading."""

    __slots__ = ("cve", "score", "percentile", "date")

    def __init__(self, cve: str, score: float, percentile: float | None = None,
                 date: str | None = None) -> None:
        self.cve = cve
        self.score = score
        self.percentile = percentile
        self.date = date

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "score": self.score,
            "percentile": self.percentile,
            "date": self.date,
        }


class EpssClient:
    """Batch EPSS lookup with a per-CVE cache."""

    def __init__(
        self,
        url: str = EPSS_API_URL,
        cache: Cache | None = None,
        batch_size: int = EPSS_BATCH_SIZE,
        fetch=get_json,
    ) -> None:
        self.url = url
        self.cache = cache if cache is not None else Cache("epss", ttl_seconds=EPSS_TTL_SECONDS)
        self.batch_size = max(1, batch_size)
        self._fetch = fetch
        self._scores: dict[str, EpssScore] = {}
        self.error: str | None = None

    def fetch_many(self, cve_ids: Iterable[str]) -> dict[str, EpssScore]:
        """Look up every CVE, using the cache first and batching the remainder.

        A CVE with no EPSS row is a normal outcome (very new or very old CVEs
        often have none) and is simply absent from the result.
        """
        wanted = [c.strip().upper() for c in cve_ids if c and c.strip()]
        unique = list(dict.fromkeys(wanted))
        missing: list[str] = []

        for cve in unique:
            if cve in self._scores:
                continue
            cached = self.cache.get(cve)
            if cached is not None:
                # A cached miss is stored as {} so we do not re-ask every run.
                if cached:
                    self._scores[cve] = EpssScore(**cached)
                continue
            missing.append(cve)

        for start in range(0, len(missing), self.batch_size):
            batch = missing[start : start + self.batch_size]
            self._fetch_batch(batch)

        self.cache.save()
        return {cve: self._scores[cve] for cve in unique if cve in self._scores}

    def _fetch_batch(self, batch: list[str]) -> None:
        try:
            payload = self._fetch(self.url, params={"cve": ",".join(batch)})
        except LiveFetchError as exc:
            # Degrade: findings simply carry no EPSS and score as they did before.
            self.error = str(exc)
            log.warning("EPSS unavailable for %d CVE(s), continuing without: %s", len(batch), exc)
            return

        returned: set[str] = set()
        for row in (payload or {}).get("data", []) or []:
            cve = str(row.get("cve") or "").strip().upper()
            if not cve:
                continue
            try:
                score = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
            percentile: float | None
            try:
                percentile = float(row.get("percentile"))
            except (TypeError, ValueError):
                percentile = None

            entry = EpssScore(cve=cve, score=score, percentile=percentile, date=row.get("date"))
            self._scores[cve] = entry
            self.cache.set(cve, entry.as_dict())
            returned.add(cve)

        # Record the misses too, so a CVE with no EPSS row is not re-requested
        # on every run for the life of the cache.
        for cve in batch:
            if cve not in returned:
                self.cache.set(cve, {})

    def get(self, cve_id: str) -> EpssScore | None:
        return self._scores.get((cve_id or "").strip().upper())

    @property
    def count(self) -> int:
        """How many CVEs actually came back with a score."""
        return len(self._scores)
