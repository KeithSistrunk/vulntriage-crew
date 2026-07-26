"""Cache for live intel lookups.

Two jobs, and the second is the one that matters most here:

1. Stay inside NVD's rate limit. A re-run over the same findings should cost
   zero API calls, not another 18 of them.
2. Keep a run reproducible. A triage report that ranks differently because a
   feed was refreshed halfway through is not something an analyst can argue
   with, which is the whole point of `ScoreBreakdown`.

In-memory is authoritative for the life of a run. The on-disk copy is the part
that survives between runs; it is keyed by client and entry, carries a TTL, and
is written under `.cache/` (gitignored). A corrupt or unreadable cache file is
treated as an empty one -- never as a failure.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("vulntriage.live")

DEFAULT_CACHE_DIR = Path(__file__).resolve().parent.parent.parent / ".cache"

# CVE records barely change; KEV and EPSS move daily. Callers override per client.
DEFAULT_TTL_SECONDS = 24 * 60 * 60


class Cache:
    """A namespaced, TTL'd key/value store backed by one JSON file."""

    def __init__(
        self,
        namespace: str,
        directory: Path | str | None = DEFAULT_CACHE_DIR,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        enabled: bool = True,
    ) -> None:
        self.namespace = namespace
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled
        self.directory = Path(directory) if directory else None
        self._entries: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self.hits = 0
        self.misses = 0
        if self.enabled and self.directory:
            self._load()

    @property
    def path(self) -> Path | None:
        return self.directory / f"{self.namespace}.json" if self.directory else None

    def _load(self) -> None:
        path = self.path
        if not path or not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            entries = payload.get("entries", {})
            if isinstance(entries, dict):
                self._entries = entries
        except (OSError, json.JSONDecodeError) as exc:
            # A cache is an optimization. A broken one is an empty one.
            log.warning("ignoring unreadable cache %s: %s", path, exc)
            self._entries = {}

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        entry = self._entries.get(key)
        if not entry:
            self.misses += 1
            return None
        if self.ttl_seconds and (time.time() - entry.get("at", 0)) > self.ttl_seconds:
            self.misses += 1
            return None
        self.hits += 1
        return entry.get("value")

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        self._entries[key] = {"at": time.time(), "value": value}
        self._dirty = True

    def save(self) -> None:
        """Flush to disk. Failing to write a cache never fails a run."""
        path = self.path
        if not self.enabled or not path or not self._dirty:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"namespace": self.namespace, "entries": self._entries}, indent=2),
                encoding="utf-8",
            )
            self._dirty = False
        except OSError as exc:
            log.warning("could not write cache %s: %s", path, exc)

    def stats(self) -> str:
        return f"{self.namespace}: {self.hits} hit(s), {self.misses} miss(es)"
