"""Shared HTTP plumbing for the live intel clients.

`urllib` rather than `requests` on purpose: the deterministic pipeline is meant
to run with nothing but pydantic installed, and a live client that drags in a
new hard dependency would quietly break that promise. urllib is stdlib.

Every fetch here either returns parsed JSON or raises `LiveFetchError`. Callers
catch it and degrade -- an intel feed being down is a reason to score a finding
with less context, never a reason to lose the run.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

log = logging.getLogger("vulntriage.live")

USER_AGENT = "vulntriage-crew/1.0 (+https://github.com/KeithSistrunk/vulntriage-crew)"

DEFAULT_TIMEOUT = 20.0
DEFAULT_RETRIES = 2


class LiveFetchError(RuntimeError):
    """A live feed could not be read. Always recoverable by degrading."""


def get_json(
    url: str,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    backoff: float = 2.0,
) -> Any:
    """GET a JSON document, retrying transient failures.

    Retries 429 and 5xx with a widening delay; 4xx other than 429 fails straight
    away, because a bad key or a malformed CVE id will not fix itself.
    """
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"

    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    request_headers.update(headers or {})

    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=request_headers, method="GET")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))

        except urllib.error.HTTPError as exc:
            last = exc
            retryable = exc.code == 429 or exc.code >= 500
            if not retryable or attempt == retries:
                raise LiveFetchError(f"{url} returned HTTP {exc.code} {exc.reason}") from exc
            # 429 usually carries Retry-After; honour it when it is sane.
            wait = _retry_after(exc) or backoff ** (attempt + 1)
            log.warning("%s -> HTTP %s, retrying in %.1fs", url, exc.code, wait)
            time.sleep(wait)

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            if attempt == retries:
                raise LiveFetchError(f"{url} unreachable: {exc}") from exc
            wait = backoff ** (attempt + 1)
            log.warning("%s unreachable (%s), retrying in %.1fs", url, exc, wait)
            time.sleep(wait)

        except json.JSONDecodeError as exc:
            raise LiveFetchError(f"{url} returned invalid JSON: {exc}") from exc

    raise LiveFetchError(f"{url} failed after {retries + 1} attempts: {last}")


def _retry_after(exc: urllib.error.HTTPError) -> float | None:
    raw = (exc.headers or {}).get("Retry-After") if hasattr(exc, "headers") else None
    try:
        wait = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    # Ignore an absurd Retry-After rather than stalling an unattended run for an hour.
    return wait if 0 < wait <= 60 else None
