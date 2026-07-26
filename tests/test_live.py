"""Tests for the live API integration.

**No test here touches the network.** Every client takes its `fetch` callable by
injection, and each test hands it a stub. A test suite that quietly depends on
CISA being up is a test suite that fails on a plane, and one that hammers NVD
from CI gets the key revoked.

Caches are constructed with `directory=None` so nothing is written to `.cache/`.

    python -m pytest tests/test_live.py -v
    python tests/test_live.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulntriage.intel import enrich_all, lookup_cve  # noqa: E402
from vulntriage.live import LiveIntel  # noqa: E402
from vulntriage.live.cache import Cache  # noqa: E402
from vulntriage.live.epss import EpssClient  # noqa: E402
from vulntriage.live.http import LiveFetchError  # noqa: E402
from vulntriage.live.kev import KevClient  # noqa: E402
from vulntriage.live.nvd import DELAY_WITH_KEY, DELAY_WITHOUT_KEY, NvdClient  # noqa: E402
from vulntriage.live.tenable import TenableAuthError, TenableClient  # noqa: E402
from vulntriage.normalize import normalize, normalize_file  # noqa: E402
from vulntriage.scoring import EXPLOIT_WEIGHTS, epss_weight, score_all  # noqa: E402

SAMPLE_JSON = ROOT / "data" / "sample_findings.json"


def _cache(namespace: str, **kwargs) -> Cache:
    """A cache that never touches disk."""
    return Cache(namespace, directory=None, **kwargs)


class Recorder:
    """A stub fetch that records calls and replays canned responses."""

    def __init__(self, *responses, error: Exception | None = None):
        self.responses = list(responses)
        self.error = error
        self.calls: list[dict] = []

    def __call__(self, url, headers=None, params=None, **kwargs):
        self.calls.append({"url": url, "headers": headers or {}, "params": params or {}})
        if self.error:
            raise self.error
        if not self.responses:
            return {}
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


# --------------------------------------------------------------------------- #
# 1. CISA KEV
# --------------------------------------------------------------------------- #

KEV_FEED = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2019-0708",
            "vulnerabilityName": "BlueKeep",
            "dateAdded": "2021-11-03",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {"cveID": "", "vulnerabilityName": "malformed row with no id"},
    ],
}


def test_kev_downloads_and_flags_known_exploited():
    fetch = Recorder(KEV_FEED)
    client = KevClient(cache=_cache("kev"), fetch=fetch)

    assert client.is_known_exploited("CVE-2021-44228") is True
    assert client.is_known_exploited("CVE-2016-2183") is False
    assert len(client) == 2, "the row with no cveID must be skipped"
    assert len(fetch.calls) == 1, "one download for the whole catalogue"


def test_kev_reads_the_ransomware_flag_as_a_string_not_a_boolean():
    """The feed says "Known"/"Unknown", not true/false."""
    client = KevClient(cache=_cache("kev"), fetch=Recorder(KEV_FEED))
    assert client.entry("CVE-2021-44228").ransomware is True
    assert client.entry("CVE-2019-0708").ransomware is False
    assert client.entry("CVE-2021-44228").date_added == "2021-12-10"


def test_kev_is_downloaded_once_per_run():
    fetch = Recorder(KEV_FEED)
    client = KevClient(cache=_cache("kev"), fetch=fetch)
    for _ in range(5):
        client.is_known_exploited("CVE-2021-44228")
    assert len(fetch.calls) == 1


def test_kev_cache_survives_a_new_client():
    shared = _cache("kev")
    first = Recorder(KEV_FEED)
    KevClient(cache=shared, fetch=first).load()

    second = Recorder(error=AssertionError("must not refetch"))
    client = KevClient(cache=shared, fetch=second)
    assert client.is_known_exploited("CVE-2021-44228") is True
    assert second.calls == []


def test_kev_outage_degrades_instead_of_raising():
    client = KevClient(cache=_cache("kev"), fetch=Recorder(error=LiveFetchError("CISA down")))
    assert client.load() is False
    assert client.available is False
    assert client.is_known_exploited("CVE-2021-44228") is False
    assert "CISA down" in client.error


# --------------------------------------------------------------------------- #
# 2. FIRST EPSS
# --------------------------------------------------------------------------- #

EPSS_RESPONSE = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99999", "date": "2026-07-26"},
        {"cve": "CVE-2016-2183", "epss": "0.00291", "percentile": "0.65432", "date": "2026-07-26"},
    ],
}


def test_epss_scores_attach_to_findings():
    client = EpssClient(cache=_cache("epss"), fetch=Recorder(EPSS_RESPONSE))
    scores = client.fetch_many(["CVE-2021-44228", "CVE-2016-2183"])
    assert scores["CVE-2021-44228"].score == 0.97565
    assert scores["CVE-2021-44228"].percentile == 0.99999
    assert scores["CVE-2016-2183"].score == 0.00291


def test_epss_batches_into_one_call():
    fetch = Recorder(EPSS_RESPONSE)
    EpssClient(cache=_cache("epss"), fetch=fetch).fetch_many(
        ["CVE-2021-44228", "CVE-2016-2183"]
    )
    assert len(fetch.calls) == 1
    assert fetch.calls[0]["params"]["cve"] == "CVE-2021-44228,CVE-2016-2183"


def test_epss_respects_the_batch_size():
    fetch = Recorder(EPSS_RESPONSE)
    client = EpssClient(cache=_cache("epss"), batch_size=1, fetch=fetch)
    client.fetch_many(["CVE-2021-44228", "CVE-2016-2183"])
    assert len(fetch.calls) == 2, "two CVEs at batch_size=1 is two calls"


def test_epss_does_not_re_request_a_cve_with_no_score():
    """A CVE with no EPSS row is a normal outcome; caching the miss matters."""
    fetch = Recorder({"status": "OK", "data": []})
    shared = _cache("epss")
    client = EpssClient(cache=shared, fetch=fetch)
    assert client.fetch_many(["CVE-2000-0001"]) == {}

    again = Recorder(error=AssertionError("must not refetch a known miss"))
    assert EpssClient(cache=shared, fetch=again).fetch_many(["CVE-2000-0001"]) == {}
    assert again.calls == []


def test_epss_outage_degrades_instead_of_raising():
    client = EpssClient(cache=_cache("epss"), fetch=Recorder(error=LiveFetchError("FIRST down")))
    assert client.fetch_many(["CVE-2021-44228"]) == {}
    assert "FIRST down" in client.error


# --------------------------------------------------------------------------- #
# 3. NVD
# --------------------------------------------------------------------------- #

def _nvd_response(cve="CVE-2021-44228", version="cvssMetricV31", score=10.0):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve,
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2023-11-07T03:39:22.567",
                    "descriptions": [
                        {"lang": "es", "value": "no usar"},
                        {"lang": "en", "value": "JNDI features used in configuration..."},
                    ],
                    "metrics": {
                        version: [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-502"}]}
                    ],
                    "references": [{"url": "https://logging.apache.org/"}],
                }
            }
        ]
    }


def test_nvd_parses_the_fields_enrichment_needs():
    client = NvdClient(cache=_cache("nvd"), fetch=Recorder(_nvd_response()), sleep=lambda s: None)
    record = client.fetch("CVE-2021-44228")
    assert record.cvss == 10.0
    assert record.cvss_severity == "Critical"
    assert record.cvss_vector.startswith("CVSS:3.1/")
    assert record.cwe == "CWE-502"
    assert record.description.startswith("JNDI")
    assert record.references == ["https://logging.apache.org/"]


def test_nvd_falls_back_from_v31_to_v30():
    response = _nvd_response(version="cvssMetricV30", score=9.8)
    client = NvdClient(cache=_cache("nvd"), fetch=Recorder(response), sleep=lambda s: None)
    assert client.fetch("CVE-2021-44228").cvss == 9.8


def test_nvd_prefers_nvds_own_score_over_the_cnas():
    """The Zerologon case, verbatim from the live API.

    NVD returns Microsoft's 5.5 *first* and its own 10.0 second, both tagged
    Secondary. Taking the first entry halves Zerologon's risk score and drops it
    from 2nd to 15th in the queue.
    """
    zerologon = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2020-1472",
                    "descriptions": [{"lang": "en", "value": "Netlogon elevation of privilege"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "secure@microsoft.com",
                                "type": "Secondary",
                                "cvssData": {"baseScore": 5.5, "baseSeverity": "MEDIUM"},
                            },
                            {
                                "source": "nvd@nist.gov",
                                "type": "Secondary",
                                "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"},
                            },
                        ]
                    },
                }
            }
        ]
    }
    client = NvdClient(cache=_cache("nvd"), fetch=Recorder(zerologon), sleep=lambda s: None)
    record = client.fetch("CVE-2020-1472")
    assert record.cvss == 10.0, "NVD's own analysis must win over the CNA's"
    assert record.cvss_severity == "Critical"


def test_nvd_falls_back_to_primary_then_to_whatever_exists():
    only_cna = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-0001",
                    "metrics": {
                        "cvssMetricV31": [
                            {"source": "cna@example.com", "type": "Secondary",
                             "cvssData": {"baseScore": 7.1, "baseSeverity": "HIGH"}},
                            {"source": "other@example.com", "type": "Primary",
                             "cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}},
                        ]
                    },
                }
            }
        ]
    }
    client = NvdClient(cache=_cache("nvd"), fetch=Recorder(only_cna), sleep=lambda s: None)
    assert client.fetch("CVE-2021-0001").cvss == 8.8, "Primary wins when NVD's own is absent"


def test_nvd_caches_and_does_not_refetch():
    fetch = Recorder(_nvd_response())
    shared = _cache("nvd")
    NvdClient(cache=shared, fetch=fetch, sleep=lambda s: None).fetch("CVE-2021-44228")

    again = Recorder(error=AssertionError("must not refetch"))
    client = NvdClient(cache=shared, fetch=again, sleep=lambda s: None)
    assert client.fetch("CVE-2021-44228").cvss == 10.0
    assert again.calls == []


def test_nvd_respects_the_rate_limit_between_calls():
    slept: list[float] = []
    client = NvdClient(
        cache=_cache("nvd"), api_key="",
        fetch=Recorder(_nvd_response(), _nvd_response("CVE-2019-0708")),
        sleep=slept.append,
    )
    client.fetch("CVE-2021-44228")
    client.fetch("CVE-2019-0708")

    assert slept, "the second call must be paced"
    assert slept[0] > DELAY_WITHOUT_KEY - 1, f"unkeyed pacing should be ~{DELAY_WITHOUT_KEY}s"


def test_nvd_api_key_raises_the_rate_and_is_sent_as_a_header():
    fetch = Recorder(_nvd_response())
    client = NvdClient(cache=_cache("nvd"), api_key="secret-key", fetch=fetch, sleep=lambda s: None)
    client.fetch("CVE-2021-44228")
    assert client.delay == DELAY_WITH_KEY
    assert fetch.calls[0]["headers"]["apiKey"] == "secret-key"
    assert fetch.calls[0]["params"]["cveId"] == "CVE-2021-44228"


def test_nvd_unknown_cve_and_outage_both_degrade():
    empty = NvdClient(cache=_cache("nvd"), fetch=Recorder({"vulnerabilities": []}),
                      sleep=lambda s: None)
    assert empty.fetch("CVE-2000-0001") is None

    down = NvdClient(cache=_cache("nvd"), fetch=Recorder(error=LiveFetchError("NVD 503")),
                     sleep=lambda s: None)
    assert down.fetch("CVE-2021-44228") is None
    assert "NVD 503" in down.error


# --------------------------------------------------------------------------- #
# 4. Tenable
# --------------------------------------------------------------------------- #

# These fixtures are the *observed* Tenable.io payloads, captured from a live
# instance -- not the shapes the integration spec describes. They differ in four
# ways that each broke the pull, and every one is load-bearing here:
#
#   - /outputs returns {"outputs": [...]}, not a bare list
#   - results carry `assets`, not `hosts`, and the assets are inline (fqdn, ipv4)
#   - the transport is `transport_protocol`; the service is `application_protocol`
#   - the vulnerability workbench has NO cve field at all -- CVEs live only on
#     /info, under reference_information
#
# A fixture matching the documentation instead of the API is worse than no test:
# it passes while the integration is broken.

TENABLE_VULNS = {
    "vulnerabilities": [
        {
            "plugin_id": 155999,
            "plugin_name": "Apache Log4j RCE (Log4Shell)",
            "plugin_family": "Web Servers",
            "severity": 4,
            "cvss_base_score": 9.3,
            "count": 1,
            "vulnerability_state": "Active",
        },
        {
            "plugin_id": 10114,
            "plugin_name": "ICMP Timestamp Request Remote Date Disclosure",
            "severity": 1,
            "count": 89,
        },
    ]
}

TENABLE_INFO = {
    155999: {
        "info": {
            "severity": 4,
            "plugin_details": {"name": "Apache Log4j RCE (Log4Shell)", "family": "Web Servers"},
            "reference_information": [
                {"name": "cve", "values": ["CVE-2021-44228"]},
                {"name": "iava", "values": ["2021-A-0573"]},
            ],
            "risk_information": {"cvss3_base_score": "10.0", "cvss_base_score": "9.3"},
        }
    },
    # A plugin with no CVE reference at all: must be skipped before its outputs
    # are ever requested.
    10114: {"info": {"severity": 1, "reference_information": [{"name": "xref", "values": ["x"]}]}},
}

TENABLE_OUTPUTS = {
    "outputs": [
        {
            "plugin_output": "Log4j 2.14.1 detected",
            "states": [
                {
                    "name": "active",
                    "results": [
                        {
                            "application_protocol": "www",
                            "port": 8080,
                            "transport_protocol": "tcp",
                            "assets": [
                                {
                                    "id": "8e8434bf-41d0-48ad-b2e6-05e71b38785f",
                                    "hostname": "prod-db-01",
                                    "fqdn": "prod-db-01.corp.example.net",
                                    "ipv4": "10.20.4.11",
                                    "first_seen": "2026-07-01T00:00:00Z",
                                    "last_seen": "2026-07-20T00:00:00Z",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ]
}

TENABLE_ASSETS = {
    "assets": [
        {"id": "asset-1", "fqdn": ["prod-db-01.corp.example.net"], "ipv4": ["10.20.4.11"]}
    ]
}

_OUTPUTS_REQUESTED: list[str] = []


def _tenable_fetch(url, headers=None, params=None, **kwargs):
    if "/workbenches/assets" in url:
        return TENABLE_ASSETS
    if "/info" in url:
        plugin = int(url.rstrip("/info").rsplit("/", 1)[-1])
        return TENABLE_INFO.get(plugin, {"info": {}})
    if "/outputs" in url:
        _OUTPUTS_REQUESTED.append(url)
        return TENABLE_OUTPUTS
    if "/workbenches/vulnerabilities" in url:
        return TENABLE_VULNS
    raise AssertionError(f"unexpected URL {url}")


def test_tenable_requires_credentials():
    client = TenableClient(access_key="", secret_key="", fetch=_tenable_fetch)
    assert client.configured is False
    try:
        client.fetch_findings()
    except TenableAuthError as exc:
        assert "TENABLE_ACCESS_KEY" in str(exc)
    else:
        raise AssertionError("missing keys must raise TenableAuthError")


def test_tenable_sends_the_documented_auth_header():
    seen: dict = {}

    def fetch(url, headers=None, params=None, **kwargs):
        seen.update(headers or {})
        return _tenable_fetch(url, headers, params)

    TenableClient(access_key="AK", secret_key="SK", fetch=fetch).fetch_findings()
    assert seen["X-ApiKeys"] == "accessKey=AK; secretKey=SK"


def test_tenable_rows_normalize_into_the_discovery_shape():
    """The contract: raw rows the existing normalizer can already parse."""
    client = TenableClient(access_key="AK", secret_key="SK", fetch=_tenable_fetch)
    rows = client.fetch_findings()
    assert len(rows) == 1

    findings, report = normalize(rows, source_file="tenable:io", source_format="api")
    assert report.raw_rows == 1
    assert len(findings) == 1

    finding = findings[0]
    assert finding.cve == "CVE-2021-44228"
    assert finding.hostname == "prod-db-01", "the FQDN must resolve to the short name"
    assert finding.fqdn == "prod-db-01.corp.example.net"
    assert finding.ip == "10.20.4.11"
    assert finding.port == 8080
    assert finding.protocol == "tcp", "transport_protocol, not protocol"
    assert finding.service == "www", "application_protocol, not service"
    assert finding.scanner_severity == 4
    assert finding.scanner_cvss == 10.0, "risk_information's v3 score beats the summary's v2"
    assert finding.finding_id == "prod-db-01:8080:CVE-2021-44228"


def test_tenable_reads_cves_from_the_info_endpoint():
    """The vulnerability workbench carries no CVE field; /info is the only source."""
    assert "cve" not in TENABLE_VULNS["vulnerabilities"][0], "fixture must match the real API"
    client = TenableClient(access_key="AK", secret_key="SK", fetch=_tenable_fetch)
    rows = client.fetch_findings()
    assert rows[0]["cve"] == ["CVE-2021-44228"]


def test_tenable_skips_plugins_with_no_cve_before_fetching_outputs():
    """Most plugins on a real estate have no CVE, and the normalizer drops them.

    Requesting their outputs anyway is a wasted round trip per plugin -- 16 of
    105 on the instance this was built against.
    """
    _OUTPUTS_REQUESTED.clear()
    client = TenableClient(access_key="AK", secret_key="SK", fetch=_tenable_fetch)
    client.fetch_findings()
    assert client.plugins_seen == 2
    assert client.plugins_without_cve == 1
    assert len(_OUTPUTS_REQUESTED) == 1, "the CVE-less plugin must not cost an outputs call"
    assert "10114" not in "".join(_OUTPUTS_REQUESTED)


def test_tenable_outputs_endpoint_returns_a_dict_not_a_list():
    """`list(payload)` on this endpoint yields the dict's keys -- a list of
    strings -- which fails later as "'str' object has no attribute 'get'"."""
    client = TenableClient(access_key="AK", secret_key="SK", fetch=_tenable_fetch)
    outputs = client.fetch_vulnerability_outputs(155999)
    assert isinstance(outputs, list)
    assert outputs and isinstance(outputs[0], dict), "must unwrap the 'outputs' key"


def test_acr_maps_to_the_models_criticality_bands():
    from vulntriage.live.tenable import acr_to_criticality

    assert acr_to_criticality(10) == "critical"
    assert acr_to_criticality(9) == "critical"
    assert acr_to_criticality(7) == "high"
    assert acr_to_criticality(6) == "medium"
    assert acr_to_criticality(4) == "medium"
    assert acr_to_criticality(3) == "low"
    assert acr_to_criticality(None) == "unknown", "no ACR must not invent a criticality"
    assert acr_to_criticality("") == "unknown"


def test_tenable_asset_contexts_are_indexed_by_every_identity():
    client = TenableClient(access_key="AK", secret_key="SK", fetch=_tenable_fetch)
    index = client.fetch_asset_contexts()
    ctx = index.get("prod-db-01.corp.example.net")
    assert ctx is not None and ctx.known_asset is True
    # The same asset must be reachable by short name and IP too, because the
    # normalizer may have identified the host by any of them.
    assert index.get("10.20.4.11") is ctx


def test_scanner_asset_criticality_fills_the_gap_the_cmdb_leaves():
    """The failure this exists to prevent: against a live estate the mock CMDB
    knows nothing, so every finding scored at a flat 1.00 asset weight and the
    whole queue collapsed into P3/P4."""
    from vulntriage.intel import enrich_all
    from vulntriage.live.tenable import acr_to_criticality
    from vulntriage.models import AssetContext, NormalizedFinding

    finding = NormalizedFinding(
        finding_id="unknown-box:443:CVE-2021-44228",
        hostname="unknown-box", ip="10.9.9.9", port=443, cve="CVE-2021-44228",
        plugin_id="1", plugin_name="p", scanner_severity=4,
        scanner_severity_name="Critical", scanner_cvss=10.0,
    )

    without = enrich_all([finding])[0]
    assert without.asset.known_asset is False
    assert without.asset.criticality == "unknown"

    index = {"unknown-box": AssetContext(
        hostname="unknown-box", known_asset=True,
        criticality=acr_to_criticality(9), notes="Tenable asset (ACR 9)",
    )}
    with_assets = enrich_all([finding], assets=index)[0]
    assert with_assets.asset.known_asset is True
    assert with_assets.asset.criticality == "critical"


def test_the_local_cmdb_still_beats_the_scanner():
    """The CMDB carries owner, compliance scope and exposure; Tenable does not."""
    from vulntriage.intel import enrich_all
    from vulntriage.models import AssetContext, NormalizedFinding

    finding = NormalizedFinding(
        finding_id="prod-db-01:8080:CVE-2021-44228",
        hostname="prod-db-01", port=8080, cve="CVE-2021-44228",
        plugin_id="1", plugin_name="p", scanner_severity=4,
        scanner_severity_name="Critical", scanner_cvss=10.0,
    )
    index = {"prod-db-01": AssetContext(hostname="prod-db-01", known_asset=True,
                                        criticality="low", notes="Tenable")}
    enriched = enrich_all([finding], assets=index)[0]
    assert enriched.asset.criticality == "critical", "the CMDB entry must win"
    assert enriched.asset.owner, "and it brings owner/scope the scanner lacks"


def test_tenable_one_noisy_plugin_does_not_lose_the_pull():
    def fetch(url, headers=None, params=None, **kwargs):
        if "/outputs" in url:
            raise LiveFetchError("outputs 500")
        return _tenable_fetch(url, headers, params)

    client = TenableClient(access_key="AK", secret_key="SK", fetch=fetch)
    assert client.fetch_findings() == [], "a failed plugin is skipped, not fatal"


# --------------------------------------------------------------------------- #
# 5. The overlay: live data onto CVEContext
# --------------------------------------------------------------------------- #

def _live() -> LiveIntel:
    return LiveIntel(
        kev=KevClient(cache=_cache("kev"), fetch=Recorder(KEV_FEED)),
        epss=EpssClient(cache=_cache("epss"), fetch=Recorder(EPSS_RESPONSE)),
        nvd=NvdClient(cache=_cache("nvd"), fetch=Recorder(_nvd_response()), sleep=lambda s: None),
    )


def test_live_overlay_records_which_feeds_answered():
    live = _live()
    live.prime(["CVE-2021-44228"])
    intel = live.apply(lookup_cve("CVE-2021-44228"))
    assert set(intel.intel_sources) == {"NVD", "CISA KEV", "FIRST EPSS"}
    assert intel.epss_score == 0.97565
    assert intel.kev is True
    assert intel.ransomware_campaign_use is True
    assert intel.cwe == "CWE-502"


def test_kev_absence_clears_a_stale_local_flag():
    """KEV is authoritative in both directions, not just for membership."""
    live = LiveIntel(
        kev=KevClient(cache=_cache("kev"), fetch=Recorder({"vulnerabilities": []})),
        epss=None, nvd=None,
    )
    live.prime(["CVE-2020-1472"])
    local = lookup_cve("CVE-2020-1472")
    assert local.kev is True, "the mock DB says KEV"
    assert live.apply(local).kev is False, "the live catalogue does not"


def test_live_keeps_the_curated_remediation_guidance():
    """No public feed carries "a POS terminal cannot reboot during trading hours"."""
    live = _live()
    live.prime(["CVE-2021-44228"])
    intel = live.apply(lookup_cve("CVE-2021-44228"))
    assert intel.remediation, "mock remediation guidance must survive the overlay"


def test_total_feed_outage_still_produces_enriched_findings():
    dead = LiveFetchError("everything is down")
    live = LiveIntel(
        kev=KevClient(cache=_cache("kev"), fetch=Recorder(error=dead)),
        epss=EpssClient(cache=_cache("epss"), fetch=Recorder(error=dead)),
        nvd=NvdClient(cache=_cache("nvd"), fetch=Recorder(error=dead), sleep=lambda s: None),
    )
    findings, _ = normalize_file(SAMPLE_JSON)
    enriched = enrich_all(findings, live=live)
    assert len(enriched) == 18, "a total outage must not lose a single finding"
    assert score_all(enriched), "and the run still scores"
    assert live.warnings, "but it must say so loudly"


# --------------------------------------------------------------------------- #
# 6. EPSS in the risk model
# --------------------------------------------------------------------------- #

def test_epss_curve_is_banded_not_a_raw_multiply():
    assert epss_weight(None) is None
    assert epss_weight(0.001) is None, "below the floor EPSS says nothing"
    assert epss_weight(0.02)[0] == 1.25
    assert epss_weight(0.10)[0] == 1.40
    assert epss_weight(0.30)[0] == 1.50
    assert epss_weight(0.97)[0] == 1.60


def test_epss_never_outranks_confirmed_exploitation():
    """The ceiling is the KEV/weaponized weight. Nothing beats in-the-wild."""
    assert epss_weight(0.999)[0] == EXPLOIT_WEIGHTS["weaponized"]


def test_high_epss_promotes_a_finding_with_no_catalogued_exploit():
    findings, _ = normalize_file(SAMPLE_JSON)
    baseline = {f.cve: f for f in score_all(enrich_all(findings))}

    target = "CVE-2016-2183"  # scanner noise, ranks last on the mock path
    assert baseline[target].rank == len(baseline)

    class Boosted(LiveIntel):
        def __init__(self):
            super().__init__(kev=None, epss=None, nvd=None)

        def prime(self, cve_ids):
            return None

        def apply(self, intel):
            if intel.cve == target:
                intel.epss_score = 0.92
            return intel

    promoted = {f.cve: f for f in score_all(enrich_all(findings, live=Boosted()))}
    assert promoted[target].rank < baseline[target].rank, "a 92% EPSS must move it up"
    assert promoted[target].breakdown.exploit_weight == 1.60
    assert "EPSS" in promoted[target].breakdown.exploit_reason


def test_low_epss_does_not_bury_a_genuine_critical():
    """A 2% EPSS critical is still a critical -- the curve only ever promotes."""
    findings, _ = normalize_file(SAMPLE_JSON)
    baseline = {f.cve: f for f in score_all(enrich_all(findings))}

    class Damp(LiveIntel):
        def __init__(self):
            super().__init__(kev=None, epss=None, nvd=None)

        def prime(self, cve_ids):
            return None

        def apply(self, intel):
            intel.epss_score = 0.002
            return intel

    damped = {f.cve: f for f in score_all(enrich_all(findings, live=Damp()))}
    for cve, finding in baseline.items():
        assert damped[cve].risk_score == finding.risk_score, cve


# --------------------------------------------------------------------------- #
# 7. the mock path is untouched
# --------------------------------------------------------------------------- #

def test_mock_path_scores_identically_with_no_live_intel():
    findings, _ = normalize_file(SAMPLE_JSON)
    without = score_all(enrich_all(findings))
    explicit_none = score_all(enrich_all(findings, live=None))
    assert [(f.cve, f.risk_score, f.rank) for f in without] == [
        (f.cve, f.risk_score, f.rank) for f in explicit_none
    ]
    assert all(f.intel.epss_score is None for f in without)
    assert all(f.intel.intel_sources == [] for f in without)


def test_a_failing_tenable_pull_raises_rather_than_returning_nothing():
    """The contract `main.py` relies on to exit cleanly instead of tracebacking.

    A findings-source failure cannot be degraded around -- there is nothing to
    continue with -- so it must surface as an exception main can catch, never as
    an empty finding list that looks like a clean run over an empty scan.
    """
    from vulntriage.pipeline import run_discovery_tenable
    from vulntriage.state import PipelineState

    def dead(url, headers=None, params=None, **kwargs):
        raise LiveFetchError("HTTP 401 Unauthorized")

    client = TenableClient(access_key="AK", secret_key="SK", fetch=dead)
    try:
        run_discovery_tenable(client, PipelineState())
    except LiveFetchError as exc:
        assert "401" in str(exc)
    else:
        raise AssertionError("a dead Tenable must not look like an empty scan")


def test_main_treats_source_failures_as_a_clean_exit_not_a_crash():
    import main as entry

    assert LiveFetchError in entry.SOURCE_ERRORS
    assert TenableAuthError in entry.SOURCE_ERRORS


def test_state_configuration_survives_a_reset():
    """The crew resets state before it runs; losing the source there would
    silently drop a live pull back to the sample file."""
    from vulntriage.state import PipelineState

    state = PipelineState()
    state.configure(finding_source="tenable", tenable_client="client", live="live")
    state.reset()
    assert state.finding_source == "tenable"
    assert state.tenable_client == "client"
    assert state.live == "live"


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001 - a hand-rolled runner wants everything
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
