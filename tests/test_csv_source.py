"""Tests for `--source csv`: a Tenable CSV export, sampled like a live pull.

**No test here touches the network**, and that is a property of the source under
test rather than of the stubs: `TenableCsvClient` is constructed with a `fetch`
that raises, so any call that fell through to the live client would fail loudly
here instead of quietly reaching for cloud.tenable.com.

Each test writes its own export to a temp directory. The point of most of them is
that the sampling is the *same* sampling `--source tenable` uses -- the floor, the
one-CVE-once dedupe, the one-host-per-CVE pick and the cap -- so the assertions
deliberately mirror the ones in test_live.py.

    python -m pytest tests/test_csv_source.py -v
    python tests/test_csv_source.py
"""

from __future__ import annotations

import csv
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulntriage.intel import enrich_all  # noqa: E402
from vulntriage.live.tenable_csv import CsvSourceError, TenableCsvClient  # noqa: E402
from vulntriage.normalize import normalize  # noqa: E402
from vulntriage.remediation import remediation_for  # noqa: E402
from vulntriage.scoring import score_all  # noqa: E402

# Every column the real export carries that we read, in the real export's order.
HEADERS = [
    "Plugin ID", "CVE", "CVSS", "Risk", "Host", "Protocol", "Port", "Name",
    "Solution", "Plugin Output", "IP Address", "FQDN", "NetBios", "OS",
    "CVSS3 Base Score", "Vulnerability State", "Severity", "Service",
    "First Found", "Last Found",
]

DEFAULTS = {
    "Plugin ID": "100001",
    "CVE": "CVE-2021-44228",
    "CVSS": "9.3",
    "CVSS3 Base Score": "10.0",
    "Risk": "Critical",
    "Severity": "4",
    "Host": "web-01.corp.example.net",
    "IP Address": "10.1.0.10",
    "FQDN": "web-01.corp.example.net",
    "Protocol": "TCP",
    "Port": "8080",
    "Service": "www",
    "Name": "Apache Log4j Remote Code Execution",
    "Solution": "Upgrade to Log4j 2.17.1 or later.",
    "Plugin Output": "Installed version : 2.14.1",
    "Vulnerability State": "New",
    "First Found": "2026-01-04T09:00:00Z",
    "Last Found": "2026-08-07T19:15:04Z",
}


def _export(*rows: dict, headers: list[str] | None = None) -> Path:
    """Write a Tenable-shaped CSV to a temp file and return its path."""
    headers = headers or HEADERS
    path = Path(tempfile.mkdtemp(prefix="vulntriage-csv-")) / "export.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in headers})
    return path


def _row(**overrides) -> dict:
    row = dict(DEFAULTS)
    row.update(overrides)
    return row


def _client(*rows: dict, headers: list[str] | None = None, **kwargs) -> TenableCsvClient:
    return TenableCsvClient(_export(*rows, headers=headers), **kwargs)


def _cves(rows) -> list[str]:
    return [c for row in rows for c in row["cve"]]


# --------------------------------------------------------------------------- #
# parsing: the fields the API client normalizes, read from the export
# --------------------------------------------------------------------------- #

def test_an_export_row_normalizes_into_the_discovery_shape():
    """Every field the pipeline reads survives the trip through the CSV."""
    rows = _client(_row()).fetch_findings()
    assert len(rows) == 1

    row = rows[0]
    assert row["cve"] == ["CVE-2021-44228"]
    assert row["cvss3_base_score"] == 10.0, "CVSS3 must beat the v2 score in the CVSS column"
    assert row["severity"] == 4 and row["severity_name"] == "Critical"
    assert row["host"] == "web-01.corp.example.net", "the FQDN is what reconciles against a CMDB"
    assert row["ip"] == "10.1.0.10"
    assert row["plugin_name"] == "Apache Log4j Remote Code Execution"
    assert row["solution"] == "Upgrade to Log4j 2.17.1 or later."
    assert row["port"] == "8080" and row["protocol"] == "TCP" and row["svc_name"] == "www"
    assert row["plugin_output"] == "Installed version : 2.14.1"
    assert row["first_found"] == "2026-01-04T09:00:00Z"


def test_the_rows_normalize_into_findings_without_a_special_case():
    """The whole design: the normalizer never learns a CSV export produced these."""
    client = _client(_row())
    findings, report = normalize(client.fetch_findings(), source_format="csv")

    assert report.normalized_findings == 1
    finding = findings[0]
    assert finding.finding_id == "web-01:8080:CVE-2021-44228"
    assert finding.hostname == "web-01" and finding.fqdn == "web-01.corp.example.net"
    assert finding.scanner_cvss == 10.0
    assert finding.solution == "Upgrade to Log4j 2.17.1 or later."


def test_the_column_spellings_tenable_actually_exports_are_all_read():
    """Tenable.io, Tenable.sc and the Nessus UI disagree on the column names."""
    headers = ["Plugin", "CVE", "CVSS v3.0 Base Score", "Risk Factor", "DNS Name",
               "Name", "Solution", "State"]
    client = _client(
        {
            "Plugin": "100001",
            "CVE": "CVE-2021-44228",
            "CVSS v3.0 Base Score": "10.0",
            "Risk Factor": "Critical",
            "DNS Name": "web-01.corp.example.net",
            "Name": "Log4Shell",
            "Solution": "Upgrade.",
            "State": "open",
        },
        headers=headers,
    )
    rows = client.fetch_findings()
    assert len(rows) == 1
    assert rows[0]["cvss3_base_score"] == 10.0
    assert rows[0]["severity"] == 4
    assert rows[0]["host"] == "web-01.corp.example.net"


def test_severity_is_read_from_the_risk_word_when_there_is_no_severity_column():
    """An export with no numeric Severity must not land every finding at Info."""
    headers = ["Plugin ID", "CVE", "CVSS3 Base Score", "Risk", "Host", "Name"]
    client = _client(
        {"Plugin ID": "1", "CVE": "CVE-2021-44228", "CVSS3 Base Score": "9.8",
         "Risk": "High", "Host": "web-01", "Name": "x"},
        headers=headers,
    )
    assert client.fetch_findings()[0]["severity"] == 3


def test_a_row_carrying_two_cves_becomes_two_findings():
    """One CVE per row is what makes the cap mean distinct CVEs, not rows."""
    rows = _client(_row(CVE="CVE-2021-44228, CVE-2021-45046")).fetch_findings()
    assert sorted(_cves(rows)) == ["CVE-2021-44228", "CVE-2021-45046"]
    assert all(len(row["cve"]) == 1 for row in rows)


def test_a_cve_only_in_the_plugin_name_is_recovered():
    """Same recovery the normalizer does, so nothing vanishes between the two."""
    client = _client(_row(CVE="", Name="Windows Print Spooler CVE-2021-34527 RCE"))
    rows = client.fetch_findings()
    assert _cves(rows) == ["CVE-2021-34527"]
    assert client.cves_recovered_from_name == 1


def test_a_row_with_no_cve_anywhere_is_skipped():
    rows = _client(_row(CVE="", Name="SSL Certificate Cannot Be Trusted")).fetch_findings()
    assert rows == []


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #

def test_resurfaced_is_an_open_finding_and_fixed_is_not():
    """Tenable's state vocabulary is not the normalizer's, and reading
    'Resurfaced' as remediated would drop a live exposure."""
    client = _client(
        _row(**{"Plugin ID": "1", "CVE": "CVE-2021-44228", "Vulnerability State": "Resurfaced"}),
        _row(**{"Plugin ID": "2", "CVE": "CVE-2021-45046", "Vulnerability State": "Fixed"}),
        limit=None,
    )
    findings, report = normalize(client.fetch_findings())
    assert [f.cve for f in findings] == ["CVE-2021-44228"]
    assert report.dropped_not_open == 1


# --------------------------------------------------------------------------- #
# sampling: the floor
# --------------------------------------------------------------------------- #

def test_findings_below_the_cvss_floor_are_dropped():
    client = _client(
        _row(**{"Plugin ID": "1", "CVE": "CVE-2021-44228", "CVSS3 Base Score": "9.8"}),
        _row(**{"Plugin ID": "2", "CVE": "CVE-1999-0524", "CVSS3 Base Score": "2.1",
                "Risk": "Low", "Severity": "1"}),
    )
    assert _cves(client.fetch_findings()) == ["CVE-2021-44228"]
    assert client.plugins_below_min_cvss == 1


def test_the_cvss_floor_is_configurable_and_zero_removes_it():
    rows = [
        _row(**{"Plugin ID": "1", "CVE": "CVE-2021-44228", "CVSS3 Base Score": "9.8"}),
        _row(**{"Plugin ID": "2", "CVE": "CVE-1999-0524", "CVSS3 Base Score": "2.1",
                "Risk": "Low", "Severity": "1"}),
    ]
    assert len(_client(*rows, min_cvss=2.0).fetch_findings()) == 2
    assert len(_client(*rows, min_cvss=0).fetch_findings()) == 2
    assert len(_client(*rows, min_cvss=9.9).fetch_findings()) == 0


def test_a_row_with_no_cvss_at_all_is_judged_on_its_severity():
    """Dropping unscored rows would discard Criticals for a missing column."""
    client = _client(_row(**{"CVSS": "", "CVSS3 Base Score": ""}))
    assert len(client.fetch_findings()) == 1, "Critical severity clears a 7.0 floor"


# --------------------------------------------------------------------------- #
# sampling: the dedupe and the cap
# --------------------------------------------------------------------------- #

def _estate(plugins: int = 40, hosts_per_plugin: int = 5) -> list[dict]:
    """An export big enough that the cap has to do something."""
    rows: list[dict] = []
    for p in range(plugins):
        for h in range(hosts_per_plugin):
            rows.append(_row(**{
                "Plugin ID": str(200000 + p),
                "CVE": f"CVE-2024-{1000 + p}",
                "Name": f"Plugin {p}",
                "Host": f"host-{h}.corp.example.net",
                "FQDN": f"host-{h}.corp.example.net",
                "IP Address": f"10.1.0.{h}",
                "CVSS3 Base Score": "9.0",
            }))
    return rows


def test_a_pull_is_capped_at_twenty_distinct_cves_by_default():
    client = _client(*_estate())
    rows = client.fetch_findings()
    assert len(rows) == 20
    assert len(set(_cves(rows))) == 20, "the cap counts distinct CVEs, not rows"
    assert client.truncated


def test_the_cap_is_configurable():
    assert len(_client(*_estate(), limit=7).fetch_findings()) == 7


def test_a_capped_pull_keeps_one_host_per_cve_and_says_how_many_it_dropped():
    client = _client(*_estate(plugins=3, hosts_per_plugin=5), limit=3)
    rows = client.fetch_findings()
    assert len(rows) == 3, "one host per CVE while the cap is in force"
    assert client.hosts_not_sampled == 12, "4 unsampled hosts x 3 CVEs, disclosed not hidden"


def test_limit_zero_lifts_the_cap_and_the_dedupe():
    """`--limit 0` is the escape hatch: every affected host, uncapped."""
    client = _client(*_estate(plugins=3, hosts_per_plugin=5), limit=0)
    rows = client.fetch_findings()
    assert len(rows) == 15
    assert client.hosts_not_sampled == 0
    assert not client.truncated


def test_the_dedupe_keeps_the_highest_severity_instance_of_a_cve():
    """Two plugins report one CVE; the sample must keep the more severe."""
    client = _client(
        _row(**{"Plugin ID": "1", "Name": "low-severity report", "Risk": "Medium",
                "Severity": "2", "CVSS3 Base Score": "7.1"}),
        _row(**{"Plugin ID": "2", "Name": "critical report", "Risk": "Critical",
                "Severity": "4", "CVSS3 Base Score": "10.0"}),
    )
    rows = client.fetch_findings()
    assert len(rows) == 1
    assert rows[0]["plugin_name"] == "critical report"
    assert client.duplicate_cves_skipped == 1


def test_one_plugin_reporting_several_cves_on_one_host_invents_no_extra_hosts():
    """A Tenable export writes one row per (plugin, CVE).

    Read naively that makes a four-CVE plugin on one box look like four affected
    hosts, and the report would claim three hosts that do not exist.
    """
    client = _client(*[
        _row(**{"Plugin ID": "500", "CVE": f"CVE-2024-{n}", "Name": "one plugin"})
        for n in (1001, 1002, 1003, 1004)
    ])
    rows = client.fetch_findings()
    assert len(rows) == 4, "four CVEs, all kept"
    assert {row["host"] for row in rows} == {"web-01.corp.example.net"}
    assert client.hosts_not_sampled == 0, "one host is one host, however many CVEs it has"


def test_the_sample_is_reproducible_run_to_run():
    """A demo that reshuffles its findings between runs demos nothing."""
    export = _export(*_estate())
    first = _cves(TenableCsvClient(export).fetch_findings())
    second = _cves(TenableCsvClient(export).fetch_findings())
    assert first == second


# --------------------------------------------------------------------------- #
# the report says what the sample covered
# --------------------------------------------------------------------------- #

def test_a_sampled_run_declares_itself_in_the_report():
    from vulntriage.pipeline import run_discovery_tenable
    from vulntriage.state import PipelineState

    client = _client(*_estate(plugins=30, hosts_per_plugin=4))
    report = run_discovery_tenable(client, PipelineState())

    assert any("Sampled pull" in a for a in report.anomalies), "a sample must declare itself"
    assert any("not sampled" in a for a in report.anomalies), \
        "the hosts the dedupe dropped must be disclosed"
    assert any("export.csv" in a for a in report.anomalies), \
        "the report must name what was sampled, not say 'workbench'"
    assert report.source_format == "csv"
    assert report.source_file.endswith("export.csv")


def test_the_state_routes_a_csv_source_to_the_client_not_the_file():
    """`--source csv` must not fall through to reading --input straight."""
    from vulntriage.pipeline import run_discovery
    from vulntriage.state import PipelineState

    client = _client(*_estate(plugins=3, hosts_per_plugin=2))
    state = PipelineState()
    state.configure(finding_source="csv", tenable_client=client)
    report = run_discovery("data/sample_findings.json", state)

    assert report.normalized_findings == 3, "the client sampled it, not normalize_file"
    assert state.normalized[0].plugin_id.startswith("2000")


# --------------------------------------------------------------------------- #
# assets
# --------------------------------------------------------------------------- #

def test_asset_context_is_indexed_by_every_identity_in_the_export():
    index = _client(_row()).fetch_asset_contexts()
    for key in ("web-01.corp.example.net", "10.1.0.10"):
        assert key in index, f"a finding identified by {key} must still resolve"


def test_a_csv_export_does_not_claim_an_asset_criticality_it_cannot_know():
    """The API path reads Tenable's ACR. A CSV export has no such column, so the
    finding stays an intel gap rather than being scored on an invented rating."""
    context = _client(_row()).fetch_asset_contexts()["10.1.0.10"]
    assert context.criticality == "unknown"
    assert context.known_asset is False
    assert not context.internet_facing

    findings, _ = normalize(_client(_row()).fetch_findings())
    scored = score_all(enrich_all(findings, assets=_client(_row()).fetch_asset_contexts()))
    assert scored[0].intel_gap
    assert scored[0].breakdown.asset_weight == 1.00


# --------------------------------------------------------------------------- #
# the Solution column
# --------------------------------------------------------------------------- #

def test_the_scanner_solution_becomes_the_remediation_when_the_db_has_none():
    """The export's own fix text beats 'no vendor guidance on file'."""
    client = _client(_row(CVE="CVE-2035-0001", Solution="Upgrade to 7-Zip 26.01 or later."))
    findings, _ = normalize(client.fetch_findings())
    scored = score_all(enrich_all(findings))
    plan = remediation_for(scored[0])

    assert "Upgrade to 7-Zip 26.01 or later." in plan["summary"]
    assert plan["type"] == "patch"
    assert plan["effort"] == "unknown", "a one-line fix text does not scope the work"
    assert any("scanner's" in c for c in plan["constraints"]), \
        "unvetted guidance must be labelled as the scanner's, not the database's"


def test_the_curated_database_still_beats_the_scanners_fix_text():
    """CVE-2021-44228 is in the local DB; its remediation is the researched one."""
    client = _client(_row(Solution="Reboot the server."))
    findings, _ = normalize(client.fetch_findings())
    plan = remediation_for(score_all(enrich_all(findings))[0])
    assert "Reboot the server." not in plan["summary"]
    assert plan["effort"] != "unknown"


def test_an_export_with_no_solution_column_still_works():
    headers = ["Plugin ID", "CVE", "CVSS3 Base Score", "Risk", "Host", "Name"]
    client = _client(
        {"Plugin ID": "1", "CVE": "CVE-2021-44228", "CVSS3 Base Score": "10.0",
         "Risk": "Critical", "Host": "web-01", "Name": "Log4Shell"},
        headers=headers,
    )
    findings, _ = normalize(client.fetch_findings())
    assert findings[0].solution is None


# --------------------------------------------------------------------------- #
# failure modes
# --------------------------------------------------------------------------- #

def test_a_missing_file_is_not_configured_and_fails_with_a_sentence():
    client = TenableCsvClient(ROOT / "data" / "no-such-export.csv")
    assert not client.configured
    try:
        client.fetch_findings()
    except CsvSourceError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("a missing export must raise, not return nothing")


def test_a_csv_that_is_not_a_tenable_export_says_so():
    path = Path(tempfile.mkdtemp(prefix="vulntriage-csv-")) / "shopping.csv"
    path.write_text("item,price\nmilk,2.40\n", encoding="utf-8")
    try:
        TenableCsvClient(path).fetch_findings()
    except CsvSourceError as exc:
        assert "does not look like a Tenable export" in str(exc)
    else:
        raise AssertionError("a wrong file must fail with a message, not an empty report")


def test_a_bad_export_degrades_to_no_asset_context_rather_than_raising():
    """Same contract as the API client: assets are context, never the run."""
    client = TenableCsvClient(ROOT / "data" / "no-such-export.csv")
    assert client.fetch_asset_contexts() == {}
    assert client.error


def test_the_csv_source_never_reaches_for_the_network():
    """The credentials are not read and the fetch is not callable. Both matter:
    a file source that authenticated would be a file source that could be down."""
    import os

    os.environ["TENABLE_ACCESS_KEY"] = "should-be-ignored"
    os.environ["TENABLE_SECRET_KEY"] = "should-be-ignored"
    try:
        client = _client(_row())
        assert client.access_key is None and client.secret_key is None
        assert client.configured, "the file is the credential"
        try:
            client._fetch("https://cloud.tenable.com/workbenches/vulnerabilities")
        except CsvSourceError:
            pass
        else:
            raise AssertionError("a CSV client must not be able to make an HTTP call")
    finally:
        del os.environ["TENABLE_ACCESS_KEY"]
        del os.environ["TENABLE_SECRET_KEY"]


# --------------------------------------------------------------------------- #
# the other two sources are untouched
# --------------------------------------------------------------------------- #

def test_the_mock_source_reads_a_csv_straight_through_with_no_sampling():
    """`--source mock` on a CSV is the old path and stays the old path: every
    row, no floor, no cap. That difference is the reason `--source csv` exists."""
    from vulntriage.pipeline import run_discovery
    from vulntriage.state import PipelineState

    state = PipelineState()
    report = run_discovery(ROOT / "data" / "sample_findings.csv", state)
    assert report.source_format == "csv"
    assert not any("Sampled" in a or "Capped" in a for a in report.anomalies)


def test_a_tenable_client_still_describes_itself_as_a_workbench_or_a_scan():
    from vulntriage.live.tenable import TenableClient

    assert TenableClient(access_key="AK", secret_key="SK").pool == "workbench"
    assert TenableClient(access_key="AK", secret_key="SK", scan_id=58373).pool == "scan 58373"
    assert TenableClient(access_key="AK", secret_key="SK").source_format == "api"


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
