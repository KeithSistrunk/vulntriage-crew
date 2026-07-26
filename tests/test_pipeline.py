"""Tests for the deterministic pipeline.

No LLM required — that is the point of keeping the data path deterministic. The
risk model is the project's actual thesis, so the cases that matter most are the
CVSS inversions: a medium on a host that matters beating a critical on one that
does not.

    python -m pytest tests/ -v
    python tests/test_pipeline.py      # runs without pytest installed
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulntriage.intel import enrich_all, lookup_asset, lookup_cve  # noqa: E402
from vulntriage.normalize import normalize_file  # noqa: E402
from vulntriage.pipeline import run_offline  # noqa: E402
from vulntriage.report import (  # noqa: E402
    CSV_COLUMNS,
    _csv_safe,
    build_csv_rows,
    build_json,
    build_markdown,
    usable_note,
    write_csv,
    write_reports,
)
from vulntriage.remediation import remediation_for  # noqa: E402
from vulntriage.scoring import MAX_RAW_SCORE, priority_for, score_all  # noqa: E402
from vulntriage.state import PipelineState  # noqa: E402

SAMPLE_JSON = ROOT / "data" / "sample_findings.json"
SAMPLE_CSV = ROOT / "data" / "sample_findings.csv"


def _scored(path=SAMPLE_JSON):
    state = PipelineState()
    return run_offline(path, state), state


def _find(scored, cve, host):
    return next(f for f in scored if f.cve == cve and f.hostname == host)


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #

def test_reconciles_every_raw_row():
    """Rows in must equal findings out plus explained drops plus splits."""
    findings, report = normalize_file(SAMPLE_JSON)
    accounted = (
        report.normalized_findings
        - report.multi_cve_rows_split
        + report.duplicates_collapsed
        + report.dropped_informational
        + report.dropped_no_cve
        + report.dropped_not_open
    )
    assert accounted == report.raw_rows, f"{accounted} accounted for vs {report.raw_rows} raw rows"
    assert len(findings) == report.normalized_findings


def test_drops_informational_and_remediated_rows():
    _, report = normalize_file(SAMPLE_JSON)
    assert report.dropped_informational == 1      # "Nessus Scan Information"
    assert report.dropped_no_cve == 1             # "SSL Certificate Cannot Be Trusted"
    assert report.dropped_not_open == 1           # Log4Shell already fixed on dev-build-02


def test_collapses_duplicate_plugins_reporting_one_exposure():
    findings, report = normalize_file(SAMPLE_JSON)
    assert report.duplicates_collapsed == 1
    eternalblue = [f for f in findings if f.cve == "CVE-2017-0144"]
    assert len(eternalblue) == 1
    assert eternalblue[0].source_rows == 2, "both plugins should be recorded on the one finding"


def test_splits_rows_carrying_multiple_cves():
    findings, report = normalize_file(SAMPLE_JSON)
    assert report.multi_cve_rows_split == 1
    hr_port_80 = {f.cve for f in findings if f.hostname == "hr-app-03" and f.port == 80}
    assert {"CVE-2023-4863", "CVE-2019-11043"} <= hr_port_80


def test_recovers_cve_id_from_plugin_name():
    findings, report = normalize_file(SAMPLE_JSON)
    assert report.cve_recovered_from_plugin_name == 1
    assert any(f.cve == "CVE-2018-15473" for f in findings)


def test_normalizes_inconsistent_host_naming():
    findings, _ = normalize_file(SAMPLE_JSON)
    # 'DC-01.CORP.EXAMPLE.NET', 'dc-01', and 'dc-01.corp.example.net' are one host.
    assert {f.hostname for f in findings if "dc-01" in f.hostname} == {"dc-01"}


def test_host_level_findings_have_no_port():
    findings, _ = normalize_file(SAMPLE_JSON)
    pwnkit = next(f for f in findings if f.cve == "CVE-2021-4034")
    assert pwnkit.port is None, "port 0 means a host-level finding, not port zero"


def test_csv_input_produces_the_same_shape():
    findings, report = normalize_file(SAMPLE_CSV)
    assert report.source_format == "csv"
    assert findings, "CSV export should normalize to findings"
    assert all(f.cve.startswith("CVE-") for f in findings)


# --------------------------------------------------------------------------- #
# enrichment
# --------------------------------------------------------------------------- #

def test_unknown_cve_degrades_without_raising():
    intel = lookup_cve("CVE-2022-31813")
    assert intel.known_cve is False
    assert intel.exploit_maturity == "unknown"
    assert intel.notes and "unknown, not absent" in intel.notes


def test_unknown_host_is_flagged_not_dropped():
    asset = lookup_asset("10.114.8.55")
    assert asset.known_asset is False
    assert asset.criticality == "unknown"


def test_asset_resolves_by_hostname_fqdn_and_ip():
    for key in ("prod-db-01", "prod-db-01.corp.example.net", "10.20.4.11"):
        assert lookup_asset(key).criticality == "critical", key


def test_ip_only_host_is_reconciled_to_the_cmdb_name():
    """The scanner reported PwnKit against 10.20.4.11; the CMDB knows it as prod-db-01."""
    scored, _ = _scored()
    pwnkit = next(f for f in scored if f.cve == "CVE-2021-4034")
    assert pwnkit.hostname == "prod-db-01"
    assert pwnkit.asset.criticality == "critical"
    assert "10.20.4.11" in (pwnkit.asset.notes or "")


def test_missing_cvss_is_supplied_by_intel():
    """PrintNightmare ships with a null CVSS in the export."""
    findings, _ = normalize_file(SAMPLE_JSON)
    raw = next(f for f in findings if f.cve == "CVE-2021-34527")
    assert raw.scanner_cvss is None

    enriched = next(f for f in enrich_all(findings) if f.cve == "CVE-2021-34527")
    assert enriched.effective_cvss == 8.8
    assert "intel database" in enriched.cvss_source


def test_kev_and_ransomware_flags_are_attached():
    scored, _ = _scored()
    zerologon = _find(scored, "CVE-2020-1472", "dc-01")
    assert zerologon.intel.kev is True
    assert zerologon.intel.ransomware_campaign_use is True


# --------------------------------------------------------------------------- #
# the risk model — the reason this project exists
# --------------------------------------------------------------------------- #

def test_medium_cve_on_exposed_asset_beats_critical_on_lab_box():
    """The headline case. CVSS 5.3 internet-facing outranks CVSS 9.8 on a QA box."""
    scored, _ = _scored()
    ssh_enum = _find(scored, "CVE-2018-15473", "edge-web-01")     # CVSS 5.3
    curl = _find(scored, "CVE-2023-38545", "test-lab-07")          # CVSS 9.8

    assert ssh_enum.effective_cvss < curl.effective_cvss
    assert ssh_enum.risk_score > curl.risk_score
    assert ssh_enum.rank < curl.rank


def test_high_cvss_on_a_build_agent_lands_in_the_backlog():
    scored, _ = _scored()
    openssl = _find(scored, "CVE-2022-0778", "dev-build-02")       # CVSS 7.5
    assert openssl.priority == "P4"


def test_critical_asset_with_kev_exploit_tops_the_queue():
    scored, _ = _scored()
    assert all(f.priority == "P1" for f in scored[:4])
    assert all(f.intel.kev for f in scored[:4])


def test_exposure_breaks_a_tie_between_equal_cvss():
    """Spring4Shell (internet-facing, high) outranks BlueKeep (internal, critical)."""
    scored, _ = _scored()
    spring4shell = _find(scored, "CVE-2022-22965", "edge-web-01")
    bluekeep = _find(scored, "CVE-2019-0708", "dc-01")
    assert spring4shell.effective_cvss == bluekeep.effective_cvss == 9.8
    assert spring4shell.risk_score > bluekeep.risk_score


def test_scanner_noise_ranks_last():
    """SWEET32: reported constantly, exploitable essentially never."""
    scored, _ = _scored()
    assert scored[-1].cve == "CVE-2016-2183"
    assert scored[-1].priority == "P4"


def test_breakdown_reconstructs_the_score():
    scored, _ = _scored()
    for f in scored:
        b = f.breakdown
        raw = b.base_cvss * b.asset_weight * b.exploit_weight * b.exposure_weight
        assert abs(raw - b.raw_score) < 0.01
        assert abs(round(min(100.0, raw / MAX_RAW_SCORE * 100), 1) - f.risk_score) < 0.05


def test_every_multiplier_carries_a_reason():
    scored, _ = _scored()
    for f in scored:
        assert f.breakdown.asset_reason and f.breakdown.exploit_reason
        assert f.breakdown.exposure_reason and f.rationale


def test_kev_floors_the_exploit_weight():
    """KEV means confirmed in-the-wild exploitation — never averaged away."""
    scored, _ = _scored()
    for f in scored:
        if f.intel.kev:
            assert f.breakdown.exploit_weight == 1.60, f.cve


def test_priority_bands():
    assert priority_for(90.0)[0] == "P1"
    assert priority_for(75.0)[0] == "P1"
    assert priority_for(74.9)[0] == "P2"
    assert priority_for(55.0)[0] == "P2"
    assert priority_for(35.0)[0] == "P3"
    assert priority_for(0.0)[0] == "P4"


def test_ranks_are_dense_and_ordered():
    scored, _ = _scored()
    assert [f.rank for f in scored] == list(range(1, len(scored) + 1))
    assert all(a.risk_score >= b.risk_score for a, b in zip(scored, scored[1:]))


def test_rank_delta_is_measured_against_the_cvss_ordering():
    scored, _ = _scored()
    smbghost = _find(scored, "CVE-2020-0796", "branch-114-fs01")
    assert smbghost.cvss_rank == 1, "CVSS 10.0 would top a raw-CVSS sort"
    assert smbghost.rank > 5, "a medium-criticality branch file server should not be P1"
    assert smbghost.rank_delta == smbghost.cvss_rank - smbghost.rank


def test_score_is_capped_at_100():
    scored, _ = _scored()
    assert all(0 <= f.risk_score <= 100 for f in scored)


# --------------------------------------------------------------------------- #
# remediation + report
# --------------------------------------------------------------------------- #

def test_remediation_plan_has_actionable_steps():
    scored, _ = _scored()
    for f in scored[:5]:
        plan = remediation_for(f)
        assert plan["summary"] and plan["steps"]
        assert plan["effort"] in ("low", "medium", "high", "unknown")


def test_heartbleed_flags_that_patching_is_not_enough():
    scored, _ = _scored()
    plan = remediation_for(_find(scored, "CVE-2014-0160", "hr-app-03"))
    assert any("rotation" in c.lower() for c in plan["constraints"])


def test_pos_terminal_constraint_is_raised():
    scored, _ = _scored()
    plan = remediation_for(_find(scored, "CVE-2021-34527", "pos-term-221"))
    joined = " ".join(plan["constraints"]).lower()
    assert "pos" in joined or "trading hours" in joined
    assert "pci" in joined


def test_unknown_cve_gets_an_investigate_plan_not_a_fake_fix():
    scored, _ = _scored()
    plan = remediation_for(_find(scored, "CVE-2022-31813", "10.114.8.55"))
    assert plan["type"] == "investigate"
    assert plan["effort"] == "unknown"


def test_markdown_report_contains_the_essentials():
    _, state = _scored()
    md = build_markdown(state, top_n=5)
    for expected in (
        "# Vulnerability Triage Report",
        "## Executive summary",
        "## Why this ranking is not the CVSS ranking",
        "## Ranked findings",
        "## Remediation plan",
        "Appendix A",
        "Appendix B",
    ):
        assert expected in md, expected
    assert "CVE-2018-15473" in md


def test_json_report_is_complete():
    _, state = _scored()
    payload = build_json(state, top_n=5)
    assert payload["summary"]["findings"] == len(state.scored)
    assert sum(payload["summary"]["by_priority"].values()) == len(state.scored)
    assert all("remediation_plan" in f for f in payload["findings"])
    assert all("breakdown" in f for f in payload["findings"])


def test_csv_has_one_row_per_finding_in_rank_order():
    _, state = _scored()
    rows = build_csv_rows(state)
    assert len(rows) == len(state.scored)
    assert [int(r["rank"]) for r in rows] == list(range(1, len(rows) + 1))


def test_csv_carries_the_requested_columns():
    """CVE, CVSS, asset, risk rank, and remediation — the point of the export."""
    _, state = _scored()
    top = build_csv_rows(state)[0]
    assert top["cve"].startswith("CVE-")
    assert float(top["cvss"]) > 0
    assert top["hostname"] and top["asset_criticality"] and top["asset_owner"]
    assert top["rank"] == "1" and float(top["risk_score"]) > 0 and top["priority"] == "P1"
    assert top["remediation_summary"] and top["remediation_steps"]
    assert top["effort"] in ("low", "medium", "high", "unknown")


def test_csv_rows_are_single_line_and_fully_populated():
    """A stray newline turns one finding into two rows in every spreadsheet."""
    _, state = _scored()
    for row in build_csv_rows(state):
        assert set(row) == set(CSV_COLUMNS)
        for column, value in row.items():
            assert "\n" not in value and "\r" not in value, f"{column} spans lines"


def test_csv_neutralizes_spreadsheet_formula_injection():
    assert _csv_safe("=cmd|'/c calc'!A1").startswith("'=")
    assert _csv_safe("+1234").startswith("'+")
    assert _csv_safe("-DOPENSSL_NO_HEARTBEATS").startswith("'-")
    assert _csv_safe("@SUM(A1)").startswith("'@")
    assert _csv_safe("CVE-2021-44228") == "CVE-2021-44228", "normal values are untouched"


def test_csv_booleans_and_lists_are_readable():
    _, state = _scored()
    rows = {r["cve"]: r for r in build_csv_rows(state)}
    assert rows["CVE-2020-1472"]["kev"] == "yes"
    assert rows["CVE-2016-2183"]["kev"] == "no"
    assert "PCI-DSS" in rows["CVE-2022-22965"]["compliance_scope"]
    assert "1. " in rows["CVE-2022-22965"]["remediation_steps"]


def test_csv_file_round_trips_through_a_reader():
    import csv as _csv
    import tempfile

    _, state = _scored()
    with tempfile.TemporaryDirectory() as tmp:
        path = write_csv(state, Path(tmp) / "triage.csv")
        with path.open(newline="", encoding="utf-8-sig") as handle:
            parsed = list(_csv.DictReader(handle))
    assert len(parsed) == len(state.scored)
    assert parsed[0]["cve"] == state.scored[0].cve
    assert parsed[0]["rank"] == "1"


def test_write_reports_emits_all_three_formats():
    import tempfile

    _, state = _scored()
    with tempfile.TemporaryDirectory() as tmp:
        out = write_reports(state, tmp, top_n=5)
        assert out.markdown.exists() and out.json.exists() and out.csv.exists()
        assert out.csv.suffix == ".csv"
        assert out.csv.read_text(encoding="utf-8-sig").count("\n") >= len(state.scored)
        assert out.warnings == []


def test_locked_output_file_falls_back_instead_of_losing_the_run():
    """A CSV open in Excel must not destroy a completed crew run."""
    import tempfile

    _, state = _scored()
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "triage_report.csv"
        target.write_text("held open", encoding="utf-8")
        handle = target.open("a", encoding="utf-8")  # Windows: takes a write lock
        try:
            out = write_reports(state, tmp, top_n=5)
        finally:
            handle.close()

        assert out.markdown.exists() and out.json.exists()
        assert out.csv.exists() and out.csv.read_text(encoding="utf-8-sig")
        if out.csv != target:  # POSIX allows the overwrite; Windows does not
            assert out.warnings and "locked" in out.warnings[0]
            assert out.csv.name.startswith("triage_report-")


def test_unusable_agent_output_is_rejected():
    """A refusal or a leaked tool call must never be published as analysis."""
    assert usable_note("I can't help you with that.") is None
    assert usable_note('{"name": "get_findings", "parameters": {"top_n": "5"}}') is None
    assert usable_note("") is None
    assert usable_note(None) is None
    assert usable_note("x" * 200) == "x" * 200


def test_stage_guards_refuse_to_run_out_of_order():
    state = PipelineState()
    for guard in (state.require_normalized, state.require_enriched, state.require_scored):
        try:
            guard()
        except RuntimeError:
            continue
        raise AssertionError(f"{guard.__name__} should refuse an empty pipeline")


def test_rerunning_discovery_invalidates_downstream_stages():
    from vulntriage.pipeline import run_discovery, run_enrichment

    state = PipelineState()
    run_offline(SAMPLE_JSON, state)
    assert state.scored
    run_discovery(SAMPLE_CSV, state)
    assert not state.enriched and not state.scored, "stale results must not survive new input"
    run_enrichment(state)
    assert state.enriched and not state.scored


def test_scoring_is_deterministic():
    first, _ = _scored()
    second, _ = _scored()
    assert [(f.finding_id, f.risk_score, f.rank) for f in first] == [
        (f.finding_id, f.risk_score, f.rank) for f in second
    ]


def test_empty_input_does_not_crash_scoring():
    assert score_all([]) == []


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
