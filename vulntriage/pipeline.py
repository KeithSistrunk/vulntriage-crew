"""The deterministic pipeline underneath the crew.

Each function here is exactly what the corresponding agent's tool calls. Running
them in order (`run_offline`) reproduces the whole triage without touching an LLM
— useful for testing the risk model, for CI, and for demoing the project on a
machine with no Ollama and no API key.

Importing this module must never import CrewAI. That is what keeps `--offline`
working with nothing but pydantic installed.
"""

from __future__ import annotations

from pathlib import Path

from .intel import enrich_all
from .models import NormalizationReport, ScoredFinding
from .normalize import normalize, normalize_file
from .scoring import score_all
from .state import STATE, PipelineState


# Sources that arrive through a client rather than by reading `path`. The Tenable
# API and a Tenable CSV export both land here: the export is parsed by a client
# that subclasses the API one, so both are sampled by the same code.
CLIENT_SOURCES = {"tenable", "csv"}


def run_discovery(path: str | Path, state: PipelineState = STATE) -> NormalizationReport:
    """Discovery from whichever source the state is configured for.

    The agent's tool calls this with a file path and does not know or care where
    findings actually come from -- `--source tenable` is a run-level decision,
    not something to re-explain to a language model.
    """
    if state.finding_source in CLIENT_SOURCES and state.tenable_client is not None:
        return run_discovery_tenable(state.tenable_client, state)

    findings, report = normalize_file(path)
    state.source_file = str(path)
    state.normalized = findings
    state.normalization_report = report
    # A new input invalidates anything downstream.
    state.enriched = []
    state.scored = []
    return report


def run_discovery_tenable(client, state: PipelineState = STATE) -> NormalizationReport:
    """Discovery against a Tenable pull -- the API, one scan, or a CSV export.

    The client hands back raw rows in the same shape the mock export uses, so the
    normalizer -- and every quirk it already handles -- runs unchanged. That is
    the entire reason the Tenable client returns dicts rather than models.

    The client samples and caps the pull; this re-applies the cap to the findings
    as a backstop, because the ceiling has to hold on what *enrichment* sees --
    a rate-limited NVD call per CVE -- not on what the pull happened to return.

    It also records the sampling in the report. A capped run is a sample of the
    estate, and a report that does not say so reads as a clean bill of health.
    """
    rows = client.fetch_findings()
    findings, report = normalize(
        rows,
        source_file=getattr(client, "source_label", f"tenable:{client.flavor}"),
        source_format=getattr(client, "source_format", "api"),
    )
    findings = _apply_limit(findings, getattr(client, "limit", None), report)
    _note_sampling(client, report)
    state.source_file = report.source_file
    state.normalized = findings
    state.normalization_report = report
    state.enriched = []
    state.scored = []
    return report


def _apply_limit(findings, limit, report: NormalizationReport):
    """Trim to `limit` findings and say so in the report.

    The report has to be trimmed with the findings: `normalized_findings` and
    `hosts` are what the run summary and the narrative guard read, and leaving
    them describing findings that were dropped would make the report claim
    coverage the run does not have.
    """
    if not limit or len(findings) <= limit:
        return findings

    dropped = len(findings) - limit
    findings = findings[:limit]
    report.normalized_findings = len(findings)
    report.hosts = sorted({f.hostname for f in findings})
    report.anomalies.append(
        f"Capped at {limit} finding(s) (--limit): {dropped} more were pulled and "
        "discarded before enrichment. This run does not cover the whole estate."
    )
    return findings


def _note_sampling(client, report: NormalizationReport) -> None:
    """Record what the sampled pull left behind, in the report itself."""
    limit = getattr(client, "limit", None)
    if not limit:
        return

    # "workbench", "scan 58373", "export Keith-Scan.csv" -- whatever the client
    # says it walked, so a new source describes itself instead of being guessed at.
    pool = getattr(client, "pool", "workbench")
    scope = "of the estate" if pool == "workbench" else f"of {pool}"
    report.anomalies.append(
        f"Sampled pull: up to {limit} distinct CVE(s) at CVSS >= "
        f"{getattr(client, 'min_cvss', 0)}, most severe first, one host per CVE. "
        f"{getattr(client, 'plugins_examined', 0)} of {getattr(client, 'plugins_seen', 0)} "
        f"{pool} plugin(s) were examined. This is a sample {scope}, not a survey."
    )
    recovered = getattr(client, "cves_recovered_from_name", 0)
    if recovered:
        report.anomalies.append(
            f"{recovered} CVE id(s) were recovered from the plugin name because the source "
            "carried no CVE reference for them. Treat the identifier as inferred, not asserted."
        )
    crowded_out = getattr(client, "hosts_not_sampled", 0)
    if crowded_out:
        report.anomalies.append(
            f"{crowded_out} further affected host(s) carry the CVEs shown and were not "
            "sampled. Remediation scope per CVE is wider than this report's host list."
        )


def run_enrichment(state: PipelineState = STATE, live=None) -> int:
    state.enriched = enrich_all(
        state.require_normalized(), live=live or state.live, assets=state.asset_index
    )
    state.scored = []
    return len(state.enriched)


def run_prioritization(state: PipelineState = STATE) -> list[ScoredFinding]:
    state.scored = score_all(state.require_enriched())
    return state.scored


def run_offline(path: str | Path, state: PipelineState = STATE) -> list[ScoredFinding]:
    """Full triage with no LLM in the loop."""
    state.reset()
    run_discovery(path, state)
    run_enrichment(state)
    return run_prioritization(state)
