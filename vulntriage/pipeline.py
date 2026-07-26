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


def run_discovery(path: str | Path, state: PipelineState = STATE) -> NormalizationReport:
    """Discovery from whichever source the state is configured for.

    The agent's tool calls this with a file path and does not know or care where
    findings actually come from -- `--source tenable` is a run-level decision,
    not something to re-explain to a language model.
    """
    if state.finding_source == "tenable" and state.tenable_client is not None:
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
    """Discovery against a live Tenable pull.

    The client hands back raw rows in the same shape the mock export uses, so the
    normalizer -- and every quirk it already handles -- runs unchanged. That is
    the entire reason the Tenable client returns dicts rather than models.
    """
    rows = client.fetch_findings()
    findings, report = normalize(rows, source_file=f"tenable:{client.flavor}", source_format="api")
    state.source_file = report.source_file
    state.normalized = findings
    state.normalization_report = report
    state.enriched = []
    state.scored = []
    return report


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
