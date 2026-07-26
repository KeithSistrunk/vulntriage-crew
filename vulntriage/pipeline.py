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
from .normalize import normalize_file
from .scoring import score_all
from .state import STATE, PipelineState


def run_discovery(path: str | Path, state: PipelineState = STATE) -> NormalizationReport:
    findings, report = normalize_file(path)
    state.source_file = str(path)
    state.normalized = findings
    state.normalization_report = report
    # A new input invalidates anything downstream.
    state.enriched = []
    state.scored = []
    return report


def run_enrichment(state: PipelineState = STATE) -> int:
    state.enriched = enrich_all(state.require_normalized())
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
