"""Shared pipeline state.

CrewAI passes one task's output to the next as *text*. That is fine for reasoning
and terrible for a hundred structured findings -- an LLM re-typing a JSON array at
every hop is where these pipelines lose data.

So the crew passes analysis through the LLM and data through here. Each stage's
tool writes its structured output to this store and returns a compact summary for
the agent to reason over; the next stage's tool reads the structured copy back.
The final report is assembled from this store, not from the model's transcript.

Single process, single run -- a module-level singleton is the right amount of
machinery. Persistence is a future add-on, not a POC concern.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    EnrichedFinding,
    NormalizationReport,
    NormalizedFinding,
    ScoredFinding,
)


class PipelineState:
    """Structured hand-off between pipeline stages."""

    def __init__(self) -> None:
        # Run configuration: which feed findings come from and which live intel
        # is switched on. Deliberately *not* cleared by `reset()` -- the crew
        # resets state before it runs, and losing the source mid-run would
        # silently drop a live pull back to the sample file.
        self.finding_source: str = "mock"
        self.tenable_client: Any | None = None
        self.live: Any | None = None
        self.reset()

    def configure(
        self,
        finding_source: str = "mock",
        tenable_client: Any | None = None,
        live: Any | None = None,
    ) -> None:
        """Point the pipeline at live sources. Called once, before discovery."""
        self.finding_source = finding_source
        self.tenable_client = tenable_client
        self.live = live

    @property
    def live_warnings(self) -> list[str]:
        return list(getattr(self.live, "warnings", []) or [])

    def reset(self) -> None:
        self.source_file: str | None = None
        self.normalized: list[NormalizedFinding] = []
        self.normalization_report: NormalizationReport | None = None
        self.enriched: list[EnrichedFinding] = []
        self.scored: list[ScoredFinding] = []
        self.agent_notes: dict[str, str] = {}

    # -- stage guards -------------------------------------------------------
    def require_normalized(self) -> list[NormalizedFinding]:
        if not self.normalized:
            raise RuntimeError(
                "No normalized findings in the pipeline. Run the discovery tool "
                "(load_and_normalize_findings) first."
            )
        return self.normalized

    def require_enriched(self) -> list[EnrichedFinding]:
        if not self.enriched:
            raise RuntimeError(
                "No enriched findings in the pipeline. Run the enrichment tool "
                "(enrich_findings) first."
            )
        return self.enriched

    def require_scored(self) -> list[ScoredFinding]:
        if not self.scored:
            raise RuntimeError(
                "No scored findings in the pipeline. Run the prioritization tool "
                "(score_and_rank_findings) first."
            )
        return self.scored

    # -- accessors ----------------------------------------------------------
    def top(self, n: int) -> list[ScoredFinding]:
        return self.require_scored()[: max(0, n)]

    def by_id(self, finding_id: str) -> ScoredFinding | EnrichedFinding | None:
        for pool in (self.scored, self.enriched):
            for finding in pool:
                if finding.finding_id == finding_id:
                    return finding
        return None

    def note(self, stage: str, text: str) -> None:
        """Record an agent's narrative for a stage, for the final report."""
        self.agent_notes[stage] = (text or "").strip()

    # -- serialization ------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "normalization_report": (
                self.normalization_report.model_dump() if self.normalization_report else None
            ),
            "normalized": [f.model_dump() for f in self.normalized],
            "enriched": [f.model_dump() for f in self.enriched],
            "scored": [f.model_dump() for f in self.scored],
            "agent_notes": self.agent_notes,
        }

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.snapshot(), indent=2), encoding="utf-8")
        return path


STATE = PipelineState()
"""The process-wide pipeline state the agent tools read and write."""
