"""Crew orchestration.

Four agents, sequential process, one stage each:

    Discovery -> Enrichment -> Prioritization -> Remediation

Sequential is the right shape here and not just the easy one: enrichment has
nothing to enrich until discovery has normalized, and scoring is meaningless
until the asset and exploit context exists. The dependencies are real.
"""

from __future__ import annotations

from pathlib import Path

from crewai import Crew, Process

from .agents import build_agents
from .config import LLMSettings, build_llm
from .state import STATE, PipelineState
from .tasks import build_tasks

STAGES = ("discovery", "enrichment", "prioritization", "remediation")


class VulnTriageCrew:
    """The four-agent triage crew."""

    def __init__(
        self,
        findings_path: str | Path,
        top_n: int = 5,
        settings: LLMSettings | None = None,
        verbose: bool = False,
        state: PipelineState = STATE,
    ) -> None:
        self.findings_path = str(findings_path)
        self.top_n = top_n
        self.settings = settings or LLMSettings()
        self.verbose = verbose
        self.state = state

        self.llm = build_llm(self.settings)
        self.agents = build_agents(llm=self.llm, verbose=verbose)
        self.tasks = build_tasks(self.agents, self.findings_path, top_n)

    def build(self) -> Crew:
        return Crew(
            agents=[self.agents[s] for s in STAGES],
            tasks=self.tasks,
            process=Process.sequential,
            verbose=self.verbose,
            # CrewAI otherwise prompts on stdin for trace collection after a run,
            # which hangs any non-interactive invocation until it times out.
            tracing=False,
        )

    def run(self):
        """Run the crew, then capture each agent's narrative into the pipeline state.

        The crew's return value is only the last task's output, so the per-stage
        analysis is read back off the task objects.
        """
        self.state.reset()
        result = self.build().kickoff()

        for stage, task in zip(STAGES, self.tasks):
            output = getattr(task, "output", None)
            if output is not None:
                self.state.note(stage, str(getattr(output, "raw", output)))

        return result
