"""CrewAI tools — the agents' hands.

Design rule for this project: **mechanical work goes in a tool, judgment goes in
the prompt.** Parsing a scanner export, joining a CVE database, and multiplying
four weights together are all deterministic, testable operations. Asking a
language model to do them by hand is how these pipelines silently corrupt data.

So each tool does the mechanical work, writes its structured result to
`vulntriage.state.STATE`, and returns a compact summary for the agent to reason
over. The agent then does the thing only it can do: notice what looks wrong,
weigh trade-offs, and explain the result to a human.
"""

from .asset_lookup import AssetLookupTool
from .cve_lookup import CVELookupTool, CVERemediationTool
from .enrichment import EnrichFindingsTool
from .findings_loader import LoadFindingsTool
from .risk_scoring import RankedFindingsTool, ScoreAndRankTool

__all__ = [
    "AssetLookupTool",
    "CVELookupTool",
    "CVERemediationTool",
    "EnrichFindingsTool",
    "LoadFindingsTool",
    "RankedFindingsTool",
    "ScoreAndRankTool",
]
