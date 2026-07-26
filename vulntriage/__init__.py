"""VulnTriage — a CrewAI multi-agent vulnerability triage workflow.

Four agents run in sequence over raw scanner output:

    Discovery  ->  Enrichment  ->  Prioritization  ->  Remediation

Importing this package does not import CrewAI. The crew lives in
`vulntriage.crew`; the deterministic engine underneath it lives in
`vulntriage.pipeline` and runs with nothing but pydantic.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
