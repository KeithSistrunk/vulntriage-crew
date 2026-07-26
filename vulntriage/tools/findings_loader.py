"""Discovery agent tool: load and normalize a raw scanner export."""

from __future__ import annotations

from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from ..live.http import LiveFetchError
from ..live.tenable import TenableAuthError
from ..pipeline import run_discovery
from ..state import STATE


class LoadFindingsInput(BaseModel):
    file_path: str = Field(
        ...,
        description="Path to the raw scanner export (.json or .csv), "
        "e.g. 'data/sample_findings.json'.",
    )


class LoadFindingsTool(BaseTool):
    name: str = "load_and_normalize_findings"
    description: str = (
        "Read a raw Tenable/Nessus export (JSON or CSV) and normalize it into one clean "
        "finding per host + port + CVE. Handles inconsistent host naming, rows carrying "
        "several CVEs, duplicate plugins reporting the same exposure, missing CVSS values, "
        "and CVE ids that only appear in the plugin name. Drops informational rows, rows "
        "with no CVE, and rows already marked remediated. "
        "Returns a normalization audit plus the finding inventory. Call this exactly once."
    )
    args_schema: Type[BaseModel] = LoadFindingsInput

    def _run(self, file_path: str, **_: object) -> str:
        try:
            report = run_discovery(file_path.strip().strip("'\""), STATE)
        except (FileNotFoundError, ValueError) as exc:
            return f"ERROR: {exc}"
        except (LiveFetchError, TenableAuthError) as exc:
            # A live pull failing must reach the agent as a readable error, not
            # as a traceback that takes the whole crew run down with it.
            return f"ERROR: could not read findings from Tenable: {exc}"

        lines = [
            f"Normalized `{report.source_file}` ({report.source_format.upper()}).",
            "",
            "AUDIT",
            f"- raw rows read: {report.raw_rows}",
            f"- findings after normalization: {report.normalized_findings}",
            f"- dropped, informational: {report.dropped_informational}",
            f"- dropped, no CVE reference: {report.dropped_no_cve}",
            f"- dropped, already remediated: {report.dropped_not_open}",
            f"- duplicate findings collapsed: {report.duplicates_collapsed}",
            f"- multi-CVE rows split: {report.multi_cve_rows_split}",
            f"- CVE ids recovered from plugin names: {report.cve_recovered_from_plugin_name}",
            f"- hosts: {', '.join(report.hosts)}",
            "",
            "ANOMALIES",
        ]
        lines += [f"- {a}" for a in report.anomalies] or ["- none"]

        # A per-host rollup rather than the full finding list. The findings
        # themselves are in the pipeline; the agent needs the shape, not the rows.
        by_host: dict[str, int] = {}
        for f in STATE.normalized:
            by_host[f.hostname] = by_host.get(f.hostname, 0) + 1
        lines += ["", "FINDINGS PER HOST"]
        lines += [
            f"- {host}: {count}" for host, count in sorted(by_host.items(), key=lambda kv: -kv[1])
        ]
        lines += [
            "",
            f"{report.normalized_findings} findings are now in the pipeline and ready for "
            "enrichment. Write your review from the audit and anomalies above — do not "
            "reproduce this output.",
        ]
        return "\n".join(lines)
