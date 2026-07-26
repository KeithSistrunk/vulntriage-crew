#!/usr/bin/env python3
"""VulnTriage — entry point.

    python main.py                          # run the crew on the sample findings
    python main.py --offline                # deterministic pipeline, no LLM required
    python main.py --input data/sample_findings.csv
    python main.py --provider openai --model gpt-4o-mini
    python main.py --top-n 8 --verbose
    python main.py --strict-narrative       # fail the run if the guard flags a claim

Writes `output/triage_report.md` and `output/triage_report.json`.

Every crew run passes through the narrative guard (`vulntriage/guard.py`) before
the report is written: anything an agent asserts that contradicts the structured
data is flagged inline. Exit 3 with --strict-narrative, 0 otherwise.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulntriage.pipeline import (
    run_discovery,
    run_enrichment,
    run_offline,
    run_prioritization,
)
from vulntriage.report import write_reports, write_with_fallback
from vulntriage.state import STATE

ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT = ROOT / "data" / "sample_findings.json"
DEFAULT_OUTPUT = ROOT / "output"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vulntriage",
        description="Multi-agent vulnerability triage: discovery, enrichment, prioritization, remediation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input", "-i", default=str(DEFAULT_INPUT),
                        help="Raw scanner export, .json or .csv (default: data/sample_findings.json)")
    parser.add_argument("--output-dir", "-o", default=str(DEFAULT_OUTPUT),
                        help="Where to write the report (default: output/)")
    parser.add_argument("--top-n", "-n", type=int, default=5,
                        help="How many findings get a full remediation write-up (default: 5)")
    parser.add_argument("--offline", action="store_true",
                        help="Run the deterministic pipeline only — no LLM, no CrewAI, no API key")
    parser.add_argument("--provider", choices=["ollama", "openai"], default=None,
                        help="LLM backend (default: ollama, or $LLM_PROVIDER)")
    parser.add_argument("--model", default=None,
                        help="Model name, e.g. llama3.1:8b or gpt-4o-mini (default: $LLM_MODEL)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Stream each agent's reasoning and tool calls")
    parser.add_argument("--strict-narrative", action="store_true",
                        help="Exit 3 if the narrative guard flags an unsupported claim "
                             "(the report is still written). For CI.")
    return parser.parse_args(argv)


def print_summary(top_n: int) -> None:
    scored = STATE.scored
    report = STATE.normalization_report
    counts: dict[str, int] = {}
    for f in scored:
        counts[f.priority] = counts.get(f.priority, 0) + 1

    print()
    print("=" * 78)
    print("TRIAGE SUMMARY")
    print("=" * 78)
    if report:
        print(
            f"{report.raw_rows} raw rows -> {len(scored)} findings "
            f"({report.dropped_informational} informational, {report.dropped_no_cve} no-CVE, "
            f"{report.dropped_not_open} already remediated, {report.duplicates_collapsed} duplicates "
            f"collapsed, {report.multi_cve_rows_split} multi-CVE rows split)"
        )
    print("Priority: " + "  ".join(f"{p}={counts.get(p, 0)}" for p in ("P1", "P2", "P3", "P4")))
    print()
    print(f"Top {min(top_n, len(scored))} by risk:")
    for f in scored[:top_n]:
        delta = f.rank_delta or 0
        moved = f" [{'+' if delta > 0 else ''}{delta} vs CVSS rank #{f.cvss_rank}]" if delta else ""
        print(
            f"  {f.rank}. {f.risk_score:>5}  {f.priority}  {f.cve:<16} {f.hostname:<18} "
            f"CVSS {f.effective_cvss:<5}{moved}"
        )
    print()


def run_crew(args: argparse.Namespace) -> int:
    """Run the four-agent crew, then make sure a report gets written either way."""
    import os

    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider
    if args.model:
        os.environ["LLM_MODEL"] = args.model

    from vulntriage.config import LLMSettings, preflight

    settings = LLMSettings()
    ok, message = preflight(settings)
    if not ok:
        print(f"LLM backend unavailable ({settings.describe()}).\n", file=sys.stderr)
        print(message, file=sys.stderr)
        return 2

    from vulntriage.crew import VulnTriageCrew

    print(f"Running the VulnTriage crew on {args.input}")
    print(f"  LLM: {settings.describe()}")
    print(f"  Agents: Discovery -> Enrichment -> Prioritization -> Remediation (sequential)")
    print()

    crew = VulnTriageCrew(
        findings_path=args.input,
        top_n=args.top_n,
        settings=settings,
        verbose=args.verbose,
    )
    crew.run()

    # An agent can decline to call its tool — small local models sometimes answer
    # from the previous stage's text instead. The data stages are deterministic, so
    # finish any the crew skipped rather than emitting a half-empty report.
    fallbacks = (
        ("discovery", lambda: not STATE.normalized, lambda: run_discovery(args.input, STATE)),
        ("enrichment", lambda: not STATE.enriched, lambda: run_enrichment(STATE)),
        ("prioritization", lambda: not STATE.scored, lambda: run_prioritization(STATE)),
    )
    for stage, is_missing, complete in fallbacks:
        if not is_missing():
            continue
        print(
            f"WARNING: the {stage} agent did not invoke its tool. Completing that stage "
            f"deterministically so the report is still correct.",
            file=sys.stderr,
        )
        complete()
        STATE.note(
            stage,
            (
                STATE.agent_notes.get(stage, "")
                + "\n\n> *This stage was completed deterministically because the agent "
                  "did not invoke its tool. The data is correct; the narrative is not.*"
            ).strip(),
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Findings file not found: {input_path}", file=sys.stderr)
        return 1

    if args.offline:
        print(f"Running the deterministic pipeline on {input_path} (no LLM).")
        run_offline(input_path, STATE)
    else:
        code = run_crew(args)
        if code:
            return code

    outputs = write_reports(STATE, args.output_dir, args.top_n)

    # Same lock fallback as the three reports: an unattended run must not lose its
    # state file to an editor holding a handle on it.
    state_path, state_warning = write_with_fallback(
        Path(args.output_dir) / "pipeline_state.json", lambda p: STATE.save(p)
    )

    print_summary(args.top_n)
    print(f"Report:  {outputs.markdown}")
    print(f"JSON:    {outputs.json}")
    print(f"CSV:     {outputs.csv}  ({len(STATE.scored)} rows, one per finding)")
    print(f"State:   {state_path}")

    guard = outputs.guard
    print(f"Guard:   {guard.summary()}")
    for violation in guard.violations:
        print(f"           {violation.stage}: {violation.code} {violation.check} — "
              f"{violation.message}")
    if guard.violations:
        print(
            "\nWARNING: the narrative contradicts the structured data in the places "
            "listed above. They are flagged inline in the report; the findings, "
            "scores and remediation steps are unaffected.",
            file=sys.stderr,
        )

    for warning in [*outputs.warnings, *filter(None, [state_warning])]:
        print(f"\nWARNING: {warning}", file=sys.stderr)
    print()
    print("Proposals only — an analyst approves before anything is changed.")

    if args.strict_narrative and guard.violations:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
