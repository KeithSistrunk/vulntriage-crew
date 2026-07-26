#!/usr/bin/env python3
"""VulnTriage — entry point.

    python main.py                          # run the crew on the sample findings
    python main.py --offline                # deterministic pipeline, no LLM required
    python main.py --input data/sample_findings.csv
    python main.py --provider openai --model gpt-4o-mini
    python main.py --top-n 8 --verbose
    python main.py --source tenable --limit 50    # cap the live pull (default 20)
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

# Imported lazily-ish: these live in vulntriage.live, which pulls in no CrewAI
# and no third-party HTTP library, so importing it here costs nothing.
from vulntriage.live.http import LiveFetchError  # noqa: E402
from vulntriage.live.tenable import (  # noqa: E402
    DEFAULT_FINDING_LIMIT,
    DEFAULT_MIN_CVSS,
    TenableAuthError,
)

SOURCE_ERRORS = (LiveFetchError, TenableAuthError)


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
    parser.add_argument("--source", choices=["mock", "tenable"], default="mock",
                        help="Where findings come from: the sample export (default) or a live "
                             "Tenable pull (needs TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY)")
    parser.add_argument("--limit", type=int, default=DEFAULT_FINDING_LIMIT,
                        help=f"Cap a live Tenable pull at this many distinct CVEs "
                             f"(default: {DEFAULT_FINDING_LIMIT}, 0 for no cap). Applied at the "
                             f"pull, so nothing beyond the cap is enriched. No effect on "
                             f"--source mock.")
    parser.add_argument("--min-cvss", type=float, default=DEFAULT_MIN_CVSS,
                        help=f"Drop live findings below this CVSS before the cap is applied "
                             f"(default: {DEFAULT_MIN_CVSS}, 0 for no floor). Lower it if too "
                             f"few findings survive.")
    parser.add_argument("--live-intel", action="store_true",
                        help="Enrich against live CISA KEV, FIRST EPSS and NVD instead of the "
                             "local CVE database")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass the on-disk live-intel cache and re-fetch everything")
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
    # A capped run is a sample of the estate, not a survey of it. Saying so next
    # to the counts is the difference between a demo and a misleading report.
    client = STATE.tenable_client
    if client is not None and getattr(client, "limit", None):
        cap = "capped" if client.truncated else "under the cap"
        print(
            f"Sampled: {len(scored)} distinct CVE(s) at CVSS >= {client.min_cvss} ({cap} at "
            f"{client.limit}) — {client.plugins_examined} of {client.plugins_seen} workbench "
            f"plugin(s) examined, {client.plugins_below_min_cvss} below the floor."
        )
        if client.hosts_not_sampled:
            print(
                f"         {client.hosts_not_sampled} further affected host(s) share these "
                f"CVEs and were not sampled. One host per CVE is shown."
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


def configure_sources(args: argparse.Namespace) -> int:
    """Point STATE at whatever live feeds were asked for. Returns an exit code.

    Failing to *configure* a source is fatal here -- if you asked for Tenable and
    the keys are missing, silently triaging the sample file instead would be a
    lie. Failing to *reach* a feed later is not: the clients degrade and the run
    continues with less context.
    """
    # A stale exported variable silently beating .env looks identical to a
    # rejected credential. Never let that be silent.
    try:
        from vulntriage.config import SHADOWED_BY_SHELL

        if SHADOWED_BY_SHELL:
            print(
                f"WARNING: {', '.join(sorted(SHADOWED_BY_SHELL))} differ between .env and your\n"
                f"  shell environment, and the shell wins. The value in .env is NOT being used.\n"
                f"  Clear the exported variable, or export the value you actually want.",
                file=sys.stderr,
            )
    except ImportError:
        pass

    live = None
    if args.live_intel:
        from vulntriage.live import EpssClient, KevClient, LiveIntel, NvdClient
        from vulntriage.live.cache import Cache
        from vulntriage.live.epss import EPSS_TTL_SECONDS
        from vulntriage.live.kev import KEV_TTL_SECONDS
        from vulntriage.live.nvd import NVD_TTL_SECONDS

        use_cache = not args.no_cache
        live = LiveIntel(
            kev=KevClient(cache=Cache("kev", ttl_seconds=KEV_TTL_SECONDS, enabled=use_cache)),
            epss=EpssClient(cache=Cache("epss", ttl_seconds=EPSS_TTL_SECONDS, enabled=use_cache)),
            nvd=NvdClient(cache=Cache("nvd", ttl_seconds=NVD_TTL_SECONDS, enabled=use_cache)),
        )
        print("Live intel: CISA KEV + FIRST EPSS + NVD" + ("" if use_cache else " (cache bypassed)"))

    client = None
    if args.source == "tenable":
        from vulntriage.live import TenableClient

        client = TenableClient(limit=args.limit, min_cvss=args.min_cvss)
        if not client.configured:
            print(
                "--source tenable needs TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY.\n"
                "  Copy .env.example to .env and fill them in, or run with --source mock.",
                file=sys.stderr,
            )
            return 2
        print(f"Findings source: Tenable ({client.flavor}) at {client.base_url}")
        floor = f"CVSS >= {client.min_cvss}" if client.min_cvss else "no CVSS floor"
        if client.limit:
            print(f"  Sampling: {floor}, one host per CVE, most severe first, "
                  f"up to {client.limit} distinct CVEs")
        else:
            print(f"  Sampling: {floor}, no cap — every affected host")

    # Asset criticality from the scanner. Without it every live finding scores at
    # the neutral asset weight, and the ranking collapses toward a CVSS sort --
    # the exact thing this project exists to avoid.
    asset_index: dict = {}
    if client is not None:
        asset_index = client.fetch_asset_contexts()
        if asset_index:
            print(f"Asset criticality: {len(asset_index)} identities from Tenable ACR")
        else:
            print(
                "WARNING: no Tenable asset data — every finding will score at the neutral\n"
                "  asset weight, which flattens the ranking toward raw CVSS.",
                file=sys.stderr,
            )

    STATE.configure(
        finding_source=args.source, tenable_client=client, live=live, asset_index=asset_index
    )
    return 0


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
    # A live Tenable pull does not read the sample file, so only require it when
    # the mock source is actually in play.
    if args.source == "mock" and not input_path.exists():
        print(f"Findings file not found: {input_path}", file=sys.stderr)
        return 1

    code = configure_sources(args)
    if code:
        return code

    try:
        if args.offline:
            origin = "Tenable" if args.source == "tenable" else str(input_path)
            print(f"Running the deterministic pipeline on {origin} (no LLM).")
            run_offline(input_path, STATE)
        else:
            code = run_crew(args)
            if code:
                return code
    except SOURCE_ERRORS as exc:
        # The findings source failing is fatal in a way the intel feeds are not:
        # there is nothing to degrade *to*. Falling back to the sample file would
        # silently hand back a triage of mock data labelled as a live run, so
        # this fails loudly and cleanly instead -- a message, not a traceback.
        print(f"\nCould not read findings from {args.source}: {exc}", file=sys.stderr)
        if args.source == "tenable":
            print(
                "  Check TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY, and TENABLE_URL if this is\n"
                "  Tenable.sc or a non-default region. Run with --source mock to use the\n"
                "  sample export instead.",
                file=sys.stderr,
            )
        return 2

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

    if STATE.live is not None:
        print(f"Intel:   {STATE.live.summary()}")

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

    for warning in [*STATE.live_warnings, *outputs.warnings, *filter(None, [state_warning])]:
        print(f"\nWARNING: {warning}", file=sys.stderr)
    print()
    print("Proposals only — an analyst approves before anything is changed.")

    if args.strict_narrative and guard.violations:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
