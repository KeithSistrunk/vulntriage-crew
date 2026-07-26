"""Narrative guard: mechanical grounding checks on everything an agent writes.

The report's numbers are computed deterministically and never depend on the
model. The prose does, and on an 8B local model the prose drifts in a small set
of repeatable ways -- observed, not hypothesised, across real runs:

    E1  wrong host attribution    a CVE named alongside a host that is not its own
    E2  borrowed CVE reasoning    a rationale phrase tied to CVE A used for CVE B
    E3  schedule contradiction    one finding given two different slots
    E4  effort misstatement       an effort band or hour total the data disagrees with
    E5  unsupported extra work    "a patch is not enough" where the constraints say it is
    E6  fabricated finding        a CVE that is not in this run at all
    E7  echoed tool scaffolding   the tool's data sheet restated instead of analysed

Every one of those is checkable against `PipelineState`, so it is checked --
on every stage's narrative, on every run, rather than by an analyst reading
carefully. This runs after the crew and before the report is published.

The guard annotates; it does not silence. These are regex heuristics over
free text: a false positive that hides real analysis costs more than one that
adds a visible footnote. Violations are surfaced in the markdown report next to
the sentence that caused them, recorded in the JSON, and can fail a CI run via
`main.py --strict-narrative`.

Standalone, against a saved run:

    python -m vulntriage.guard output/pipeline_state.json
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence

from pydantic import BaseModel, Field

from .models import ScoredFinding
from .remediation import effort_summary, effort_total, patch_is_not_enough

STAGES: tuple[str, ...] = ("discovery", "enrichment", "prioritization", "remediation")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

CHECK_NAMES = {
    "E1": "wrong host attribution",
    "E2": "borrowed CVE reasoning",
    "E3": "schedule contradiction",
    "E4": "effort misstatement",
    "E5": "unsupported extra work",
    "E6": "fabricated finding",
    "E7": "echoed tool scaffolding",
}

# Which stages each check applies to. Host attribution, borrowed reasoning and
# fabricated CVEs are grounding failures wherever they appear; scheduling and
# effort claims only exist in the stages that make them.
CHECK_STAGES: dict[str, frozenset[str]] = {
    "E1": frozenset(STAGES),
    "E2": frozenset(STAGES),
    "E3": frozenset({"remediation"}),
    "E4": frozenset({"prioritization", "remediation"}),
    "E5": frozenset({"remediation"}),
    "E6": frozenset(STAGES),
    "E7": frozenset(STAGES),
}

# Rationale phrases that belong to exactly one CVE. Seeing one attached to a
# different CVE means reasoning was carried across findings -- the failure that
# produced a Zerologon fix justified with Heartbleed's argument. Curated against
# the mock intel DB; extend it as new borrowings show up in the failure taxonomy.
SIGNATURES: dict[str, list[str]] = {
    "CVE-2014-0160": [
        r"keys? (are|were) already gone",
        r"rotate .{0,25}(key|secret|credential)",
        r"reissue the (tls )?certificate",
        r"revoke the old certificate",
        r"assume memory was read",
    ],
    "CVE-2020-1472": [r"enforcement mode", r"netlogon", r"zeroed client challenge"],
    "CVE-2019-0708": [r"network level authentication", r"\bnla\b"],
    "CVE-2021-44228": [r"jndilookup", r"log4j-core", r"jndi"],
    "CVE-2022-22965": [r"controlleradvice", r"classloader"],
    "CVE-2017-5638": [r"\bognl\b", r"content-type"],
    "CVE-2017-0144": [r"smbv1", r"ms17-010"],
}


class GuardViolation(BaseModel):
    """One flagged claim: what broke, where, and the text that broke it."""

    code: str
    check: str
    stage: str
    message: str
    excerpt: str = ""

    def render(self) -> str:
        return f"**{self.code} {self.check}** — {self.message}"


class GuardReport(BaseModel):
    """Outcome of running every applicable check over every stage's narrative."""

    top_n: int
    checked: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    violations: list[GuardViolation] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations

    def for_stage(self, stage: str) -> list[GuardViolation]:
        return [v for v in self.violations if v.stage == stage]

    def summary(self) -> str:
        if not self.checked:
            return "Narrative guard: no agent narrative to check."
        scope = f"{len(self.checked)} stage{'s' if len(self.checked) != 1 else ''}"
        if self.passed:
            return f"Narrative guard: PASS ({scope} checked, no unsupported claims)."
        codes = sorted({v.code for v in self.violations})
        return (
            f"Narrative guard: {len(self.violations)} flagged claim"
            f"{'s' if len(self.violations) != 1 else ''} across {scope} "
            f"({', '.join(codes)})."
        )


# --------------------------------------------------------------------------- #
# roster — the closed set of facts a narrative is allowed to assert
# --------------------------------------------------------------------------- #

class _Roster:
    """Everything true about this run, indexed for lookup."""

    def __init__(self, scored: Sequence[ScoredFinding], top_n: int) -> None:
        self.scored = list(scored)
        self.top = self.scored[:top_n]
        self.top_n = top_n

        # A CVE can legitimately sit on several hosts -- one row per host is the
        # normal shape of a real export. Map to a set, or the guard invents a
        # contradiction the moment the same CVE appears twice.
        self.cve_hosts: dict[str, set[str]] = {}
        for f in self.scored:
            self.cve_hosts.setdefault(f.cve, set()).add(f.hostname)

        self.all_cves = set(self.cve_hosts)
        self.top_cves = {f.cve for f in self.top}
        # Longest first, so `dc-01.corp.example.net` wins over `dc-01`.
        self.hosts = sorted({f.hostname for f in self.scored}, key=len, reverse=True)
        self._host_re = (
            re.compile(
                r"(?<![\w.-])(" + "|".join(re.escape(h) for h in self.hosts) + r")(?![\w-])"
            )
            if self.hosts
            else None
        )

    def hosts_in(self, text: str) -> list[str]:
        if not self._host_re:
            return []
        return list(dict.fromkeys(m.group(1) for m in self._host_re.finditer(text)))

    def host_positions(self, text: str) -> list[tuple[int, str]]:
        if not self._host_re:
            return []
        return [(m.start(1), m.group(1)) for m in self._host_re.finditer(text)]

    def owns(self, cve: str, host: str) -> bool:
        return host in self.cve_hosts.get(cve, set())


# A sentence ends at punctuation, a blank line, or the start of a list item --
# but *not* at a single newline. Models hard-wrap their output, and splitting on
# every newline tears "...CVE-2020-1472 and\nCVE-2022-22965 both land on dc-01"
# into two fragments, which is precisely the sentence E1 exists to catch.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n\s*\n+|\n(?=\s*(?:[-*•]|\d+\.))")


def _sentences(text: str) -> list[str]:
    return [s for s in _SENTENCE_SPLIT_RE.split(text) if s and s.strip()]


def _blocks(text: str) -> list[str]:
    """Split into bullets/paragraphs -- one coherent claim about one finding.

    A bullet's rationale often lands in a follow-on sentence naming no CVE
    ("...patching is not enough. The keys are already gone."), so checking
    sentence-by-sentence misses exactly the error being hunted.
    """
    return [b for b in re.split(r"\n(?=\s*[-*•]|\s*\d+\.|\s*\*\*)", text) if b.strip()]


def _clip(text: str, limit: int = 170) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _violation(code: str, stage: str, message: str, excerpt: str = "") -> GuardViolation:
    return GuardViolation(
        code=code, check=CHECK_NAMES[code], stage=stage, message=message, excerpt=excerpt
    )


# --------------------------------------------------------------------------- #
# E1 — wrong host attribution
# --------------------------------------------------------------------------- #

# Words that actually attach a CVE to a host. Deliberately narrow: "in" and "for"
# would qualify "...in this list, but edge-web-01 has no shared hosts", binding a
# CVE to a host it is only sharing a sentence with.
_CONNECTOR_RE = re.compile(r"\b(?:on|affects?|at)\b", re.I)

# "<host>:" / "<host> (" followed only by CVEs and separators up to this CVE --
# a host introducing a list that this CVE belongs to.
_LIST_OPENER_RE = re.compile(
    r"[\s(:,–—-]*(?:CVE-\d{4}-\d{4,7}(?:\s*(?:,|and)\s*)?)*", re.I
)

# How far after a CVE a connector-linked host can sit and still be its host.
_FORWARD_WINDOW = 80


def _check_hosts(stage: str, text: str, roster: _Roster) -> list[GuardViolation]:
    out: list[GuardViolation] = []
    for sent in _sentences(text):
        cves = [c for c in CVE_RE.findall(sent) if c in roster.cve_hosts]
        hosts = roster.hosts_in(sent)
        if not cves or not hosts:
            continue

        if len(hosts) == 1:
            # The strict case, and the one that produced the real error: a
            # batching sentence about dc-01 that listed edge-web-01's CVE.
            host = hosts[0]
            for cve in dict.fromkeys(cves):
                if not roster.owns(cve, host):
                    owner = "/".join(sorted(roster.cve_hosts[cve]))
                    out.append(_violation(
                        "E1", stage,
                        f"{cve} is on `{owner}`, but is named in a sentence about `{host}`.",
                        _clip(sent),
                    ))
        else:
            # Several hosts in play, so a CVE has to be bound to one of them before
            # the pairing can be judged. Proximity is not good enough -- it gets
            # both of the constructions models actually write exactly backwards:
            #
            #   "CVE-2019-0708 on dc-01 and CVE-2017-5638 on hr-app-03"
            #       dc-01 is nearer to the second CVE than its own host is
            #   "the shared hosts are dc-01 (CVE-2020-1472 and CVE-2019-0708) and
            #    prod-db-01 is not shared"
            #       the owning host sits *before* the list, an unrelated one after
            #
            # Both are correct sentences that a nearest-host rule flags. So bind on
            # grammar instead: either the CVE points forward at a host through a
            # connector ("... on dc-01"), or a host introduces a list the CVE is a
            # member of ("dc-01 (CVE-..., CVE-...)"). No binding, no judgement --
            # a sentence too loose to bind is one the single-host rule above and
            # E6 already cover.
            positions = roster.host_positions(sent)
            marks = [
                (m.start(), m.group())
                for m in CVE_RE.finditer(sent)
                if m.group() in roster.cve_hosts
            ]
            for idx, (cve_pos, cve) in enumerate(marks):
                cve_end = cve_pos + len(cve)
                next_pos = marks[idx + 1][0] if idx + 1 < len(marks) else len(sent)
                candidates: list[str] = []

                # Forward: "<CVE> ... on <host>", allowing a parenthetical name in
                # between ("CVE-2019-0708 (BlueKeep) on dc-01").
                forward = [
                    (pos, h) for pos, h in positions
                    if cve_end <= pos < min(next_pos, cve_end + _FORWARD_WINDOW)
                ]
                if forward and _CONNECTOR_RE.search(sent[cve_end:forward[0][0]]):
                    candidates = [h for _, h in forward]

                # Backward: "<host>: <CVE>, <CVE>" / "<host> (<CVE> and <CVE>)".
                if not candidates:
                    before = [(pos, h) for pos, h in positions if pos < cve_pos]
                    if before:
                        pos, host = before[-1]
                        if _LIST_OPENER_RE.fullmatch(sent[pos + len(host):cve_pos]):
                            candidates = [host]

                # One correct host acquits: "affects both edge-web-01 and dc-01"
                # is true whenever the CVE really is on either of them.
                if not candidates or any(roster.owns(cve, h) for h in candidates):
                    continue

                owner = "/".join(sorted(roster.cve_hosts[cve]))
                out.append(_violation(
                    "E1", stage,
                    f"{cve} is on `{owner}`, but is paired with `{candidates[0]}`.",
                    _clip(sent),
                ))
    return out


# --------------------------------------------------------------------------- #
# E2 — borrowed CVE reasoning
# --------------------------------------------------------------------------- #

def _check_borrowed(stage: str, text: str, roster: _Roster) -> list[GuardViolation]:
    out: list[GuardViolation] = []
    for block in _blocks(text):
        cves = set(CVE_RE.findall(block))
        if not cves:
            continue
        for owner, patterns in SIGNATURES.items():
            if owner in cves:
                continue
            for pattern in patterns:
                match = re.search(pattern, block, re.I)
                if not match:
                    continue
                out.append(_violation(
                    "E2", stage,
                    f'"{match.group()}" is {owner}\'s rationale, but appears in a '
                    f"passage about {', '.join(sorted(cves))}.",
                    _clip(block, 180),
                ))
    return out


# --------------------------------------------------------------------------- #
# E3 — schedule contradiction
# --------------------------------------------------------------------------- #

WEEK_RE = re.compile(r"\bweek\s*(\d+)\b", re.I)
DAY_RE = re.compile(r"\bdays?\s*(\d+)\s*(?:[-–—]\s*(\d+))?\b", re.I)
MARKER_RE = re.compile(r"\b(?:week\s*\d+|days?\s*\d+(?:\s*[-–—]\s*\d+)?)\b", re.I)


def _check_schedule(stage: str, text: str, roster: _Roster) -> list[GuardViolation]:
    """Slots are hierarchical: "Day 1-2" inside "Week 1" is consistent, not a
    contradiction. Compare weeks against weeks and day-ranges against day-ranges."""
    weeks: dict[str, set[str]] = {}
    days: dict[str, set[str]] = {}
    week_context: str | None = None

    for line in text.split("\n"):
        if not line.strip():
            continue
        line_weeks = WEEK_RE.findall(line)
        # A standalone heading like "**Week 1**" sets context for the lines below.
        if line_weeks and not CVE_RE.search(line):
            week_context = line_weeks[-1]
            continue

        # Split at each slot marker so a CVE binds to the marker before it.
        parts = MARKER_RE.split(line)
        markers = MARKER_RE.findall(line)
        for idx, segment in enumerate(parts):
            marker = markers[idx - 1] if 0 < idx <= len(markers) else None
            seg_week = WEEK_RE.search(marker) if marker else None
            seg_day = DAY_RE.search(marker) if marker else None
            for cve in CVE_RE.findall(segment):
                week = seg_week.group(1) if seg_week else week_context
                if week:
                    weeks.setdefault(cve, set()).add(f"week {week}")
                if seg_day:
                    span = seg_day.group(1) + (f"-{seg_day.group(2)}" if seg_day.group(2) else "")
                    days.setdefault(cve, set()).add(f"day {span}")

    out: list[GuardViolation] = []
    for cve, slots in sorted(weeks.items()):
        if len(slots) > 1:
            out.append(_violation(
                "E3", stage, f"{cve} is scheduled into conflicting weeks: {', '.join(sorted(slots))}."
            ))
    for cve, slots in sorted(days.items()):
        if len(slots) > 1:
            out.append(_violation(
                "E3", stage,
                f"{cve} is scheduled into conflicting day ranges: {', '.join(sorted(slots))}.",
            ))
    return out


# --------------------------------------------------------------------------- #
# E4 — effort misstatement
# --------------------------------------------------------------------------- #

HOURS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*[-–—]\s*(\d+(?:\.\d+)?)\s*(?:engineer[- ])?hours", re.I)


def _check_effort(stage: str, text: str, roster: _Roster) -> list[GuardViolation]:
    out: list[GuardViolation] = []
    bands = effort_summary(roster.top)
    totals = effort_total(roster.top)

    # "<band> effort ... x N findings" over-generalization.
    for band in ("low", "medium", "high"):
        for match in re.finditer(
            rf"{band}\s+effort[^.\n]{{0,40}}?[x×]\s*(\d+)\s*finding", text, re.I
        ):
            claimed, actual = int(match.group(1)), bands.get(band, 0)
            if claimed != actual:
                out.append(_violation(
                    "E4", stage,
                    f"claims {band} effort covers {claimed} findings; only {actual} of the "
                    f"top {roster.top_n} are {band}.",
                    _clip(match.group()),
                ))

    # A single band asserted across a set that spans several.
    present = {b: n for b, n in bands.items() if n}
    if len(present) > 1:
        for match in re.finditer(
            r"(?:each|all)\s+(?:of\s+the\s+)?(?:\d+\s+)?findings?[^.\n]{0,60}"
            r"(low|medium|high)\s+effort", text, re.I,
        ):
            out.append(_violation(
                "E4", stage,
                f"asserts one effort band for every finding, but the top {roster.top_n} span "
                f"{', '.join(f'{n} {b}' for b, n in sorted(present.items()))}.",
                _clip(match.group()),
            ))

    # A stated hour total must match the precomputed roll-up.
    for match in HOURS_RE.finditer(text):
        low, high = float(match.group(1)), float(match.group(2))
        if (low, high) != (totals["low_hours"], totals["high_hours"]):
            out.append(_violation(
                "E4", stage,
                f"states {match.group()} but the top {roster.top_n} total "
                f"{totals['range']}.",
                _clip(match.group()),
            ))
    return out


# --------------------------------------------------------------------------- #
# E5 — unsupported extra-work claims
# --------------------------------------------------------------------------- #

CLAIM_RE = re.compile(
    r"patch(?:ing)?\s+alone|requires?\s+(?:a\s+)?combination|"
    r"more than (?:just )?(?:a )?patch|beyond (?:the )?patch", re.I,
)
SCOPE_ALL_RE = re.compile(r"\beach\b|\ball\b|\bevery\b|\bthese fixes\b", re.I)
NEGATED_RE = re.compile(r"\bnone\b|\bno finding\b|\bdoes not\b|\bdo not\b|\bnot the whole\b", re.I)


def _check_extra_work(stage: str, text: str, roster: _Roster) -> list[GuardViolation]:
    """"Patching alone is not enough" may only be claimed where the constraint exists.

    The truth comes from `patch_is_not_enough()` -- the same function the
    remediation tool hands the agent -- so the guard and the prompt cannot drift.
    """
    needs_more = {f.cve for f in patch_is_not_enough(roster.top)}
    out: list[GuardViolation] = []

    for sent in _sentences(text):
        if not CLAIM_RE.search(sent):
            continue
        negated = NEGATED_RE.search(sent)
        # Scope words sit outside the claim phrase ("Each finding requires a
        # combination of..."), so the unit of judgement is the whole sentence.
        if SCOPE_ALL_RE.search(sent) and not needs_more and not negated:
            out.append(_violation(
                "E5", stage,
                f"claims findings generally need more than a patch, but none of the top "
                f"{roster.top_n} carry that constraint.",
                _clip(sent),
            ))
        for cve in sorted(set(CVE_RE.findall(sent)) & roster.top_cves):
            if cve not in needs_more and not negated:
                out.append(_violation(
                    "E5", stage,
                    f"{cve} is described as needing more than a patch; its constraints say "
                    f"otherwise.",
                    _clip(sent),
                ))

    # The inverse: denying extra work that the data does require.
    if needs_more:
        for sent in _sentences(text):
            if CLAIM_RE.search(sent) and NEGATED_RE.search(sent):
                named = set(CVE_RE.findall(sent))
                if not (named & needs_more):
                    out.append(_violation(
                        "E5", stage,
                        f"states no finding needs more than a patch, but "
                        f"{', '.join(sorted(needs_more))} does.",
                        _clip(sent),
                    ))
                break
    return out


# --------------------------------------------------------------------------- #
# E6 — fabricated findings
# --------------------------------------------------------------------------- #

def _check_fabricated(stage: str, text: str, roster: _Roster) -> list[GuardViolation]:
    """A CVE the run never produced. Unambiguous -- there is no reading of the
    input in which it belongs in the output."""
    unknown = sorted(set(CVE_RE.findall(text)) - roster.all_cves)
    return [
        _violation("E6", stage, f"{cve} is not one of the {len(roster.scored)} findings in this run.")
        for cve in unknown
    ]


# --------------------------------------------------------------------------- #
# E7 — echoed tool scaffolding
# --------------------------------------------------------------------------- #

# Field labels and section headings emitted by the agent tools. A narrative that
# reproduces these is transcribing its input rather than analysing it -- and when
# the tools still carried inline directives, this is how guardrail text ("do not
# attribute CVE-2020-1472 to any other host") ended up quoted into the report.
SCAFFOLD_LABELS = (
    "cve / host index",
    "ranking basis:",
    "fix profile:",
    "shared hosts",
    "effort total",
    "findings not closed by patching alone",
    "target:",
    "window:",
    "exploit:",
    # Retired phrasings. Kept so an old prompt, a cached run or a reverted tool
    # is caught rather than silently passing.
    "valid cve -> host pairings",
    "this finding's host:",
    "hosts with multiple top findings",
    "total effort for this set",
    "findings where patching alone is not sufficient",
)

# Directives can only have come from a tool -- no analyst writes these -- so one
# occurrence anywhere in the text is diagnostic by itself.
SCAFFOLD_DIRECTIVES = ("do not attribute", "this finding's host:", "any other pairing is wrong")

# Labels are matched at the start of a line, after any bullet or bold marker.
# Transcription reproduces them as headings; prose mentions them mid-sentence
# ("the effort total is 16-56 hours"), which must not be flagged.
_LINE_LEAD_RE = re.compile(r"^[\s>*#•\-–—\d.)\]]*")

# One echoed label can be coincidence; two is a restated data sheet.
SCAFFOLD_THRESHOLD = 2


def _check_scaffolding(stage: str, text: str, roster: _Roster) -> list[GuardViolation]:
    found: list[str] = []
    for line in text.split("\n"):
        stripped = _LINE_LEAD_RE.sub("", line).strip().lower().lstrip("*_ ")
        for label in SCAFFOLD_LABELS:
            if stripped.startswith(label) and label not in found:
                found.append(label)

    lowered = text.lower()
    directives = [d for d in SCAFFOLD_DIRECTIVES if d in lowered]
    if len(found) < SCAFFOLD_THRESHOLD and not directives:
        return []

    echoed = ", ".join(f'"{label}"' for label in found + [d for d in directives if d not in found])
    detail = (
        "carries the tool's inline guardrail text"
        if directives
        else "reproduces the tool's data sheet rather than analysing it"
    )
    return [_violation("E7", stage, f"{detail} — echoes {echoed}.")]


CHECKS = {
    "E1": _check_hosts,
    "E2": _check_borrowed,
    "E3": _check_schedule,
    "E4": _check_effort,
    "E5": _check_extra_work,
    "E6": _check_fabricated,
    "E7": _check_scaffolding,
}


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #

def check_stage(
    stage: str,
    narrative: str,
    scored: Sequence[ScoredFinding],
    top_n: int = 5,
    codes: Iterable[str] | None = None,
) -> list[GuardViolation]:
    """Run every check that applies to `stage` over one narrative."""
    if not narrative or not narrative.strip() or not scored:
        return []
    roster = _Roster(scored, top_n)
    wanted = set(codes) if codes else set(CHECKS)
    out: list[GuardViolation] = []
    for code, check in CHECKS.items():
        if code in wanted and stage in CHECK_STAGES[code]:
            out.extend(check(stage, narrative, roster))
    # Regex alternatives can flag the same sentence twice; report each once.
    seen: set[tuple[str, str, str]] = set()
    deduped: list[GuardViolation] = []
    for v in out:
        key = (v.code, v.message, v.excerpt)
        if key not in seen:
            seen.add(key)
            deduped.append(v)
    return deduped


def check_narratives(state, top_n: int = 5) -> GuardReport:
    """Guard every stage's narrative against the run's structured data.

    Takes a `PipelineState` (untyped here so importing the guard never drags in
    the state singleton). Safe on an offline run, which has no narrative at all.
    """
    scored = list(getattr(state, "scored", []) or [])
    notes = dict(getattr(state, "agent_notes", {}) or {})
    report = GuardReport(top_n=top_n)

    for stage in STAGES:
        narrative = (notes.get(stage) or "").strip()
        if not narrative:
            report.skipped.append(stage)
            continue
        report.checked.append(stage)
        report.violations.extend(check_stage(stage, narrative, scored, top_n))

    # Any note under a stage name the pipeline does not define still gets checked.
    for stage, narrative in notes.items():
        if stage in STAGES or not (narrative or "").strip():
            continue
        report.checked.append(stage)
        report.violations.extend(
            check_stage(stage, narrative, scored, top_n, codes={"E1", "E2", "E6", "E7"})
        )
    return report


def _main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="python -m vulntriage.guard",
        description="Check a saved run's agent narratives against its structured data.",
    )
    parser.add_argument("state", help="path to pipeline_state.json")
    parser.add_argument("--top-n", "-n", type=int, default=5)
    args = parser.parse_args(argv)

    snapshot = json.loads(Path(args.state).read_text(encoding="utf-8"))

    class _Snapshot:
        scored = [ScoredFinding.model_validate(f) for f in snapshot.get("scored", [])]
        agent_notes = snapshot.get("agent_notes") or {}

    report = check_narratives(_Snapshot(), args.top_n)
    print(report.summary())
    for stage in report.checked:
        violations = report.for_stage(stage)
        status = "PASS" if not violations else f"{len(violations)} flagged"
        print(f"\n{stage:<15} {status}")
        for v in violations:
            print(f"    {v.code} {v.check}: {v.message}")
            if v.excerpt:
                print(f'        "{v.excerpt}"')
    if report.skipped:
        print(f"\nno narrative: {', '.join(report.skipped)}")
    return 1 if report.violations else 0


if __name__ == "__main__":
    raise SystemExit(_main())
