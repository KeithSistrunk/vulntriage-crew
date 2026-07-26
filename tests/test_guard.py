"""Tests for the narrative guard.

The guard's PASS on a new run means nothing unless it fails on the runs that
were genuinely wrong. So the fixtures here are the real 8B failures, quoted from
the early runs recorded in the README:

  - a Spring4Shell finding attributed to the wrong host
  - a Zerologon fix justified with Heartbleed's reasoning
  - a schedule that puts one finding in two different weeks

plus the effort and extra-work fabrications the tools were later built to
prevent. Every one of them must be caught before a PASS is worth anything.

    python -m pytest tests/test_guard.py -v
    python tests/test_guard.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulntriage.guard import (  # noqa: E402
    STAGES,
    GuardReport,
    check_narratives,
    check_stage,
)
from vulntriage.pipeline import run_offline  # noqa: E402
from vulntriage.state import PipelineState  # noqa: E402

SAMPLE_JSON = ROOT / "data" / "sample_findings.json"


def _scored():
    state = PipelineState()
    return run_offline(SAMPLE_JSON, state), state


def _codes(violations) -> set[str]:
    return {v.code for v in violations}


def _check(narrative: str, stage: str = "remediation"):
    scored, _ = _scored()
    return check_stage(stage, narrative, scored, top_n=5)


# --------------------------------------------------------------------------- #
# the known-bad baseline — every one of these was a real 8B failure
# --------------------------------------------------------------------------- #

WRONG_HOST = """
Batch the dc-01 work into a single maintenance window: CVE-2020-1472 and
CVE-2022-22965 both land on that host and share a reboot.
"""

BORROWED_REASONING = """
- CVE-2020-1472 (Zerologon) — patching the domain controller is not the end of
  it. The keys are already gone, so rotate the credentials before you close the
  finding.
"""

CONTRADICTORY_SCHEDULE = """
**Week 1**

- CVE-2022-22965 on edge-web-01 — patch Spring first, it is internet-facing.

**Week 2**

- CVE-2022-22965 on edge-web-01 — schedule the Spring upgrade here instead.
"""

FLATTENED_EFFORT = """
The top five are uniform: medium effort x 5 findings, so budget one sprint and
treat them as interchangeable.
"""

WRONG_HOUR_TOTAL = "Total remediation effort across the top five: 8-20 engineer-hours."

UNSUPPORTED_EXTRA_WORK = """
Each of these findings requires a combination of patching and credential
rotation; a patch alone will not close any of them.
"""

FABRICATED_CVE = """
- CVE-2023-99999 on edge-web-01 — patch immediately, it is the highest risk in
  the set.
"""


def test_catches_wrong_host_attribution():
    """Spring4Shell is on edge-web-01, not dc-01."""
    violations = _check(WRONG_HOST)
    assert "E1" in _codes(violations), violations
    assert any("CVE-2022-22965" in v.message for v in violations)


def test_catches_borrowed_cve_reasoning():
    """Heartbleed's argument used to justify a Zerologon fix."""
    violations = _check(BORROWED_REASONING)
    assert "E2" in _codes(violations), violations
    assert any("CVE-2014-0160" in v.message for v in violations)


def test_catches_schedule_contradiction():
    violations = _check(CONTRADICTORY_SCHEDULE)
    assert "E3" in _codes(violations), violations
    assert any("week 1" in v.message and "week 2" in v.message for v in violations)


def test_catches_flattened_effort_band():
    """The top five are 4 medium + 1 high, never 5 medium."""
    violations = _check(FLATTENED_EFFORT)
    assert "E4" in _codes(violations), violations


def test_catches_wrong_hour_total():
    violations = _check(WRONG_HOUR_TOTAL)
    assert "E4" in _codes(violations), violations
    assert any("16-56" in v.message for v in violations)


def test_catches_unsupported_extra_work():
    """No finding in the top five carries the rotation constraint."""
    violations = _check(UNSUPPORTED_EXTRA_WORK)
    assert "E5" in _codes(violations), violations


def test_catches_fabricated_cve():
    violations = _check(FABRICATED_CVE)
    assert "E6" in _codes(violations), violations
    assert any("CVE-2023-99999" in v.message for v in violations)


# Verbatim from the run that exposed the leak: the agent restated the tool's data
# sheet field by field, guardrail text included. Kept exactly as emitted.
LEAKED_SCAFFOLDING = """
Based on the output of `get_ranked_findings` with top_n=5, I propose the following remediation strategy:

**SEQUENCE**

1. #2 CVE-2020-1472 (Zerologon) — risk 80.0/100, P1
This finding's host: dc-01 (do not attribute CVE-2020-1472 to any other host)
Target: dc-01:445 (cifs)
Asset: Primary domain controller (forest root) | owner Identity & Directory Services | critical criticality | production | scope: SOX

2. #1 CVE-2022-22965 (Spring4Shell) — risk 81.7/100, P1
This finding's host: edge-web-01 (do not attribute CVE-2022-22965 to any other host)
Target: edge-web-01:8443 (https-alt)

**HOSTS WITH MULTIPLE TOP FINDINGS**

* dc-01: CVE-2020-1472, CVE-2019-0708

**TOTAL EFFORT FOR THIS SET**

* 4 finding(s) at medium effort (2-8h)
"""


def test_catches_echoed_tool_scaffolding():
    """The regression this check exists for: a restated data sheet."""
    violations = _check(LEAKED_SCAFFOLDING)
    assert "E7" in _codes(violations), violations


def test_inline_guardrail_text_is_caught_on_its_own():
    """"do not attribute" can only have come from the tool. One occurrence is enough."""
    leaked = "Patch Zerologon first. This finding's host: dc-01 (do not attribute CVE-2020-1472 to any other host)."
    assert "E7" in _codes(_check(leaked))


def test_effort_total_mentioned_in_prose_is_not_scaffolding():
    """Prose that discusses the numbers must not be mistaken for transcription."""
    prose = (
        "Working the queue in this order, the effort total is 16-56 engineer-hours, "
        "which is what I would tell the VM lead this week costs. The shared hosts "
        "question is simple: only dc-01 carries two of the top five."
    )
    assert "E7" not in _codes(_check(prose)), _check(prose)


def test_the_whole_known_bad_baseline_fails_at_once():
    """The composite case: one narrative carrying every failure mode."""
    narrative = "\n".join([
        WRONG_HOST, BORROWED_REASONING, CONTRADICTORY_SCHEDULE,
        FLATTENED_EFFORT, UNSUPPORTED_EXTRA_WORK, FABRICATED_CVE,
        LEAKED_SCAFFOLDING,
    ])
    codes = _codes(_check(narrative))
    assert {"E1", "E2", "E3", "E4", "E5", "E6", "E7"} <= codes, f"missed: {codes}"


# --------------------------------------------------------------------------- #
# the guard must not cry wolf
# --------------------------------------------------------------------------- #

GROUNDED = """
SEQUENCE

1. CVE-2022-22965 (Spring4Shell) - risk 81.7/100, P1
2. CVE-2020-1472 (Zerologon) - risk 80.0/100, P1
3. CVE-2021-44228 (Log4Shell) - risk 80.0/100, P1

BATCHING

dc-01: CVE-2020-1472, CVE-2019-0708

TOTAL EFFORT

16-56 engineer-hours

PATCH IS NOT THE WHOLE FIX

none in this set.
"""


def test_grounded_narrative_passes():
    """The real, grounded 8B output. A guard that flags this is unusable."""
    assert _check(GROUNDED) == []


def test_correct_host_pairing_is_not_flagged():
    ok = "CVE-2020-1472 and CVE-2019-0708 both sit on dc-01 and share one window."
    assert _codes(_check(ok)) == set()


def test_enumerated_correct_pairings_are_not_flagged():
    """Verbatim from a real run, and correct: each CVE sits with its own host.

    Raw nearest-host binding flagged this, because `dc-01` is textually closer to
    CVE-2017-5638 than its own `hr-app-03` is. Each CVE binds to the host in its
    own clause, not the nearest one on the line.
    """
    enumerated = (
        "FINDING #4 - CVE-2019-0708 (BlueKeep) on dc-01 and FINDING #5 - "
        "CVE-2017-5638 (Apache Struts 2 Jakarta Multipart RCE) on hr-app-03 will be "
        "addressed after the first three findings have been remediated."
    )
    assert "E1" not in _codes(_check(enumerated)), _check(enumerated)


def test_host_introducing_a_cve_list_is_not_flagged():
    """Also verbatim from a real run, also correct: the owning host precedes the list.

    `dc-01 (CVE-2020-1472 and CVE-2019-0708)` attributes both CVEs to dc-01, but
    the next host named in the sentence is prod-db-01 — so any rule that looks
    only forwards binds the second CVE to the wrong box.
    """
    listed = (
        "We can batch the findings that share a host. The shared hosts are dc-01 "
        "(CVE-2020-1472 and CVE-2019-0708) and prod-db-01 is not shared with any "
        "other finding in this list, but edge-web-01 has no shared hosts."
    )
    assert "E1" not in _codes(_check(listed)), _check(listed)


def test_wrong_pairing_inside_an_enumeration_is_still_caught():
    """Clause binding must not become a way to smuggle a wrong host through."""
    swapped = "Patch CVE-2022-22965 on dc-01 first, then CVE-2019-0708 on edge-web-01."
    violations = _check(swapped)
    assert "E1" in _codes(violations), violations
    assert len(violations) == 2, violations


def test_hierarchical_schedule_is_not_a_contradiction():
    """"Day 1-2" inside "Week 1" is consistent, not two different slots."""
    nested = """
**Week 1**

- Day 1-2: CVE-2022-22965 on edge-web-01 — patch Spring.
"""
    assert "E3" not in _codes(_check(nested))


def test_a_cve_on_several_hosts_is_not_a_contradiction():
    """A real export puts one CVE on many hosts; the guard must allow it."""
    scored, _ = _scored()
    duplicated = list(scored)
    clone = scored[0].model_copy(update={"hostname": "dc-01"})
    duplicated.append(clone)
    text = f"{clone.cve} affects both edge-web-01 and dc-01; patch them together."
    assert check_stage("remediation", text, duplicated, top_n=5) == []


def test_denying_extra_work_that_is_real_is_flagged():
    """The inverse failure: Heartbleed does need rotation, so 'none' is wrong."""
    scored, _ = _scored()
    text = "No finding here needs more than a patch."
    # Heartbleed sits outside the top 5, so widen the window until it is in scope.
    top_n = next(f.rank for f in scored if f.cve == "CVE-2014-0160")
    violations = check_stage("remediation", text, scored, top_n=top_n)
    assert "E5" in _codes(violations), violations


# --------------------------------------------------------------------------- #
# stage scoping and wiring
# --------------------------------------------------------------------------- #

def test_schedule_check_does_not_run_on_discovery():
    """Discovery has no schedule to contradict; only remediation is scoped for E3."""
    assert "E3" not in _codes(_check(CONTRADICTORY_SCHEDULE, stage="discovery"))
    assert "E3" in _codes(_check(CONTRADICTORY_SCHEDULE, stage="remediation"))


def test_host_and_fabrication_checks_run_on_every_stage():
    for stage in STAGES:
        assert "E1" in _codes(_check(WRONG_HOST, stage=stage)), stage
        assert "E6" in _codes(_check(FABRICATED_CVE, stage=stage)), stage


def test_guard_runs_over_every_stage_with_a_narrative():
    _, state = _scored()
    state.note("discovery", GROUNDED)
    state.note("remediation", WRONG_HOST)
    report = check_narratives(state, top_n=5)
    assert set(report.checked) == {"discovery", "remediation"}
    assert set(report.skipped) == {"enrichment", "prioritization"}
    assert report.for_stage("remediation") and not report.for_stage("discovery")
    assert not report.passed


def test_offline_run_has_nothing_to_check_and_does_not_fail():
    """`--offline` produces no narrative. That is a pass, not a failure."""
    _, state = _scored()
    report = check_narratives(state, top_n=5)
    assert report.passed and report.checked == []
    assert "no agent narrative" in report.summary()


def test_report_is_serializable_for_the_json_output():
    _, state = _scored()
    state.note("remediation", WRONG_HOST)
    payload = check_narratives(state, top_n=5).model_dump()
    assert payload["violations"] and payload["violations"][0]["code"] == "E1"
    assert GuardReport.model_validate(payload).passed is False


def test_empty_and_missing_narratives_are_safe():
    scored, _ = _scored()
    assert check_stage("remediation", "", scored) == []
    assert check_stage("remediation", "   \n ", scored) == []
    assert check_stage("remediation", WRONG_HOST, []) == []


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception as exc:  # noqa: BLE001 - a hand-rolled runner wants everything
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
