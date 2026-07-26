# Future Add-ons

The POC deliberately stops at a local, offline, human-reviewed workflow. This is
the roadmap, roughly in the order the value shows up.

Each item lists the seam it plugs into, because the POC was built so that none of
these require rewriting the pipeline — the data models and the stage boundaries
stay the same.

---

## 1. Live Tenable API integration

**Now:** findings come from an exported JSON/CSV file.
**Next:** pull them directly from Tenable.sc / Tenable.io.

Replace `load_raw()` in `vulntriage/normalize.py` with a client that hits
`/analysis` (Tenable.sc) or the vulnerability export endpoint (Tenable.io) and
yields the same row dicts. Nothing downstream changes — `normalize()` already
handles the messy shape the API returns.

Worth doing early: it removes the manual export step, which is the thing that
stops this running on a schedule.

**Watch out for:** export jobs are asynchronous and paginated, credentials belong
in a secrets store rather than `.env`, and a full export of a real environment is
tens of thousands of rows — the pipeline needs batching before it sees that.

---

## 2. Live NVD / CVE lookup

**Now:** `data/cve_db.json`, a hand-curated snapshot of 17 CVEs.
**Next:** the real NVD 2.0 API.

Replace the body of `lookup_cve()` in `vulntriage/intel.py`. It already returns a
`CVEContext`, and unknown CVEs already degrade gracefully, so the caller does not
change at all.

**Watch out for:** NVD rate-limits hard without an API key (5 requests per 30s;
50 with a key). Cache aggressively — CVE records barely change — and keep the
local snapshot as the fallback when the API is unreachable, so a triage run never
fails because NVD is having a bad day.

---

## 3. Exploit-DB / CISA KEV integration

**Now:** KEV membership and exploit maturity are fields in the mock database.
**Next:** the real CISA KEV catalogue and Exploit-DB, plus EPSS.

KEV is a single JSON file, refreshed daily, no auth — this is the cheapest
high-value upgrade on the list. Exploit-DB adds "is there a working exploit" for
CVEs that are not yet KEV-listed.

The bigger win is **EPSS**: a probability that a CVE will be exploited in the next
30 days. That turns `EXPLOIT_WEIGHTS` in `vulntriage/scoring.py` from four
hand-picked constants into a continuous, evidence-based multiplier.

**Watch out for:** EPSS is a probability, not a severity. Blending it into the
score needs a deliberate curve, not a raw multiply, or low-probability criticals
get buried.

---

## 4. Human approval gate

**Now:** the crew proposes; a human reads `output/triage_report.md` and decides.
That boundary is already the point — nothing is ever applied.
**Next:** make the approval an explicit, recorded step rather than an implied one.

A `pending -> approved | rejected | deferred` state on each remediation, an
analyst identity, a timestamp, and a reason on every rejection. CrewAI's
`human_input=True` on the remediation task gives the interactive version; a
review queue gives the durable one.

This is the authority boundary, and it should get *harder* to bypass as the rest
of the system gets more automated. An agent that can propose a domain controller
reboot must never be one config flag away from performing it.

---

## 5. Richer per-finding narrative (needs a bigger model)

**Now:** the remediation agent writes ~100 words of grounded transcription, and
`vulntriage/guard.py` mechanically flags any claim that contradicts the pipeline
state.
**Next:** a real per-finding write-up — why *this* fix on *this* host in *this*
order, what breaks if it slips, what the analyst should tell the asset owner.

This is the one item on the list that **cannot be built by changing this
codebase.** It is a model-capacity problem, not an engineering one.

On `llama3.1:8b` the two failure modes trade directly against each other. The
early runs wrote 434 words of genuinely useful analysis and invented facts while
doing it — a Spring4Shell finding pinned to the wrong host, a Zerologon fix
justified with Heartbleed's reasoning, one finding scheduled into two different
weeks. Closing those holes (a tool that states the closed set, task rules that
name each failure mode) worked, and cost the analysis: the narrative fell to 104
words and stopped naming hosts almost entirely. It stopped attributing findings
to the wrong host partly by no longer attributing them at all. That is grounding
bought with substance, and at 8B there is no setting that buys both.

Word count is not the measure, and a later run made that concrete: 284 words and
still no analysis. The agent restated the tool's data sheet field by field and
echoed its guardrail text ("do not attribute CVE-2020-1472 to any other host")
straight into the report. It padded rather than reasoned.

Part of that was our bug, and it is fixed: the tool was interleaving directives
with facts, so quoting the facts dragged the instructions along. The tool now
emits data only and the behavioural rules live in the task prompt, with guard
check E7 flagging any narrative that reproduces the tool's headings or labels.

But the underlying problem is not a formatting bug. Every fact in that narrative
was true, which is why the guard passed it at the time — **the guard measures
grounding, not usefulness**, and nothing mechanical can measure the second one.
An 8B model given a clean data sheet still restates it; what it cannot do is
reason about it. That is the part a bigger model buys.

So the honest prerequisite is a larger or hosted model — `gpt-4o-mini` upward, or
a 70B-class local model if the data cannot leave the building (see
PRODUCTION_GUARDRAILS.md §3, which is the constraint that put this on Ollama in
the first place). The seam is already there: `vulntriage/config.py` takes
`--provider openai --model gpt-4o-mini` today, and the guard runs against
whatever the model writes, so a bigger model can be given a longer leash without
giving up the safety net.

**Watch out for:** do not reach for this by loosening the constraints on 8B. That
trade has been measured and it goes the wrong way. And keep the guard on when the
model gets bigger — a more fluent model writes more plausible wrong sentences, not
fewer, and the failure taxonomy in `guard.py` is exactly what should be re-run
against any model change (PRODUCTION_GUARDRAILS.md §6, "re-validate on model
change").

**Also worth doing:** the guard currently annotates. Once narratives are rich
enough to be load-bearing, revisit whether a flagged claim should be suppressed
rather than footnoted — but that decision belongs with the human approval gate in
item 4, not with the report writer.

---

## 6. LangChain comparison

Rebuild the Enrichment agent in LangChain (or LangGraph) against the same tools
and the same mock data, and write up the difference.

Enrichment is the right agent to port: it has multiple tools, a real branch
(known CVE vs. gap), and no dependency on the stages around it.

What to compare: how each framework defines a tool, how state moves between
steps, what happens when the model returns a malformed tool call, and how much
scaffolding each needs before the first run. The write-up is the deliverable —
"I used both" is worth less than "here is where they differ and which I would
pick for what."

---

## 7. A triage dashboard

Serve the ranked queue as a web view instead of a markdown file: filter by
priority, owner, or asset; show the score breakdown on click; track queue burn-down
over time.

`output/triage_report.json` is already the API response — it carries the full
`ScoreBreakdown` for every finding specifically so a UI can show *why* something
ranks where it does, not just where it ranks.

**Watch out for:** the interesting view is not the finding list, it is the
disagreement with CVSS — the `rank_delta` column is the thing an analyst cannot
get from Tenable.

---

## 8. Ticketing integration

Auto-create ServiceNow or Jira tickets for P1 and P2 findings, grouped by host so
one maintenance window closes several findings —
`vulntriage/remediation.py:group_by_change()` already does that grouping.

**Watch out for:** duplicate suppression. A weekly scan re-reports everything
still open, and a triage bot that opens 200 tickets a week gets switched off in
week two. Ticket creation needs an idempotency key (host + CVE) and a link back
to the existing ticket when the finding recurs. Gate it behind item 4.

---

## 9. Feedback loop

When an analyst overrides a rank — deferring a P1, escalating a P4 — record the
finding's features and the correction. Over time that becomes evidence about
where the weights are wrong.

Start descriptive, not predictive: "criticals on `branch-*` hosts are deferred 80%
of the time" is directly actionable and needs no model. Only fit something once
there is enough signal to beat the hand-tuned constants, and keep the scoring
explainable — an analyst has to be able to argue with the number, which is why
`ScoreBreakdown` records every multiplier and its reason.

---

## Beyond the list

- **Reachability, not just presence.** A vulnerable library that no code path
  calls is not the same risk as one behind a public endpoint. This is the single
  biggest source of false urgency in real VM programs.
- **Compensating controls.** A WAF rule or a segmentation boundary should lower
  the score. Right now the model has no way to represent "yes, but it is not
  reachable from anywhere that matters."
- **Scale.** 18 findings fit in one context window; 20,000 do not. At real
  volume the agents should reason over aggregates and exceptions, with the
  deterministic pipeline handling the long tail — which is why the data already
  moves through `PipelineState` rather than through the model.
- **Evaluation.** A fixed set of findings with an experienced analyst's expected
  ranking, run as a test. Without it, "the ranking makes sense" is an opinion,
  and every prompt change is an unmeasured regression risk.

---

# Priority inputs for a live environment

The roadmap above is ordered by engineering effort. This section orders the same
territory by **impact** — when moving from mock data to a live environment, these
are the context sources that turn a CVSS sorter into a real triage tool.

The POC already implements 1 and 3 against mock data, which is why the demo
ranking inverts the way it does. **Input 2 — SLA timing — has no corresponding
item in the roadmap above and is the largest genuine gap in the current design.**

## Top 3 (highest impact)

### 1. Asset criticality / business context

The single biggest lever. An asset inventory with criticality tags so the crew
knows which hosts matter:

- Crown-jewel / business-critical
- Internet-facing vs internal
- Production vs dev/test
- Data sensitivity (PII, financial, regulated)

This is what drove the demo's ranking inversions — a CVSS 5.3 on a payment
system outranking a 9.8 on a test box. Without asset context, the crew is just
sorting by CVSS.

**Source:** CMDB, asset inventory, or a tagged host list.

**Status:** implemented against `data/asset_inventory.json`. Going live means
replacing `lookup_asset()` in `vulntriage/intel.py` with a CMDB client — see
item 1 above, which covers the same join from the Tenable side.

### 2. SLA / remediation windows

Company patch deadlines by severity so the prioritization agent can flag what's
overdue or about to breach:

- Critical = X days, High = Y days, Medium = Z days
- Time since the finding was first detected

This turns "severe" into "overdue critical on a crown-jewel asset" — the finding
a VM team acts on first. SLA breach risk is often more actionable than raw
severity.

**Source:** Security policy / VM program SLA matrix.

**Status: not built.** The pieces are in place but unused — `PRIORITY_BANDS` in
`vulntriage/scoring.py` already attaches an SLA string to each band, and every
finding carries `first_found`, so days-open is a subtraction away. What is
missing is the breach calculation and a term in the risk model. The open design
question is whether SLA urgency should be a multiplier like the others or a
separate axis: a finding that is *about to breach* is not more dangerous, it is
more **due**, and collapsing those two ideas into one number hides the
distinction an analyst is actually managing. Surfacing `days_open`,
`sla_days`, and `days_to_breach` as their own sortable columns is likely the
better first move — cheap, and immediately useful in the CSV export.

### 3. Exploit / threat intelligence

Whether a vulnerability is actually being exploited, not just theoretically bad:

- CISA KEV (Known Exploited Vulnerabilities) — is it on the list?
- EPSS score — probability of exploitation in the next 30 days
- Public exploit availability (Exploit-DB, Metasploit module exists)

An actively-exploited medium outranks a high with no known exploit. This is
already hinted at in the demo (KEV-listed HTTP/2 Rapid Reset climbing the ranks).

**Source:** CISA KEV feed, FIRST.org EPSS API, Exploit-DB.

**Status:** implemented against the mock database — KEV membership floors the
exploit multiplier at ×1.60. Live feeds and the EPSS curve are items 2 and 3
above.

## Strong fourth-tier (add after the top 3)

- **Network exposure** — is the vulnerable port actually reachable, or firewalled?
- **Compensating controls** — WAF, EDR, segmentation that reduces real risk
- **Patch availability** — is there even a fix yet, or is it zero-day?
- **Downstream dependencies** — what breaks if this host goes down for patching?
- **Remediation effort** — quick config change vs full migration

Two notes on these. **Remediation effort is already built** — every CVE in the
mock database carries an effort level, hour estimate, change risk, and
reboot/downtime flags, and they surface in the report and the CSV. And the first
two overlap with *Reachability* and *Compensating controls* under "Beyond the
list" above; treat those as the same work item, not two.

## How the crew uses these

- **Discovery Agent:** ingests findings + joins asset inventory (adds criticality)
- **Enrichment Agent:** pulls KEV/EPSS/exploit intel per CVE
- **Prioritization Agent:** scores using severity × asset criticality × exploit
  likelihood × SLA urgency (the real risk formula)
- **Remediation Agent:** factors patch availability + effort into the proposed fix

The current implementation matches this, with two deviations worth knowing. The
asset join happens at **enrichment**, not discovery — discovery cannot know that
`10.20.4.11` and `prod-db-01` are the same host, because that fact only exists in
the CMDB. And the live formula is severity × asset criticality × exploit
availability × **exposure**; SLA urgency is the term that is not there yet.

## The interview line

> "Raw CVSS tells you a vulnerability is severe. It doesn't tell you if it's on a
> system that matters, if it's being exploited right now, or if you're about to
> breach your remediation SLA. My triage crew factors in asset criticality, threat
> intel, and SLA timing — so it surfaces what a VM analyst would actually work
> first, not just what scores highest."

One caveat before using this verbatim: the crew factors in asset criticality and
threat intel today, but **not SLA timing**. Either build input 2 first, or say
"asset criticality, threat intel, and exposure" — which is what it actually does,
and is still the right answer to the question.
