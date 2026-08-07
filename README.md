<p align="center">
  <img src="docs/vulntriage_diagram.png"
       alt="VulnTriage Crew architecture: raw scanner findings flow through four agents - Discovery, Enrichment, Prioritization and Remediation - over a shared pipeline state, producing a ranked triage report"
       width="900">
</p>

**A CrewAI multi-agent system that takes raw vulnerability scanner output and runs
it through a triage-to-remediation workflow — discovery, enrichment,
prioritization, and remediation proposal — with each stage owned by a specialized
agent.**

The point is not that it finds vulnerabilities. Tenable already did that. The
point is that it answers the question a scanner cannot: *of these 18 findings,
which three actually matter this week, and why?*

> **Related:** [Vulnerability-Management-Program](https://github.com/KeithSistrunk/Vulnerability-Management-Program)
> — the documented, manual vulnerability-management pipeline this project
> automates. That repo is the process: intake, triage criteria, risk acceptance,
> SLAs. This one is the same judgment expressed as code.

---

## The thesis

A vulnerability scanner sorts by CVSS. CVSS describes a vulnerability *in the
abstract* — it has no idea whether it is looking at a domain controller or a lab
box that gets rebuilt every night, and no idea whether anyone is actually
exploiting the thing.

So this pipeline scores risk as:

```
risk = CVSS  ×  asset criticality  ×  exploit availability  ×  exposure
```

On the sample data, that produces a ranking that disagrees with CVSS in ways an
experienced analyst would recognize:

| | Finding | CVSS | CVSS rank | **Risk rank** |
|---|---|---:|---:|---:|
| ⬆ | **CVE-2023-44487** (HTTP/2 Rapid Reset) on `edge-web-01` | 7.5 | #15 | **#8** |
| ⬆ | **CVE-2018-15473** (OpenSSH user enum) on `edge-web-01` | 5.3 | #17 | **#14** |
| ⬇ | **CVE-2020-0796** (SMBGhost) on `branch-114-fs01` | 10.0 | #1 | **#12** |
| ⬇ | **CVE-2023-38545** (curl SOCKS5) on `test-lab-07` | 9.8 | #8 | **#15** |

A **CVSS 5.3** medium on the internet-facing storefront outranks a **CVSS 9.8**
critical on a nightly-rebuilt QA box — because the medium is reachable from the
internet with a public PoC, and the critical needs a very specific SOCKS5 proxy
configuration on a host with nothing on it.

That inversion is the whole product. Everything else is plumbing.

---

## Validated against live data

The sample export above is the quick-start demo: small, deterministic, and backed
by a hand-curated CVE database. The same pipeline has also been run against a
real Tenable scan of a live Windows host — 198 rows, 172 plugins — sampled to 20
distinct CVEs and enriched against CISA KEV, FIRST EPSS and NVD:

```bash
python main.py --source csv --input Keith-Scan.csv --limit 20 --live-intel
```

**Live intel escalates.** Without it, all 20 findings scored P4 inside a
nine-point band: not one of these CVEs is in the local database, so every exploit
weight was a neutral ×1.00 and the ranking was a CVSS sort wearing a hat. With
KEV and EPSS attached, seven findings promoted to P3:

| CVE | Baseline | Live | Why |
|---|---:|---:|---|
| CVE-2013-3900 (WinVerifyTrust) | 29.3 | **46.9** | KEV-listed, EPSS 44.6% |
| CVE-2023-31102 (7-Zip) | 26.0 | **41.6** | EPSS 71.0%, *not* KEV-listed |
| CVE-2026-45498 (Defender) | 25.0 | **40.0** | KEV-listed, EPSS 63.1% |

CVE-2013-3900 arriving at the top is the result worth looking at: a 2013
signature-validation weakness that a CVSS sort buries beneath four higher-scored
2023–2026 findings, and that CISA lists as exploited in the wild.

**The inversion holds on real data.** CVE-2026-45498 at **CVSS 7.5** outranks
CVE-2023-52168 at **CVSS 8.4** — 40.0 against 28.0. Both sit on the same host, so
asset criticality and exposure are identical and cancel out: the entire
difference is that one is exploited in the wild and the other has an EPSS of 0.3%.

**Live intel de-escalates too, and that matters just as much.** NVD is
authoritative on CVSS, and it corrected the scanner *downward* on five of the
twenty — three of them sharply:

| CVE | Tenable | NVD | Risk score |
|---|---:|---:|---:|
| CVE-2023-40036 (Notepad++) | 7.8 | **5.5** | 26.0 → 18.3 |
| CVE-2023-40164 (Notepad++) | 7.8 | **5.5** | 26.0 → 18.3 |
| CVE-2023-40166 (Notepad++) | 7.8 | **5.5** | 26.0 → 18.3 |

plus CVE-2023-52169 (8.4 → 8.2) and CVE-2026-48101 (7.1 → 6.5). A triage tool
that only ever raised priorities would be one nobody could act on — the queue has
to shrink at the bottom as well as grow at the top.

The narrative guard passed the live run clean (4 stages, no unsupported claims),
having flagged two fabricated effort estimates on the same data without intel.

**One honest limit.** Nothing reached P2, and that is structural rather than
reassuring: a CSV export carries no Asset Criticality Rating, so every finding
scores at the neutral ×1.00 asset weight and the reachable maximum is 53.3
(CVSS 10.0 × 1.60 exploited ÷ 30) against a P2 threshold of 55.0. Priority bands
on this path describe the *vulnerabilities*, not the business. `--source tenable`
reads Tenable's ACR and restores the asset dimension.

---

## Run it without an LLM

The data pipeline is deterministic, so you can see the whole thing work before
setting up a model:

```bash
python main.py --offline
```

## Run the actual crew (local, free)

```bash
ollama serve
ollama pull llama3.1:8b
python main.py
```

Ollama is the default backend — no API key, no bill. To use OpenAI instead:

```bash
export OPENAI_API_KEY=sk-...        # PowerShell: $env:OPENAI_API_KEY="sk-..."
python main.py --provider openai --model gpt-4o-mini
```

Both write three outputs to `output/`:

| File | For |
|---|---|
| `triage_report.md` | Reading — the narrative report |
| `triage_report.json` | Programs — full nested structure, ready to be an API response |
| `triage_report.csv` | Spreadsheets — one row per finding, 55 columns, sorts and pivots |

The CSV is the one to hand a VM lead. It opens cleanly in Excel (UTF-8 BOM), every
row is a single line, and it carries the score breakdown alongside the result — so
someone can sort by `risk_score`, filter `priority = P1`, and still see the
`asset_weight` and `exploit_weight` that produced the number.

## Which model to use

**8B parameters is the practical floor.** The agents have to call tools reliably
and then write a few hundred words of analysis, and small models struggle with
the second part in particular.

| Model | Observed on the sample findings |
|---|---|
| `llama3.1:8b` *(recommended)* | All four agents produce usable analysis. Prioritization correctly justifies all three rank inversions; remediation produces a real sequenced plan with batching and effort. Still hallucinates in places — see the narrative guard below |
| `qwen2.5:7b`, `mistral:7b` | Not tested here; expect roughly 8B-class behaviour |
| `llama3.2:3b` | Calls tools correctly — the **data is still right** — but the narrative fails: it pastes tool output back verbatim, the enrichment agent refused outright, and remediation emitted a raw tool-call blob instead of an answer |
| `gpt-4o-mini` | Not tested here; costs money, best narrative quality |

**8B is a large improvement, not a fix.** An early 8B run had the remediation
agent contradict its own schedule (a finding in Week 2 in one paragraph, Week 1
in the next), attribute a Spring4Shell finding to the wrong host, and justify the
Zerologon fix with Heartbleed's reasoning ("the keys are already gone") — the
conclusion happened to be right, the reasoning was borrowed from another CVE.

The 3B behaviour is worth understanding, because it is the reason the pipeline is
built the way it is: **the report's data was correct in every run regardless of
how badly the model narrated it.** When an agent returns a refusal or a malformed
tool call, the report says so in that agent's section instead of publishing the
artifact — see `usable_note()` in `vulntriage/report.py`. Numbers never depend on
the model.

## Output

Every run writes four artifacts to `output/`:

| File | For |
|---|---|
| `triage_report.md` | reading — tables, remediation plan, and the agents' narrative, guard-checked |
| `triage_report.json` | machines — the full state, including the risk breakdown per finding |
| `triage_report.csv` | spreadsheets and ticket imports — one row per finding |
| `triage_report.pdf` | forwarding — every finding with CVE, CVSS, host, priority and remediation |

`--pdf-only` writes the PDF and nothing else, for when the forwardable artifact
is the whole point:

```bash
python main.py --source tenable --scan-id 58373 --offline --pdf-only
```

The PDF is byte-for-byte what a full run would have produced — the flag drops
artifacts, it does not change the one it keeps. The narrative guard still runs,
so `--strict-narrative` still decides the exit code; because the markdown it
normally annotates was not written, a pdf-only run that flags a claim says so on
stderr rather than dropping it silently.

**The PDF contains no agent narrative at all.** It is rendered from the same
deterministic state as the CSV — scanner output, CVE intelligence, asset
inventory — and never from `agent_notes`. A PDF is the artifact that travels
furthest from the run that produced it, so it carries only what the pipeline can
show its working for. Narrative belongs in the markdown report, where it is
attributed to a named agent and flagged inline wherever the guard caught it.

It is written directly, with no PDF library (`vulntriage/pdfwriter.py`), for the
same reason `--offline` needs nothing but pydantic: a report that only appears
after a `pip install` is not a report the run produces.

## Running against live data

The POC ships with mock findings and a hand-curated CVE database. Both can be
swapped for live feeds without touching the agents:

```bash
python main.py --offline --live-intel          # real KEV + EPSS + NVD, mock findings
python main.py --source tenable --live-intel   # everything live
python main.py --source tenable --limit 50     # widen the 20-CVE sample
python main.py --source tenable --min-cvss 4   # lower the floor if too little survives
python main.py --source csv --input Keith-Scan.csv   # a Tenable CSV export, no keys
python main.py --offline                       # unchanged: pure mock, no network
```

| Flag | Effect |
|---|---|
| `--source mock` *(default)* | findings from `data/sample_findings.json` |
| `--source tenable` | findings pulled from the Tenable API (estate workbench by default) |
| `--source csv` | findings read from the Tenable CSV export named by `--input` — no keys, no network |
| `--scan-id N` | pull one scan's results (`/scans/{id}`) instead of the workbench; also skips the source menu |
| `--limit N` *(default 20)* | sample a pull or an export down to N distinct CVEs; `0` lifts the cap |
| `--min-cvss X` *(default 7.0)* | drop findings below CVSS X before the cap; `0` lifts the floor |
| `--live-intel` | enrich against CISA KEV, FIRST EPSS and NVD instead of `cve_db.json` |
| `--no-cache` | bypass the on-disk intel cache and re-fetch |

### The live pull is sampled, not truncated

The estate this was built against has 105 workbench plugins behind thousands of
findings, and enrichment spends a rate-limited NVD call on every distinct CVE —
unkeyed, that is 30 seconds a page. So a live pull is capped at 20 by default.

**What the cap keeps matters as much as the cap.** Tenable returns the workbench
in plugin order, and taking the first 20 rows off it returned 20 hosts carrying
one CVE-1999-0524 ICMP timestamp disclosure: 1 of 105 plugins, every finding P4,
nothing to triage. A capped pull is therefore sampled:

1. drop anything below `--min-cvss` (default 7.0, the CVSS v3 High boundary)
2. keep each CVE once, at the highest-severity plugin reporting it
3. walk the workbench in severity order
4. stop at `--limit`

which returns up to 20 *distinct* high-severity CVEs instead of 20 copies of the
noisiest one. All four steps run inside the pull, so plugins beyond the cap are
never requested and never enriched.

Two things this deliberately trades away, both stated in the run summary and in
the report's anomalies rather than hidden: only one affected host is shown per
CVE (the rest are counted, not listed), and the sample is the severe end of the
estate, not a survey of it. `--limit 0` lifts both the cap and the one-host-per-CVE
dedupe for a real run; `--min-cvss` is its own filter and applies either way.
`--source mock` ignores both flags entirely.

### A CSV export instead of the API

```bash
python main.py --source csv --input Keith-Scan.csv
python main.py --source csv --input Keith-Scan.csv --limit 0 --min-cvss 4
```

A Tenable CSV export is what people actually have. Handing one over costs nobody
an API key, and it is the only way to triage an estate you can no longer reach —
an old scan, a customer's export, a scan someone else ran.

`--source csv` reads the columns the API client already normalizes — CVE, CVSS3
Base Score, Risk, Host, FQDN, Name, Solution, plus port, protocol, state and
plugin output — under whichever of Tenable's several spellings the export uses
(`CVSS3 Base Score` and `CVSS v3.0 Base Score` are both read, as are `Risk` and
`Risk Factor`, `Host` and `DNS Name`).

**It is sampled by exactly the code a live pull is sampled by.** `TenableCsvClient`
subclasses the API client and overrides only the three seams the sampling loop
reads — which plugins exist, what a plugin's CVEs and score are, which hosts
report it. The floor, the one-CVE-once dedupe, the one-host-per-CVE pick and the
cap are inherited, not reimplemented, so the two sources cannot drift about what
a report covers. `--limit`, `--min-cvss` and `--limit 0` mean the same thing here
as they do above, and the run summary and report anomalies declare the sample the
same way.

Two things are specific to a file source:

- **A CSV export carries no Asset Criticality Rating.** The API path reads
  Tenable's ACR and bands it into the risk model's criticality; an export has no
  such column, so findings stay flagged as an intel gap and score at the neutral
  asset weight rather than on an invented rating. Identity and OS still come from
  the file, so findings reconcile across FQDN, NetBIOS name and IP.
- **An export writes one row per (plugin, CVE)**, so a four-CVE plugin on one box
  is four rows describing one instance. Those are folded back into one instance
  before sampling — otherwise the report would claim three affected hosts that do
  not exist.

`Solution` has no equivalent in the API's workbench response, so it is the one
field the export knows that a live pull does not. Where the local intel database
has no entry for a CVE, that text becomes the baseline remediation instead of
"no vendor guidance on file" — labelled as the scanner's words, with the effort
left unscoped, because a one-line fix string is a head start and not an approved
change plan.

**`--source mock` also reads CSV, and stays exactly as it was:** every row, no
floor, no cap, no dedupe. That difference is the whole reason `--source csv`
exists — one is "parse this file", the other is "sample this estate".

### One scan instead of the estate

```bash
python main.py --source tenable --scan-id 58373
```

`--scan-id` reads `/scans/{id}` and its host and plugin detail instead of the
workbench. The scan payloads are translated into the workbench's shapes on the
way in, so the sampling, the normalizer and the risk model are the same code on
both paths — only the three endpoints differ. Without the flag, nothing changes.

**At a terminal, `--source tenable` without `--scan-id` asks which one you
want:**

```
Tenable source:
  1. Estate scan (full workbench)
  2. Scan by ID

Select 1 or 2 [1]:
```

Option 1 is the workbench pull as before; option 2 prompts for the ID and then
behaves exactly as `--scan-id` would — the menu's only job is to fill that flag
in, and nothing downstream can tell which way it was set.

The menu appears in exactly one situation, and the exclusions are the point:

| Situation | What happens |
|---|---|
| `--source tenable`, no `--scan-id`, a terminal | the menu |
| `--scan-id N` passed | that scan, no menu |
| No terminal — `scripts/lab_run.ps1`, CI, redirected stdin | the estate workbench, no menu |
| `--source mock` | unchanged, never asked |

An unattended run must never meet a prompt, so the check is for a real terminal
on stdin rather than for anything the caller has to remember to pass.
`scripts/lab_run.ps1` already redirects stdin from an empty file and now also
takes `-ScanId`; `--source tenable` alone still means the workbench there, as it
always has. Ctrl+C at the menu exits 130 without running anything.

Two things the real API forced, both specific to scan mode:

- **A scan summary carries no CVSS, only a severity.** Applying the CVSS floor
  would otherwise mean a detail call per plugin — 153 of them on the test scan,
  135 informational — and Tenable rate-limits those endpoints hard enough to
  fail the pull with HTTP 429. So a scan pull floors on the severity *band's
  ceiling* first, which is free, and only then pays for the detail call: 153
  plugins down to 6 calls. The workbench keeps judging on the authoritative
  score, because it has one and is not throttled the same way.
- **The scan detail returns `ref_information: null`** for every plugin on this
  instance, while Tenable puts the id in the plugin name
  (`... CVE-2021-34527 OOB Security Update RCE`). Discovery already recovers
  those, so the pull does too — otherwise it would drop findings the normalizer
  would have kept. Recovered ids are counted and declared in the report, because
  an inferred identifier is not one the scanner asserted.

### Keys

Copy `.env.example` to `.env` and fill in what you need. `.env` is gitignored;
`.env.example` documents the shape and is committed.

```
TENABLE_ACCESS_KEY=      # Settings -> My Account -> API Keys
TENABLE_SECRET_KEY=
TENABLE_FLAVOR=io        # or "sc" for Tenable.sc
# TENABLE_URL=           # override for Tenable.sc or a non-default region
NVD_API_KEY=             # free: nvd.nist.gov/developers/request-an-api-key
```

**KEV and EPSS need no key.** NVD works without one but throttles to 5 requests
per 30 seconds instead of 50 — an 18-finding cold run takes about two minutes
unkeyed and a few seconds with a key.

### What each feed contributes

| Feed | Auth | Gives | Wins on |
|---|---|---|---|
| CISA KEV | none | confirmed in-the-wild exploitation, ransomware use | exploited-or-not, in both directions |
| FIRST EPSS | none | probability of exploitation in the next 30 days | the exploit multiplier's graduated band |
| NVD | free key | description, CVSS v3.1, CWE, references | the vulnerability itself |
| Tenable | keys | the findings | what is actually on your estate |

The local database still wins on **remediation guidance** — no public feed knows
that a POS terminal cannot reboot during trading hours.

### What the Tenable API actually returns

Worth writing down, because it differs from the documented shape in four ways
that each silently broke the pull:

- `/workbenches/vulnerabilities` carries **no CVE field**. CVEs live only on
  `/workbenches/vulnerabilities/{id}/info`, under `reference_information`, so
  the pull is two calls per plugin, not one.
- `/outputs` returns `{"outputs": [...]}`, not a bare list. Treating it as a
  list yields the dict's *keys* and fails later as `'str' object has no
  attribute 'get'`.
- Results carry `assets`, not `hosts`, and each asset has its `fqdn` and `ipv4`
  inline — so the separate asset-workbench call is not needed.
- The transport is `transport_protocol` and the service is
  `application_protocol`.

Plugins whose `/info` lists no CVE are skipped before their outputs are ever
requested: the normalizer drops CVE-less rows anyway, and that was 16 of 105
plugins on the instance this was built against.

### A stale exported variable beats .env

`python-dotenv` does not override a variable already exported in your shell, so
`TENABLE_ACCESS_KEY` left over in your environment silently wins over the one in
`.env` — which looks exactly like your new credentials being rejected. The run
now warns when the two disagree. Clear the exported variable, or export the value
you actually want.

### Caching

`.cache/` (gitignored) holds the KEV catalogue, EPSS scores and NVD records. It
exists for two reasons: NVD's rate limit, and reproducibility — a report that
ranks differently because a feed refreshed mid-run is not one an analyst can
argue with. A warm run makes **zero** NVD requests and finishes in under a
second; the cold run that populated it made 17.

### When a feed is down

Intel feeds degrade: the run continues with less context and says so, on stdout
and in `pipeline_state.json`. A total outage of all three still produces a
complete, scored report from the local database.

The findings source is different. If Tenable cannot be read there is nothing to
degrade *to*, and quietly triaging the sample file instead would be a live run
that is actually a mock one — so that fails with exit 2 and an explanation.

## The narrative guard

Seven checks, each one a failure actually observed on an 8B run, each one decidable
against `PipelineState`:

| | Check | Catches |
|---|---|---|
| E1 | wrong host attribution | a CVE named alongside a host that is not its own |
| E2 | borrowed CVE reasoning | a rationale phrase tied to CVE A used for CVE B |
| E3 | schedule contradiction | one finding given two different slots |
| E4 | effort misstatement | an effort band or hour total the data disagrees with |
| E5 | unsupported extra work | "a patch is not enough" where the constraints say it is |
| E6 | fabricated finding | a CVE that is not in this run at all |
| E7 | echoed tool scaffolding | the tool's data sheet restated instead of analysed |

Violations are flagged inline in the report beside the paragraph that caused
them, recorded under `narrative_guard` in the JSON, and printed at the end of a
run. `--strict-narrative` turns them into exit code 3.

**The guard annotates; it does not silence.** These are regex heuristics over
free text, and a false positive that hides real analysis costs more than one that
adds a visible footnote. The data was never at risk either way.

A guard's PASS is worth nothing until it fails on the runs that were genuinely
wrong, so `tests/test_guard.py` holds the known-bad baseline — the real early-run
narratives, wrong host and borrowed reasoning and contradictory schedule — and
asserts every one is caught.

    python -m vulntriage.guard output/pipeline_state.json   # check a saved run

---

## How it actually works

### Mechanical work goes in tools; judgment goes in prompts

CrewAI passes one task's output to the next as *text*. That is fine for analysis
and dangerous for data — an LLM re-typing a JSON array at every hop is where these
pipelines silently lose findings, and a lost finding is one nobody ever fixes.

So this crew splits the two:

- **Structured data** moves through `vulntriage/state.py` — a shared pipeline
  state. Each stage's tool does the deterministic work (parse, join, multiply),
  writes the structured result there, and returns a compact summary.
- **Analysis** moves through the LLM. Each agent reads its tool's summary and
  does the part only it can do: notice what looks wrong, weigh trade-offs, and
  explain the result to a human.

The final report's tables and numbers are assembled from the pipeline state, so
they always reconcile with the input file. The agents' narrative is dropped in
alongside them — clearly attributed, never load-bearing for the data.

This also means `--offline` isn't a toy mode. It is the same pipeline with the
narration turned off, which makes the risk model testable in CI.

### The risk model

Defined in `vulntriage/scoring.py`, deliberately blunt and fully auditable:

| Factor | Weights |
|---|---|
| **Asset criticality** | critical ×1.50 · high ×1.25 · medium ×1.00 · low ×0.70 |
| **Exploit availability** | weaponized ×1.60 · functional ×1.45 · PoC ×1.30 · none ×1.00 |
| **Exposure** | internet-facing ×1.25 · internal ×1.00 |

CISA KEV membership floors the exploit weight at ×1.60 — CISA only lists CVEs
with confirmed in-the-wild exploitation, so it is not a signal to average away.

The product is normalized against the worst possible case (10.0 × 1.5 × 1.6 ×
1.25 = 30.0) into a 0–100 score, then banded:

| Band | Score | SLA |
|---|---|---|
| **P1** | ≥ 75 | Emergency change — 24–48 hours |
| **P2** | ≥ 55 | Expedited — 7 days |
| **P3** | ≥ 35 | Scheduled — next monthly patch cycle |
| **P4** | < 35 | Backlog — bundle with routine hardening |

Every finding carries a `ScoreBreakdown` recording each multiplier *and the
reason it was applied*, so an analyst can argue with the number instead of
guessing at it. That matters more than the weights being exactly right.

### The messy-input problem

`data/sample_findings.json` is deliberately realistic. It contains every failure
mode a real Tenable export has, and the Discovery stage handles each one:

| In the export | What Discovery does |
|---|---|
| The same SMBv1 exposure reported by two plugins | Collapses to one finding, keeps the richer evidence |
| One row carrying two CVEs | Splits into two findings, each scored on its own merits |
| A host identified only by `10.20.4.11` | Reconciled to `prod-db-01` at enrichment, via the CMDB |
| `severity` as `4` in one row and `"4"` in another | Coerced |
| PrintNightmare with a null CVSS | Filled from the intel database |
| A CVE that only appears in the plugin *name* | Recovered by regex, and flagged |
| An informational "Nessus Scan Information" row | Dropped, counted |
| A finding already marked `fixed` | Dropped, counted, and explained |

Every dropped row is accounted for in Appendix A of the report. 21 raw rows in,
18 findings out, and the difference is fully reconciled — because a triage tool
you cannot reconcile is a triage tool nobody trusts.

---

## Sample output

```
21 raw rows -> 18 findings (1 informational, 1 no-CVE, 1 already remediated,
                            1 duplicates collapsed, 1 multi-CVE rows split)
Priority: P1=4  P2=7  P3=3  P4=4

Top 5 by risk:
  1.  81.7  P1  CVE-2022-22965   edge-web-01     CVSS 9.8   [+5 vs CVSS rank #6]
  2.  80.0  P1  CVE-2020-1472    dc-01           CVSS 10.0
  3.  80.0  P1  CVE-2021-44228   prod-db-01      CVSS 10.0  [+1 vs CVSS rank #4]
  4.  78.4  P1  CVE-2019-0708    dc-01           CVSS 9.8   [+1 vs CVSS rank #5]
  5.  66.7  P2  CVE-2017-5638    hr-app-03       CVSS 10.0  [-2 vs CVSS rank #3]
```

The full report includes the ranked queue, a "why this ranking is not the CVSS
ranking" section, per-finding remediation with effort estimates and operational
constraints, suggested change-ticket batching, each agent's analysis, a
normalization audit, and an explicit list of intelligence gaps.

### The CSV export

`output/triage_report.csv` — one row per finding, in rank order:

| rank | risk_score | priority | cve | cvss | hostname | asset_criticality | effort | change_risk |
|---|---|---|---|---|---|---|---|---|
| 1 | 81.7 | P1 | CVE-2022-22965 | 9.8 | edge-web-01 | high | medium | medium |
| 2 | 80.0 | P1 | CVE-2020-1472 | 10.0 | dc-01 | critical | medium | high |
| 3 | 80.0 | P1 | CVE-2021-44228 | 10.0 | prod-db-01 | critical | medium | medium |
| … | | | | | | | | |
| 15 | 29.7 | P4 | CVE-2023-38545 | 9.8 | test-lab-07 | low | low | low |
| 18 | 19.3 | P4 | CVE-2016-2183 | 3.7 | edge-web-01 | high | low | low |

55 columns in five groups: **triage result** (rank, score, priority, SLA), **the
score breakdown** (each multiplier, the raw product, the CVSS rank it moved from),
**threat and exposure context** (KEV, exploit maturity, internet-facing,
compliance scope), **remediation** (summary, numbered steps, effort in hours,
change risk, reboot/downtime, constraints), and **provenance** (plugin id,
scanner severity, first/last seen, whether the CVE and asset were actually found
in the lookups).

Two details that matter for a file people open without thinking:

- **Every row is one line.** Multi-value fields — remediation steps, constraints,
  compliance scope — are joined with `|` rather than newlines, so a finding can
  never split into two rows.
- **Formula injection is neutralized.** Cells beginning with `=`, `+`, `-`, or `@`
  are prefixed with an apostrophe. Excel executes those otherwise, and in a real
  deployment CVE text is attacker-influenced.

---

## Project layout

```
main.py                        entry point — load, run, report
requirements.txt
README.md
FUTURE_ADDONS.md               the roadmap
PRODUCTION_GUARDRAILS.md       what production would require

docs/
  vulntriage_diagram.png       the architecture diagram above

scripts/
  lab_run.ps1                  unattended run wrapper (revives Ollama, logs)

vulntriage/
  agents.py                    the four agent definitions
  tasks.py                     one task per agent, chained
  crew.py                      orchestration (sequential)
  config.py                    LLM backend — Ollama or OpenAI
  models.py                    pydantic models, one per stage
  state.py                     shared pipeline state between stages
  normalize.py                 Discovery: raw export -> clean findings
  intel.py                     Enrichment: CVE + asset joins
  scoring.py                   Prioritization: the risk model
  remediation.py               Remediation: fixes, effort, constraints
  report.py                    markdown + JSON + CSV report builders
  guard.py                     narrative guard — the seven grounding checks
  pipeline.py                  deterministic pipeline (the --offline path)
  live/
    kev.py                     CISA KEV catalogue
    epss.py                    FIRST EPSS, batched
    nvd.py                     NVD 2.0, cached + rate-limited
    tenable.py                 Tenable pull -> raw rows for the normalizer
    cache.py                   TTL'd on-disk cache for the above
    http.py                    shared urllib fetch with retries
  tools/
    findings_loader.py         Discovery agent's tool
    cve_lookup.py              the mock CVE lookup tool
    asset_lookup.py            the mock CMDB lookup tool
    enrichment.py              Enrichment agent's batch tool
    risk_scoring.py            Prioritization + Remediation agent tools

data/
  sample_findings.json         mock Tenable export (deliberately messy)
  sample_findings.csv          same, in Tenable's CSV shape
  cve_db.json                  mock CVE intel — 17 real CVEs, NVD CVSS v3.x
  asset_inventory.json         mock CMDB — 8 assets

tests/
  test_pipeline.py             risk model + normalization tests
  test_guard.py                the guard's known-bad baseline
  test_live.py                 live clients, every external call mocked
```

---

## The four agents

| Agent | Role | Owns |
|---|---|---|
| **Discovery** | Vulnerability Data Normalizer | Parsing, dedup, splitting, filtering, and reconciling raw rows to findings |
| **Enrichment** | Threat Intelligence Enricher | CVE context, exploit reality, KEV status, asset criticality, and naming the gaps |
| **Prioritization** | Risk Prioritization Analyst | Scoring, ranking, and defending the places it disagrees with CVSS |
| **Remediation** | Remediation Advisor | Fixes, effort in hours, change batching, and the constraints that gate them |

They run sequentially, and the dependencies are real: enrichment has nothing to
enrich until discovery normalizes, and scoring is meaningless without exploit and
asset context.

---

## Scope

**In:** the four-agent crew, mock Tenable input in two formats, mock CVE and CMDB
lookups, a ranked markdown + JSON report, Ollama or OpenAI, and a deterministic
offline path.

**Out (for now):** live Tenable / NVD APIs, a UI, persistence, an interactive
approval gate, and parallel execution. All of it is in
[FUTURE_ADDONS.md](FUTURE_ADDONS.md) with the seam each one plugs into.

---

## Tests

```bash
python -m pytest tests/ -v          # or: python tests/test_pipeline.py
```

Covers normalization (dedup, multi-CVE splits, filtering, CVE recovery, host
reconciliation), the risk model's weights and bands, and — most importantly —
the CVSS-inversion cases that are the reason the project exists.

---

## The authority boundary

The crew proposes. The analyst approves. Nothing in this pipeline changes a
system, opens a ticket, or touches a host — it produces a document for a human to
read and act on.

That boundary is deliberate, and it should get *harder* to cross as the rest gets
more automated. An agent that can recommend a domain controller reboot must never
be one config flag away from performing one.

---

*POC built against mock data. The CVEs and their CVSS scores are real; the hosts,
the asset inventory, and the scan are not.*
