# VulnTriage Crew — Multi-Agent Vulnerability Triage Workflow

**A CrewAI multi-agent system that takes raw vulnerability findings and runs them
through a triage-to-remediation workflow — discovery, enrichment, prioritization,
and remediation proposal — with each step handled by a specialized agent.**

Weekend proof-of-concept. Portfolio piece demonstrating agent orchestration on a
real security workflow you already understand (Tenable, CVEs, branch remediation).

---

## Why this project

- Uses **CrewAI** (multi-agent orchestration) — the resume keyword you want
- Mirrors your actual RXO work (VM pipeline, Tenable, CVE dashboards) — you can
  speak to it with authority
- Workflow automation is in-demand — this is the "hot" category
- Bounded enough for a weekend, extensible enough to grow

---

## The workflow (Sifu Agent framing)

**Audit:** VM teams drown in raw scanner output. Hundreds of findings, no context,
no prioritization. A human manually correlates each against advisories, asset
value, and exploitability. Slow, repetitive, judgment-heavy.

**Architect:** Four specialized agents in a crew, each owning one stage:

```
Raw findings (Tenable/mock JSON)
        │
        ▼
┌───────────────────┐
│ 1. Discovery Agent│  parses + normalizes scanner output
└─────────┬─────────┘
          ▼
┌───────────────────┐
│ 2. Enrichment     │  adds CVE details, CVSS, exploit availability
│    Agent          │
└─────────┬─────────┘
          ▼
┌───────────────────┐
│ 3. Prioritization │  scores by severity × asset value × exploitability
│    Agent          │
└─────────┬─────────┘
          ▼
┌───────────────────┐
│ 4. Remediation    │  proposes fix + effort estimate per finding
│    Agent          │
└─────────┬─────────┘
          ▼
   Triage report (ranked, actionable)
```

**Evaluate:** Run it on a set of sample findings; check that the ranking matches
what an experienced analyst would decide.

**Deploy:** POC runs locally. Human reviews the output — the crew proposes, the
analyst approves (authority stays with the human).

---

## The four agents (CrewAI roles)

### 1. Discovery Agent
- **Role:** Vulnerability Data Normalizer
- **Goal:** Parse raw scanner output (Tenable/Nessus JSON or CSV) into a clean,
  structured list of findings
- **Task:** Take messy input, output normalized findings (host, CVE, port,
  service, raw severity)

### 2. Enrichment Agent
- **Role:** Threat Intelligence Enricher
- **Goal:** Add context to each finding — CVE description, CVSS score, whether a
  known exploit exists
- **Task:** For each finding, look up (or from a local mock DB) the CVE details
  and attach them
- **Tool:** A lookup tool (mock CVE database for the POC; real NVD API as a
  future add-on)

### 3. Prioritization Agent
- **Role:** Risk Prioritization Analyst
- **Goal:** Rank findings by actual risk, not just raw CVSS
- **Task:** Score each finding using severity × asset criticality × exploit
  availability; output a ranked list
- **Logic:** A medium CVE on a critical asset with a public exploit outranks a
  high CVE on a test box with no exploit

### 4. Remediation Agent
- **Role:** Remediation Advisor
- **Goal:** Propose a concrete fix and effort estimate for each top finding
- **Task:** For the ranked findings, output remediation steps (patch, config
  change, mitigation) and a rough effort level

---

## In scope (weekend POC)

- CrewAI crew with the four agents above, orchestrated sequentially
- Input: a sample Tenable/Nessus findings file (JSON or CSV) — use mock data if
  you don't want to export real data
- A mock CVE lookup tool (small local dict/JSON — no live API needed for POC)
- Output: a ranked triage report (markdown or JSON) with enrichment,
  prioritization, and remediation
- LLM backend: Ollama (local, free) or OpenAI — configurable
- A README explaining the workflow and how to run it
- A FUTURE_ADDONS.md documenting what comes next (see below)

## Out of scope (POC)

- Live Tenable API integration (mock/exported data is fine)
- Live NVD/CVE API (mock lookup for now)
- A UI (command-line output is fine for the POC)
- Persistence / database
- Human-in-the-loop approval UI (note it as future)
- Parallel agent execution (sequential is fine)

---

## Future add-ons (put these in FUTURE_ADDONS.md)

1. **Live Tenable API integration** — pull findings directly instead of a file
2. **Live NVD/CVE lookup** — real threat intel instead of mock DB
3. **Exploit-DB / CISA KEV integration** — flag actively exploited CVEs
4. **Human approval gate** — analyst approves remediations before they're
   finalized (Sifu Agent authority boundary)
5. **LangChain comparison** — rebuild one agent in LangChain to compare
   frameworks (gets both on the resume)
6. **A dashboard** — visualize the triage queue (reuse the honeypot dashboard
   pattern)
7. **Ticketing integration** — auto-create ServiceNow/Jira tickets for top
   findings
8. **Feedback loop** — analyst corrections train the prioritization over time

---

## Deliverables

- `vulntriage/` project with the CrewAI crew
- `agents.py` — the four agent definitions
- `tasks.py` — the task for each agent
- `crew.py` — orchestration (the crew that runs them in sequence)
- `tools/cve_lookup.py` — the mock CVE lookup tool
- `data/sample_findings.json` — mock scanner output to run against
- `main.py` — entry point: load findings, run the crew, output the report
- `README.md` — what it does, how to run, the workflow diagram
- `FUTURE_ADDONS.md` — the roadmap above
- `requirements.txt` — crewai + deps

---

## Verification checklist

- [ ] Crew runs end to end on the sample findings
- [ ] Discovery agent normalizes the raw input
- [ ] Enrichment agent attaches CVE context from the mock DB
- [ ] Prioritization agent produces a ranked list that makes sense (critical
      asset + exploit beats raw CVSS)
- [ ] Remediation agent proposes concrete fixes for the top findings
- [ ] Final report is readable and actionable
- [ ] README explains the workflow; FUTURE_ADDONS.md captures the roadmap
- [ ] Runs on Ollama (local) without paid API keys

---

## Portfolio story

"I built a multi-agent system with CrewAI that automates vulnerability triage —
four specialized agents that normalize scanner output, enrich it with threat
intel, prioritize by real risk, and propose remediations. It mirrors the manual
VM workflow I ran across a 200+ branch environment, but as an orchestrated agent
crew."

That ties your existing VM experience to modern agent frameworks — exactly the
bridge that makes you more hireable.
