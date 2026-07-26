# VulnTriage Crew — Priority Inputs for Live Environment

**When moving from mock data to a live environment, these are the context
sources that turn a CVSS sorter into a real triage tool. Add to FUTURE_ADDONS.md.**

---

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

### 2. SLA / remediation windows
Company patch deadlines by severity so the prioritization agent can flag what's
overdue or about to breach:
- Critical = X days, High = Y days, Medium = Z days
- Time since the finding was first detected

This turns "severe" into "overdue critical on a crown-jewel asset" — the finding
a VM team acts on first. SLA breach risk is often more actionable than raw
severity.

**Source:** Security policy / VM program SLA matrix.

### 3. Exploit / threat intelligence
Whether a vulnerability is actually being exploited, not just theoretically bad:
- CISA KEV (Known Exploited Vulnerabilities) — is it on the list?
- EPSS score — probability of exploitation in the next 30 days
- Public exploit availability (Exploit-DB, Metasploit module exists)

An actively-exploited medium outranks a high with no known exploit. This is
already hinted at in the demo (KEV-listed HTTP/2 Rapid Reset climbing the ranks).

**Source:** CISA KEV feed, FIRST.org EPSS API, Exploit-DB.

---

## Strong fourth-tier (add after the top 3)

- **Network exposure** — is the vulnerable port actually reachable, or firewalled?
- **Compensating controls** — WAF, EDR, segmentation that reduces real risk
- **Patch availability** — is there even a fix yet, or is it zero-day?
- **Downstream dependencies** — what breaks if this host goes down for patching?
- **Remediation effort** — quick config change vs full migration

---

## How the crew uses these

- **Discovery Agent:** ingests findings + joins asset inventory (adds criticality)
- **Enrichment Agent:** pulls KEV/EPSS/exploit intel per CVE
- **Prioritization Agent:** scores using severity × asset criticality × exploit
  likelihood × SLA urgency (the real risk formula)
- **Remediation Agent:** factors patch availability + effort into the proposed fix

---

## The interview line

"Raw CVSS tells you a vulnerability is severe. It doesn't tell you if it's on a
system that matters, if it's being exploited right now, or if you're about to
breach your remediation SLA. My triage crew factors in asset criticality, threat
intel, and SLA timing — so it surfaces what a VM analyst would actually work
first, not just what scores highest."
