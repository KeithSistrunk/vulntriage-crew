# VulnTriage Crew — Live API Integration Spec

**Wire the crew to real data: Tenable (findings), NVD (CVE details), CISA KEV
(known-exploited), and FIRST EPSS (exploit probability). Ticketing stays mocked
for now.**

The architecture rule holds throughout: API results are fetched into the shared
state layer (state.py), normalized there, and only analysis flows through the
LLM. The four external calls replace the mock lookups; the agent logic doesn't
change.

---

## What changes vs the POC

| Stage | POC (mock) | Live |
|-------|-----------|------|
| Discovery | sample_findings.json | Tenable API pull |
| Enrichment | mock CVE dict | NVD API + CISA KEV + EPSS |
| Prioritization | uses enriched data | same, now with real exploit intel |
| Remediation | mock | unchanged (ticketing still future) |

---

## 1. Tenable Integration (Discovery)

**API:** Tenable.io (`https://cloud.tenable.com`) or Tenable.sc depending on the
CyberRange setup. Confirm which one.

**Auth:** API keys — an access key and secret key, sent in the header:
`X-ApiKeys: accessKey=<KEY>; secretKey=<SECRET>`

**Keys go in a .env file, never in code or git.** (.env is already gitignored.)

**Endpoints (Tenable.io):**
- `GET /workbenches/assets` — asset list
- `GET /workbenches/vulnerabilities` — vulnerability findings
- Or export API for larger pulls: `POST /vulns/export` then poll for chunks

**What to pull per finding:** plugin ID, CVE(s), CVSS, host/asset, severity,
port, state (open/fixed).

**Build:** a `tools/tenable_client.py` that authenticates, pulls findings, and
normalizes them into the same shape the Discovery agent already expects. The
mock loader becomes one option; Tenable becomes another (a --source flag).

---

## 2. NVD / CVE Integration (Enrichment)

**API:** NVD 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`)

**Auth:** free API key (request at nvd.nist.gov). Without a key you get 5
requests / 30 sec; with one, 50 / 30 sec. Key goes in .env.

**Per CVE, pull:** description, CVSS v3.1 base score + vector, CWE, published/
modified dates, references.

**Important:** NVD rate-limits hard. Build in:
- A local cache (don't re-fetch a CVE you already have)
- Respect the rate limit with a small delay between calls
- Batch where possible

**Build:** `tools/nvd_client.py` with caching. Replaces the mock CVE dict.

---

## 3. CISA KEV Integration (Enrichment)

**API:** single public JSON feed, no auth:
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**Use:** download the full feed once per run (it's one file), build a set of
KEV CVE IDs, and flag any finding whose CVE is in the set. KEV = actively
exploited = major priority boost.

**Build:** `tools/kev_client.py` — fetch, cache for the run, expose
`is_known_exploited(cve_id)`.

---

## 4. FIRST EPSS Integration (Prioritization)

**API:** `https://api.first.org/data/v1/epss?cve=CVE-2021-44228` (public, no auth)

**Returns:** an EPSS score (0-1) = probability the CVE will be exploited in the
next 30 days, plus a percentile.

**Use:** pull the EPSS score per CVE and feed it into the prioritization
formula. Can batch multiple CVEs in one call (comma-separated).

**Build:** `tools/epss_client.py` — batch lookup, cache per run.

---

## The real prioritization formula (now possible)

With live data, Prioritization can score properly:

```
risk_score = base_severity (CVSS)
           × asset_criticality      (from Tenable asset data / tags)
           × exploit_factor         (KEV = high boost, EPSS score = graduated)
```

KEV-listed CVEs jump to the top. High-EPSS CVEs climb even without KEV. This is
what produces the "real risk over raw CVSS" inversions your POC demonstrated —
now with live intel instead of mock flags.

---

## Config & secrets

`.env` (gitignored):
```
TENABLE_ACCESS_KEY=...
TENABLE_SECRET_KEY=...
NVD_API_KEY=...
```
KEV and EPSS need no keys.

Add a `.env.example` (committed) showing the variable names with empty values,
so anyone cloning knows what to set.

---

## Build order (do it incrementally, verify each)

1. **KEV first** — easiest (one public file, no auth, no rate limit). Wire it,
   confirm findings get flagged.
2. **EPSS second** — public, simple batch call. Add scores.
3. **NVD third** — needs the key + caching + rate-limit handling. More moving
   parts.
4. **Tenable last** — the biggest piece; confirm which Tenable variant and
   whether the CyberRange allows API egress.

Keep the mock path working alongside (a --source mock|tenable flag) so you can
still run without hitting live APIs.

---

## Guardrails carry over

- All four clients fetch into state.py; raw API JSON never goes to the LLM
- Cache per run to respect rate limits and stay reproducible
- The narrative guard (E1-E7) still validates output against the enriched state
- .env keeps secrets out of git; .env.example documents the shape
- On any API failure, degrade gracefully — log it, continue with what you have,
  don't crash the run

---

## Deliverables

- `tools/tenable_client.py`, `tools/nvd_client.py`, `tools/kev_client.py`,
  `tools/epss_client.py`
- Caching layer (per-run) for NVD/EPSS
- `.env.example` committed; real `.env` gitignored
- `--source mock|tenable` flag so both paths work
- README section: how to set up keys and run against live data
- Tests: each client mocked (don't hit live APIs in tests); verify normalization
  into state

---

## Verification checklist

- [ ] KEV feed downloads and flags known-exploited CVEs
- [ ] EPSS scores attach to findings
- [ ] NVD enrichment works with caching and respects rate limits
- [ ] Tenable pull normalizes into the Discovery agent's expected shape
- [ ] Prioritization uses real KEV + EPSS in the ranking
- [ ] Secrets are in .env, never committed; .env.example documents them
- [ ] Mock path still works via --source mock
- [ ] Tests mock all external calls (no live hits in CI)
- [ ] Graceful degradation on any API failure
