# VulnTriage Crew — Production Guardrails

**What would need to be in place before this multi-agent system could run in a
real production environment. The operating principle: autonomy is earned through
evidence, not granted by default. The agents propose; humans approve; every
decision is logged and validated.**

---

## 1. Output Integrity

The hallucination problem, at scale. The model writes prose; prose drifts.

- **Template the narrative from state data** — the model fills defined slots, it
  doesn't free-write findings. Structured output beats free text.
- **Validation layer** — every host, CVE, IP, and date in the output must exist
  in the input state. If it doesn't, the finding is flagged or rejected, not
  published.
- **Confidence thresholds** — below a set score, route to a human instead of
  auto-publishing.
- **Cross-check against the deterministic pipeline** — the CSV data is
  ground truth (SHA-256 verifiable). Any narrative claim that contradicts the
  structured data is a defect.

---

## 2. Human Authority Boundaries (most important)

The agents must never act on production systems.

- **Propose, don't execute** — no agent patches, changes configs, or touches a
  live system. It outputs recommendations; a human carries them out.
- **Tiered approval:**
  - Low-risk, reversible → may auto-close or auto-ticket
  - High-risk (crown-jewel assets, irreversible actions, production changes) →
    always require human sign-off
- **Authority proportional to risk** — the harder something is to undo, the more
  human oversight it requires.

---

## 3. Data Handling

Findings expose sensitive infrastructure detail.

- **Encrypt at rest and in transit.** Scope access by role.
- **Don't send real asset data to a hosted LLM without review.** Use a local
  model (Ollama) or a vetted enterprise endpoint. Assume anything sent to a
  third-party API could be logged.
- **Redact where possible** — the model may not need real hostnames/IPs to
  reason about a CVE.
- **Full audit log** — every agent's input, decision, and output recorded (reuse
  the honeypot's JSONL decision-log pattern).

---

## 4. Reliability & Failure Handling

- **Rate limits and token caps** — the LLM10 lesson from the honeypot. Cap input
  size and per-run token spend.
- **Timeout + retry per agent** — a stuck agent must not hang the whole pipeline.
- **Fail gracefully, never lose work** — the file-lock fix (timestamped fallback)
  is exactly this category. Extend the pattern everywhere output is written.
- **Idempotency** — re-running the same findings must not create duplicate
  tickets or duplicate remediations.
- **Defined fallback when the model is unavailable** — degrade to the
  deterministic pipeline output (which doesn't need the LLM).

---

## 5. Observability

- **Evidence trail per run** — what came in, what each agent decided, what went
  out. Inspectable and challengeable.
- **Divergence alerting** — flag when the crew's output deviates from expected
  patterns (sudden spike in criticals, a new host type, etc.).
- **Quality metric: human override rate** — how often does a reviewer overrule
  the crew? That number is your accuracy signal over time.

---

## 6. Model Governance

- **Pin the model version** — don't let the model silently change under you
  (llama3.1:8b stays llama3.1:8b until you deliberately upgrade).
- **Regression tests on known findings** — a fixed set of inputs with expected
  rankings; run before every release (you already have this pattern).
- **Re-validate on model change** — any model upgrade re-runs the full eval suite
  before going live.
- **Failure taxonomy** — track the categories of mistakes (wrong host, borrowed
  reasoning, schedule contradiction) so you know what to test for.

---

## The One-Line Version (for interviews)

"The agents never touch production. They propose, a human approves, and every
decision is logged and validated against the source data. The structured pipeline
is deterministic and verifiable; the model only writes the narrative, and that
narrative is validated against the data it's allowed to reference. Autonomy is
earned through evidence, not granted by default."

---

## Mapping to the Sifu Agent Framework

| Sifu discipline | Guardrail above |
|---|---|
| Audit | Know the workflow, the assets, the authority boundaries |
| Architect | Structured pipeline + model only for analysis |
| Evaluate | Regression tests, confidence thresholds, human override rate |
| Deploy | Tiered approval, observability, rollback, gradual autonomy |
| Loop | Failure taxonomy feeds back into tighter prompts and tests |
