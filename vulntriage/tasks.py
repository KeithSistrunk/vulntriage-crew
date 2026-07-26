"""One task per agent, chained in sequence.

Each task's `context` is the previous task's output, so the crew reads as a
pipeline. The *data* moves through `vulntriage.state.STATE`; what moves through
these tasks is the analysis — which is the part worth having a language model do.

Expected outputs are deliberately narrow. An agent asked for "a report" writes
filler; an agent asked for four short sections with a stated word budget writes
something an analyst will actually read.
"""

from __future__ import annotations

from crewai import Agent, Task


def build_tasks(agents: dict[str, Agent], findings_path: str, top_n: int = 5) -> list[Task]:
    discovery = Task(
        description=(
            f"Load and normalize the raw scanner export at '{findings_path}'.\n\n"
            "Call `load_and_normalize_findings` once with that exact path. Then review "
            "what it reports and write a short normalization review for the analyst who "
            "will read the final triage report.\n\n"
            "Cover:\n"
            "1. How many raw rows went in and how many findings came out — and account "
            "for the difference. Every dropped row should be explained.\n"
            "2. The data-quality problems in this export: duplicates, rows carrying "
            "multiple CVEs, hosts identified only by IP, missing CVSS values, CVE ids "
            "hiding in plugin names. Say which ones actually occurred here.\n"
            "3. Anything downstream stages need to be careful about.\n\n"
            "Do not assess severity, business impact, or remediation — later stages own "
            "those. Do not invent findings that the tool did not report."
        ),
        expected_output=(
            "150-250 words of plain prose (no preamble, no restating the instructions) "
            "reconciling raw rows to normalized findings, naming the specific data-quality "
            "issues found in this export, and flagging what downstream stages should watch. "
            "Write prose, not bullets, and do not paste the tool's output back — the report "
            "already contains it. Your value is the interpretation."
        ),
        agent=agents["discovery"],
    )

    enrichment = Task(
        description=(
            "Enrich every normalized finding.\n\n"
            "Call `enrich_findings` once — it takes no arguments and processes the whole "
            "set. Then use `lookup_cve` and `lookup_asset` to dig into the handful of "
            "findings that most deserve comment before you write.\n\n"
            "Write an intelligence assessment covering:\n"
            "1. The overall exploit picture: how many findings are on the CISA KEV list, "
            "how many are tied to ransomware campaigns, how many sit on internet-facing "
            "hosts.\n"
            "2. Two or three findings where the intelligence changes the story — a high "
            "CVSS with no real exploit, or a modest CVSS on a host that matters. Name the "
            "CVE and the host.\n"
            "3. Every intelligence gap, explicitly: CVEs missing from the database, hosts "
            "missing from the CMDB, and what that means for trusting their rank.\n\n"
            "Do not rank anything yet and do not propose fixes."
        ),
        expected_output=(
            "200-300 words of plain prose: the exploit picture in numbers, two to three "
            "named findings where context changes the interpretation, and an explicit list "
            "of intelligence gaps with their consequence for confidence. "
            "Write prose, not bullets, and do not paste the tool's output back."
        ),
        agent=agents["enrichment"],
        context=[discovery],
    )

    prioritization = Task(
        description=(
            "Score and rank every enriched finding.\n\n"
            "Call `score_and_rank_findings` once — it takes no arguments. It applies "
            "risk = CVSS x asset criticality x exploit availability x exposure, normalizes "
            "to 0-100, and bands the result into P1-P4.\n\n"
            "Then audit the ranking it produced:\n"
            "1. Summarize the queue: how many findings in each priority band, and what the "
            "top of the queue has in common.\n"
            "2. Explain the two or three biggest disagreements with a raw-CVSS ranking. "
            "For each, name the CVE and host, give both ranks, and justify the move in "
            "terms an owner would accept — asset value, exploit reality, exposure.\n"
            "3. Say plainly whether you would defend this ordering to a system owner, and "
            "name anything in it you would not.\n\n"
            "Use `lookup_asset` or `lookup_cve` if you need to check a specific claim. "
            "Do not propose remediations."
        ),
        expected_output=(
            "200-300 words of plain prose: the band distribution and what the top of the "
            "queue shares, two to three named rank movements with both ranks and a "
            "justification for each, and an explicit statement of confidence in the "
            "ordering including any reservation. "
            "Write prose, not bullets, and do not reproduce the ranked table — the report "
            "already contains it. Every claim about a finding's asset criticality or "
            "exploit status must match what the tools reported; do not guess."
        ),
        agent=agents["prioritization"],
        context=[enrichment],
    )

    remediation = Task(
        description=(
            f"Build the remediation strategy for the top {top_n} findings.\n\n"
            f"Call `get_ranked_findings` with top_n={top_n}. Its output is the complete "
            "and only set of facts you may use. It is a data sheet, not a template: a "
            "`CVE / HOST INDEX` giving the valid CVE-to-host pairings, then one labelled "
            "block per finding (host, risk, target, asset, window, exploit, ranking "
            "basis, fix, steps, constraints), then `SHARED HOSTS`, `EFFORT TOTAL` and "
            "`FINDINGS NOT CLOSED BY PATCHING ALONE`.\n\n"
            "FIVE RULES. Each exists because a previous run broke it, and a violation "
            "makes the plan unsafe to act on:\n\n"
            "1. NEVER PAIR A CVE WITH A HOST THAT IS NOT ITS OWN. Every finding is one "
            "CVE on one host. Before you write a host name in the same sentence as a CVE, "
            "check it against the roster. A plan that sends an engineer to the wrong box "
            "is worse than no plan.\n\n"
            "2. NEVER CARRY REASONING FROM ONE CVE TO ANOTHER. Justify each fix using "
            "only the details printed under that finding. Do not reuse an explanation, "
            "caveat, or turn of phrase from a different CVE — they are different "
            "vulnerabilities with different remediations, and a borrowed rationale is a "
            "false statement even when the conclusion happens to be right.\n\n"
            "3. SCHEDULE EACH FINDING EXACTLY ONCE. Your sequence assigns every finding "
            "to exactly one slot. Never restate the schedule in a later section. If you "
            "refer back to a finding, name it without repeating or revising its slot — "
            "two different slots for one finding makes the whole plan untrustworthy.\n\n"
            "4. EVERY FACT COMES FROM THE TOOL. Hosts, owners, windows, effort figures, "
            "compliance scope, and constraints must appear in the tool output for that "
            "finding. If you want to say something the tool did not give you, leave it "
            "out. Do not fill gaps from memory of how these CVEs usually behave.\n\n"
            "5. USE THE TOOL'S FACTS, NOT ITS FORMATTING. The data sheet is your source, "
            "never your model. Do not reproduce its section headings, its field labels "
            "('host:', 'risk:', 'ranking basis:', 'fix profile:'), its indentation, or its "
            "CVE / HOST INDEX. Do not copy any of its lines through into your answer. A "
            "reader of your plan should not be able to tell what shape the tool's output "
            "was. Write connected prose that states the facts in your own words — an "
            "analyst reading a restated data sheet learns nothing they could not read "
            "themselves, and the report already contains the underlying table.\n\n"
            "The per-finding steps are already in the report. Write the layer above them, "
            "in this order:\n\n"
            "a. SEQUENCE — the order to work the findings, each appearing once, with a "
            "one-line reason drawn from its own risk score, exposure, or window.\n"
            "b. BATCHING — which findings share a host and should ride one maintenance "
            "window and one change ticket. Take the groupings only from the tool's "
            "SHARED HOSTS data; if it reports none, say in one sentence that every top "
            "finding is on a different host and there is nothing to batch. Name the host "
            "and its findings; do not restate when they are scheduled.\n"
            "c. CONSTRAINTS — the operational realities that gate the work, drawn from "
            "the constraints listed under the findings they belong to.\n"
            "d. TOTAL EFFORT — state the per-band counts and the combined range exactly "
            "as the tool computed them, written into your own sentence. Do not add the "
            "bands up yourself, do not round or restate the arithmetic, and do not "
            "describe findings as sharing one effort level unless the tool's counts say "
            "so. Then say what you would tell the VM lead this week costs.\n"
            "e. PATCH IS NOT THE WHOLE FIX — name exactly the findings the tool lists "
            "under FINDINGS NOT CLOSED BY PATCHING ALONE. If it lists none, write one "
            "sentence saying no finding in this set needs work beyond its listed steps, "
            "and stop. Do not claim these fixes need anything extra.\n\n"
            "Everything here is a proposal for a human analyst to approve. Never state or "
            "imply that a change has been made."
        ),
        expected_output=(
            "250-400 words of plain prose covering, in order: the sequence (each finding "
            "exactly once), the host batching, the gating constraints, the total effort, "
            "and any finding where patching alone does not close it. "
            "Framed throughout as a proposal awaiting analyst approval. "
            "Write prose, not bullets, and do not repeat the per-finding steps — the "
            "report already contains them. "
            "Every CVE-to-host pairing must match the tool's CVE / HOST INDEX, every "
            "justification must come from that CVE's own details, and no finding may be "
            "given two different positions in the schedule. "
            "None of the tool's headings, field labels or lines may appear in your answer — "
            "restating the data sheet is not an answer."
        ),
        agent=agents["remediation"],
        context=[prioritization],
    )

    return [discovery, enrichment, prioritization, remediation]
