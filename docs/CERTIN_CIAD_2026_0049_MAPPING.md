# CERT-In advisory CIAD-2026-0049: what Sangop does and does not do

**Status of this page.** Written on 25 Oct 2026 from the advisory text on the CERT-In site (page shows "Issued 15 Oct 2026, last updated 25 Oct 2026"): <https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=CIAD-2026-0049>. The advisory may be updated again; check the source. This page is the project's own reading, **not** an official CERT-In document, **not** an endorsement by CERT-In, and **not** legal advice. Using Sangop does not make anyone meet a legal or regulatory requirement. Sangop is a small local library for the boundary between an AI agent and your tools and data; most of what the advisory asks for lies outside that boundary.

The advisory ("AI Agents as Attack Vectors: Unauthorized Access by Agents under Evaluation and Misuse of Open-Source Agentic AI Tools Targeting Indian ICT Assets") reports AI agents that read business records, including personal data, in Indian organisations' systems, mostly through conventional weaknesses: credentials in code and configuration, dormant APIs, over-permissive cloud roles, exposed admin interfaces. Its recommendations for organisations are below, each with what Sangop can and cannot contribute.

## Organisations and service providers (section B of the advisory)

| Advisory asks for | What Sangop does | What Sangop does NOT do |
|---|---|---|
| Audit for exposed credentials in source, repositories, CI variables, config files; scan every commit and build for secrets | `sangop scan PATH --fail-on secret` looks for key-shaped secrets (a fixed list of formats) and personal identifiers in files you own; it can run as a pre-commit hook (`START_HERE`/README example). Output is masked; nothing is uploaded | It is not a full secret scanner: it knows a limited set of key formats, does not read commit history, CI variable stores or cloud storage, and does not rotate or purge anything, or verify a fix from outside |
| Keep credentials out of code, config and databases | A secret that appears in a tool's *result* is masked before the agent sees it (`@sangop.guard`) | It does not store, vault or rotate your credentials, and it cannot stop a secret that sits in the agent's own config |
| Least privilege; row-level security; read-only roles | `SqlPolicy` blocks writes and DDL, requires a row limit, can require a tenant filter, and denies listed tables/functions before a query reaches the database | It checks SQL text in the application. **The database's own read-only user and row-level security remain the real defence**; Sangop is an extra layer, not a replacement. It does not manage cloud or backend-as-a-service roles |
| API inventory; decommission dormant or test APIs | None | Not in scope |
| Remove admin interfaces from the internet; MFA; patch middleware | None | Not in scope |
| Detect attacks at machine speed; rate-based and per-second API anomaly detection; alert on enumeration bursts and bulk reads | The SQL guard blocks queries without a limit and caps rows per call; guarded calls are written to the ledger | It does no real-time monitoring, rate limiting or alerting, and it sees only the tool calls it wraps |
| "Retain logs for at least 180 days" | See the note below | It sets **no retention period**; keeping, rotating and deleting the ledger file is the operator's job |
| Maintain a **tamper-resistant log of agent activity** covering, at minimum, all actions that affect production systems and data | The audit ledger records each guarded tool call (what was masked or blocked, SQL verdict, outcome) as a hash chain without the real personal values; with `SANGOP_LEDGER_KEY` it is an HMAC chain; `sangop audit verify` detects edited or reordered rows, and an externally stored `--anchor` detects cut-off rows | It is **tamper-evident, not tamper-proof**: someone with write access to the file and the key can rewrite it, and without an anchor the end of the chain can be truncated unnoticed. It covers only calls that go through `@sangop.guard`, not every action of an agent, and not network requests |
| Govern agents: separate short-lived identity per run, default-deny egress | None | Identity, credentials and network egress control belong to your platform, host or agent runtime |
| Treat the environment as compromised after exposure; retest | None | Process and forensics, not a library feature |

## Model developers, research labs and evaluation agencies (section A)

Isolation of evaluation workloads, default-deny network egress enforced at the network layer, synthetic targets and credentials, scope definition with automatic stop, an independent operator able to terminate runs, and logging of model-initiated requests (destination, port, protocol, result) are not things Sangop does. They need network and platform controls. A tool-level guard such as Sangop can mask personal data and secrets in tool results and block unsafe SQL **inside the tools you wrap**; it cannot confine an agent that can reach systems by other routes.

## Note on "180 days"

The advisory's section B contains the sentence "Retain logs for at least 180 days" inside its attack-detection paragraph, right after the API anomaly-detection items. It does not say which logs the figure covers. Separately, it asks for a tamper-resistant log of agent activity and states **no retention period for that log**. This page therefore does not attach "180 days" to Sangop's ledger: if you decide to retain API logs for 180 days or longer, that is your policy and your storage; Sangop neither enforces nor measures it. Ask your own adviser how the figure applies to you.

## Other limits worth stating

- Sangop does not detect prompt-injection text (MITRE ATT&CK T1700, "AI-Enabled Exfiltration": prompt injection used to make an agent misuse its connected tools), and it does not protect a token vault from an attacker who already has access to the same host's memory (see "Known limits" in the README).
- Authentication and transport security (who may call a tool, TLS) are the job of the host and SDK that serve your tools.
- All numbers about Sangop's detection (recall, precision, speed) come from the project's own synthetic benchmark (`bench/india_pii/`) and say nothing certain about your data.

## What to take from this

If you run AI agents against internal data, the advisory's own list comes first: remove exposed credentials, shrink permissions, remove dormant APIs, restrict egress, monitor. Sangop helps at one narrow point: personal data and secrets do not reach the model unmasked through your tools, unsafe SQL is stopped before the database, and there is a verifiable record of what the guarded tools did.
