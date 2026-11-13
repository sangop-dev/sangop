# Keeping a record of AI agent tool calls (CERT-In advisory CIAD-2026-0058)

**Status of this page.** Written on 11 Nov 2026 from the advisory text on the CERT-In site (original issue date
4 Nov 2026; the page footer shows "Last Updated On November 10, 2026"):
<https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=CIAD-2026-0058>. The advisory may be updated;
check the source. This page is the project's own reading, **not** an official CERT-In document, **not** an
endorsement by CERT-In, and **not** legal advice. Using Sangop does not make anyone meet a legal or regulatory
requirement.

## What the advisory is about

CIAD-2026-0058 (severity: critical) describes an escalation of AI-driven attacks on banking, financial services and
insurance (BFSI) entities by a threat actor it calls "CRAFTY FALCON", as an update to CIAD-2026-0046. Most of its
recommended actions are about monitoring, incident response, cloud and network controls, application security,
payments and zero-trust architecture.

The points that touch records and agents are:

- preserve forensic evidence and logs when an incident is detected, and report suspicious activity to CERT-In or
  CSIRT-Fin together with the relevant logs;
- monitor LLM API usage, and watch for AI coding-agent processes running with permission checks disabled;
- remove hard-coded credentials and scan repositories and pipelines for secrets.

The advisory does **not** ask specifically for a record of the tool calls an AI agent makes, and it sets no
retention period for such a record.

## Where Sangop can help

- **A record you can verify.** Each call to a tool wrapped with `@sangop.guard` writes one event to a local audit
  ledger: tool, purpose, what was masked (counts by kind, not the values it recognised), the SQL verdict, and the
  outcome. The events form a hash chain (an HMAC chain with `SANGOP_LEDGER_KEY`), and `sangop audit verify` reports
  whether rows were edited or reordered; an `--anchor` kept elsewhere also shows whether the newest rows were cut off.
  This helps you keep a record of what your guarded tools did, as evidence you can verify and hand over with the
  other logs an incident report needs.
- **Fewer secrets in the wrong place.** `sangop scan PATH --fail-on secret` looks for a fixed list of key formats in
  files you own (masked output, nothing uploaded); secrets in a tool's result are masked before the agent sees them.

## What Sangop does not do here

- It records only the calls that go through `@sangop.guard`, not everything an agent does, and not LLM API traffic.
- It does no real-time monitoring, alerting, rate limiting or cloud audit logging.
- The ledger is **tamper-evident, not tamper-proof**: someone with write access to the file and the key can rewrite
  it. It sets no retention period; keeping, copying and deleting the file is the operator's job.
- It is not a secret scanner for commit history, CI variables or cloud storage, and it does not rotate credentials.

See the [Disclaimer](../README.md#disclaimer) and [Shared responsibility](../SHARED_RESPONSIBILITY.md).
