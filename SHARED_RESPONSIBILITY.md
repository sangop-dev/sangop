# Shared Responsibility Model

Sangop is one layer of defence. This page states plainly what Sangop does,
what it promises, and what remains the responsibility of the organisation
that deploys it. It is part of how we earn trust: no hidden claims.

## What Sangop does

- Detects common personal identifiers and secrets in tool outputs and replaces
  them with reversible tokens (or redacts / only logs, depending on mode).
- Parses SQL produced by AI agents and blocks writes, DDL, multi-statement,
  unparseable, unbounded and unscoped queries according to your policy.
- Writes a local, hash-chained audit log in which the personal data it detects is
  not stored in clear.

## What we commit to

- **Local only.** Sangop runs inside your process. It is designed to make no
  network connections and send no telemetry, so your data does not reach us.
- **Open and verifiable.** The full source and test suite are public, including
  tests that check, on every change, that no network connection is made and that
  values Sangop detects as PII are not written to the audit log in clear (tested
  behaviour, not a guarantee; see Known limits in the README).
- **Honest limits.** Known gaps are listed in the README and updated each release.
- **Measured accuracy.** We publish latency and false-positive measurements.
- **Responsible disclosure.** We aim to acknowledge, fix and disclose vulnerabilities
  reported via SECURITY.md through security advisories.
- **No compliance claims.** We never claim that using Sangop makes you compliant with any law.

## What remains your responsibility

- Choosing and testing the configuration (start in `shadow` mode).
- Least-privilege database access for agents (read-only roles, replicas,
  row-level security) - Sangop complements these, it does not replace them.
- Network isolation, secret management, access control and monitoring.
- Your legal obligations as a Data Fiduciary or controller (notices, consent,
  breach reporting, retention, data-subject rights).
- Reviewing Sangop's code and keeping it updated.

## What Sangop does not do

- It does not guarantee detection of every piece of personal data.
- It does not stop all prompt-injection attacks; it limits the damage a
  manipulated agent can do.
- It is not legal advice and not a certification.

Licensed under Apache-2.0, provided "AS IS", without warranties of any kind.
