# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
"Report a vulnerability" (Security Advisories) on this repository.
Do not open a public issue for a vulnerability, and do not include real
personal data in any report - use synthetic examples.

We aim to acknowledge reports within 7 days.

## Scope: design properties we test for

These are behaviours the test suite checks on every change, not guarantees:

- The library is designed to make no network connections (`tests/test_no_network.py`).
- Values that Sangop detects as PII are not written to the audit ledger in clear
  (`tests/test_guard_and_ledger.py`); personal data it does not recognise can still appear (README, Known limits).
- Unparseable or multi-statement SQL is blocked by default (fail-closed).
- A SQL argument that is not a string or `None` is blocked, and a SQL argument that gets real values back through
  detokenization is checked again before the tool runs (`tests/test_hardening_2026_11.py`).
- Exception messages are scrubbed, including exceptions that are not `Exception` subclasses, which keep their type.

## Out of scope

This project is a best-effort engineering aid. A bypass of a detection
pattern is a bug we want to fix, but no pattern set can catch all personal
data. Defence in depth (least-privilege database roles, read-only replicas,
network isolation) remains the user's responsibility.
