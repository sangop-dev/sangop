# Changelog

All notable changes to the open-core `sangop` package. Versions are dates: `YEAR.MONTH.PATCH` (a new release
every month or so; Sangop Pro, a separate add-on, follows the same numbering). Pre-release (alpha).

## Unreleased

- **CI hardening:** GitHub Actions pinned to full commit SHAs, checkout without stored credentials, minimal
  per-job permissions, `pip-audit` and `bandit` in CI, Dependabot for pip and GitHub Actions. Also: an exception
  attribute that cannot be overwritten is now dropped instead of keeping its unscrubbed value (found by bandit).
- **Dependabot:** removed the label settings (those labels do not exist in the repository) and stopped automatic
  major-version update pull requests; minor and patch updates continue.

## 2026.11.0 (2026-11-15) - first public release of the open core

What the open core does today:

- **Detectors (basic rule set, ASCII digits 0-9):** Aadhaar (Verhoeff checksum), PAN, GSTIN (check character), IFSC,
  Indian mobile numbers (5-5 digits with or without one space or hyphen, optional `+91`, `91` or `0`), e-mail, payment
  cards (Luhn; ISBN-13 excluded), UPI IDs (known handles, or any handle right after the word "UPI" or "VPA"), and nine
  secret formats (private keys, Anthropic, OpenAI, GitHub, AWS access key, Google API, Slack, Telegram bot, JWT).
  A PEM private key block cut off before its `END` line (length limit, pagination) is masked from the header to the
  end of its key lines; scanning stays linear on 1 MB of headers without `END` (measured under 0.5 s).
- **Tokenizer:** values are replaced by tokens such as `[PII_PAN_3f9a12c04b7d51e8]` (64 bit) before a tool result
  reaches the model; a tool you trust can get selected kinds back (`detokenize_kinds`, every reveal is logged).
  Results are scrubbed in nested containers, dataclasses, pydantic models, generators and error messages.
- **`@guard` decorator** for MCP / FastMCP tools, with `shadow` modes that only count and log.
- **SQL guard** (sqlglot AST): blocks writes, DDL, several statements, missing or unsafe LIMITs (also on set
  operations and hidden aggregates in scalar sub-queries), row-folding aggregates, file/network/session functions,
  `FOR UPDATE`, and weak tenant filters; optional allow-lists for tables and functions.
- **Audit ledger:** SQLite hash chain, HMAC-keyed with `SANGOP_LEDGER_KEY`; `verify` reports keyed / unkeyed / mixed
  and detects cut-off rows with an anchor; values Sangop detects as personal data are not written in clear. `sangop keygen`.
- **Media:** images, PDFs, Office files, archives and audio are recognised by their first bytes and blocked by default
  (`media_mode="block"`), or passed unscanned and logged (`"allow"`).
- **CLI:** `sangop scan`, `sql-check`, `audit verify/tail`, `keygen`, `selftest`.
- **Rules plugins:** an installed package can provide a different rule set through the `sangop.plugins` entry point;
  `selftest()` reports which rule set is active, and a plugin that fails to load stops detection instead of falling
  back to weaker rules.
- **Hardening before the first release:** a SQL argument that is not a string or `None` is blocked (`None`, for
  example an optional argument that was not given, means "no SQL"); a misspelt `sql_param` is
  an error when the guard is made; a SQL argument that gets real values back through detokenization is checked
  again before the tool runs; exceptions that are not `Exception` subclasses keep their type but lose personal
  data from their message; `memoryview` results are read like bytes; `Enum` members and other shared objects are
  never changed by scrubbing; pydantic models are also checked in their JSON form.

- **Minimum sqlglot raised to 28.5** (found by the weekly maintenance check, test first): measured on sqlglot
  28.4.0, the bulk-extraction check missed a Postgres `json_agg` with a `LIMIT`; from 28.5.0 the whole test suite
  passes. **httpx added to the `dev` extra** so the MCP compatibility tests run on a clean install.
- **Tests:** regression tests for row-folding aggregates with LIMIT (Postgres `json_agg` / `jsonb_agg`).
- SQL guard: blocks MySQL/MariaDB executable comments and more row-folding and table-dumping functions (internal AI-assisted review, 14 Nov 2026).
- SQL guard: blocked more write, row-folding and file-reading functions, PostgreSQL attribute-notation aggregates and DuckDB top-N aggregates, SQLite virtual tables and pragma functions, unicode-escaped names, http/fdw extension calls (internal AI-assisted review, 14 Nov 2026).
- SQL guard: PostgreSQL `pg_*` / `lo_*` / `txid_*` / `dblink*`, SQLite `sqlite_*` and DuckDB `read_*` / `*_scan` names are blocked as whole families, with a short named list of harmless exceptions; SQL over 100 KB is refused; with `dialect="mysql"` (also for MariaDB), `--` without a following space is refused (see README, Supported SQL dialects). README: database settings for the agent's user, each checked on PostgreSQL 16 and SQLite.
- SQL guard: blocked PostgreSQL crosstab/xpath_table, DuckDB serialized-SQL execution and dynamic PIVOT (row-folding), plus more system tables (internal AI-assisted review 3, 14 Nov 2026)
- SQL guard: PostgreSQL and SQLite now use a default function allow-list; unknown functions are refused unless added via extra_allowed_functions (internal AI-assisted review 4, 15 Nov 2026).
- SQL guard: percentile functions only take a plain number as the fraction; format() width is limited; names are checked as written (internal AI-assisted review 5, 15 Nov 2026).
- SQL guard: schema-qualified calls (pg_catalog., main.) are checked like plain names; sha2 functions allowed; nested-value and bind-parameter limits documented (internal AI-assisted review 6, 15 Nov 2026).
- **Windows:** the first full test run on Windows found two gaps in the open core's tests (none in the library): the
  test that keeps the examples offline also blocked the loopback connection that every asyncio event loop makes on
  Windows, and the HTTP compatibility test sent its helper server's output to a pipe nobody read, so the server
  stopped once Windows' small pipe was full. Both are fixed, with tests of their own; the CI workflow now runs on
  Linux and Windows.
- **Docs and examples:** the README starts with the install line and a short before/after example whose output is
  checked by a test; three short examples (`examples/fastmcp_guarded_tool.py`, `sql_guard_only.py`,
  `ledger_verify.py`), run offline by the test suite; a note on CERT-In advisory CIAD-2026-0058 and agent tool-call
  records (`docs/CERT_IN_AGENT_LOGGING.md`).

See the README for measured accuracy and the Known limits.

## Earlier private previews

Versions 0.1.0 to 0.1.4 (October-November 2026) were private previews, not published.
