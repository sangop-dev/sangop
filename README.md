# Sangop

**Sangop open core 2026.11 · Sangop Pro 2026.11 (separate add-on with tuned Indian rules; not yet publicly available)**

*Sangop (संगोप, from Sanskrit sam + gup, roughly "to guard well" - the name is an aim, not a promise).*

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10 to 3.13](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)

**A local, deterministic trust boundary between AI agents and your tools, built for Indian identifiers and DPDP
evidence.**

## Install

```bash
pip install sangop             # "sangop[fastmcp]" for the FastMCP integration
```

**Tested on:** Linux with Python 3.10, 3.11, 3.12 and 3.13, and Windows 10 with Python 3.12 (the maintainer's
laptop). Windows is not in automated CI yet; the CI workflow runs Linux and Windows once the repository is public.

## Before and after (invented values)

<!-- readme-example:code -->
```python
import sangop

sangop.configure(ledger_path="demo_audit.db")   # local audit ledger; no network, no telemetry

@sangop.guard(purpose="support", sql_param="query")
def run_query(query: str) -> list[dict]:
    return [{"id": 7, "pan": "ABCPE1234F", "phone": "9876543210"}]   # your real DB call; invented row

print(run_query("SELECT id, pan, phone FROM customers WHERE id = 7 LIMIT 1"))
try:
    run_query("DELETE FROM users")
except sangop.SangopBlocked as e:
    print(e)
```

<!-- readme-example:output -->
```text
[{'id': 7, 'pan': '[PII_PAN_6377c72335a5733d]', 'phone': '[PII_PHONE_IN_0fa10752bcd92ccd]'}]
Sangop blocked this query: write/DDL statement blocked by read-only policy (DELETE)
$ sangop audit verify --db demo_audit.db
OK (unkeyed): 3 event(s) checked. Ledger is UNKEYED (plain SHA-256 chain, no SANGOP_LEDGER_KEY): edits that recompute the chain and cut-off last rows (truncation) are NOT detected.
anchor: 3:1776e4b2aa53bbc3d1459f310bb67eedf85ea62516f6f3be0923c65a4b2e438f
(keep a copy of the anchor where the ledger's writer cannot change it; pass it as --anchor next time)
```

The agent gets tokens instead of the PAN and phone number, the `DELETE` never reaches the database, and the audit
ledger checks out. Set `SANGOP_LEDGER_KEY` (see `sangop keygen`) to make the ledger an HMAC chain.

## What it does by default

- **Scrubs tool results.** Personal data and secrets it recognises in what a guarded tool returns become tokens
  before the agent sees them (arguments the agent sends are not scrubbed).
- **Blocks unsafe SQL.** For the argument you name in `sql_param`, the query is parsed into an AST; writes, DDL,
  several statements and reads without a limit are blocked (`sql_mode="shadow"` only logs).
- **Logs every guarded call** to a local, hash-chained audit ledger, without the values it recognised, once
  `sangop.configure()` has set a ledger path (the default path is `.sangop/audit.db`).
- **No network, no telemetry.** It runs inside your process and opens no connections (`tests/test_no_network.py`).

> **Status: 2026.11 alpha.** Engineering aid only.
> **Not legal advice, and not a compliance guarantee.**
> See [Shared responsibility](SHARED_RESPONSIBILITY.md) and the [Disclaimer](#disclaimer).

## How it is built

It sits inside your MCP / FastMCP tool server, between the agent and your database or other tools. One decorator is
designed to keep the personal data and secrets it recognises from reaching the model, blocks the destructive or bulk
SQL its checks recognise (on by default), and writes a tamper-evident audit log of what it masked, blocked or let
through. It helps reduce risk; it does not catch everything - see [Known limits](#known-limits-open-core).

- **Local and deterministic.** Runs in-process. **It makes no network connections and sends no telemetry** (checked
  by `tests/test_no_network.py`, which blocks sockets while the library runs). No LLM in the hot path: compiled
  regex + checksums + SQL AST (sqlglot), so the same input gives the same result every time.
- **Built around Indian identifiers:** Aadhaar (Verhoeff), PAN, GSTIN (check char), IFSC, Indian mobile, UPI ID -
  plus email, cards (Luhn) and nine secret formats (exact list under Known limits). This open core ships a **basic
  rule set** (ASCII digits, the common written forms). Accuracy is measured and published with its limits stated
  (see [Accuracy](#accuracy-measured-with-caveats)).
- **Evidence, not a certificate.** The audit ledger is a hash-chained (optionally HMAC-keyed) record you can verify
  and keep as evidence of the safeguards your agents ran under. It does not make an organisation compliant with the
  DPDP Act or any other law, and it is not an audit or a certification (see [Disclaimer](#disclaimer)).
- **Adopt in small steps:** `sangop scan` your own code, run the guard in `shadow` mode (it counts and logs, changes
  nothing), then switch to the default modes (mask and block). See [Recommended adoption path](#recommended-adoption-path-low-risk).
- Small, readable codebase so your team can audit every line before trusting it.

## Quickstart (5 minutes)

You need Python 3.10+ and a copy of this folder. No account, no network, no MCP host.

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[fastmcp]"
python examples\quickstart\client_demo.py
```

**macOS / Linux (bash)**

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[fastmcp]"
python examples/quickstart/client_demo.py
```

You should see three calls (a customer record, a note with an API key pasted in it, an unfiltered query),
each answered three ways: without Sangop, in `shadow` mode (looks, changes nothing) and in `enforce` mode
(personal data replaced by tokens like `[PII_AADHAAR_xxxxxxxxxxxxxxxx]`, the query refused). A destructive `DROP TABLE`
is shown only against `enforce`. Then check the audit log: `sangop audit verify --db .sangop/quickstart_enforce.db`
should print `OK`. All data is invented and generated at run time.

To run the same tools as a real stdio MCP server: `python examples/quickstart/server.py` (or `... shadow`);
`examples/quickstart/claude_desktop_config.example.json` shows the shape of a host config with placeholder paths
(we have not run it in every MCP host; check yours). The step-by-step adoption path (scan, shadow, enforce) is in
[`examples/quickstart/ladder.md`](examples/quickstart/ladder.md).

**What Sangop does not do** (details in Known limits below): it does not detect names or addresses that have no
pattern, bank account numbers, digits written in Indian scripts (open core), or anything outside tool calls that go
through `@guard`; it can mask values that are not personal data; it is a pattern matcher, not a judge of your data. Who is responsible for what:
[Shared responsibility](SHARED_RESPONSIBILITY.md).

## Protect an MCP tool

```python
from fastmcp import FastMCP
import sangop

sangop.configure(ledger_path=".sangop/audit.db")   # runs a canary self-test
mcp = FastMCP("support")

@mcp.tool
@sangop.guard(purpose="support", sql_param="query",
              sql_policy=sangop.SqlPolicy(max_rows=20, require_filter_column="tenant_id"))
def run_query(query: str) -> list[dict]:
    ...
```

What happens on each call:

1. **SQL guard** - the `query` argument is parsed into an AST. Writes/DDL,
   multiple statements, unparseable SQL, row locks (`FOR UPDATE`), a missing or non-literal `LIMIT` (or one above
   `max_rows`, also on `UNION`/`INTERSECT`/`EXCEPT`), row-folding aggregates (`string_agg`, `group_concat`,
   `json_agg`, ...), file/network/session functions (`pg_read_file`, `dblink`, `load_extension`, `LOAD_FILE`, ...)
   and missing tenant filters are blocked (`SangopBlocked`). A SQL argument that is not a string or `None` (bytes,
   a list, a number, ...) is blocked too; `None` (an optional SQL argument that was not given) means "no SQL", is
   not checked and is noted in the ledger. A `sql_param` name that is not a parameter of the function is an error when the
   guard is made. If the SQL argument is also in `detokenize_params`, the query is checked again after the real
   values are put back, and blocked if it no longer passes (the tool never receives SQL the guard did not check).
   Use `sql_mode="shadow"` to only log. This is a **second layer**: see "Security model" below.
2. **PII/secret scrubbing** - the result is scrubbed before the model sees it:
   `ABCPE1234F` -> `[PII_PAN_3f9a12c04b7d51e8]`. Modes: `tokenize` (reversible,
   default), `redact`, `shadow` (log only; the original object is returned). Strings, bytes, dict keys and values,
   lists/tuples/sets, dataclasses, pydantic models, plain objects, generators (item by item) and exception
   messages are all scrubbed (bytes only when they are not media, see item 3). A lazy iterable **nested inside** a result (a generator, `map`, `zip`, `filter`,
   `iter(...)`, `itertools.chain` inside a dict or list) is read into a list of at most 10,000 items and scrubbed;
   a longer one, an async iterator nested inside a result, or one that raises while being read is replaced by a
   `[SANGOP_BLOCKED: ...]` placeholder and a `nested_iterable_blocked` ledger event (fail closed). A tool that raises gets a `SangopToolError` with a scrubbed message (the original
   exception is not chained) and an `error` event in the ledger. An exception that is not an `Exception`
   (`KeyboardInterrupt`, `SystemExit`, `asyncio.CancelledError`, a library's own `BaseException`) keeps its type,
   with its message, arguments and attributes scrubbed and chained exceptions dropped. A `memoryview` is read like
   bytes. Shared objects are never changed in place: an `Enum` member, or an object whose copy is the object
   itself, is replaced in the result by its scrubbed value (or a scrubbed dict of its attributes). A pydantic model
   is also checked in its JSON form (`model_dump(mode="json")`), so a custom serializer cannot put a value the
   fields do not show into the output.
3. **Recognised media is not let through silently, by default (D-078)** - images, PDFs, Office files, archives and audio are **not
   read** by Sangop (no OCR). They are recognised by their first bytes (PNG, JPEG, GIF, WebP, BMP, TIFF, HEIC/HEIF,
   AVIF, PDF, ZIP/Office, OLE, WAV, Ogg, FLAC, MP3, MP4; a PDF also when `%PDF-` comes after a BOM or junk within
   its first 1024 bytes) as raw `bytes`/`bytearray`/`memoryview`, as a `data:...;base64,...` URI anywhere inside a
   string (decoded and checked whatever MIME type it claims, spaces around `;` and `,` allowed), as a long (256+
   characters) base64 string or a base64 piece of that length inside longer text (`img=<base64>`), or as an MCP
   `ImageContent`, `AudioContent` or `EmbeddedResource` with a blob - also nested anywhere inside a result. Only the
   media piece is replaced; the text around it is still scanned for personal data. By default (`media_mode="block"`) each one is replaced by
   `[SANGOP_BLOCKED: media <kind> not scanned]` (an MCP content block becomes a `TextContent`) and a
   `media_blocked` ledger event records kind, detected and claimed MIME type, size, tool and purpose - never the
   content, never a plain hash (an HMAC fingerprint only when a ledger key is set). `media_mode="allow"` (per tool:
   `@sangop.guard(..., media_mode="allow")`, or for all tools: `sangop.configure(media_mode="allow")`) passes media
   on unchanged and **unscanned** and writes `media_unscanned`. Data that claims to be media but cannot be decoded
   is always blocked. `pii_mode="shadow"` changes nothing and only logs.
4. **Just-in-time detokenization** - a trusted tool can receive the real value, but only for the token kinds you
   name: `@sangop.guard(purpose="notify", detokenize_params=("phone",), detokenize_kinds=("PHONE_IN",))`.
   `detokenize_kinds` is **required** with `detokenize_params` (leaving it out is an error); `"*"` reveals every
   kind and is flagged in the ledger. Each reveal writes a `detokenize` event (counts by kind, never the values),
   and a value revealed in a call is masked again if the tool echoes it back.
5. **Audit ledger** - one event per call in SQLite (WAL) with a hash chain. Values Sangop detects as PII are not written in
   clear (personal data it does not recognise can still appear, see Known limits); SQL text is
   stored redacted. Set `SANGOP_LEDGER_KEY` (a long random value, at least 16 characters and preferably 32+, kept outside the ledger) to make it an
   HMAC-SHA256 chain; without a key `sangop audit verify` says the ledger is **unkeyed**. `sangop keygen` prints a
   suitable random key (see CLI). See Known limits.

## Recommended adoption path (low risk)

1. `sangop scan .` - offline scan of your own code; changes nothing.
2. `pii_mode="shadow"`, `sql_mode="shadow"` - observe in staging; blocks nothing.
3. Default modes - tokenize PII and block dangerous SQL once you trust the results.

## CLI

```bash
sangop scan PATH            # find secrets/PII in YOUR OWN files (masked output, exit 1 on secrets)
sangop sql-check "SQL"      # check one statement against the policy
sangop audit verify         # detect tampering in .sangop/audit.db (prints an anchor; use --anchor ID:HASH later)
sangop audit tail -n 20
sangop keygen               # print a random 32-byte ledger key (64 hex characters); writes no file
sangop selftest             # canary test with synthetic values; also prints which rule set is active
```

`sangop keygen` prints only the key on stdout and a short safety note on stderr. It never writes the key to a
file. Keep the key in a password manager (never in git, chat or screenshots) and put it in the environment of the
process that writes the ledger, for example (PowerShell, current session only):

```powershell
$env:SANGOP_LEDGER_KEY = (sangop keygen)
```

Anyone who has the key can write valid ledger rows, so treat it like a password. If you lose it, older keyed rows
can no longer be verified with a new key.

## Measured on the dev machine (v0.1, Python 3.13, synthetic data)

| Operation | p50 | p99 |
|---|---|---|
| scrub one sentence | ~0.06 ms | ~0.14 ms |
| `check_sql` one query | ~0.3-0.5 ms | ~1.2 ms |
| full guard, 20-row result with ~80 PII values, with ledger | ~2.5 ms | ~5.4 ms |

**Long texts (D-063, same machine, indicative).** `find_all` used to compare every candidate with every kept finding,
which is quadratic: a 260 KB text with 20,000 phone numbers took about 9.3 s (a 280 KB text with grouped numbers about
9.6 s). It now takes about 0.2 s for either (the kept findings are kept sorted and only the two neighbours are
checked). Results are identical to the old code on all 14,400 benchmark rows. Ordinary short texts are unchanged. A
database `statement_timeout` and a limit on the size of tool results are still your protection against very large
inputs; this change only removes a quadratic cost inside the detectors.

Numbers depend on hardware. Run `python bench/bench.py` on your machine.

## Accuracy (measured, with caveats)

We measure on our own synthetic **India-PII benchmark** (English, Hindi and Hinglish, with look-alike decoys): a main
dataset plus seven holdout sets with different seeds, templates and value generators. The sets themselves are kept
private (their values are synthetic but checksum-valid, so one could match a real person by chance); their **sha256
fingerprints** are published in [`bench/india_pii/README.md`](bench/india_pii/README.md), together with the file format
and the exact method, so anyone can run `bench/india_pii/score.py` on their own data. Strict span matching (kind and
exact start/end must match), micro-averaged, all rows measured on 5 Nov 2026.

**Sangop open core** (this repository, basic rule set):

| Set | Precision | Recall | F1 |
|---|---:|---:|---:|
| main dataset | 1.000 on this synthetic set | 0.977 | 0.988 |
| holdout 1 | 0.995 | 0.860 | 0.922 |
| holdout 2 | 0.986 | 0.737 | 0.843 |
| holdout 3 | 0.883 | 0.531 | 0.663 |
| holdout 4 | 0.926 | 0.459 | 0.614 |
| holdout 5 | 0.742 | 0.404 | 0.523 |
| holdout 6 | 0.708 | 0.749 | 0.728 |
| holdout 7 | 0.929 | 0.338 | 0.495 |

**Sangop Pro** (a separate, closed add-on with tuned rules for how Indian identifiers are actually written; not
publicly available yet; installed on top of this package through the [rules plugin](#rules-plugins) hook, still local):

| Set | Precision | Recall | F1 |
|---|---:|---:|---:|
| main dataset | 1.000 on this synthetic set | 1.000 on this synthetic set | 1.000 on this synthetic set |
| holdout 1 | 0.993 | 0.968 | 0.980 |
| holdout 2 | 0.911 | 0.955 | 0.932 |
| holdout 3 | 0.750 | 0.869 | 0.805 |
| holdout 4 | 0.965 | 0.558 | 0.707 |
| holdout 5 | 0.952 | 0.853 | 0.900 |
| holdout 6 | 0.717 | 0.785 | 0.749 |
| holdout 7 | 0.996 | 0.896 | 0.944 |

How to read these numbers:

- **Holdouts are not all fresh.** Our rule: a holdout is only *scored* until its misses are looked at; after that it
  becomes a development set. Holdouts 1-3 and 5-7 have been used that way, so their numbers are an upper bound. Holdout
  4 is a "known limits" set that is only scored.
- **Where the open core's precision is lower, it is mostly partial masks, not false alarms.** For example a phone
  number written `0091 98765 43210` is masked as `98765 43210` (the sensitive part is masked, the prefix is not), and
  strict scoring counts that as one wrong and one missed value. Masks that touch no real value at all are no more
  frequent in the open core than with Pro on any of the eight sets.
- **Holdout 4 recall is low for both** because most of its values are kinds Sangop does not detect at all: person
  names, postal addresses and bank account numbers (930 of the 1,236 values Pro misses there).
- Some sets were built to stress fail-safe choices that mask more than strictly needed (an ambiguous number is masked
  whole rather than guessed), which lowers strict precision on purpose.

The benchmark is authored by this project and its generator knows the checksum rules, so treat it as a regression
and comparison aid, not a promise about your data. Speed and memory on one machine (indicative, not a performance
claim): about 0.03-0.07 ms per example for the detector loop, about 35 MB peak RAM including imports.

Measured on a synthetic dataset authored by this project; real-world results will differ.

## Security model (read this first)

Sangop is a **second layer**, not the first. The real defence for your database is its own **read-only database
user**, restricted to the tables, schemas and rows that the agent may see (row-level security, a separate
read replica, no file/extension privileges). The SQL guard is a deterministic check in front of that user: it
catches the common mistakes and the obvious attacks. For PostgreSQL and SQLite it accepts only functions on a
default allow-list (see "Function allow-list" below); for the other dialects it uses a deny-list of functions, which
can never be complete, and SQL dialects differ. Give the agent's database account no more rights than it needs, and
treat a guard bypass as a bug to report (see `SECURITY.md`).

SELECT-only grants are not enough: also set default_transaction_read_only = on for the agent's database user (PostgreSQL lets every role create large objects).

Set a **`statement_timeout`** (and a row/memory limit) on the database account: Sangop blocks `WITH RECURSIVE` by
default (`SqlPolicy(allow_recursive=True)` to allow it), but it cannot stop every query that is merely expensive,
for example `SELECT count(*) FROM generate_series(1, 1000000000000)` or a large cartesian join.

A separate security review of 0.1.3 (October 2026, synthetic data only; done by the project's own AI research
assistant, **not** a third-party audit) found six issues that are fixed in 0.1.4: scrubbing skipped some return types, error messages and
generators; bulk-extraction and tenant-filter checks could be bypassed; dangerous functions were not blocked. Each
has a regression test in `tests/test_security_regressions.py`. A re-review of 0.1.4 closed four of them and found
two partial (unknown custom objects, `ARRAY(subquery)` and `*_object_agg` folding) plus two small ones (configuration
reads, denial of service); these are fixed in the same release and covered by `tests/test_reaudit_regressions.py`.
This is an early release maintained by one person: treat it as an aid, not an assurance.

### Database settings for the agent's user

Each line below was checked on PostgreSQL 16.15 and on Python 3.13 with SQLite 3.53 (14 Nov 2026, synthetic data).

PostgreSQL:

- Grant `SELECT` only on the tables (or columns) the agent needs. Never give the agent's user `pg_read_all_data`
  (it reads every table without a `GRANT`) or `pg_read_all_stats` (it shows other sessions' query texts).
- `ALTER ROLE agent SET default_transaction_read_only = on;` makes writes such as `lo_creat()` fail. It is a default,
  not a lock: the session can switch it off with `SET default_transaction_read_only = off` or
  `set_config('default_transaction_read_only', 'off', false)` (Sangop blocks both: only `SELECT` passes and
  `set_config` is denied). Switching it off inside a running transaction fails ("must be set before any query").
  `pg_logical_emit_message()` and `txid_current()` still run under it; Sangop denies them.
- `REVOKE EXECUTE ON FUNCTION set_config(text, text, boolean) FROM PUBLIC;` stops `set_config()` but not the `SET`
  command, and it also affects every other application that uses the same database.
- `ALTER ROLE agent SET statement_timeout = '5s';`, `... SET lock_timeout = '1s';` and
  `... SET idle_in_transaction_session_timeout = '30s';` (pick your own values). The guard does not stop a query
  that is merely heavy, such as `count(*)` over a cross join of five tables; the timeout cancels it.

SQLite:

- Open the database read-only: `sqlite3.connect("file:shop.db?mode=ro", uri=True)`; writes then fail. `ATTACH` can
  still create a new database file on such a connection (Sangop blocks `ATTACH`).
- `PRAGMA query_only = ON` and `PRAGMA trusted_schema = OFF`. The same connection can switch `query_only` off again
  with another `PRAGMA` (Sangop blocks `PRAGMA` statements).
- `conn.enable_load_extension(False)` where your Python build has it; in Python's `sqlite3` loading extensions is
  already off by default.

### Function allow-list (default for PostgreSQL and SQLite)

With `dialect` set to `postgres`, `redshift`, `materialize`, `risingwave` or `sqlite`, or left as `None`, the SQL
guard accepts only functions on a default allow-list: common aggregates (`count`, `sum`, `avg`, `min`, `max`,
`stddev`, `percentile_cont`, ...), window functions (`row_number`, `rank`, `lag`, `lead`, ...), conditionals
(`coalesce`, `nullif`, `greatest`, `least`), math, strings (`lower`, `trim`, `substring`, `replace`,
`regexp_replace`, ...), date and time (`now`, `date_trunc`, `extract`, `to_char`, `strftime`, ...) and functions that
read JSON values, plus syntax such as CAST, CASE, EXTRACT, INTERVAL, LIKE, IN and BETWEEN.
`sangop.sqlguard.default_allowed_functions("postgres")` returns the full list. Any other function is refused, and the
message names it:

```text
function 'my_fn' is not in the default allow-list for postgres; if it is safe for your database, add it with SqlPolicy(extra_allowed_functions={...})
```

Add the names you have checked:

```python
SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"my_fn", "reporting.my_fn"}))
```

A call written with a schema (`reporting.my_fn(...)`) is accepted when you add `reporting.my_fn` or `my_fn`; a listed
name called in a schema other than `pg_catalog` (`public.lower(...)`) is treated as your own function and refused
until you add it. `SqlPolicy(allowed_functions=...)` replaces the default list with your own, as before. The other
dialects (MySQL/MariaDB, DuckDB, SQL Server, Oracle, ...) keep the deny-list; set `allowed_functions` for them.

**The backstop still applies to every name, also to names you add:** the deny-list, the family rules below, the
row-folding rules (aggregates and constructs that put many rows into one value), the text-query rule, unicode escapes
and MySQL executable comments. Adding `pg_sleep` or `json_agg` to `extra_allowed_functions` does not let them through.
`repeat`, `printf`, `randomblob` and `zeroblob` are not on the list, because they build large values.

`lpad` and `rpad` are accepted only when the length is written as a number of at most 1000 (`lpad(code, 5, '0')`); a column, an expression or a larger number is refused.

### Supported SQL dialects

Tested in depth: PostgreSQL and SQLite, which use the default function allow-list above. Experimental: MySQL/MariaDB, DuckDB, SQL Server (T-SQL), Oracle and others, which use a deny-list of functions. For experimental dialects, always set allowed_tables and an allowed_functions allow-list; we fix reported gaps in point releases.

Always set SqlPolicy(dialect=...) to the database you run; the default (None) is a generic reading and can differ from MySQL/SQLite on comments.
For MariaDB use `dialect="mysql"`.

These rules run in every case, also on names you allow. For PostgreSQL and SQLite (and for the default
`dialect=None`; the PostgreSQL rules also for `redshift`, `materialize` and `risingwave`) whole families of system
names are blocked, so a new
system function is refused before anyone lists it: functions starting with `pg_`, `lo_`, `txid_` or `dblink`, and
tables starting with `pg_`, except `pg_typeof`, `pg_size_pretty`, `pg_column_size` and the schema tables `pg_tables`,
`pg_views`, `pg_indexes`, `pg_class`, `pg_namespace`, `pg_attribute`, `pg_type` (and `information_schema`, except
`user_mapping_options`); functions and tables starting with `sqlite_`, except `sqlite_version`, `sqlite_source_id`,
`sqlite_compileoption_used` and the tables `sqlite_master`, `sqlite_schema`, `sqlite_temp_master` and
`sqlite_temp_schema`; SQLite `pragma_` functions and tables, except `pragma_table_info`, `pragma_table_xinfo`,
`pragma_index_list`, `pragma_index_info` and `pragma_foreign_key_list`, and the `dbstat` table. PostgreSQL also
blocks functions starting with `postgres_fdw`, `http_` or `crosstab`, and `http`. For DuckDB (and `dialect=None`),
functions starting with `read_`, ending in `_scan`, or with `execute` or `serialize` in the name are blocked. A PIVOT
whose output columns come from the data (DuckDB `ON col` without `IN`, Snowflake `IN (ANY ...)` or `IN (SELECT ...)`)
is blocked as row-folding; a PIVOT that lists its values is allowed. `--` without a following space is refused for
`mysql`, `doris`, `starrocks`, `singlestore` and `dialect=None`. A unicode-escaped name or string (`U&"..."`, `U&'...'`) is
blocked in every dialect. A function whose argument is a bare query (`JSON_ARRAY(SELECT ...)`, `ARRAY(SELECT ...)`)
is blocked as row-folding; EXISTS, IN, ANY / ALL and a bracketed scalar sub-query are allowed.

### Who maintains it, and how

Sangop is maintained by Arvind Kumar, an independent developer in Raipur, India, who decides what it does and
signs off every release. Development uses AI coding assistants under fixed rules: every change starts with a
failing test; the full suite (about 2,100 tests) runs on Linux and Windows before a release; a separate AI-assisted
security review attacks each release candidate, and every fixed finding gets a regression test. None of this is a
third-party audit; one is planned before any enterprise offering. You don't have to take our word for it: the code,
the tests and the speed benchmark are all here. Run them, and try to break it ([SECURITY.md](SECURITY.md)).

## Known limits (open core)

- **Basic rules only: ASCII digits and the common written forms (measured on 5 Nov 2026 with synthetic values).**
  Found: an Aadhaar as 12 digits or as 4-4-4 groups with one space or one hyphen; an Indian mobile as 10 digits or as
  5-5 groups with one space or one hyphen, optionally after `+91`, `91` or `0`; a card with one space or one hyphen
  between groups. **Not found by the open core:**
  - digits written in an Indian script (for example Devanagari `२३४५ ६७८९ ०१२४`) - only `0`-`9` are read;
  - any other separator between groups: a dot, two spaces, a tab, a no-break or thin space, an en dash, a slash, a
    newline (`2345.6789.0124`, `98765\u00a043210`, `4111.1111.1111.1111`);
  - a mobile number as 4-6 or 3-3-4 groups (`9876 543210`, `987 654 3210`), with a dot (`98765.43210`), glued to letters
    (`ph9876543210`), or with brackets (`(+91) 98765 43210` - the 10 digits are masked, the prefix is not; the same
    for `0091 98765 43210`);
  - an Aadhaar glued to letters or digits (`xx234567890124`), or next to another 4-digit group (`2345 6789 0124 2026`):
    neither is masked;
  - a UPI ID at a handle that is not in the built-in list, unless the word "UPI" or "VPA" stands just before it (the
    Hindi word for UPI does not count).

  If your data is written in these forms, measure it in `shadow` mode first. (Sangop Pro, not yet publicly
  available, covers more of these forms; see Accuracy for what that changes on our benchmark.)
- **Nested lazy iterables:** more than 10,000 items, async iterators nested inside a result, and iterators that
  raise are replaced by a placeholder, so that part of the result is lost (by design: fail closed). Reading a
  nested iterator consumes it; in `shadow` mode the result is returned with the iterator turned into a list of the
  original values.
- **Secrets: only these nine formats are detected** (kind names in brackets): PEM private key blocks
  (`SECRET_PRIVATE_KEY`; a block that is cut off before its `END` line, for example by a length limit or
  pagination, is masked from the header to the end of its key lines; a cut that leaves only the header and fewer
  than 16 characters of key text is not masked), Anthropic keys `sk-ant-...` (`SECRET_ANTHROPIC`), OpenAI keys `sk-...`, `sk-proj-...`,
  `sk-svcacct-...` (`SECRET_OPENAI`), GitHub tokens `ghp_/gho_/ghu_/ghs_/ghr_...` and `github_pat_...`
  (`SECRET_GITHUB`), AWS access key IDs `AKIA.../ASIA...` (`SECRET_AWS_ACCESS_KEY`), Google API keys `AIza...`
  (`SECRET_GOOGLE_API`), Slack tokens `xoxa-/xoxb-/xoxp-/xoxr-/xoxs-...` (`SECRET_SLACK`), Telegram bot tokens
  (`SECRET_TELEGRAM_BOT`) and JWTs (`SECRET_JWT`). **Anything else is not recognised as a secret**, for example
  AWS *secret* access keys, Stripe keys (`sk_live_...`), Azure storage keys, Hugging Face tokens, generic
  high-entropy strings, and passwords inside connection strings (`postgres://user:password@host/db`; part of such
  a string may be masked as an e-mail address by chance, the password is not detected as a secret).
- **Images, PDFs, Office files and audio are not scanned for personal data** (no OCR, no document parsing): an
  Aadhaar card photographed or scanned into a PNG or PDF is not recognised. By default they are blocked
  (`media_mode="block"`); `"allow"` passes them unscanned and logs a `media_unscanned` event. Recognition is by the
  first bytes only. **Not recognised as media** (measured 27 Oct 2026, pinned by
  `tests/test_media_m0_followups.py`): an image written as a **hex string** or as a **list/tuple of integers**;
  base64 that is **line-wrapped inside longer text** (each line is shorter than 256 characters; a string that is
  only wrapped base64 is recognised); a base64 piece shorter than 256 characters, or one with more than three letters
  glued directly in front; a PDF whose `%PDF-` header starts after byte 1024; media inside a ZIP that is not itself
  returned; a file the MCP framework reads later from a path (for example an image object that only holds a file
  path); and formats not in the list above (for example SVG text, RAR, 7z). Media that was **gzip-compressed and
  then base64-encoded** is not recognised either (gzip has no media magic number; measured 28 Oct 2026).
- **Hidden or encoded forms are not detected.** A value split by zero-width characters (U+200B and similar), or
  written as base64, URL-encoding (`%40`), or HTML entities (`&#64;`, `&#65;...`) passes through unchanged. Sangop
  checks the text as it is; it does not decode it first. Measured on synthetic values on 26 Oct 2026: a PAN with a
  zero-width space, a base64 PAN, a URL-encoded e-mail and an HTML-entity PAN or e-mail were all missed.
- **Other written forms the open core does not find** (measured on synthetic values on 5 Nov 2026): a PAN, GSTIN or
  IFSC in lower case (`abcpe1234f`); a PAN with a space inside (`ABCPE 1234F`); a value with a combining mark inside
  (for example an accent, U+0301, after one of its letters or digits); values written with JSON `\u` escapes in raw
  JSON text (`\u0039876543210`); e-mail addresses with a non-ASCII (IDN) domain, a full-width `＠` or `[at]` instead
  of `@`; letters or digits written in full-width form (`ＡＢＣＰＥ１２３４Ｆ`).
- Names and addresses without a pattern are **not** detected.
- Bank account numbers are not detected (too generic without context).
- Phone detection can flag other 10-digit numbers starting 6-9, including order, invoice or transaction IDs such as
  `ord-6407135664`, `inv_8161570948`, `txn#8855460850` (ten digits after a letter prefix and a `-`, `_` or `#`).
  Ten digits glued directly to letters (`INV9876543210`) are not flagged.
- A UPI ID is recognised when its handle is a well-known one (a built-in list, not exhaustive, may be out of date) or
  when the word "UPI" or "VPA" appears just before it. An unknown handle with no such hint is **not** reported as UPI
  (a phone-style ID like `9876543210@newapp` is then reported as a phone number).
- A card or other digit run is treated as a card only when it is not glued to letters, and a 13-digit
  number starting 978 or 979 (an ISBN-13) is never treated as a card.
- Tokens live in process memory and can be reversed only by the process that made them; with several
  server instances a token from another instance stays a token (nothing leaks, but a tool that needs the real
  value will not get it). See [MCP compatibility notes](docs/MCP_COMPAT.md) (spec 2026-07-28: what was tested, what was not).
- There is no stdio/HTTP proxy wrapper: protection applies to functions decorated with `@guard`.
- **Detokenization is limited by token kind, not by caller.** `detokenize_kinds` decides which kinds a tool may
  see, but any `@guard`-ed tool that lists the parameter and the kind can reveal a token minted for another
  tool in the same process. Each reveal is in the ledger (`detokenize` event); `detokenize_kinds="*"` opens everything
  and is flagged. Binding a token to the tool or purpose that may receive it is not built.
- **The audit ledger is tamper-*evident*, not tamper-*proof*.** Without `SANGOP_LEDGER_KEY` the chain is a plain
  SHA-256 chain: someone who can write the SQLite file can edit rows and recompute every later hash, and `verify`
  can only tell you the ledger is **unkeyed**. With a key, recomputing is detected, but cutting off the newest
  rows still is not: keep the printed `anchor` (id and hash of the newest row) somewhere the writer cannot reach
  and verify with `--anchor`. The key must never be stored in the ledger folder, the repository or logs. A process
  that holds the key can write valid rows; this is not a defence against a malicious administrator of the
  same machine. A **weak key** (shorter than 32 characters, fewer than 8 different characters, a repeated block, or
  mostly a simple sequence such as `1234...` or `aaaa...`) is accepted if it has at least 16 characters, but Sangop
  then raises a `UserWarning`: with a weak key, anyone who can read the ledger file can try to guess it and rewrite
  rows undetected. Use a long random value, for example from `sangop keygen` (or `python -c "import secrets; print(secrets.token_hex(32))"`).
- **Prompt-injection text is not recognised.** Sangop looks for personal data, secrets and unsafe SQL; it does not
  read the *meaning* of text, so an instruction hidden in a web page, file or tool result that tells the agent to misuse
  its tools (MITRE ATT&CK T1700, "AI-Enabled Exfiltration") passes through unchanged. What Sangop can still do in that
  situation is limited to its own checks: masked values stay masked, blocked SQL stays blocked, and the ledger records
  the calls.
- **The token vault is in the memory of your process.** An attacker who can read that process's memory (or run code in
  it) on the same host can read the original values; Sangop does not defend against that. Tokens only keep values away
  from the model, not from the machine that runs the tools.
- **Authentication and transport are not Sangop's job.** Who may call a tool, and whether the connection is
  encrypted, are decided by the host and the MCP/SDK layer that serve your tools. `@guard` sees only a function call.
- Tokens are 64 bit (16 hex characters) and the vault gives a longer token if two values ever collide, so two
  values never share a token. Tokens from 0.1.3 and earlier (8 hex characters) are no longer recognised.
- `allowed_tables`: a bare name (`orders`) allows only the default schema (`public`, `main` or `dbo` for the
  dialect, or no prefix); another schema must be written `schema.table`. `denied_tables`: a bare name is denied in
  every schema. A catalog prefix in the query is ignored unless your entry has one. Which schema an unqualified name
  reaches in your database depends on its `search_path`; pin that on the database account as well.
- **Quoted names in table lists are matched case-insensitively.** In PostgreSQL `"ORDERS"` and `orders` can be two
  different tables; Sangop treats them as the same name, so an allow-list entry `orders` also lets `"ORDERS"` through
  (and a deny-list entry `orders` also blocks `"ORDERS"`). Do not keep tables whose names differ only by case.
- **Rules plugins can change detection.** Any installed package that registers a `sangop.plugins` entry point can
  replace the active rule set, including with weaker rules. Install only plugins you trust (as with any Python
  package) and check `sangop selftest`, which prints the active rule set (`"rules": "basic"` without a plugin).
- The SQL guard does not stop a query that is merely heavy (for example `count(*)` over a cross join of five
  tables); set `statement_timeout`, `lock_timeout` and `idle_in_transaction_session_timeout` on the database user.
- Wide self-joins or pivots that list their values can still return many values per row within the LIMIT; keep allowed_tables narrow and database timeouts on.
- For PostgreSQL, SQLite and `dialect=None` the SQL guard accepts only functions on its default allow-list plus the names you add; it judges a function by its name, so a name you add is trusted as you added it (the backstop rules still apply). For the other dialects it is deny-list based for functions. MySQL/MariaDB executable comments (/*! */) are blocked outright. Database-user permissions remain the primary defence (see Security model).
- `generate_series` is on the default allow-list; a very large range is a heavy query, so keep the database timeouts above.
- Function arguments that look like SQL text (e.g. 'SELECT …') are refused, except as arguments of common string and date functions (coalesce, replace, concat, lower …), because several database functions run such text as a query.
- Text assembled at run time (for example 'SEL' || 'ECT …' or concat(...)) is not recognised as a query; functions that run text are blocked by name, and database-user permissions remain the main defence.
- SQL checks assume the right `dialect` is set in `SqlPolicy`; a statement the chosen dialect cannot parse is
  blocked, one it parses differently from your database may not be judged as your database reads it.
- Joins: with `require_filter_column`, every directly joined table needs its own qualified filter
  (`o.tenant_id = 5 AND s.tenant_id = 5`); this is stricter than necessary on purpose.
- Tool return values of an unknown type: attributes, `__slots__` and the object's `str()` / `repr()` are
  checked and an object whose text form still shows personal data is replaced by its masked text. Objects that
  keep text where neither attributes nor `str()`/`repr()` show it (for example inside a C extension) can still hide
  a value. Return plain data (dicts, lists, strings, dataclasses).
- A generator that is never iterated writes no ledger event; one that is closed early is recorded as `incomplete`.

## Rules plugins

The detection rules can come from an installed plugin instead of the basic set in this package. A plugin is a normal
Python package that declares an entry point in the group `sangop.plugins`:

```toml
[project.entry-points."sangop.plugins"]
myrules = "my_package.plugin:register"
```

`register(api)` may replace the rule set (`api.set_detectors(...)`, at most one plugin may do this), accept its own
`sangop.configure(...)` options, filter the kinds a guarded call reports, and add fields to ledger records (never raw
values). Plugins load on first use, not at import time. **Fail closed:** if an installed plugin fails to load, every
detection call raises an error instead of falling back to the weaker basic rules, and a `configure(...)` option that no
installed plugin accepts raises `TypeError`. `sangop selftest` reports the active rule set. Sangop Pro uses this hook.

## Policy packs

`sangop.load_pack(path)` loads a small, strict, fail-closed YAML policy pack (retention floor, purpose
to PII-kind allowances, safeguard mapping). A tiny **example** pack ships inside the package so you can
try the loader: `sangop.load_pack(sangop.example_pack_path())` (`pip install "sangop[policy]"`). It
is marked EXAMPLE ONLY and is not legal advice. It does not tell you what you must do, and using it
does not make anyone compliant.

## Security

Report vulnerabilities privately - see [SECURITY.md](SECURITY.md).

## Disclaimer

This software is provided "AS IS" under the Apache License 2.0, without
warranties of any kind. It helps engineers implement technical safeguards; it
does not make any organisation compliant with the DPDP Act 2023, DPDP Rules
2025, GDPR, the EU AI Act or any other law, and it is not legal advice.
Use `sangop scan` only on code and data you own or are authorised to inspect.
All examples and tests use synthetic data.

Notes on CERT-In advisories (the project's own reading, not official documents):
[CIAD-2026-0049](docs/CERTIN_CIAD_2026_0049_MAPPING.md) and [CIAD-2026-0058](docs/CERT_IN_AGENT_LOGGING.md).
More examples: [`examples/`](examples/) (`fastmcp_guarded_tool.py`, `sql_guard_only.py`, `ledger_verify.py`).

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
