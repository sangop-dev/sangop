"""Quickstart tools: three FastMCP tools over a SYNTHETIC database, with or without Sangop.

Everything here is fake. The "customer" rows are generated at run time (checksum-valid but invented numbers),
and the "API key" in the note is assembled from two halves so that this file itself contains no key-shaped text.

build_server(mode) returns a FastMCP server whose tools are:
    "off"      plain functions, no Sangop at all                     (the "before" picture)
    "shadow"   Sangop looks and writes the audit log, changes and blocks nothing   (step 2 of the ladder)
    "enforce"  Sangop masks PII/secrets and blocks risky SQL         (step 3, the default for real use)
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from fastmcp import FastMCP  # noqa: E402

import sangop  # noqa: E402
from sangop.detectors import verhoeff_check_digit  # noqa: E402

MODES = ("off", "shadow", "enforce")
N_CUSTOMERS = 30
FAKE_KEY = "gh" + "p_" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"          # synthetic, assembled at run time


def fake_aadhaar(i: int) -> str:
    base = f"2{i:010d}"
    return base + verhoeff_check_digit(base)


def fake_pan(i: int) -> str:
    """An invented PAN-shaped value for customer i, made at run time (no PAN is written in this file)."""
    return "QZX" + "P" + chr(65 + i % 26) + f"{5000 + i:04d}" + chr(90 - i % 26)


def db_path() -> str:
    return os.environ.get("SANGOP_QS_DB") or os.path.join(tempfile.gettempdir(), "sangop_quickstart.db")


def build_fake_db(path: str | None = None) -> str:
    path = path or db_path()
    con = sqlite3.connect(path)
    con.execute("DROP TABLE IF EXISTS customers")
    con.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, tenant_id INT, name TEXT, phone TEXT, "
                "pan TEXT, email TEXT, aadhaar TEXT)")
    for i in range(1, N_CUSTOMERS + 1):
        con.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?)",
                    (i, 1 + i % 3, f"Test Customer {i}", f"98765{i:05d}", fake_pan(i),
                     f"customer{i}@example.com", fake_aadhaar(i)))
    con.execute("DROP TABLE IF EXISTS notes")
    con.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
    con.execute("INSERT INTO notes VALUES (1, ?)",
                (f"Deploy note: use token {FAKE_KEY} for the staging script, then delete it.",))
    con.commit()
    con.close()
    return path


def _rows(sql: str, params: tuple = ()) -> list[dict]:
    con = sqlite3.connect(db_path())
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(sql, params).fetchall()]
    finally:
        con.close()


def run_query(query: str) -> list[dict]:
    """Run a read-only SQL query on the customers/notes tables. Always filter by tenant_id."""
    return _rows(query)


def lookup_customer(customer_id: int) -> dict:
    """Return one customer record."""
    rows = _rows("SELECT * FROM customers WHERE id = ?", (customer_id,))
    return rows[0] if rows else {}


def read_note(note_id: int) -> str:
    """Return the text of one internal note."""
    rows = _rows("SELECT body FROM notes WHERE id = ?", (note_id,))
    return rows[0]["body"] if rows else ""


POLICY = dict(max_rows=20, require_filter_column="tenant_id", dialect="sqlite")


def build_server(mode: str = "enforce", ledger_path: str | None = ".sangop/quickstart_audit.db") -> FastMCP:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    build_fake_db()
    mcp = FastMCP(f"sangop-quickstart-{mode}")
    if mode == "off":
        for fn in (run_query, lookup_customer, read_note):
            mcp.tool(fn)
        return mcp
    sangop.configure(ledger_path=ledger_path)                     # runs the canary self-test
    pii = "tokenize" if mode == "enforce" else "shadow"
    sql = "enforce" if mode == "enforce" else "shadow"
    mcp.tool(sangop.guard(purpose="support", pii_mode=pii, sql_mode=sql, sql_param="query",
                          sql_policy=sangop.SqlPolicy(**POLICY))(run_query))
    mcp.tool(sangop.guard(purpose="support", pii_mode=pii)(lookup_customer))
    mcp.tool(sangop.guard(purpose="support", pii_mode=pii)(read_note))
    return mcp
