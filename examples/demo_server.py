"""Demo: a FastMCP server over a SYNTHETIC SQLite database, protected by Sangop.

Run:   uv run --extra fastmcp python examples/demo_server.py
Then connect it to Claude Desktop / Cursor as a stdio MCP server, or test with
`uv run --extra fastmcp fastmcp dev examples/demo_server.py`.

All customer data below is generated at runtime and is fake.
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastmcp import FastMCP  # noqa: E402

import sangop  # noqa: E402
from sangop.detectors import verhoeff_check_digit  # noqa: E402

DB = os.path.join(os.path.dirname(__file__), "demo.db")


def build_fake_db() -> None:
    con = sqlite3.connect(DB)
    con.execute("DROP TABLE IF EXISTS customers")
    con.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, tenant_id INT, name TEXT, "
                "phone TEXT, pan TEXT, ticket TEXT)")
    for i in range(1, 51):
        base = f"2{i:010d}"
        aadhaar = base + verhoeff_check_digit(base)
        con.execute("INSERT INTO customers VALUES (?,?,?,?,?,?)", (
            i, 1 + i % 3, f"Test Customer {i}", f"98765{i:05d}", "ABCPE1234F",
            f"Refund pending. I am sharing my aadhaar {aadhaar} for verification.",
        ))
    con.commit()
    con.close()


build_fake_db()
sangop.configure(ledger_path=os.path.join(os.path.dirname(__file__), "..", ".sangop", "demo_audit.db"))
mcp = FastMCP("sangop-demo")


@mcp.tool
@sangop.guard(
    purpose="customer_support",
    sql_param="query",
    sql_policy=sangop.SqlPolicy(max_rows=20, require_filter_column="tenant_id", dialect="sqlite"),
)
def run_query(query: str) -> list[dict]:
    """Run a read-only SQL query on the customers table. Always filter by tenant_id."""
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(query).fetchall()]
    finally:
        con.close()


@mcp.tool
@sangop.guard(purpose="notify_customer", detokenize_params=("phone",), detokenize_kinds=("PHONE_IN",),
              pii_mode="redact")
def send_sms(phone: str, message: str) -> str:
    """Pretend to send an SMS. Receives the real number only inside this trusted tool."""
    return f"SMS queued to a number ending {phone[-2:]}"


if __name__ == "__main__":
    mcp.run()
