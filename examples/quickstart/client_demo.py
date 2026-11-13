"""Side-by-side demo: the same tools, without Sangop and with it. No MCP host needed (in-process client).

    pip install -e ".[fastmcp]"
    python examples/quickstart/client_demo.py

All values are synthetic and generated at run time. Nothing is sent anywhere.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastmcp import Client  # noqa: E402
from tools import build_server  # noqa: E402

CALLS = [
    ("lookup_customer", {"customer_id": 7}, "a customer record (Aadhaar, PAN, phone, e-mail)"),
    ("read_note", {"note_id": 1}, "a note with an API key pasted into it"),
    ("run_query", {"query": "SELECT * FROM customers"}, "a query with no tenant filter and no LIMIT"),
]


async def call(mcp, name: str, args: dict) -> str:
    async with Client(mcp) as c:
        r = await c.call_tool(name, args, raise_on_error=False)
        text = r.content[0].text if r.content else ""
        return ("[tool error] " + text) if r.is_error else text


def short(text: str, n: int = 230) -> str:
    try:
        text = json.dumps(json.loads(text), ensure_ascii=True)
    except ValueError:
        pass
    return text if len(text) <= n else text[:n] + " ...(shortened)"


def quiet_logs() -> None:
    """FastMCP prints a traceback for every blocked call; the demo shows the short message instead."""
    import logging
    for name in ("fastmcp", "FastMCP", "mcp"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
        logging.getLogger(name).propagate = False


def shadow_summary() -> str:
    """What shadow mode saw (it changed nothing): totals from its own audit log. Counts only, no values."""
    import sangop
    totals: dict = {}
    sql_flags = 0
    for e in sangop.get_ledger().tail(100):
        if e["event"] != "tool_call":
            continue
        for k, v in e["record"].get("pii_found", {}).items():
            totals[k] = totals.get(k, 0) + v
        sql_flags += 1 if e["record"].get("sql", {}).get("allowed") is False else 0
    return f"shadow log: would mask {dict(sorted(totals.items()))}; {sql_flags} query(ies) would be blocked"


async def main() -> int:
    quiet_logs()
    results: dict = {}                                    # mode -> {call index -> text}
    notes: dict = {}
    for mode in ("off", "shadow", "enforce"):             # Sangop keeps one global ledger, so go one mode at a time
        mcp = build_server(mode, ledger_path=None if mode == "off" else f".sangop/quickstart_{mode}.db")
        results[mode] = [await call(mcp, n, a) for n, a, _ in CALLS]
        if mode == "shadow":
            notes["shadow"] = shadow_summary()
        if mode == "enforce":
            notes["drop"] = await call(mcp, "run_query", {"query": "DROP TABLE customers"})
    for i, (name, _, what) in enumerate(CALLS):
        print(f"\n=== {name}: {what}")
        for mode, label in (("off", "without Sangop "), ("shadow", "Sangop shadow  "), ("enforce", "Sangop enforce ")):
            print(f"  {label}: {short(results[mode][i])}")
    print("\n=== run_query: a destructive statement (shown with Sangop enforce only; never run without Sangop here)")
    print(f"  Sangop enforce : {short(notes['drop'])}")
    print(f"\n{notes['shadow']}")
    print("Check the audit log of the enforce run: sangop audit verify --db .sangop/quickstart_enforce.db")
    print("This is a demo on invented data, not a promise about your data (see Known limits in the README).")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
