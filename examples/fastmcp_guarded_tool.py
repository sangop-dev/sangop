"""A FastMCP tool guarded by Sangop, called in-process: no MCP host, no network. Invented values only.
Run: pip install "sangop[fastmcp]"  then  python examples/fastmcp_guarded_tool.py"""
import asyncio, os, tempfile

import sangop
from fastmcp import Client, FastMCP

sangop.configure(ledger_path=os.path.join(tempfile.mkdtemp(), "audit.db"))
mcp = FastMCP("support")

@mcp.tool
@sangop.guard(purpose="support")
def lookup_customer(customer_id: int) -> dict:
    return {"id": customer_id, "pan": "ABCPE1234F", "phone": "9876543210"}   # your real lookup goes here

async def main():
    async with Client(mcp) as client:
        print((await client.call_tool("lookup_customer", {"customer_id": 7})).data)   # the agent sees tokens

asyncio.run(main())
