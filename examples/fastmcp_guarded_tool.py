"""A FastMCP tool guarded by Sangop, called in-process: no MCP host, no network. Invented values only.
Run: pip install "sangop[fastmcp]"  then  python examples/fastmcp_guarded_tool.py"""
import asyncio, os, random, string, tempfile

import sangop
from fastmcp import Client, FastMCP
sangop.configure(ledger_path=os.path.join(tempfile.mkdtemp(), "audit.db"))
mcp = FastMCP("support")
rnd, AZ = random.Random(2026), string.ascii_uppercase   # invented values are made at run time, none is written here

@mcp.tool
@sangop.guard(purpose="support")
def lookup_customer(customer_id: int) -> dict:      # your real lookup goes here
    pan = "".join(rnd.choices(AZ, k=3)) + "P" + rnd.choice(AZ) + str(rnd.randint(1000, 9999)) + rnd.choice(AZ)
    return {"id": customer_id, "pan": pan, "phone": f"{rnd.randint(7, 9)}{rnd.randrange(10**8, 10**9)}"}

async def main():
    async with Client(mcp) as client:
        print((await client.call_tool("lookup_customer", {"customer_id": 7})).data)   # the agent sees tokens
asyncio.run(main())
