"""Sangop under the official MCP Python SDK's own server class, `mcp.server.mcpserver.MCPServer` (mcp 2.x), as opposed to FastMCP.

In-memory client, and a stdio subprocess with the official client. Synthetic data only; no network (stdio and in-process)."""
import asyncio
import json
import subprocess
import sys
import textwrap

import pytest

import sangop

pytest.importorskip("mcp.server.mcpserver")
from mcp.client import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402

PAN = "ABCPE1234F"
PHONE = "9876543210"


@pytest.fixture(autouse=True)
def _cfg():
    sangop.configure(ledger_path=None, run_selftest=False)
    yield
    sangop.configure(ledger_path=None, run_selftest=False)


def _text(result) -> str:
    return "".join(c.text for c in result.content if getattr(c, "text", None))


def _server():
    srv = MCPServer("compat")

    @srv.tool()
    @sangop.guard(purpose="lookup")
    def lookup(name: str) -> dict:
        """Return a record."""
        return {"name": name, "pan": PAN, "phone": PHONE}

    @srv.tool()
    @sangop.guard(purpose="lookup")
    async def alookup(name: str) -> str:
        """Async variant."""
        await asyncio.sleep(0)
        return f"{name}: {PAN}"

    @srv.tool()
    @sangop.guard(purpose="sql", sql_param="query", sql_policy=sangop.SqlPolicy(max_rows=50, dialect="sqlite"))
    def run_query(query: str) -> str:
        """Run SQL."""
        return "ran"

    return srv


def test_in_memory_sync_and_async_tools_are_masked():
    async def go():
        async with Client(_server()) as c:
            r1 = await c.call_tool("lookup", {"name": "asha"})
            r2 = await c.call_tool("alookup", {"name": "asha"})
            return _text(r1), _text(r2)
    t1, t2 = asyncio.run(go())
    for t in (t1, t2):
        assert PAN not in t and PHONE not in t
    assert "[PII_PAN_" in t1 and "[PII_PHONE_IN_" in t1 and "[PII_PAN_" in t2


def test_in_memory_sql_guard_blocks_and_allows():
    async def go():
        async with Client(_server()) as c:
            bad = await c.call_tool("run_query", {"query": "DELETE FROM users"})
            good = await c.call_tool("run_query", {"query": "SELECT id FROM users LIMIT 5"})
            return bad, good
    bad, good = asyncio.run(go())
    assert bad.is_error
    assert not good.is_error and _text(good) == "ran"


def test_a_tool_that_raises_gives_a_scrubbed_error():
    srv = MCPServer("err")

    @srv.tool()
    @sangop.guard(purpose="x")
    def boom(name: str) -> str:
        """Fail with personal data in the message."""
        raise RuntimeError(f"cannot find {PAN} for {name}")

    async def go():
        async with Client(srv) as c:
            return await c.call_tool("boom", {"name": "asha"})
    r = asyncio.run(go())
    assert r.is_error and PAN not in _text(r)


def test_stdio_subprocess_with_the_official_client(tmp_path):
    server_py = tmp_path / "srv.py"
    server_py.write_text(textwrap.dedent(f'''
        import sangop
        from mcp.server.mcpserver import MCPServer
        sangop.configure(ledger_path=None, run_selftest=False)
        srv = MCPServer("stdio-compat")

        @srv.tool()
        @sangop.guard(purpose="lookup")
        def lookup(name: str) -> dict:
            """Return a record."""
            return {{"name": name, "pan": "{PAN}"}}

        srv.run("stdio")
    '''))
    from mcp.client.stdio import StdioServerParameters

    async def go():
        params = StdioServerParameters(command=sys.executable, args=[str(server_py)])
        async with Client(params) as c:
            return await c.call_tool("lookup", {"name": "asha"})
    r = asyncio.run(asyncio.wait_for(go(), 60))
    assert PAN not in _text(r) and "[PII_PAN_" in _text(r)
