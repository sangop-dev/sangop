import asyncio

import pytest
from conftest import GITHUB_TOKEN, PAN, PHONE

import sangop
from sangop.cli import main as cli_main


def test_scan_masks_and_fails_on_secret(tmp_path, capsys):
    (tmp_path / "config.py").write_text(f'TOKEN = "{GITHUB_TOKEN}"\nowner_pan = "{PAN}"\n')
    (tmp_path / "clean.txt").write_text("nothing here\n")
    assert cli_main(["scan", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "SECRET_GITHUB" in out and "PAN" in out
    assert GITHUB_TOKEN not in out and PAN not in out


def test_sql_check_cli(capsys):
    assert cli_main(["sql-check", "DROP TABLE x"]) == 2
    assert cli_main(["sql-check", "SELECT a FROM x LIMIT 3"]) == 0


fastmcp = pytest.importorskip("fastmcp")


def test_works_inside_fastmcp_server():
    from fastmcp import Client, FastMCP

    mcp = FastMCP("demo")

    @mcp.tool
    @sangop.guard(purpose="support", sql_param="query", sql_policy=sangop.SqlPolicy(max_rows=10))
    def run_query(query: str) -> str:
        return f"row: pan={PAN} phone={PHONE}"

    async def go():
        async with Client(mcp) as c:
            ok = await c.call_tool("run_query", {"query": "SELECT * FROM users LIMIT 1"})
            text = ok.content[0].text
            assert PAN not in text and PHONE not in text and "[PII_PAN_" in text
            bad = await c.call_tool("run_query", {"query": "DROP TABLE users"}, raise_on_error=False)
            assert bad.is_error and "blocked" in bad.content[0].text.lower()

    asyncio.run(go())
