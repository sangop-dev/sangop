"""Does Sangop work with the MCP 2026-07-28 revision (stateless, no handshake, no sessions) and with older
transports? Each test states what it covers. Synthetic data only; loopback sockets only (FastMCP's own HTTP
server on 127.0.0.1), Sangop itself opens no connection (see test_no_network.py).

Official source for the spec points: https://modelcontextprotocol.io/specification/2026-07-28/changelog
"""
from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import sangop
from sangop.audit import AuditLedger
from sangop.detectors import verhoeff_check_digit
from sangop.tokenizer import Vault, detokenize_text, scrub_text

pytest.importorskip("fastmcp")
httpx = pytest.importorskip("httpx")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
QS = ROOT / "examples" / "quickstart"
sys.path.insert(0, str(QS))
import tools as qs_tools  # noqa: E402

AAD7 = qs_tools.fake_aadhaar(7)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _log_tail(log_path, n: int = 2000) -> str:
    try:
        return Path(log_path).read_text(encoding="utf-8", errors="replace")[-n:]
    except OSError:
        return "(no server log)"


def _wait(port: int, proc, log_path) -> None:
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f"server exited; its log ({log_path}):\n" + _log_tail(log_path))
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server did not start; its log ({log_path}):\n" + _log_tail(log_path))


def _spawn_server(cmd, env, cwd, log_path):
    """Start a helper server process with its stdout+stderr going to a log FILE, never to an unread pipe.

    Windows, 13 Nov 2026: with stdout=PIPE nobody read the pipe; Windows pipes are small (Linux ~64 KB), so the
    server stopped once its logs (about 11 KB in the three-connection test, mostly tracebacks of the blocked DROP)
    filled it, and the client got ReadTimeout. A file never fills up. The log is shown if the server does not start,
    and after each test that used the server (pytest prints it only for a failing test).
    """
    log = open(log_path, "wb")
    try:
        return subprocess.Popen(cmd, env=env, cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    finally:
        log.close()          # the child keeps its own handle


@pytest.fixture
def http_server(tmp_path):
    port = _free_port()
    log_path = tmp_path / "server.log"
    env = dict(os.environ, SANGOP_QS_DB=str(tmp_path / "q.db"), PYTHONPATH=str(ROOT / "src"))
    proc = _spawn_server([sys.executable, str(HERE / "compat_server.py"), str(port), str(tmp_path / "led.db")],
                         env, tmp_path, log_path)
    try:
        _wait(port, proc, log_path)
        yield f"http://127.0.0.1:{port}/mcp", tmp_path / "led.db"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        print(f"--- compat server log ({log_path}), last 2000 characters ---\n" + _log_tail(log_path))


def test_spawned_server_never_blocks_on_its_own_output(tmp_path):
    """Windows, 13 Nov 2026: the HTTP server's output went to a pipe nobody read. Windows pipes are small, so the
    server stopped as soon as its logs filled the pipe and the client got ReadTimeout. A child that writes far more
    than any pipe holds (300 KB) must still finish on its own within 10 s, and its output must be in the log."""
    code = "import sys; sys.stdout.write('x' * 300_000); sys.stdout.flush(); sys.stderr.write('e' * 1000)"
    log_path = tmp_path / "child.log"
    proc = _spawn_server([sys.executable, "-c", code], dict(os.environ), tmp_path, log_path)
    try:
        assert proc.wait(timeout=10) == 0
    except subprocess.TimeoutExpired:
        pytest.fail("the child process blocked on a full output pipe")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    data = log_path.read_bytes()
    assert data.count(b"x") == 300_000 and data.count(b"e") == 1000


# ---- 1. transports: stdio and stateless streamable HTTP -------------------------------------------------------

def test_stdio_server(tmp_path):
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport
    env = dict(os.environ, SANGOP_QS_DB=str(tmp_path / "q.db"), PYTHONPATH=str(ROOT / "src"))

    async def go():
        t = StdioTransport(sys.executable, [str(QS / "server.py"), "enforce"], env=env, cwd=str(tmp_path))
        async with Client(t) as c:
            r = await c.call_tool("lookup_customer", {"customer_id": 7})
            return r.content[0].text
    text = asyncio.run(go())
    assert AAD7 not in text and "[PII_AADHAAR_" in text


def test_stateless_http_via_fastmcp_client(http_server):
    from fastmcp import Client
    url, _ = http_server

    async def go():
        out = []
        for _ in range(3):                                  # separate connections, as a load balancer would make them
            async with Client(url) as c:
                r = await c.call_tool("lookup_customer", {"customer_id": 7})
                out.append(r.content[0].text)
                bad = await c.call_tool("run_query", {"query": "DROP TABLE customers"}, raise_on_error=False)
                out.append((bad.is_error, bad.content[0].text))
        return out
    out = asyncio.run(go())
    for text in out[0::2]:
        assert AAD7 not in text and "[PII_AADHAAR_" in text
    for is_err, msg in out[1::2]:
        assert is_err and "blocked" in msg.lower()


_META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}
_HDR = {"content-type": "application/json", "accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28"}


def _rpc(url, id_, method, params, extra=None):
    body = {"jsonrpc": "2.0", "id": id_, "method": method, "params": {**params, "_meta": _META}}
    return httpx.post(url, json=body, headers={**_HDR, "Mcp-Method": method, **(extra or {})}, timeout=30)


def test_raw_2026_07_28_requests_without_handshake_or_session(http_server):
    """The spec's core change: no initialize, no Mcp-Session-Id; every request carries its own version."""
    url, _ = http_server
    d = _rpc(url, 1, "server/discover", {})
    if d.status_code != 200 or "supportedVersions" not in d.text:
        pytest.skip("this MCP SDK does not serve 2026-07-28 server/discover")
    assert "2026-07-28" in d.json()["result"]["supportedVersions"]
    r = _rpc(url, 2, "tools/call", {"name": "lookup_customer", "arguments": {"customer_id": 7}},
             {"Mcp-Name": "lookup_customer"})
    assert r.status_code == 200
    assert "mcp-session-id" not in {k.lower() for k in r.headers}
    res = r.json()["result"]
    assert res.get("resultType") == "complete" and res["isError"] is False
    assert AAD7 not in r.text and "[PII_AADHAAR_" in r.text
    b = _rpc(url, 3, "tools/call", {"name": "run_query", "arguments": {"query": "DROP TABLE customers"}},
             {"Mcp-Name": "run_query"})
    assert b.json()["result"]["isError"] is True and "blocked" in b.text.lower()


def test_http_server_ledger_verifies_after_calls(http_server):
    from fastmcp import Client
    url, ledger = http_server

    async def go():
        for _ in range(5):
            async with Client(url) as c:
                await c.call_tool("lookup_customer", {"customer_id": 7})
    asyncio.run(go())
    led = AuditLedger(str(ledger))
    ok, n, bad = led.verify()
    assert ok and n >= 6                                    # selftest + calls
    assert AAD7 not in str(led.tail(50))
    led.close()


# ---- 2. the audit ledger under concurrency ----------------------------------------------------------------------

def _writer(path, n, who):
    led = AuditLedger(path)
    for k in range(n):
        led.append("e", {"who": who, "k": k})
    led.close()


def test_ledger_chain_survives_several_processes(tmp_path):
    """Found by this test in 0.1.3: before the BEGIN IMMEDIATE fix, concurrent processes broke the chain."""
    p = str(tmp_path / "a.db")
    ctx = mp.get_context("spawn")
    ps = [ctx.Process(target=_writer, args=(p, 150, i)) for i in range(4)]
    [x.start() for x in ps]
    [x.join(120) for x in ps]
    assert [x.exitcode for x in ps] == [0, 0, 0, 0]
    led = AuditLedger(p)
    ok, n, bad = led.verify()
    assert ok and n == 600, (ok, n, bad)


def test_ledger_chain_survives_several_ledger_objects_in_threads(tmp_path):
    p = str(tmp_path / "b.db")
    ts = [threading.Thread(target=_writer, args=(p, 150, i)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    ok, n, _ = AuditLedger(p).verify()
    assert ok and n == 600


def test_tampering_is_still_detected(tmp_path):
    import sqlite3
    p = str(tmp_path / "t.db")
    _writer(p, 20, 0)
    con = sqlite3.connect(p)
    con.execute("UPDATE events SET record='{\"who\":9}' WHERE id=7")
    con.commit()
    con.close()
    ok, n, bad = AuditLedger(p).verify()
    assert not ok and bad == 7


# ---- 3. tokens across instances (the known stateless limit, pinned so the docs cannot drift) --------------------

def test_token_from_another_instance_is_not_revealed_and_fails_safe():
    a, b = Vault(), Vault()
    out, _ = scrub_text(f"call {qs_tools.fake_aadhaar(5)}", a, "tokenize")
    token = re.search(r"\[PII_AADHAAR_[0-9a-f]{16}\]", out).group(0)
    assert detokenize_text(out, a) == f"call {qs_tools.fake_aadhaar(5)}"          # same instance: works
    assert detokenize_text(out, b) == out                                          # other instance: token stays
    assert b.reveal(token) is None


def test_even_a_shared_key_does_not_make_tokens_portable():
    key = b"k" * 32
    a, b = Vault(key), Vault(key)
    t_a = a.token_for("AADHAAR", qs_tools.fake_aadhaar(5))
    assert b.token_for("AADHAAR", qs_tools.fake_aadhaar(5)) == t_a                 # same token (deterministic)...
    c = Vault(key)
    assert c.reveal(t_a) is None                                                   # ...but no instance can reverse a
                                                                                   # token it has not itself minted


# ---- 4. spec points that could touch Sangop's code ---------------------------------------------------------------

SRC = list((ROOT / "src" / "sangop").glob("*.py"))


def test_no_hardcoded_old_error_code_and_no_handshake_or_session_code():
    text = "\n".join(p.read_text(encoding="utf-8") for p in SRC)
    assert "-32002" not in text                       # resource-not-found code moved to -32602 in 2026-07-28
    for needle in ("Mcp-Session-Id", "mcp-session-id", "notifications/initialized", "tasks/list", "Last-Event-ID"):
        assert needle not in text, needle


def test_sangop_does_not_use_deprecated_features():
    text = "\n".join(p.read_text(encoding="utf-8") for p in SRC)
    for needle in ("sampling/createMessage", "roots/list", "logging/setLevel", "create_message", "list_roots"):
        assert needle not in text, needle


# ---- 5. Tasks extension (needs the optional `fastmcp-tasks` package) -----------------------------------------------

def test_guard_inside_a_task_tool_scrubs_the_result(tmp_path):
    pytest.importorskip("fastmcp_tasks")
    from fastmcp import Client, FastMCP
    from fastmcp_tasks import TasksExtension, call_tool_task
    sangop.configure(ledger_path=str(tmp_path / "t.db"))
    mcp = FastMCP("tasks")
    mcp.add_extension(TasksExtension())                 # in-memory backend: single process only

    @mcp.tool(task=True)
    @sangop.guard(purpose="t", pii_mode="redact")
    async def slow(x: str) -> str:
        await asyncio.sleep(0.2)
        return f"aadhaar {AAD7} for {x}"

    async def go():
        async with Client(mcp) as c:
            direct = (await c.call_tool("slow", {"x": "q"})).content[0].text
            task = await call_tool_task(c, "slow", {"x": "q"})
            return direct, (await task.result()).content[0].text
    direct, via_task = asyncio.run(go())
    for t in (direct, via_task):
        assert AAD7 not in t and "[REDACTED_AADHAAR]" in t
    assert sangop.get_ledger().verify()[0]
    sangop.configure(ledger_path=None, run_selftest=False)
