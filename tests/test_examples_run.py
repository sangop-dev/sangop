"""The three short examples in examples/ run as they are, offline, and print what they promise. Synthetic values only."""
import asyncio
import ipaddress
import runpy
import socket
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _is_loopback(host) -> bool:
    """True only for this machine: 127.0.0.0/8, ::1 (also as ::ffff:127.x) and the name "localhost"."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    host = host.split("%", 1)[0].strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return ip.is_loopback or (mapped is not None and mapped.is_loopback)


@pytest.fixture
def offline(monkeypatch):
    """No connection to any OTHER machine. Connections to this machine's loopback (127.0.0.0/8, ::1) stay allowed:
    on Windows, socket.socketpair() - and therefore every asyncio event loop - connects to 127.0.0.1 internally
    (Python's _fallback_socketpair). Blocking that broke the FastMCP example on Windows (13 Nov 2026) without any
    network use by Sangop. Unix-domain sockets (a path, not a host) are local too. That Sangop itself opens no
    socket at all is tested separately and more strictly in tests/test_no_network.py.
    """
    real_create, real_getaddrinfo = socket.create_connection, socket.getaddrinfo
    real_connect, real_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def _check(address):
        if isinstance(address, (str, bytes)):          # AF_UNIX path: same machine
            return
        host = address[0] if isinstance(address, tuple) and address else address
        if not _is_loopback(host):
            raise AssertionError(f"an example attempted a network connection to {host!r}")

    def create_connection(address, *a, **k):
        _check(address)
        return real_create(address, *a, **k)

    def getaddrinfo(host, *a, **k):
        if host is not None and not _is_loopback(host):
            raise AssertionError(f"an example attempted a network connection (name lookup of {host!r})")
        return real_getaddrinfo(host, *a, **k)

    def connect(self, address):
        _check(address)
        return real_connect(self, address)

    def connect_ex(self, address):
        _check(address)
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)


# ---- the fixture itself: loopback allowed, everything else blocked (Windows, 13 Nov 2026) ---------------------
# Documentation-only addresses (RFC 5737 / RFC 3849): even if the fixture were broken, nothing real is contacted.
OUTSIDE_V4 = ("192.0.2.1", 80)
OUTSIDE_V6 = ("2001:db8::1", 80)


def test_offline_allows_a_loopback_connection_like_windows_socketpair(offline):
    """On Windows, socket.socketpair() (and so every asyncio event loop) connects to 127.0.0.1 internally."""
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        with socket.socket() as cli:
            cli.connect(srv.getsockname())
            conn, _ = srv.accept()
            conn.close()


def test_offline_allows_the_fallback_socketpair_and_an_event_loop(offline):
    fallback = getattr(socket, "_fallback_socketpair", None)   # the Windows implementation, present on 3.12+
    if fallback is not None:
        a, b = fallback()
        a.sendall(b"x")
        assert b.recv(1) == b"x"
        a.close()
        b.close()
    a, b = socket.socketpair()
    a.close()
    b.close()
    loop = asyncio.new_event_loop()
    try:
        assert loop.run_until_complete(asyncio.sleep(0, result=7)) == 7
    finally:
        loop.close()


@pytest.mark.parametrize("family, addr", [(socket.AF_INET, OUTSIDE_V4), (socket.AF_INET6, OUTSIDE_V6)])
def test_offline_blocks_connect_outside_loopback(offline, family, addr):
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
    except OSError:
        pytest.skip("this machine has no IPv6 sockets")
    with s:
        s.settimeout(0.01)
        with pytest.raises(AssertionError, match="network connection"):
            s.connect(addr)
        with pytest.raises(AssertionError, match="network connection"):
            s.connect_ex(addr)


def test_offline_blocks_create_connection_and_name_lookup_outside_loopback(offline):
    with pytest.raises(AssertionError, match="network connection"):
        socket.create_connection(OUTSIDE_V4, timeout=0.01)
    with pytest.raises(AssertionError, match="network connection"):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(AssertionError, match="network connection"):
        socket.getaddrinfo(OUTSIDE_V4[0], 80)


@pytest.mark.parametrize("host, local", [
    ("127.0.0.1", True), ("127.9.8.7", True), ("::1", True), ("[::1]", True), ("::ffff:127.0.0.1", True),
    ("localhost", True), (b"127.0.0.1", True),
    ("192.0.2.1", False), ("2001:db8::1", False), ("0.0.0.0", False), ("10.0.0.1", False), ("::", False),
    ("::ffff:192.0.2.1", False), ("example.com", False), ("localhost.example.com", False), (None, False), (80, False),
])
def test_loopback_rule(host, local):
    assert _is_loopback(host) is local


@pytest.mark.parametrize("name", ["fastmcp_guarded_tool.py", "sql_guard_only.py", "ledger_verify.py"])
def test_example_is_short(name):
    lines = (EXAMPLES / name).read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) <= 20, f"{name} has {len(lines)} lines"


def test_fastmcp_guarded_tool(offline, capsys):
    pytest.importorskip("fastmcp")
    runpy.run_path(str(EXAMPLES / "fastmcp_guarded_tool.py"), run_name="__main__")
    out = capsys.readouterr().out
    assert "[PII_PAN_" in out and "[PII_PHONE_IN_" in out and "ABCPE1234F" not in out


def test_sql_guard_only(offline, capsys):
    runpy.run_path(str(EXAMPLES / "sql_guard_only.py"), run_name="__main__")
    lines = capsys.readouterr().out.strip().splitlines()
    assert [ln.split(" ")[0] for ln in lines] == ["allowed", "blocked", "blocked", "blocked"]


def test_ledger_verify(offline, capsys):
    runpy.run_path(str(EXAMPLES / "ledger_verify.py"), run_name="__main__")
    out = capsys.readouterr().out
    assert "ledger OK: True" in out and "keyed" in out and "ABCPE1234F" not in out
