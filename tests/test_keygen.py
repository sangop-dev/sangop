"""`sangop keygen`: prints one random 32-byte ledger key as 64 hex characters on stdout and NOTHING else there;
a short safety note goes to stderr. It never writes a file, never touches the network, and the key it prints passes
the weak-key check. Written before the command existed (written test-first)."""
import builtins
import os
import re
import socket
import warnings

import pytest

from sangop.audit import AuditLedger, weak_key_reason
from sangop.cli import main as cli_main

HEX64 = re.compile(r"[0-9a-f]{64}")


def _run(capsys):
    rc = cli_main(["keygen"])
    out, err = capsys.readouterr()
    return rc, out, err


def _key(out: str) -> str:
    return out.strip()


def test_stdout_is_exactly_64_hex_characters(capsys):
    rc, out, err = _run(capsys)
    assert rc == 0
    assert out.endswith("\n") and out.count("\n") == 1, repr(out)      # one line, nothing else on stdout
    key = _key(out)
    assert HEX64.fullmatch(key), repr(key)
    assert len(bytes.fromhex(key)) == 32


def test_two_runs_give_different_keys(capsys):
    _, out1, _ = _run(capsys)
    _, out2, _ = _run(capsys)
    assert _key(out1) != _key(out2)


def test_safety_note_goes_to_stderr_and_does_not_repeat_the_key(capsys):
    _, out, err = _run(capsys)
    key = _key(out)
    assert key not in err
    low = err.lower()
    assert "password manager" in low
    assert "git" in low and "chat" in low and "screenshot" in low
    assert "SANGOP_LEDGER_KEY" in err


def _snapshot(root):
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            snap[os.path.join(dirpath, d)] = "dir"
        for f in filenames:
            p = os.path.join(dirpath, f)
            st = os.stat(p)
            snap[p] = (st.st_size, st.st_mtime_ns)
    return snap


def test_no_file_is_created_or_changed(tmp_path, monkeypatch, capsys):
    (tmp_path / "existing.txt").write_text("keep me\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    before = _snapshot(tmp_path)

    real_open, real_os_open = builtins.open, os.open

    def guarded_open(file, mode="r", *a, **k):
        if any(c in mode for c in "wax+"):
            raise AssertionError(f"keygen tried to open {file!r} for writing")
        return real_open(file, mode, *a, **k)

    def guarded_os_open(path, flags, *a, **k):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
            raise AssertionError(f"keygen tried to os.open {path!r} for writing")
        return real_os_open(path, flags, *a, **k)

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    rc, out, _ = _run(capsys)
    monkeypatch.undo()

    assert rc == 0 and HEX64.fullmatch(_key(out))
    assert _snapshot(tmp_path) == before
    assert not (tmp_path / ".sangop").exists()


def test_no_network(monkeypatch, capsys):
    def _blocked(*a, **k):
        raise AssertionError("keygen attempted a network connection")
    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    rc, out, _ = _run(capsys)
    assert rc == 0 and HEX64.fullmatch(_key(out))


@pytest.mark.parametrize("_", range(20))
def test_generated_key_is_not_flagged_as_weak(_, capsys, tmp_path):
    _, out, _ = _run(capsys)
    key = _key(out)
    assert weak_key_reason(key.encode()) is None, key
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        led = AuditLedger(str(tmp_path / "k.db"), key=key)
    assert led.key_warning is None
    led.append("e", {"a": 1})
    assert led.verify_report()["ok"]
    led.close()
