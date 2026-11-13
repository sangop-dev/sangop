import asyncio
import sqlite3

import pytest
from conftest import AADHAAR, EMAIL, PAN, PHONE

import sangop
from sangop import SangopBlocked, SqlPolicy


def _db_bytes():
    led = sangop.get_ledger()
    led._conn.execute("PRAGMA wal_checkpoint(FULL)")
    with open(led.path, "rb") as fh:
        data = fh.read()
    try:
        with open(led.path + "-wal", "rb") as fh:
            data += fh.read()
    except FileNotFoundError:
        pass
    return data


def test_output_is_tokenized_and_logged_without_raw_pii():
    @sangop.guard(purpose="support")
    def get_customer(cid: int) -> dict:
        return {"id": cid, "pan": PAN, "phone": PHONE, "note": f"aadhaar {AADHAAR}"}

    out = get_customer(1)
    assert PAN not in repr(out) and PHONE not in repr(out) and AADHAAR not in repr(out)
    assert out["pan"].startswith("[PII_PAN_")
    raw = _db_bytes()
    for secret in (PAN, PHONE, AADHAAR):
        assert secret.encode() not in raw, "raw PII leaked into audit ledger"
    ok, n, _ = sangop.get_ledger().verify()
    assert ok and n >= 2          # selftest + call


def test_sql_blocked_and_logged():
    calls = []

    @sangop.guard(purpose="analytics", sql_param="query", sql_policy=SqlPolicy(max_rows=20))
    def run(query: str):
        calls.append(query)
        return []

    with pytest.raises(SangopBlocked):
        run("DELETE FROM users")
    with pytest.raises(SangopBlocked):
        run(f"SELECT * FROM users WHERE phone = '{PHONE}'")       # no LIMIT
    assert calls == []
    assert PHONE.encode() not in _db_bytes()                       # SQL text redacted in log
    run("SELECT name FROM users LIMIT 5")
    assert calls == ["SELECT name FROM users LIMIT 5"]


def test_sql_shadow_mode_logs_but_allows():
    @sangop.guard(purpose="x", sql_param="q", sql_mode="shadow")
    def run(q: str):
        return "ran"
    assert run("DROP TABLE t") == "ran"
    last = sangop.get_ledger().tail(1)[0]["record"]
    assert last["sql"]["allowed"] is False and last["sql"]["mode"] == "shadow"


def test_jit_detokenization_for_trusted_tool():
    @sangop.guard(purpose="support")
    def lookup() -> str:
        return f"phone {PHONE}"

    sent = []

    @sangop.guard(purpose="notify", detokenize_params=("to",), detokenize_kinds=("PHONE_IN",))
    def send_sms(to: str, body: str) -> str:
        sent.append(to)
        return "sent"

    token = lookup().split()[1]
    assert token.startswith("[PII_PHONE_IN_")
    send_sms(to=token, body="hi")
    assert sent == [PHONE]


def test_async_tool():
    @sangop.guard(purpose="support")
    async def fetch():
        return [EMAIL]
    out = asyncio.run(fetch())
    assert EMAIL not in out[0]


def test_tamper_detection():
    @sangop.guard(purpose="x")
    def f():
        return "ok"
    f(); f()
    led = sangop.get_ledger()
    con = sqlite3.connect(led.path)
    con.execute("UPDATE events SET record = '{\"tool\":\"forged\"}' WHERE id = 2")
    con.commit(); con.close()
    ok, _, bad = led.verify()
    assert not ok and bad == 2
