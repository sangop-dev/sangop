"""Regression tests for the RE-audit of 0.1.4 (R1-R4) and the M3 / M4 decisions. Written before the fixes.
Synthetic data only."""
from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import subprocess
import sys

import pytest
from conftest import AADHAAR, EMAIL, PAN, PHONE

import sangop
from sangop.audit import AuditLedger
from sangop.sqlguard import SqlPolicy, check_sql

RAW = (EMAIL, PHONE, PAN, AADHAAR)


def leaked(obj) -> list:
    s = repr(obj) + str(obj)
    return [v for v in RAW if v in s]


# ===================================== R1: unknown custom objects ================================================

class ReprOnly:
    """Not a dataclass, not pydantic; its text form shows the phone number."""
    def __init__(self):
        self.phone = PHONE

    def __repr__(self):
        return f"ReprOnly(phone={PHONE})"

    __str__ = __repr__


class SlotsObj:
    __slots__ = ("email",)

    def __init__(self):
        self.email = EMAIL

    def __repr__(self):
        return f"SlotsObj({EMAIL})"


class StrOnly:
    def __str__(self):
        return f"row {PAN}"


def _tool(value, mode="tokenize"):
    @sangop.guard(purpose="t", pii_mode=mode)
    def tool():
        return value
    return tool()


@pytest.mark.parametrize("make", [ReprOnly, SlotsObj, StrOnly])
def test_r1_custom_object_text_form_never_leaks(make):
    assert not leaked(_tool(make()))


def test_r1_custom_objects_nested_in_containers():
    out = _tool({"a": [ReprOnly(), (SlotsObj(),)], "b": StrOnly()})
    assert not leaked(out)


def test_r1_clean_custom_object_is_returned_unchanged():
    class Clean:
        def __init__(self):
            self.n = 3
    obj = Clean()
    out = _tool(obj)
    assert out.n == 3


def test_r1_shadow_returns_original_and_counts():
    obj = ReprOnly()
    assert _tool(obj, "shadow") is obj
    assert sangop.get_ledger().tail(1)[0]["record"]["pii_found"]


def test_r1_redact_mode_too():
    assert not leaked(_tool(ReprOnly(), "redact"))


# ===================================== R2: remaining bulk-extraction paths =======================================

PG = SqlPolicy(max_rows=50, dialect="postgres")


@pytest.mark.parametrize("sql,dialect", [
    ("SELECT array_to_string(ARRAY(SELECT email FROM users), ',') LIMIT 1", "postgres"),
    ("SELECT ARRAY(SELECT email FROM users) LIMIT 1", "postgres"),
    ("SELECT jsonb_object_agg(id, email) FROM users LIMIT 1", "postgres"),
    ("SELECT json_object_agg(id, email) FROM users LIMIT 1", "postgres"),
    ("SELECT json_objectagg(id, email) FROM users LIMIT 1", "mysql"),
    ("SELECT json_group_object(id, email) FROM users LIMIT 1", "sqlite"),
    ("SELECT (SELECT array_agg(email) FROM users) LIMIT 1", "postgres"),
])
def test_r2_row_folding_paths_blocked(sql, dialect):
    assert not check_sql(sql, SqlPolicy(max_rows=50, dialect=dialect)).allowed, sql


@pytest.mark.parametrize("sql", [
    "SELECT ARRAY[1, 2, 3] LIMIT 1",
    "SELECT array_to_string(ARRAY['a', 'b'], ',') LIMIT 1",
    "SELECT id FROM users WHERE id = ANY(ARRAY[1, 2]) LIMIT 5",
    "SELECT id FROM users WHERE id IN (SELECT uid FROM orders LIMIT 5) LIMIT 5",
])
def test_r2_benign_array_and_subquery_still_allowed(sql):
    assert check_sql(sql, PG).allowed, sql


# ===================================== R3: config reads ==========================================================

@pytest.mark.parametrize("sql", [
    "SELECT current_setting('data_directory') LIMIT 1",
    "SELECT pg_catalog.current_setting('data_directory') LIMIT 1",
    "SELECT * FROM pg_settings LIMIT 5",
    "SELECT * FROM pg_catalog.pg_settings LIMIT 5",
    "SELECT * FROM pg_shadow LIMIT 5",
    "SELECT * FROM pg_authid LIMIT 5",
    "SELECT * FROM pg_hba_file_rules LIMIT 5",
])
def test_r3_config_and_credential_catalogs_blocked(sql):
    assert not check_sql(sql, PG).allowed, sql


# ===================================== R4: recursive CTE =========================================================

def test_r4_recursive_cte_blocked_by_default_and_opt_in():
    sql = "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT count(*) FROM r"
    assert not check_sql(sql, PG).allowed
    assert check_sql(sql, SqlPolicy(max_rows=50, dialect="postgres", allow_recursive=True)).allowed
    assert check_sql("WITH a AS (SELECT 1 AS x) SELECT x FROM a LIMIT 1", PG).allowed


# ===================================== M3: detokenize_kinds is mandatory =========================================

def test_m3_detokenize_params_without_kinds_is_an_error_at_decoration_time():
    with pytest.raises(ValueError, match="detokenize_kinds"):
        @sangop.guard(purpose="notify", detokenize_params=("to",))
        def send(to):
            return "x"


def test_m3_only_listed_kinds_are_revealed():
    @sangop.guard(purpose="support")
    def lookup():
        return f"{PHONE} {EMAIL}"

    seen = []

    @sangop.guard(purpose="notify", detokenize_params=("to",), detokenize_kinds=("PHONE_IN",))
    def send(to):
        seen.append(to)
        return "sent"

    phone_tok, email_tok = lookup().split()
    send(to=f"{phone_tok} {email_tok}")
    assert seen == [f"{PHONE} {email_tok}"]


def test_m3_star_reveals_everything_and_is_marked_in_the_ledger():
    @sangop.guard(purpose="support")
    def lookup():
        return f"{PHONE} {EMAIL}"

    seen = []

    @sangop.guard(purpose="notify", detokenize_params=("to",), detokenize_kinds="*")
    def send(to):
        seen.append(to)
        return "sent"

    a, b = lookup().split()
    send(to=f"{a} {b}")
    assert seen == [f"{PHONE} {EMAIL}"]
    ev = [r for r in sangop.get_ledger().tail(20) if r["event"] == "detokenize"]
    assert ev and ev[0]["record"]["kinds_allowed"] == "*" and ev[0]["record"]["unrestricted"] is True


def test_m3_detokenize_event_has_counts_and_no_raw_value():
    @sangop.guard(purpose="support")
    def lookup():
        return PHONE

    @sangop.guard(purpose="notify", detokenize_params=("to",), detokenize_kinds=("PHONE_IN",))
    def send(to):
        return "sent"

    send(to=lookup())
    ev = [r for r in sangop.get_ledger().tail(20) if r["event"] == "detokenize"]
    assert len(ev) == 1
    rec = ev[0]["record"]
    assert rec["tool"] == "send" and rec["purpose"] == "notify" and rec["revealed"] == {"PHONE_IN": 1}
    assert PHONE not in str(sangop.get_ledger().tail(50))


def test_m3_no_event_when_nothing_was_revealed():
    @sangop.guard(purpose="notify", detokenize_params=("to",), detokenize_kinds=("PHONE_IN",))
    def send(to):
        return "sent"
    send(to="plain text")
    assert not [r for r in sangop.get_ledger().tail(20) if r["event"] == "detokenize"]


def test_m3_l1_revealed_value_is_not_echoed_through_a_kinds_filter():
    @sangop.guard(purpose="support")
    def lookup():
        return PHONE

    @sangop.guard(purpose="notify", detokenize_params=("to",), detokenize_kinds=("PHONE_IN",), kinds=("EMAIL",))
    def echo(to):
        return f"sent to {to}"          # the tool echoes the real number back; the kinds filter must not let it out

    assert PHONE not in echo(to=lookup())


def test_m3_bad_kinds_value_rejected():
    with pytest.raises(ValueError):
        @sangop.guard(purpose="x", detokenize_params=("a",), detokenize_kinds=("NOT_A_KIND",))
        def f(a):
            return 1


# ===================================== M4: keyed ledger + anchor =================================================

KEY = "k" * 32


def _fill(led, n=5):
    for i in range(n):
        led.append("e", {"i": i})


def test_m4_keyed_ledger_verifies_and_reports_keyed(tmp_path):
    led = AuditLedger(str(tmp_path / "l.db"), key=KEY)
    _fill(led)
    rep = led.verify_report()
    assert rep["ok"] and rep["mode"] == "keyed" and rep["rows"] == 5
    assert led.verify() == (True, 5, None)


def test_m4_key_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("SANGOP_LEDGER_KEY", KEY)
    led = AuditLedger(str(tmp_path / "l.db"))
    _fill(led)
    assert led.verify_report()["mode"] == "keyed"


def test_m4_unkeyed_ledger_says_so_plainly(tmp_path, monkeypatch):
    monkeypatch.delenv("SANGOP_LEDGER_KEY", raising=False)
    led = AuditLedger(str(tmp_path / "l.db"))
    _fill(led)
    rep = led.verify_report()
    assert rep["ok"] and rep["mode"] == "unkeyed"
    assert "unkeyed" in rep["message"].lower() and "truncation" in rep["message"].lower()


def test_m4_forged_keyed_rows_without_the_key_fail(tmp_path):
    import hashlib
    p = str(tmp_path / "l.db")
    led = AuditLedger(p, key=KEY)
    _fill(led)
    led.close()
    con = sqlite3.connect(p)
    con.execute("UPDATE events SET record='{\"i\":99}' WHERE id=2")
    prev = "0" * 64
    for rid, ts, ev, rec in con.execute("SELECT id, ts_utc, event, record FROM events ORDER BY id").fetchall():
        h = hashlib.sha256(f"{prev}|{ts}|{ev}|{rec}".encode()).hexdigest()    # attacker has no key: plain sha256
        con.execute("UPDATE events SET prev_hash=?, hash=? WHERE id=?", (prev, h, rid))   # alg column left as it is
        prev = h
    con.commit()
    con.close()
    ok, n, bad = AuditLedger(p, key=KEY).verify()
    assert not ok and bad == 1


def test_m4_downgrade_to_sha256_rows_after_keyed_rows_is_detected(tmp_path):
    p = str(tmp_path / "l.db")
    led = AuditLedger(p, key=KEY)
    _fill(led, 3)
    led.close()
    # a later writer without the key appends plain rows
    os.environ.pop("SANGOP_LEDGER_KEY", None)
    plain = AuditLedger(p)
    plain.append("e", {"forged": True})
    plain.close()
    rep = AuditLedger(p, key=KEY).verify_report()
    assert rep["ok"] is False and rep["first_bad_id"] == 4


def test_m4_anchor_detects_truncation_and_rewrite(tmp_path):
    p = str(tmp_path / "l.db")
    led = AuditLedger(p, key=KEY)
    _fill(led, 6)
    anchor = led.anchor()                      # "id:hash", copied somewhere the writer cannot reach
    assert led.verify_report(anchor=anchor)["ok"]
    led.close()
    con = sqlite3.connect(p)
    con.execute("DELETE FROM events WHERE id > 4")
    con.commit()
    con.close()
    led = AuditLedger(p, key=KEY)
    assert led.verify_report()["ok"] is True                  # chain alone cannot see a cut tail ...
    rep = led.verify_report(anchor=anchor)                    # ... the anchor can
    assert rep["ok"] is False and "anchor" in rep["message"].lower()


def test_m4_wrong_key_fails(tmp_path):
    p = str(tmp_path / "l.db")
    led = AuditLedger(p, key=KEY)
    _fill(led)
    led.close()
    assert AuditLedger(p, key="z" * 32).verify()[0] is False
    assert AuditLedger(p, key=None).verify()[0] is False       # keyed rows cannot be checked without the key


def test_m4_short_key_rejected(tmp_path):
    with pytest.raises(ValueError):
        AuditLedger(str(tmp_path / "l.db"), key="short")


def test_m4_key_is_never_written_to_the_ledger_file(tmp_path):
    p = str(tmp_path / "l.db")
    led = AuditLedger(p, key=KEY)
    _fill(led)
    led.close()
    blob = b"".join(open(os.path.join(tmp_path, f), "rb").read() for f in os.listdir(tmp_path))
    assert KEY.encode() not in blob


def test_m4_old_unkeyed_rows_then_keyed_rows_verify(tmp_path, monkeypatch):
    monkeypatch.delenv("SANGOP_LEDGER_KEY", raising=False)
    p = str(tmp_path / "l.db")
    old = AuditLedger(p)
    _fill(old, 3)
    old.close()
    new = AuditLedger(p, key=KEY)
    _fill(new, 2)
    rep = new.verify_report()
    assert rep["ok"] and rep["mode"] == "mixed" and rep["rows"] == 5


def test_m4_configure_passes_the_key(tmp_path):
    sangop.configure(ledger_path=str(tmp_path / "k.db"), ledger_key=KEY)
    assert sangop.get_ledger().verify_report()["mode"] == "keyed"


def test_m4_cli_prints_unkeyed_message_and_anchor(tmp_path, monkeypatch):
    p = str(tmp_path / "c.db")
    monkeypatch.delenv("SANGOP_LEDGER_KEY", raising=False)
    led = AuditLedger(p)
    _fill(led)
    led.close()
    env = {k: v for k, v in os.environ.items() if k != "SANGOP_LEDGER_KEY"}
    out = subprocess.run([sys.executable, "-m", "sangop.cli", "audit", "verify", "--db", p],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0 and "unkeyed" in out.stdout.lower() and "anchor:" in out.stdout
    anchor = [ln for ln in out.stdout.splitlines() if ln.startswith("anchor:")][0].split(":", 1)[1].strip()
    out2 = subprocess.run([sys.executable, "-m", "sangop.cli", "audit", "verify", "--db", p, "--anchor", anchor],
                          capture_output=True, text=True, env=env)
    assert out2.returncode == 0
    out3 = subprocess.run([sys.executable, "-m", "sangop.cli", "audit", "verify", "--db", p, "--anchor", "3:" + "0" * 64],
                          capture_output=True, text=True, env=env)
    assert out3.returncode == 3
