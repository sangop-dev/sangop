"""M5 (64-bit tokens, collision-proof vault) and M2 (schema-aware table lists). Written before the fixes."""
from __future__ import annotations

import hashlib
import re

import pytest

import sangop
from sangop.sqlguard import SqlPolicy, check_sql
from sangop.tokenizer import TOKEN_RE, Vault, detokenize_text, scrub_text

# ============================== M5 =========================================================================

def test_m5_tokens_are_64_bit():
    v = Vault(b"k" * 32)
    t = v.token_for("PAN", "ABCPE1234F")
    assert re.fullmatch(r"\[PII_PAN_[0-9a-f]{16}\]", t)
    assert v.reveal(t) == "ABCPE1234F"


def test_m5_no_collisions_in_200k_values():
    v = Vault(b"k" * 32)
    toks = {v.token_for("PHONE_IN", f"9{n:09d}") for n in range(200_000)}
    assert len(toks) == 200_000 == len(v)


def test_m5_forced_collision_gets_a_longer_token_and_both_values_reveal_correctly():
    class Weak(Vault):
        def _hex(self, kind, value):                      # first 16 hex chars identical for every value
            return "a" * 16 + hashlib.sha256(value.encode()).hexdigest()
    v = Weak(b"k" * 32)
    t1, t2 = v.token_for("PAN", "ABCPE1234F"), v.token_for("PAN", "ABCPE1234G")
    assert t1 != t2
    assert v.reveal(t1) == "ABCPE1234F" and v.reveal(t2) == "ABCPE1234G"
    assert v.token_for("PAN", "ABCPE1234F") == t1          # stable
    assert TOKEN_RE.fullmatch(t1) and TOKEN_RE.fullmatch(t2)
    out, _ = scrub_text("a ABCPE1234F b ABCPE1234G", v)
    assert detokenize_text(out, v) == "a ABCPE1234F b ABCPE1234G"


def test_m5_same_value_different_kind_different_token():
    v = Vault(b"k" * 32)
    assert v.token_for("PAN", "X1") != v.token_for("GSTIN", "X1")


def test_m5_old_8_hex_token_is_not_revealed_and_not_mistaken():
    v = Vault()
    assert detokenize_text("[PII_PAN_deadbeef]", v) == "[PII_PAN_deadbeef]"


# ============================== M2 =========================================================================

PG = dict(dialect="postgres", max_rows=50)


@pytest.mark.parametrize("sql", [
    "SELECT * FROM secretdb.orders LIMIT 5",
    "SELECT * FROM other.orders LIMIT 5",
    "SELECT * FROM public.users u JOIN other.users x ON x.id = u.id LIMIT 5",
    'SELECT * FROM "Other"."orders" LIMIT 5',
])
def test_m2_unqualified_allow_entry_means_default_schema_only(sql):
    v = check_sql(sql, SqlPolicy(allowed_tables=frozenset({"orders", "users"}), **PG))
    assert not v.allowed and "allow-list" in v.reason, sql


@pytest.mark.parametrize("sql", [
    "SELECT * FROM orders LIMIT 5",
    "SELECT * FROM ORDERS LIMIT 5",
    "SELECT * FROM public.orders LIMIT 5",
    "SELECT * FROM mydb.public.orders LIMIT 5",
    "SELECT * FROM orders o JOIN users u ON u.id = o.uid LIMIT 5",
])
def test_m2_default_schema_and_public_are_allowed(sql):
    assert check_sql(sql, SqlPolicy(allowed_tables=frozenset({"orders", "users"}), **PG)).allowed, sql


def test_m2_schema_qualified_allow_entries():
    pol = SqlPolicy(allowed_tables=frozenset({"sales.orders", "hr.people"}), **PG)
    assert check_sql("SELECT * FROM sales.orders LIMIT 5", pol).allowed
    assert check_sql("SELECT * FROM SALES.ORDERS LIMIT 5", pol).allowed
    assert not check_sql("SELECT * FROM orders LIMIT 5", pol).allowed          # bare name = default schema != sales
    assert not check_sql("SELECT * FROM other.orders LIMIT 5", pol).allowed
    assert not check_sql("SELECT * FROM sales.secrets LIMIT 5", pol).allowed


def test_m2_denied_tables_match_in_any_schema():
    pol = SqlPolicy(denied_tables=frozenset({"users"}), **PG)
    for sql in ("SELECT * FROM users LIMIT 1", "SELECT * FROM other.users LIMIT 1", 'SELECT * FROM "Users" LIMIT 1',
                "SELECT * FROM a.b.users LIMIT 1"):
        assert not check_sql(sql, pol).allowed, sql
    pol2 = SqlPolicy(denied_tables=frozenset({"hr.salaries"}), **PG)
    assert not check_sql("SELECT * FROM hr.salaries LIMIT 1", pol2).allowed
    assert check_sql("SELECT * FROM sales.salaries LIMIT 1", pol2).allowed


def test_m2_cte_names_are_not_mistaken_for_tables():
    pol = SqlPolicy(allowed_tables=frozenset({"orders"}), **PG)
    assert check_sql("WITH x AS (SELECT * FROM orders LIMIT 5) SELECT * FROM x LIMIT 5", pol).allowed


def test_m2_sqlite_attached_schema_and_main():
    pol = SqlPolicy(allowed_tables=frozenset({"orders"}), dialect="sqlite", max_rows=50)
    assert check_sql("SELECT * FROM main.orders LIMIT 5", pol).allowed
    assert not check_sql("SELECT * FROM aux.orders LIMIT 5", pol).allowed
