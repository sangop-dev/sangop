"""Internal AI-assisted security review, 15 Nov 2026, third run ("review 6"): M1 and the sha2 false block. Written
before the fixes; every query is synthetic. M1 was confirmed by the reviewer on a throw-away local PostgreSQL 16
(own sandbox only): pg_catalog.lpad('x', 260000000) built a 260 MB value.

Root fix: a pg_catalog. qualifier (and main. for SQLite) is removed before any rule runs, so every rule sees the
plain name."""
import pytest

from sangop.sqlguard import SqlPolicy, check_sql

PG_AND_NONE = ["postgres", None]


# ---- M1: pg_catalog. / main. must not hide a call from any rule ------------------------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT length(pg_catalog.lpad('x', 260000000)) LIMIT 1",
    "SELECT pg_catalog.rpad('x', 5000, 'ab') LIMIT 1",
    "SELECT PG_CATALOG.LPAD('x', 2000) LIMIT 1",
    'SELECT "PG_CATALOG"."LPAD"(\'x\', 2000) LIMIT 1',
    "SELECT pg_catalog.\"lpad\"('x', 2000) LIMIT 1",
    "SELECT pg_catalog.\"rpad\"(code, n) FROM t LIMIT 1",
])
def test_m1_qualified_pad_keeps_the_length_limit(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "lpad/rpad length" in v.reason, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql, word", [
    ("SELECT pg_catalog.format('%*s', 900000000, 'x') LIMIT 1", "format width"),
    ("SELECT \"pg_catalog\".\"format\"('%900000000s', 'x') LIMIT 1", "format width"),
    ("SELECT pg_catalog.percentile_disc('{0,0.5,1}'::float8[]) WITHIN GROUP (ORDER BY email) FROM users LIMIT 1",
     "row-folding"),
    ("SELECT pg_catalog.string_agg(email, ',') FROM users LIMIT 1", "row-folding"),
    ("SELECT pg_catalog.json_agg(u) FROM users u LIMIT 1", "row-folding"),
    ("SELECT pg_catalog.pg_sleep(10) LIMIT 1", "denied function"),
    ("SELECT pg_catalog.pg_read_file('x') LIMIT 1", "denied function"),
    ("SELECT pg_catalog.query_to_xml('select 1', true, true, '') LIMIT 1", "denied function"),
    ("SELECT pg_catalog.ucase(name) FROM t LIMIT 5", "not in the default allow-list"),
])
def test_m1_every_rule_sees_through_pg_catalog(sql, word, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and word in v.reason, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
def test_m1_text_query_rule_sees_through_pg_catalog(dialect):
    v = check_sql("SELECT pg_catalog.some_exec('SELECT email FROM users') LIMIT 1",
                  SqlPolicy(dialect=dialect, extra_allowed_functions=frozenset({"some_exec"})))
    assert v.allowed is False and "query given as text" in v.reason, v.reason


@pytest.mark.parametrize("dialect", ["sqlite", None])
@pytest.mark.parametrize("sql, word", [
    ("SELECT main.lpad('x', 2000) LIMIT 1", "lpad/rpad length"),
    ("SELECT main.group_concat(email) FROM users LIMIT 1", "row-folding"),
    ("SELECT main.format('%*s', 900000000, 'x') LIMIT 1", "format width"),
])
def test_m1_sqlite_main_qualifier(sql, word, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and word in v.reason, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT pg_catalog.lpad(code, 5, '0') FROM t LIMIT 5",
    "SELECT lpad(id::text, 6, '0') FROM users LIMIT 5",
    "SELECT pg_catalog.lower(name), pg_catalog.count(*) FROM t GROUP BY 1 LIMIT 5",
    "SELECT pg_catalog.format('%s-%s', a, b) FROM t LIMIT 5",
    "SELECT pg_catalog.percentile_cont(0.5) WITHIN GROUP (ORDER BY total) FROM orders",
])
def test_m1_ordinary_qualified_calls_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_m1_another_schema_is_still_the_users_own_function():
    v = check_sql("SELECT public.lpad('x', 5) LIMIT 1", SqlPolicy(dialect="postgres"))
    assert v.allowed is False and "not in the default allow-list" in v.reason


# ---- L2: sha2 functions ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT sha256('x'::bytea) LIMIT 1",
    "SELECT encode(sha256(email::bytea), 'hex') FROM users LIMIT 5",
    "SELECT sha224('x'::bytea), sha384('x'::bytea), sha512('x'::bytea) LIMIT 1",
])
def test_l2_sha2_functions_are_allowed(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql, word", [
    ("SELECT pg_catalog.length(pg_catalog.lpad('x', 260000000)) LIMIT 1", "lpad/rpad length"),
    ("SELECT pg_catalog.lower(pg_catalog.upper(pg_catalog.ucase(x))) FROM t LIMIT 1", "'ucase'"),
    ("SELECT pg_catalog.coalesce(pg_catalog.format('%*s', 9000000, 'x'), 'a') LIMIT 1", "format width"),
])
def test_m1_nested_qualified_calls(sql, word, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and word in v.reason, v.reason


def test_m1_many_qualified_calls_stay_fast():
    import sys
    import time
    sql = "SELECT " + ", ".join(f"pg_catalog.lower(c{i})" for i in range(3000)) + " FROM t LIMIT 1"
    start = time.perf_counter()
    assert check_sql(sql, SqlPolicy(dialect="postgres")).allowed is True
    # Windows CI and laptops are much slower; the Linux limit stays the real gate.
    assert time.perf_counter() - start < 5 * (3 if sys.platform == "win32" else 1)
