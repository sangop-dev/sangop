"""Regression tests for the independent security audit of 0.1.3 (findings H1-H5, M1, L3).

Written BEFORE the fixes (they failed on 0.1.3 as described in each docstring) from the audit's findings; the audit's
own proof-of-concept scripts are private and are not part of this repository. Synthetic data only.
"""
from __future__ import annotations

import asyncio
import collections
import dataclasses
import decimal

import pytest
from conftest import AADHAAR, EMAIL, PAN, PHONE

import sangop
from sangop.sqlguard import SqlPolicy, check_sql

RAW = (EMAIL, PHONE, PAN, AADHAAR)


def leaked(obj) -> list:
    s = repr(obj)
    if isinstance(obj, (bytes, bytearray)):
        s += obj.decode("utf-8", "replace")
    return [v for v in RAW if v in s]


def ledger_text() -> str:
    return str(sangop.get_ledger().tail(200))


# =============================== H1: return types that were not scrubbed =========================================

@dataclasses.dataclass
class Cust:
    name: str
    phone: str
    email: str


@dataclasses.dataclass(frozen=True)
class Wrapper:
    owner: Cust
    notes: list


Pair = collections.namedtuple("Pair", "a b")


class Plain:
    def __init__(self):
        self.phone = PHONE
        self.n = 3


class OnlyStr:
    def __str__(self):
        return f"customer {EMAIL}"


def _run(value, mode="tokenize"):
    @sangop.guard(purpose="t", pii_mode=mode)
    def tool():
        return value
    return tool()


def test_h1_dataclass_scrubbed_and_type_kept():
    out = _run(Cust("Ravi", PHONE, EMAIL))
    assert isinstance(out, Cust) and not leaked(out) and out.name == "Ravi"


def test_h1_nested_frozen_dataclass_and_list():
    out = _run(Wrapper(Cust("R", PHONE, EMAIL), [PAN, {"k": AADHAAR}]))
    assert isinstance(out, Wrapper) and not leaked(out)


def test_h1_pydantic_model():
    pydantic = pytest.importorskip("pydantic")

    class Inner(pydantic.BaseModel):
        pan: str

    class M(pydantic.BaseModel):
        phone: str
        inner: Inner
        tags: list[str]

    out = _run(M(phone=PHONE, inner=Inner(pan=PAN), tags=[EMAIL]))
    assert isinstance(out, M) and isinstance(out.inner, Inner) and not leaked(out)


def test_h1_dict_keys_are_scrubbed():
    out = _run({EMAIL: {"orders": 3}, PHONE: "x", 7: "ok", "plain": 1})
    assert not leaked(out) and out[7] == "ok" and out["plain"] == 1


@pytest.mark.parametrize("value", [
    EMAIL.encode(), bytearray(PAN.encode()), {PAN}, frozenset({EMAIL}), float(PHONE),
    decimal.Decimal(PHONE), Pair(PHONE, EMAIL), (PHONE, [EMAIL]), [PHONE.encode(), {PAN}],
])
def test_h1_other_containers_and_scalars(value):
    assert not leaked(_run(value))


def test_h1_plain_object_with_attributes():
    out = _run(Plain())
    assert not leaked(vars(out)) and out.n == 3


def test_h1_unknown_type_fails_closed_through_str():
    out = _run(OnlyStr())
    assert not leaked(out)


def test_h1_shadow_mode_counts_but_returns_the_original_object():
    obj = Cust("R", PHONE, EMAIL)
    out = _run(obj, "shadow")
    assert out is obj
    rec = sangop.get_ledger().tail(1)[0]["record"]
    assert rec["pii_found"].get("PHONE_IN") == 1 and rec["pii_found"].get("EMAIL") == 1


def test_h1_numbers_that_are_not_pii_are_untouched():
    out = _run({"a": 12, "b": 3.5, "c": True, "d": None, "e": decimal.Decimal("2.50")})
    assert out == {"a": 12, "b": 3.5, "c": True, "d": None, "e": decimal.Decimal("2.50")}


# =============================== H2: errors that carried PII ======================================================

def test_h2_exception_message_is_scrubbed_and_audited():
    @sangop.guard(purpose="t")
    def tool():
        raise ValueError(f"duplicate key: email={EMAIL} phone={PHONE}")
    with pytest.raises(Exception) as ei:
        tool()
    assert not leaked(str(ei.value)) and not leaked(repr(ei.value.args))
    assert ei.value.__cause__ is None and ei.value.__context__ is None
    assert isinstance(ei.value, sangop.SangopToolError)
    rec = sangop.get_ledger().tail(1)[0]
    assert rec["event"] == "tool_call" and rec["record"]["outcome"] == "error"
    assert rec["record"]["error_type"] == "ValueError"
    assert not leaked(ledger_text())


def test_h2_async_tool_error():
    @sangop.guard(purpose="t")
    async def tool():
        raise RuntimeError(f"bad row {EMAIL}")
    with pytest.raises(sangop.SangopToolError) as ei:
        asyncio.run(tool())
    assert not leaked(str(ei.value))
    assert sangop.get_ledger().tail(1)[0]["record"]["outcome"] == "error"


def test_h2_blocked_sql_still_raises_sangop_blocked():
    @sangop.guard(purpose="t", sql_param="q")
    def tool(q):
        return []
    with pytest.raises(sangop.SangopBlocked):
        tool("DROP TABLE users")


def test_h2_keyboard_interrupt_is_not_swallowed():
    @sangop.guard(purpose="t")
    def tool():
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        tool()


# =============================== H3: generators and iterators ====================================================

def test_h3_generator_function():
    @sangop.guard(purpose="t")
    def tool():
        yield f"phone {PHONE}"
        yield {"e": EMAIL}
    out = list(tool())
    assert len(out) == 2 and not leaked(out)
    rec = sangop.get_ledger().tail(1)[0]["record"]
    assert rec["outcome"] == "ok" and rec["pii_found"]


def test_h3_async_generator_function():
    @sangop.guard(purpose="t")
    async def tool():
        yield f"phone {PHONE}"
        yield [PAN]

    async def go():
        return [x async for x in tool()]
    assert not leaked(asyncio.run(go()))


def test_h3_returned_generator_expression_and_iterators():
    @sangop.guard(purpose="t")
    def a():
        return (f"x {PHONE}" for _ in range(2))

    @sangop.guard(purpose="t")
    def b():
        return map(str.upper, [EMAIL, PAN])

    @sangop.guard(purpose="t")
    def c():
        return {"k": EMAIL}.values()
    assert not leaked(list(a())) and not leaked(list(b())) and not leaked(list(c()))


def test_h3_error_inside_a_generator_is_scrubbed():
    @sangop.guard(purpose="t")
    def tool():
        yield "fine"
        raise ValueError(f"row {EMAIL}")
    it = tool()
    assert next(it) == "fine"
    with pytest.raises(sangop.SangopToolError) as ei:
        next(it)
    assert not leaked(str(ei.value))
    assert sangop.get_ledger().tail(1)[0]["record"]["outcome"] == "error"


def test_h3_abandoned_generator_is_still_audited():
    @sangop.guard(purpose="t")
    def tool():
        yield "a"
        yield "b"
    it = tool()
    next(it)
    it.close()
    assert sangop.get_ledger().tail(1)[0]["record"]["outcome"] == "incomplete"


# =============================== H4: bulk-extraction guard ========================================================

PG = SqlPolicy(max_rows=50, dialect="postgres")


@pytest.mark.parametrize("sql", [
    "SELECT * FROM users UNION SELECT * FROM users",
    "SELECT * FROM users INTERSECT SELECT * FROM users",
    "SELECT * FROM users EXCEPT SELECT * FROM users WHERE id = 1",
    "SELECT * FROM users UNION ALL SELECT * FROM users LIMIT 100000",
    "SELECT * FROM users LIMIT 5*1000",
    "SELECT * FROM users LIMIT 5+0",
    "SELECT * FROM users LIMIT ALL",
    "SELECT * FROM users LIMIT NULL",
    "SELECT * FROM users FETCH FIRST 5000 ROWS ONLY",
])
def test_h4_postgres_unbounded_or_oversized(sql):
    assert not check_sql(sql, PG).allowed, sql


def test_h4_sqlite_negative_limit_is_unlimited():
    assert not check_sql("SELECT * FROM users LIMIT -1", SqlPolicy(max_rows=50, dialect="sqlite")).allowed


@pytest.mark.parametrize("sql,dialect", [
    ("SELECT string_agg(email, ',') FROM users", "postgres"),
    ("SELECT string_agg(email, ',') FROM users LIMIT 1", "postgres"),
    ("SELECT group_concat(email) FROM users", "sqlite"),
    ("SELECT GROUP_CONCAT(email SEPARATOR ',') FROM users", "mysql"),
    ("SELECT json_agg(u) FROM users u", "postgres"),
    ("SELECT jsonb_agg(email) FROM users", "postgres"),
    ("SELECT array_agg(email) FROM users", "postgres"),
    ("SELECT json_group_array(email) FROM users", "sqlite"),
    ("SELECT LISTAGG(email, ',') WITHIN GROUP (ORDER BY id) FROM users", "oracle"),
    ("SELECT id, (SELECT string_agg(email, ',') FROM users) FROM t LIMIT 3", "postgres"),
])
def test_h4_concatenating_aggregates_blocked_even_with_limit(sql, dialect):
    v = check_sql(sql, SqlPolicy(max_rows=50, dialect=dialect))
    assert not v.allowed and "aggregate" in v.reason, (sql, v.reason)


# H4b: row-folding aggregates (json_agg / jsonb_agg) under the postgres dialect, with and without LIMIT.
# A LIMIT on a single-row aggregate does not bound how many source rows it folds into that one row.
# With sqlglot 28.0.0 to 28.4.0 seven of these eight were allowed (fail-open; only jsonb_agg was caught);
# from 28.5.0 all eight are blocked.
# This pins the behaviour directly, so a parser change cannot reopen it unnoticed.
@pytest.mark.parametrize("sql", [
    "SELECT json_agg(u) FROM users u",
    "SELECT json_agg(u) FROM users u LIMIT 10",
    "SELECT json_agg(u) FROM users AS u LIMIT 1",
    "SELECT json_agg(email) FROM users LIMIT 10",
    "SELECT jsonb_agg(u) FROM users u LIMIT 10",
    "SELECT json_agg(u.*) FROM users u LIMIT 10",
    "SELECT id, (SELECT json_agg(u) FROM users u) FROM t LIMIT 3",
    "SELECT json_agg(u) FROM (SELECT * FROM users) u LIMIT 10",
])
def test_h4b_row_folding_aggregate_blocked_with_limit(sql):
    v = check_sql(sql, SqlPolicy(max_rows=50, dialect="postgres"))
    assert not v.allowed and "aggregate" in v.reason, (sql, v.reason)


@pytest.mark.parametrize("sql", [
    "SELECT COUNT(*) FROM users",
    "SELECT MAX(id), MIN(id), SUM(id), AVG(id) FROM users",
    "SELECT * FROM users LIMIT 50",
    "SELECT * FROM users LIMIT 5 OFFSET 10",
    "SELECT * FROM users FETCH FIRST 5 ROWS ONLY",
    "SELECT * FROM users UNION SELECT * FROM users LIMIT 10",
    "(SELECT id FROM a) UNION (SELECT id FROM b) LIMIT 10",
    "SELECT * FROM (SELECT * FROM users) t LIMIT 5",
])
def test_h4_legitimate_queries_still_allowed(sql):
    assert check_sql(sql, PG).allowed, sql


def test_h4_rewrite_limit_clamps_set_operations_and_odd_limits():
    pol = SqlPolicy(max_rows=50, dialect="postgres", rewrite_limit=True)
    for sql in ("SELECT id FROM a UNION SELECT id FROM b", "SELECT * FROM users LIMIT 5*1000",
                "SELECT * FROM users LIMIT 99999"):
        v = check_sql(sql, pol)
        assert v.allowed and "LIMIT 50" in v.sql.upper(), (sql, v)
    assert check_sql("SELECT string_agg(email, ',') FROM users", pol).allowed is False


def test_h4_unparseable_limit_forms_fail_closed():
    assert not check_sql("SELECT * FROM users LIMIT (SELECT 1000000)", PG).allowed


# =============================== H5: dangerous functions in a "read-only" SELECT ==================================

@pytest.mark.parametrize("sql,dialect", [
    ("SELECT pg_read_file('/etc/passwd') LIMIT 1", "postgres"),
    ("SELECT pg_catalog.pg_read_file('/etc/passwd') LIMIT 1", "postgres"),
    ("SELECT PG_READ_BINARY_FILE('/x') LIMIT 1", "postgres"),
    ("SELECT pg_ls_dir('/') LIMIT 1", "postgres"),
    ("SELECT lo_import('/etc/passwd') LIMIT 1", "postgres"),
    ("SELECT lo_export(1, '/tmp/x') LIMIT 1", "postgres"),
    ("SELECT * FROM dblink('host=evil','select 1') AS t(x int) LIMIT 1", "postgres"),
    ("SELECT dblink_exec('host=evil','drop table x') LIMIT 1", "postgres"),
    ("SELECT set_config('role','admin',false) LIMIT 1", "postgres"),
    ("SELECT nextval('s') LIMIT 1", "postgres"),
    ("SELECT setval('s', 1) LIMIT 1", "postgres"),
    ("SELECT pg_sleep(1000) LIMIT 1", "postgres"),
    ("SELECT pg_advisory_lock(1) LIMIT 1", "postgres"),
    ("SELECT pg_terminate_backend(1) LIMIT 1", "postgres"),
    ("SELECT pg_reload_conf() LIMIT 1", "postgres"),
    ("SELECT load_extension('evil') LIMIT 1", "sqlite"),
    ("SELECT readfile('/etc/passwd') LIMIT 1", "sqlite"),
    ("SELECT zeroblob(1000000000) LIMIT 1", "sqlite"),
    ("SELECT LOAD_FILE('/etc/passwd') LIMIT 1", "mysql"),
    ("SELECT SLEEP(100) LIMIT 1", "mysql"),
    ("SELECT BENCHMARK(100000000, MD5('a')) LIMIT 1", "mysql"),
    ("SELECT GET_LOCK('a', 100) LIMIT 1", "mysql"),
    ("SELECT * FROM read_csv('/etc/passwd') LIMIT 1", "duckdb"),
    ("SELECT * FROM read_parquet('/x.parquet') LIMIT 1", "duckdb"),
    ("SELECT * FROM users LIMIT 1 FOR UPDATE", "postgres"),
    ("SELECT * FROM users LIMIT 1 FOR SHARE", "postgres"),
])
def test_h5_dangerous_function_or_lock_blocked(sql, dialect):
    v = check_sql(sql, SqlPolicy(max_rows=50, dialect=dialect))
    assert not v.allowed, sql


@pytest.mark.parametrize("sql,dialect", [
    ("SELECT lower(email), coalesce(phone, 'x'), now(), length(name) FROM users LIMIT 5", "postgres"),
    ("SELECT upper(name), abs(id), round(score, 2), substr(name, 1, 3) FROM users LIMIT 5", "sqlite"),
    ("SELECT date_trunc('day', created_at), count(*) FROM users GROUP BY 1 LIMIT 5", "postgres"),
    ("SELECT CAST(id AS TEXT), json_extract(data, '$.a') FROM users LIMIT 5", "sqlite"),
])
def test_h5_ordinary_functions_still_allowed(sql, dialect):
    assert check_sql(sql, SqlPolicy(max_rows=50, dialect=dialect)).allowed, sql


def test_h5_extra_denied_functions_and_allow_list():
    pol = SqlPolicy(max_rows=50, dialect="postgres", extra_denied_functions=frozenset({"md5"}))
    assert not check_sql("SELECT md5(email) FROM users LIMIT 1", pol).allowed
    allow = SqlPolicy(max_rows=50, dialect="postgres", allowed_functions=frozenset({"lower", "count"}))
    assert check_sql("SELECT lower(email) FROM users LIMIT 1", allow).allowed
    v = check_sql("SELECT upper(email) FROM users LIMIT 1", allow)
    assert not v.allowed and "allow-list" in v.reason
    assert check_sql("SELECT count(*) FROM users", allow).allowed


def test_h5_function_check_does_not_depend_on_letter_case_or_quoting():
    assert not check_sql('SELECT "Pg_Read_File"(\'/x\') LIMIT 1', PG).allowed
    assert not check_sql("SELECT pg_catalog.PG_SLEEP(5) LIMIT 1", PG).allowed


# =============================== M1: tenant filter bypasses =======================================================

T = SqlPolicy(max_rows=50, require_filter_column="tenant_id")


@pytest.mark.parametrize("sql", [
    "SELECT * FROM orders WHERE tenant_id = 5 OR 1=1 LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = tenant_id LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = id LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = (SELECT max(tenant_id) FROM orders) LIMIT 10",
    "SELECT * FROM orders WHERE NOT tenant_id = 5 LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = 5 OR name = 'x' LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id <> 5 LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id > 0 LIMIT 10",
    "SELECT * FROM orders WHERE (tenant_id = 5 OR 1=1) AND id > 0 LIMIT 10",
    "SELECT * FROM orders WHERE id = 3 LIMIT 10",
    "SELECT * FROM orders o JOIN secrets s ON s.id = o.id WHERE s.name = 'x' LIMIT 10",
])
def test_m1_bypasses_blocked(sql):
    assert not check_sql(sql, T).allowed, sql


@pytest.mark.parametrize("sql", [
    "SELECT * FROM orders WHERE tenant_id = 5 LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = '5' AND id > 3 LIMIT 10",
    "SELECT * FROM orders o WHERE o.tenant_id = 5 LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id IN (5, 6) LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = 5 OR tenant_id = 6 LIMIT 10",
    "SELECT * FROM orders WHERE (tenant_id = 5) AND (status = 'x' OR status = 'y') LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = $1 LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = %s LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = :tid LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = ? LIMIT 10",
    "SELECT a.* FROM (SELECT * FROM orders WHERE tenant_id = 5) a LIMIT 10",
    "SELECT * FROM orders WHERE tenant_id = 5 UNION SELECT * FROM orders WHERE tenant_id = 5 LIMIT 10",
])
def test_m1_legitimate_filters_allowed(sql):
    # "$1" and "%s" placeholders are only understood by the postgres dialect (other dialects fail closed)
    dialect = "postgres" if ("$1" in sql or "%s" in sql) else None
    assert check_sql(sql, dataclasses.replace(T, dialect=dialect)).allowed, sql


def test_m1_union_branch_without_filter_is_blocked():
    sql = "SELECT * FROM orders WHERE tenant_id = 5 UNION SELECT * FROM orders LIMIT 10"
    assert not check_sql(sql, T).allowed
