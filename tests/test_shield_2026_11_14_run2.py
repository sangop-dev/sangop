"""Internal AI-assisted security review, 14 Nov 2026, second pass ("review 2"): C1, H4-H7, M1-M3, L1, L2.

Written before the fixes; every query is synthetic. C1 and H4 were confirmed by the reviewer on a throw-away local
PostgreSQL 16, H5-H7 on an in-memory DuckDB, M1 on a local MariaDB 10.11 (own sandboxes only).
"""
import sys
import time

import pytest

from sangop.sqlguard import SqlPolicy, check_sql

PG_AND_NONE = ["postgres", None]
DUCK_AND_NONE = ["duckdb", None]


# ---- C1 (CRITICAL): functions that WRITE inside a plain SELECT -------------------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT lo_creat(-1) LIMIT 1",
    "SELECT count(lo_creat(-1)) FROM generate_series(1,10)",
    "SELECT pg_logical_emit_message(true, 'x', 'y') LIMIT 1",
    "SELECT txid_current() LIMIT 1",
])
def test_c1_writing_functions_are_denied(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("func", ["lo_creat", "lo_truncate", "lo_truncate64", "lo_lseek", "lo_lseek64", "lo_tell",
                                  "lo_close", "pg_logical_emit_message", "txid_current", "pg_current_xact_id"])
def test_c1_names_are_on_the_deny_list(func):
    from sangop.sqlguard import DEFAULT_DENIED_FUNCTIONS
    assert func in DEFAULT_DENIED_FUNCTIONS


# ---- H4: PostgreSQL attribute notation: u.json_agg is json_agg(u) ----------------------------------------------------
@pytest.mark.parametrize("dialect", [None, "postgres", "mysql", "duckdb", "sqlite"])
@pytest.mark.parametrize("sql", [
    "SELECT u.json_agg FROM users u LIMIT 1",
    "SELECT users.jsonb_agg FROM users LIMIT 1",
    "SELECT (u).array_agg FROM users u LIMIT 1",
    "SELECT (SELECT x.json_agg FROM users x) FROM orders LIMIT 1",
    "SELECT u.jsonb_object_agg_unique_strict FROM users u LIMIT 1",
])
def test_h4_attribute_notation_aggregates_are_row_folding(sql, dialect):
    try:
        v = check_sql(sql, SqlPolicy(dialect=dialect))
    except Exception as e:                        # pragma: no cover - check_sql never raises
        pytest.fail(repr(e))
    assert v.allowed is False
    if "unparseable" not in v.reason:             # a dialect may refuse (u).x; that is a block too
        assert "row-folding" in v.reason


@pytest.mark.parametrize("sql", [
    "SELECT tag_aggregate_count FROM orders WHERE tenant_id = 5 LIMIT 20",     # Shield's own false-positive case
    "SELECT o.aggregate_id, o.total FROM orders o WHERE o.tenant_id = 5 LIMIT 20",
])
def test_h4_ordinary_columns_with_agg_inside_stay_allowed(sql):
    v = check_sql(sql, SqlPolicy(max_rows=50, dialect="postgres", require_filter_column="tenant_id"))
    assert v.allowed is True, v.reason


# ---- H5: DuckDB / PostgreSQL top-N and multi-value aggregates ----------------------------------------------------------
@pytest.mark.parametrize("dialect", DUCK_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT max(email, 1000) FROM users",
    "SELECT min(email, 1000) FROM users",
    "SELECT arg_max(email, id, 1000) FROM users",
    "SELECT arg_min(email, id, 1000) FROM users",
    "SELECT max_by(email, id, 1000) FROM users",
    "SELECT min_by(email, id, 1000) FROM users",
    "SELECT approx_top_k(email, 1000) FROM users",
    "SELECT quantile_disc(id, [0, 0.5, 1]) FROM users",
])
def test_h5_duckdb_top_n_aggregates_are_row_folding(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert "row-folding" in v.reason or "unparseable" in v.reason


def test_h5_percentile_with_an_array_is_row_folding():
    v = check_sql("SELECT percentile_disc(ARRAY[0,0.5,1]) WITHIN GROUP (ORDER BY email) FROM users",
                  SqlPolicy(dialect="postgres"))
    assert v.allowed is False and "row-folding" in v.reason


@pytest.mark.parametrize("sql, dialect", [
    ("SELECT max(total) FROM orders WHERE tenant_id = 5", "duckdb"),
    ("SELECT max(total) FROM orders WHERE tenant_id = 5", None),
    ("SELECT min(total), max(total) FROM orders WHERE tenant_id = 5", "postgres"),
    ("SELECT arg_max(id, total) FROM orders WHERE tenant_id = 5", "duckdb"),
    ("SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY total) FROM orders WHERE tenant_id = 5", "postgres"),
    ("SELECT quantile_disc(total, 0.5) FROM orders WHERE tenant_id = 5", "duckdb"),
])
def test_h5_single_value_aggregates_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


# ---- H6: run a query or a table given as text ---------------------------------------------------------------------
@pytest.mark.parametrize("dialect", DUCK_AND_NONE)
@pytest.mark.parametrize("sql, extra", [
    ("SELECT * FROM query_table('users') LIMIT 1", {"denied_tables": frozenset({"users"})}),
    ("SELECT * FROM query('SELECT 1') LIMIT 1", {}),
])
def test_h6_query_and_query_table_are_denied(sql, extra, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect, **extra))
    assert v.allowed is False and "denied function" in v.reason


# ---- H7: DuckDB functions that read files, other databases or metadata ---------------------------------------------
H7_NAMES = ["read_json_objects", "read_ndjson_objects", "read_json_objects_auto", "read_ndjson_auto", "sqlite_scan",
            "sqlite_attach", "parquet_metadata", "parquet_schema", "parquet_file_metadata", "parquet_kv_metadata",
            "iceberg_scan", "delta_scan", "st_read", "postgres_scan", "postgres_query", "mysql_query"]


@pytest.mark.parametrize("dialect", DUCK_AND_NONE)
@pytest.mark.parametrize("func", H7_NAMES)
def test_h7_file_and_database_readers_are_denied(func, dialect):
    v = check_sql(f"SELECT * FROM {func}('/x') LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("dialect", DUCK_AND_NONE)
@pytest.mark.parametrize("func", ["read_future_format", "read_x", "future_db_scan", "x_scan"])
def test_h7_any_read_or_scan_name_is_denied_in_duckdb_and_generic(func, dialect):
    v = check_sql(f"SELECT * FROM {func}('/x') LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied function" in v.reason


# ---- M1: comment spellings that differ between the generic reading (dialect=None) and MySQL ---------------------------
@pytest.mark.parametrize("sql", [
    "SELECT id FROM orders WHERE tenant_id = 5 --1 OR 1=1\nLIMIT 1",
    "SELECT id /* /* */ , (SELECT group_concat(email) FROM users) -- */\nFROM orders WHERE tenant_id = 5 LIMIT 1",
])
def test_m1_ambiguous_comments_are_blocked_in_the_generic_dialect(sql):
    v = check_sql(sql, SqlPolicy(max_rows=50, require_filter_column="tenant_id"))
    assert v.allowed is False


def test_m1_an_ordinary_line_comment_stays_allowed():
    v = check_sql("SELECT id FROM orders WHERE tenant_id = 5 -- note\nLIMIT 1",
                  SqlPolicy(max_rows=50, require_filter_column="tenant_id"))
    assert v.allowed is True, v.reason


# ---- M2: Oracle cursor / multiset and network or metadata packages -----------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT CURSOR(SELECT * FROM users) FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT CAST(MULTISET(SELECT email FROM users) AS sys.odcivarchar2list) FROM dual FETCH FIRST 1 ROWS ONLY",
])
def test_m2_oracle_cursor_and_multiset_are_row_folding(sql):
    v = check_sql(sql, SqlPolicy(dialect="oracle"))
    assert v.allowed is False and "row-folding" in v.reason


@pytest.mark.parametrize("sql", [
    "SELECT HTTPURITYPE('http://192.0.2.1/').getclob() FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT UTL_INADDR.get_host_address('example.invalid') FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT DBMS_LDAP.init('example.invalid', 389) FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT XMLGEN.getxml('SELECT * FROM users') FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT DBMS_METADATA.get_ddl('TABLE','USERS') FROM dual FETCH FIRST 1 ROWS ONLY",
])
def test_m2_oracle_network_and_metadata_packages_are_denied(sql):
    v = check_sql(sql, SqlPolicy(dialect="oracle"))
    assert v.allowed is False and "denied function" in v.reason


# ---- M3: credentials in a catalog view; extensions that schedule jobs or call the network --------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
def test_m3_user_mapping_options_is_denied(dialect):
    v = check_sql("SELECT * FROM information_schema.user_mapping_options LIMIT 5", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied table" in v.reason


@pytest.mark.parametrize("sql", [
    "SELECT cron.schedule('x', '* * * * *', 'DELETE FROM users') LIMIT 1",
    "SELECT net.http_post(url := 'https://example.invalid', body := '{}'::jsonb) LIMIT 1",
    "SELECT http_get('https://example.invalid') LIMIT 1",
    "SELECT http_post('https://example.invalid', 'x', 'text/plain') LIMIT 1",
    "SELECT http(('GET', 'https://example.invalid', NULL, NULL, NULL)::http_request) LIMIT 1",
    "SELECT aws_s3.query_export_to_s3('SELECT * FROM users', 'b') LIMIT 1",
])
def test_m3_extension_packages_are_denied(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is False
    assert "denied function" in v.reason or "unparseable" in v.reason


# ---- L1: very long SQL is refused quickly -----------------------------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT id FROM t WHERE a IN (" + ",".join(str(i) for i in range(160000)) + ") LIMIT 1",
    "SELECT 1 /*" + "x" * 1_000_000 + "*/ LIMIT 1",
    "SELECT '" + "a" * 1_000_000 + "' LIMIT 1",
])
def test_l1_sql_over_100_kb_is_blocked_fast(sql):
    start = time.perf_counter()
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    # Windows CI and laptops are much slower; the Linux limit stays the real gate.
    assert time.perf_counter() - start < 0.1 * (3 if sys.platform == "win32" else 1)
    assert v.allowed is False and v.reason == "query too long (blocked)"


def test_l1_sql_just_under_the_limit_is_judged_normally():
    sql = "SELECT id FROM t WHERE a IN (" + ",".join("1" for _ in range(40000)) + ") LIMIT 1"
    assert len(sql.encode("utf-8")) < 100 * 1024
    assert check_sql(sql, SqlPolicy(dialect="postgres")).reason != "query too long (blocked)"


# ---- L2: more advisory locks and locking hints ------------------------------------------------------------------------
@pytest.mark.parametrize("func", ["pg_try_advisory_xact_lock", "pg_advisory_xact_lock_shared",
                                  "pg_try_advisory_lock_shared", "pg_try_advisory_xact_lock_shared"])
def test_l2_advisory_lock_variants_are_denied(func):
    v = check_sql(f"SELECT {func}(1) LIMIT 1", SqlPolicy(dialect="postgres"))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("sql", [
    "SELECT TOP 1 * FROM users WITH (PAGLOCK)",
    "SELECT TOP 1 * FROM users WITH (TABLOCK)",
    "SELECT TOP 1 * FROM users WITH (TABLOCK, HOLDLOCK)",
    "SELECT TOP 1 * FROM users WITH (SERIALIZABLE)",
    "SELECT TOP 1 * FROM users WITH (REPEATABLEREAD)",
    "SELECT TOP 1 * FROM users (UPDLOCK)",                 # old-style hint without WITH (sqlglot 28.5 reads it as a call)
    "SELECT TOP 1 * FROM users (TABLOCKX)",
])
def test_l2_more_tsql_locking_hints_are_blocked(sql):
    v = check_sql(sql, SqlPolicy(dialect="tsql"))
    assert v.allowed is False
    assert "row-locking" in v.reason or "unparseable" in v.reason


@pytest.mark.parametrize("sql", ["SELECT TOP 20 id FROM dbo.orders WITH (NOLOCK) WHERE tenant_id = 5",
                                 "SELECT TOP 1 * FROM users WITH (READPAST)"])
def test_l2_non_locking_tsql_hints_stay_allowed(sql):
    v = check_sql(sql, SqlPolicy(dialect="tsql"))
    assert v.allowed is True, v.reason


# ---- a false positive introduced on 14 Nov (review 1, M1) and found by review 2's false-positive list -----------------------------
def test_bigquery_wildcard_table_is_not_a_file_path():
    v = check_sql("SELECT event FROM `proj.analytics.events_*` WHERE tenant_id = 5 LIMIT 20",
                  SqlPolicy(max_rows=50, dialect="bigquery", require_filter_column="tenant_id"))
    assert v.allowed is True, v.reason
