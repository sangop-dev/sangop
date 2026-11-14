"""Internal AI-assisted security review, 14 Nov 2026, third pass ("review 3"): N1-N3, M1-M3, L1, L2.

Written before the fixes; every query is synthetic. N1 was confirmed by the reviewer on a throw-away local
PostgreSQL 16 with tablefunc / xml2, N2 and N3 on an in-memory DuckDB (own sandboxes only).
"""
import pytest

from sangop import sqlguard
from sangop.sqlguard import SqlPolicy, check_sql

PG_AND_NONE = ["postgres", None]
DUCK_AND_NONE = ["duckdb", None]


# ---- N1 (HIGH): PostgreSQL contrib functions that run a query or a table given as text -------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT * FROM crosstab('SELECT email, 1, email FROM users') AS t(a text, b text) LIMIT 5",
    "SELECT * FROM crosstab3('SELECT 1') AS t(a text, b text, c text, d text) LIMIT 1",
    "SELECT * FROM connectby('users', 'id', 'id', '1', 0) AS t(a int, b int, c int) LIMIT 1",
    "SELECT * FROM xpath_table('id', 'x', 'users', '/a', 'true') AS t(id int, x text) LIMIT 1",
    "SELECT * FROM crosstab_future('x') AS t(a text) LIMIT 1",
    "SELECT xslt_process('<a/>', '<xsl/>') LIMIT 1",
])
def test_n1_text_running_contrib_functions_are_denied(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect, denied_tables=frozenset({"users"})))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("func", ["crosstab", "crosstab2", "crosstab3", "crosstab4", "crosstab_hash", "connectby",
                                  "xpath_table", "xslt_process"])
def test_n1_names_on_the_deny_list(func):
    assert func in sqlguard.DEFAULT_DENIED_FUNCTIONS


# ---- N2 (HIGH): DuckDB serialized-SQL execution --------------------------------------------------------------------------
@pytest.mark.parametrize("dialect", DUCK_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT * FROM json_execute_serialized_sql(json_serialize_sql('SELECT 1')) LIMIT 1",
    "SELECT json_serialize_sql('SELECT 1') LIMIT 1",
    "SELECT json_deserialize_sql('x') LIMIT 1",
    "SELECT json_serialize_plan('SELECT 1') LIMIT 1",
    "SELECT future_execute_fn('x') LIMIT 1",
    "SELECT future_serialize_fn('x') LIMIT 1",
])
def test_n2_duckdb_serialized_sql_is_denied(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied function" in v.reason


# ---- N3 (HIGH): dynamic PIVOT folds a whole column into one row -----------------------------------------------------------
def test_n3_duckdb_pivot_without_an_in_list_is_row_folding():
    v = check_sql("SELECT * FROM (PIVOT (SELECT email FROM users) ON email USING count(*)) LIMIT 1",
                  SqlPolicy(dialect="duckdb"))
    assert v.allowed is False and "row-folding" in v.reason


def test_n3_duckdb_pivot_is_row_folding_even_with_a_strict_policy():
    v = check_sql("SELECT * FROM (PIVOT (SELECT email FROM users WHERE tenant_id = 1) ON email USING count(*)) LIMIT 1",
                  SqlPolicy(dialect="duckdb", require_filter_column="tenant_id", allowed_tables=frozenset({"users"}),
                            max_rows=1))
    assert v.allowed is False and "row-folding" in v.reason


@pytest.mark.parametrize("sql", [
    "SELECT * FROM users PIVOT(count(id) FOR email IN (ANY ORDER BY email)) LIMIT 1",
    "SELECT * FROM users PIVOT(count(id) FOR email IN (SELECT email FROM users)) LIMIT 1",
])
def test_n3_snowflake_dynamic_pivot_is_row_folding(sql):
    v = check_sql(sql, SqlPolicy(dialect="snowflake"))
    assert v.allowed is False and "row-folding" in v.reason


@pytest.mark.parametrize("sql, dialect", [
    ("SELECT TOP 1 * FROM users PIVOT(count(id) FOR email IN ([a],[b])) p", "tsql"),
    ("SELECT * FROM users PIVOT(count(id) FOR email IN ('a', 'b')) LIMIT 1", "snowflake"),
    ("SELECT * FROM users PIVOT (count(id) FOR email IN ('a', 'b')) LIMIT 1", "databricks"),
    ("SELECT * FROM (PIVOT users ON status IN ('open', 'closed') USING count(*)) LIMIT 1", "duckdb"),
    ("SELECT * FROM users UNPIVOT (v FOR k IN (a, b)) LIMIT 1", "snowflake"),
])
def test_n3_literal_pivot_and_unpivot_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


# ---- M1 (MEDIUM): PostgreSQL-family and MySQL-family dialects --------------------------------------------------------------
@pytest.mark.parametrize("dialect", ["redshift", "materialize", "risingwave"])
@pytest.mark.parametrize("sql, word", [
    ("SELECT * FROM pg_user LIMIT 1", "denied table"),
    ("SELECT pg_read_file('x') LIMIT 1", "denied function"),
    ("SELECT pg_future_fn() LIMIT 1", "denied function"),
    ("SELECT lo_creat(-1) LIMIT 1", "denied function"),
    ("SELECT * FROM crosstab('x') AS t(a int) LIMIT 1", "denied function"),
    ("SELECT http_get('http://x') LIMIT 1", "denied function"),
])
def test_m1_postgres_family_rules_apply_to_postgres_like_dialects(sql, word, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert word in v.reason or "unparseable" in v.reason


@pytest.mark.parametrize("dialect", ["doris", "starrocks", "singlestore"])
def test_m1_dash_dash_rule_applies_to_mysql_like_dialects(dialect):
    v = check_sql("SELECT id FROM orders WHERE tenant_id = 5 --1 OR 1=1\nLIMIT 10",
                  SqlPolicy(dialect=dialect, require_filter_column="tenant_id"))
    assert v.allowed is False
    assert v.reason.startswith("'--' without a following space")


@pytest.mark.parametrize("dialect", ["redshift", "doris"])
def test_m1_ordinary_queries_stay_allowed_in_those_dialects(dialect):
    v = check_sql("SELECT id FROM orders WHERE tenant_id = 5 -- note\nLIMIT 10",
                  SqlPolicy(dialect=dialect, require_filter_column="tenant_id"))
    assert v.allowed is True, v.reason


# ---- M2 (MEDIUM): page inspection and maintenance functions ---------------------------------------------------------------
@pytest.mark.parametrize("call", ["get_raw_page('users', 0)", "bt_page_items('users_pkey', 1)", "bt_metap('users_pkey')",
                                  "heap_page_items(get_raw_page('users', 0))", "page_header(get_raw_page('users', 0))",
                                  "pgstattuple('users')", "pgstattuple_approx('users')", "pgstatindex('users_pkey')",
                                  "pgrowlocks('users')", "brin_summarize_new_values('i')", "brin_summarize_range('i', 0)",
                                  "brin_desummarize_range('i', 0)", "gin_clean_pending_list('i')"])
@pytest.mark.parametrize("form", ["SELECT {c} LIMIT 1", "SELECT * FROM {c} LIMIT 1"])
def test_m2_page_and_maintenance_functions_are_denied(call, form):
    v = check_sql(form.format(c=call), SqlPolicy(dialect="postgres"))
    assert v.allowed is False and "denied function" in v.reason


# ---- M3 (MEDIUM): system views with other sessions' SQL text or credentials ------------------------------------------------
@pytest.mark.parametrize("sql, dialect", [
    ("SELECT * FROM information_schema.processlist LIMIT 5", "mysql"),
    ("SELECT * FROM performance_schema.events_statements_current LIMIT 5", "mysql"),
    ("SELECT * FROM performance_schema.events_statements_history LIMIT 5", "mysql"),
    ("SELECT * FROM performance_schema.events_statements_history_long LIMIT 5", "mysql"),
    ("SELECT * FROM sys.statement_analysis LIMIT 5", "mysql"),
    ("SELECT user, authentication_string FROM mysql.user LIMIT 5", "mysql"),
    ("SELECT TOP 5 * FROM sys.sql_logins", "tsql"),
    ("SELECT TOP 5 * FROM sys.sysxlogins", "tsql"),
    ("SELECT TOP 5 * FROM sys.dm_exec_requests", "tsql"),
    ("SELECT TOP 5 * FROM sys.dm_exec_sessions", "tsql"),
    ("SELECT TOP 5 * FROM sys.dm_exec_sql_text", "tsql"),
])
def test_m3_system_views_are_denied(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied table" in v.reason


def test_m3_dm_exec_sql_text_as_a_function_is_denied():
    """Also a table-valued function (CROSS APPLY sys.dm_exec_sql_text(handle)); a table entry alone misses that form."""
    v = check_sql("SELECT TOP 5 t.text FROM sys.dm_exec_sql_text(0x01) AS t", SqlPolicy(dialect="tsql"))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("sql, dialect", [
    ("SELECT id, name FROM user WHERE tenant_id = 5 LIMIT 5", "mysql"),           # bare "user" is a common table name
    ("SELECT id, name FROM app.user WHERE tenant_id = 5 LIMIT 5", "mysql"),
    ('SELECT id FROM "user" WHERE tenant_id = 5 LIMIT 5', "postgres"),
])
def test_m3_an_application_table_called_user_stays_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect, require_filter_column="tenant_id"))
    assert v.allowed is True, v.reason


# ---- L1, L2 (LOW) --------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("sql", ["SELECT * FROM duckdb_secrets() LIMIT 5", "SELECT * FROM duckdb_settings() LIMIT 5",
                                 "SELECT which_secret('s3://b/k', 's3') LIMIT 1"])
def test_l1_duckdb_secret_and_settings_functions_are_denied(sql):
    v = check_sql(sql, SqlPolicy(dialect="duckdb"))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("call", ["source_pos_wait('f', 4, 1)", "wait_for_executed_gtid_set('x', 1)",
                                  "wait_until_sql_thread_after_gtids('x', 1)"])
def test_l2_mysql_replication_waits_are_denied(call):
    v = check_sql(f"SELECT {call} LIMIT 1", SqlPolicy(dialect="mysql"))
    assert v.allowed is False and "denied function" in v.reason
