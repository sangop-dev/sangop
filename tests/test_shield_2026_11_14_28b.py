"""SQL guard additions of 14 Nov 2026 (after review 2): SQLite virtual tables and pragma functions, unicode-escaped
names, more PostgreSQL side-effect / network / state functions, pg_stats, and the MySQL "--1" reading.
Written before the fixes; synthetic queries only."""
import pytest

from sangop import sqlguard
from sangop.sqlguard import SqlPolicy, check_sql

SQLITE_AND_NONE = ["sqlite", None]
PG_AND_NONE = ["postgres", None]
ALL_DIALECTS = [None, "postgres", "sqlite", "mysql", "duckdb", "tsql", "oracle"]


# ---- MySQL / MariaDB: "--1" is minus-minus-1, not a comment (founder's decision, 14 Nov 2026) --------------------------
# sqlglot has no separate MariaDB dialect; MariaDB users set dialect="mysql".
@pytest.mark.parametrize("sql", [
    "SELECT id FROM orders WHERE tenant_id = 5 --1 OR 1=1\nLIMIT 1",
    "SELECT id --1, (SELECT GROUP_CONCAT(email) FROM users)\nFROM orders WHERE tenant_id = 5 LIMIT 1",
    "SELECT id FROM orders LIMIT 1 --1, 100\n",
])
def test_mysql_dash_dash_without_space_is_blocked(sql):
    v = check_sql(sql, SqlPolicy(max_rows=50, dialect="mysql", require_filter_column="tenant_id",
                                 allowed_tables=frozenset({"orders"})))
    assert v.allowed is False
    assert v.reason.startswith("'--' without a following space")     # the rule itself, not a later check


@pytest.mark.parametrize("sql", ["SELECT id FROM orders WHERE tenant_id = 5 -- latest\nLIMIT 20",
                                 "SELECT id FROM orders WHERE tenant_id = 5 # latest\nLIMIT 20"])
def test_mysql_ordinary_comments_stay_allowed(sql):
    v = check_sql(sql, SqlPolicy(max_rows=50, dialect="mysql", require_filter_column="tenant_id"))
    assert v.allowed is True, v.reason


# ---- G1: SQLite row-folding names without "agg" -----------------------------------------------------------------------
@pytest.mark.parametrize("dialect", SQLITE_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT jsonb_group_array(email) FROM users LIMIT 1",
    "SELECT jsonb_group_object(id, email) FROM users LIMIT 1",
    "SELECT json_group_array(email) FROM users LIMIT 1",
    "SELECT future_group_array(email) FROM users LIMIT 1",
    "SELECT future_group_object(id, email) FROM users LIMIT 1",
])
def test_g1_group_array_and_group_object_are_row_folding(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "row-folding" in v.reason


# ---- G2: SQLite virtual tables, pragma functions and file readers -----------------------------------------------------
@pytest.mark.parametrize("dialect", SQLITE_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT pgno, hex(data) FROM sqlite_dbpage LIMIT 50",
    "SELECT * FROM dbstat LIMIT 5",
    "SELECT * FROM pragma_integrity_check LIMIT 1",
    "SELECT * FROM pragma_database_list LIMIT 5",
    "SELECT * FROM pragma_future_thing('x') LIMIT 5",
    "SELECT * FROM fsdir('/') LIMIT 5",
    "SELECT * FROM zipfile('/x.zip') LIMIT 5",
    "SELECT * FROM csv('/x.csv') LIMIT 5",
    "SELECT lsmode(493) LIMIT 1",
    "SELECT * FROM sqlite_stat1 LIMIT 5",
])
def test_g2_sqlite_virtual_tables_and_pragmas_are_denied(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert "denied function" in v.reason or "denied table" in v.reason


@pytest.mark.parametrize("dialect", SQLITE_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT name FROM sqlite_master LIMIT 50",
    "SELECT name FROM sqlite_schema LIMIT 50",
    "SELECT name FROM sqlite_temp_master LIMIT 50",
    "SELECT name FROM sqlite_temp_schema LIMIT 50",
    "SELECT * FROM pragma_table_info('users') LIMIT 50",
    "SELECT * FROM pragma_table_xinfo('users') LIMIT 50",
    "SELECT * FROM pragma_index_list('users') LIMIT 50",
    "SELECT * FROM pragma_index_info('users_email') LIMIT 50",
    "SELECT * FROM pragma_foreign_key_list('orders') LIMIT 50",
])
def test_g2_schema_discovery_stays_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_g2_exception_lists():
    assert sqlguard.SQLITE_SCHEMA_TABLES == frozenset({"sqlite_master", "sqlite_schema", "sqlite_temp_master",
                                                       "sqlite_temp_schema"})
    assert sqlguard.SQLITE_SCHEMA_PRAGMAS == frozenset({"pragma_table_info", "pragma_table_xinfo", "pragma_index_list",
                                                        "pragma_index_info", "pragma_foreign_key_list"})


@pytest.mark.parametrize("func", ["fsdir", "zipfile", "csv", "lsmode"])
def test_g2_file_readers_are_on_the_deny_list(func):
    assert func in sqlguard.DEFAULT_DENIED_FUNCTIONS


# ---- G3: unicode-escaped names and strings (every dialect, before parsing) ---------------------------------------------
@pytest.mark.parametrize("dialect", ALL_DIALECTS)
@pytest.mark.parametrize("sql", [
    'SELECT U&"pg\\005fsleep"(10) LIMIT 1',
    'SELECT u&"pg\\005fsleep"(10) LIMIT 1',
    "SELECT U&'\\0041' AS x LIMIT 1",
    "SELECT id FROM U&\"us\\0065rs\" LIMIT 1",
])
def test_g3_unicode_escaped_names_are_blocked(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert v.reason == "unicode-escaped identifier/string blocked (fail-closed)"


# ---- G4: PostgreSQL side-effect, network and state functions -------------------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT pg_export_snapshot() LIMIT 1",
    "SELECT pg_stat_clear_snapshot() LIMIT 1",
    "SELECT pg_stat_get_activity(NULL) LIMIT 1",
    "SELECT * FROM pg_stat_get_activity(NULL) LIMIT 1",
    "SELECT postgres_fdw_disconnect_all() LIMIT 1",
    "SELECT * FROM postgres_fdw_get_connections() LIMIT 1",
    "SELECT postgres_fdw_future_fn() LIMIT 1",
    "SELECT http_get('http://x') LIMIT 1",
    "SELECT http_put('http://x', 'a', 'b') LIMIT 1",
    "SELECT http('x') LIMIT 1",
    "SELECT http_set_curlopt('a', 'b') LIMIT 1",
    "SELECT http_future_verb('http://x') LIMIT 1",
    "SELECT net.http_post('http://x', '{}'::jsonb) LIMIT 1",
    "SELECT net.http_get('http://x') LIMIT 1",
    "SELECT cron.unschedule(1) LIMIT 1",
    "SELECT aws_s3.table_import_from_s3('t', '', '(format csv)', 'b', 'k', 'r') LIMIT 1",
])
def test_g4_side_effect_network_and_state_functions_are_denied(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert "denied function" in v.reason or "unparseable" in v.reason


@pytest.mark.parametrize("sql", ["SELECT httpstatus FROM requests WHERE tenant_id = 5 LIMIT 20",
                                 "SELECT id FROM orders WHERE tenant_id = 5 AND url LIKE 'http%' LIMIT 20"])
def test_g4_columns_and_strings_with_http_stay_allowed(sql):
    v = check_sql(sql, SqlPolicy(max_rows=50, dialect="postgres", require_filter_column="tenant_id"))
    assert v.allowed is True, v.reason


# ---- G5: pg_stats shows real column values (most_common_vals, histogram_bounds) -------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("table", ["pg_stats", "pg_catalog.pg_stats", "pg_stats_ext", "pg_stats_ext_exprs"])
def test_g5_pg_stats_is_denied(table, dialect):
    sql = f"SELECT tablename, most_common_vals FROM {table} WHERE tablename = 'users' LIMIT 50"
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied table" in v.reason


def test_g5_pg_stats_is_not_an_exception():
    assert "pg_stats" not in sqlguard.PG_SCHEMA_TABLES
