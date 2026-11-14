"""Whole-family rules for the SQL guard (14 Nov 2026, D-115): new PostgreSQL and SQLite system functions and tables are
blocked by default instead of waiting for someone to list them. Written before the rules; synthetic queries only."""
import pytest

from sangop import sqlguard
from sangop.sqlguard import SqlPolicy, check_sql

PG_AND_NONE = ["postgres", None]
SQLITE_AND_NONE = ["sqlite", None]


# ---- B1: PostgreSQL function families pg_* / lo_* / txid_* / dblink* -------------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("func", ["pg_logical_emit_message(true, 'x', 'y')", "pg_current_xact_id()", "lo_creat(-1)",
                                  "lo_truncate(0, 0)", "txid_current()", "pg_future_write_fn()", "lo_future_fn(1)",
                                  "txid_future_fn()", "dblink_future_fn('x')", "pg_stat_reset()", "pg_promote()",
                                  "pg_get_viewdef('users')"])
def test_b1_postgres_function_families_are_denied(func, dialect):
    v = check_sql(f"SELECT {func} LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", ["SELECT pg_typeof(id) FROM orders LIMIT 1",
                                 "SELECT pg_size_pretty(1024::bigint) LIMIT 1",
                                 "SELECT pg_column_size(total) FROM orders LIMIT 1"])
def test_b1_named_harmless_functions_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_b1_the_exception_list_is_exactly_the_three_named_functions():
    assert sqlguard.PG_HARMLESS_FUNCTIONS == frozenset({"pg_typeof", "pg_size_pretty", "pg_column_size"})


def test_b1_family_rule_does_not_apply_to_other_dialects():
    """A MySQL or SQL Server database has no pg_* functions; the rule is for PostgreSQL and the generic reading."""
    assert check_sql("SELECT pg_future_write_fn() LIMIT 1", SqlPolicy(dialect="mysql")).allowed is True


# ---- B2: PostgreSQL system tables ----------------------------------------------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("table", ["pg_stat_statements", "pg_stat_statements_info", "pg_stat_replication", "pg_roles",
                                   "pg_catalog.pg_proc", "pg_largeobject", "pg_future_view",
                                   "information_schema.user_mapping_options"])
def test_b2_postgres_system_tables_are_denied(table, dialect):
    v = check_sql(f"SELECT * FROM {table} LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied table" in v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("table", ["pg_tables", "pg_views", "pg_indexes", "pg_class", "pg_namespace", "pg_attribute",
                                   "pg_type", "pg_catalog.pg_tables", "information_schema.columns",
                                   "information_schema.tables", "information_schema.views"])
def test_b2_schema_discovery_tables_stay_allowed(table, dialect):
    v = check_sql(f"SELECT * FROM {table} LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_b2_names_on_the_default_deny_list():
    assert {"pg_stat_statements", "pg_stat_statements_info", "user_mapping_options"} <= sqlguard.DEFAULT_DENIED_TABLES
    assert sqlguard.PG_SCHEMA_TABLES == frozenset({"pg_tables", "pg_views", "pg_indexes", "pg_class", "pg_namespace",
                                                   "pg_attribute", "pg_type"})


# ---- B3: SQLite sqlite_* family ------------------------------------------------------------------------------------
@pytest.mark.parametrize("dialect", SQLITE_AND_NONE)
@pytest.mark.parametrize("sql", ["SELECT sqlite_offset(id) FROM users LIMIT 1",
                                 "SELECT sqlite_future_fn() LIMIT 1",
                                 "SELECT * FROM sqlite_dbpage LIMIT 1",
                                 "SELECT load_extension('x') LIMIT 1",
                                 "SELECT readfile('/etc/hostname') LIMIT 1",
                                 "SELECT writefile('/tmp/x', 'y') LIMIT 1",
                                 "SELECT edit('x') LIMIT 1",
                                 "SELECT fts3_tokenizer('simple') LIMIT 1"])
def test_b3_sqlite_family_and_file_functions_are_denied(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert "denied function" in v.reason or "denied table" in v.reason


@pytest.mark.parametrize("dialect", SQLITE_AND_NONE)
@pytest.mark.parametrize("sql", ["SELECT sqlite_version() LIMIT 1", "SELECT sqlite_source_id() LIMIT 1",
                                 "SELECT sqlite_compileoption_used('ENABLE_FTS5') LIMIT 1",
                                 "SELECT name, sql FROM sqlite_master WHERE type = 'table' LIMIT 20",
                                 "SELECT name FROM sqlite_schema LIMIT 20"])
def test_b3_named_sqlite_functions_and_schema_tables_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_b3_exception_lists():
    assert sqlguard.SQLITE_HARMLESS_FUNCTIONS == frozenset({"sqlite_version", "sqlite_source_id",
                                                            "sqlite_compileoption_used"})
    assert sqlguard.SQLITE_SCHEMA_TABLES == frozenset({"sqlite_master", "sqlite_schema",   # + temp variants (G2)
                                                       "sqlite_temp_master", "sqlite_temp_schema"})


# ---- B5: ordinary queries stay allowed (false-positive list) -----------------------------------------------------------
ORDINARY = [
    "SELECT o.id, c.name FROM public.orders o JOIN public.customers c ON c.id = o.customer_id "
    "WHERE o.tenant_id = 5 AND c.tenant_id = 5 LIMIT 20",
    "SELECT o.id FROM orders o LEFT JOIN customers c ON c.id = o.customer_id "
    "WHERE o.tenant_id = 5 AND c.tenant_id = 5 LIMIT 20",
    "SELECT status, count(*) FROM orders WHERE tenant_id = 5 GROUP BY status ORDER BY status LIMIT 20",
    "SELECT count(*) FROM orders WHERE tenant_id = 5",
    "SELECT sum(total) FROM orders WHERE tenant_id = 5",
    "SELECT avg(total) FROM orders WHERE tenant_id = 5",
    "SELECT min(total) FROM orders WHERE tenant_id = 5",
    "SELECT max(total) FROM orders WHERE tenant_id = 5",
    "SELECT stddev(total) FROM orders WHERE tenant_id = 5",
    "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY total) FROM orders WHERE tenant_id = 5",
    "SELECT date_trunc('day', created_at) AS d, count(*) FROM orders WHERE tenant_id = 5 GROUP BY d ORDER BY d LIMIT 20",
    "SELECT coalesce(note, '') FROM orders WHERE tenant_id = 5 LIMIT 20",
    "SELECT lower(email) FROM customers WHERE tenant_id = 5 LIMIT 20",
    "SELECT id FROM orders WHERE tenant_id = 5 AND created_at > now() - interval '7 days' LIMIT 20",
    "SELECT pg_typeof(total) FROM orders WHERE tenant_id = 5 LIMIT 1",
]


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", ORDINARY)
def test_b5_ordinary_queries_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(max_rows=50, dialect=dialect, require_filter_column="tenant_id"))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
def test_b5_information_schema_columns_stays_allowed(dialect):
    sql = "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'orders' LIMIT 50"
    assert check_sql(sql, SqlPolicy(max_rows=50, dialect=dialect)).allowed is True


@pytest.mark.parametrize("sql", [
    "SELECT name FROM sqlite_master WHERE type = 'table' LIMIT 50",
    "SELECT lower(name), coalesce(note, '') FROM orders WHERE tenant_id = 5 ORDER BY id LIMIT 20",
    "SELECT strftime('%Y', created_at), count(*) FROM orders WHERE tenant_id = 5 GROUP BY 1 LIMIT 20",
])
def test_b5_ordinary_sqlite_queries_stay_allowed(sql):
    assert check_sql(sql, SqlPolicy(max_rows=50, dialect="sqlite")).allowed is True
