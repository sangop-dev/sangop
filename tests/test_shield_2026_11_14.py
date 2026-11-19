"""Internal AI-assisted security review, 14 Nov 2026 ("Shield"): SQL guard findings H1-H3, M1, L1, L2, L4.

Written before the fixes; every query is synthetic. Each case was confirmed by running it against the guard
(and, for H1-H3, by the reviewer on a throw-away local PostgreSQL 16 / MariaDB 10.11 sandbox).
"""
from pathlib import Path

import pytest
import sqlglot

from sangop import sqlguard
from sangop.sqlguard import SqlPolicy, check_sql

ROOT = Path(__file__).resolve().parent.parent
DIALECTS_ALL = ["mysql", "postgres", None]


# ---- H1: MySQL / MariaDB executable comments /*! ... */ and /*M! ... */ --------------------------------------
# MySQL and MariaDB RUN the text inside these comments; sqlglot drops it as a comment, so the guard never saw it.
EXECUTABLE_COMMENTS = [
    "SELECT id FROM users /*!50000 UNION SELECT k FROM secret */ LIMIT 1",
    "SELECT id FROM users LIMIT 1 /*!, 100 */",
    "SELECT 'x' AS q /*!, (SELECT GROUP_CONCAT(email) FROM users) */ LIMIT 1",
    "SELECT id FROM users LIMIT 1 /*!50000 INTO OUTFILE '/tmp/x' */",
    "SELECT id FROM users /*!50000 , LOAD_FILE('/etc/hostname') */ LIMIT 1",
    "SELECT id FROM users /*M! UNION SELECT k FROM secret */ LIMIT 1",
]


@pytest.mark.parametrize("dialect", DIALECTS_ALL)
@pytest.mark.parametrize("sql", EXECUTABLE_COMMENTS)
def test_h1_executable_comment_is_blocked(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect, allowed_tables=frozenset({"users"})))
    assert v.allowed is False
    assert "executable comment" in v.reason


@pytest.mark.parametrize("dialect", DIALECTS_ALL)
@pytest.mark.parametrize("sql", [
    "SELECT /*!*/ 1 AS a LIMIT 1",                 # empty executable comment: still blocked (fail-closed)
    "SELECT id FROM users /*m! UNION SELECT k FROM secret */ LIMIT 1",
])
def test_h1_other_spellings_are_blocked(sql, dialect):
    assert check_sql(sql, SqlPolicy(dialect=dialect)).allowed is False


@pytest.mark.parametrize("dialect", DIALECTS_ALL)
@pytest.mark.parametrize("sql", [
    "/* normal */ SELECT id FROM users LIMIT 1",
    "SELECT id FROM users LIMIT 1 -- note",
    "SELECT /*+ hint */ id FROM users LIMIT 1",           # an optimizer hint is not executed
    "SELECT /* ! not executable: space after the star */ id FROM users LIMIT 1",
])
def test_h1_ordinary_comments_and_hints_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_h1_marker_inside_a_string_literal_is_blocked_too():
    """Accepted false positive (fail-closed): the raw text is checked, not the parsed SQL."""
    assert check_sql("SELECT '/*!' AS x LIMIT 1", SqlPolicy()).allowed is False


# ---- H2: row-folding aggregates that were not in the list ------------------------------------------------------
NEW_FOLDING = [
    "json_agg_strict", "jsonb_agg_strict", "json_object_agg_strict", "jsonb_object_agg_strict",
    "json_object_agg_unique", "jsonb_object_agg_unique", "json_object_agg_unique_strict",
    "jsonb_object_agg_unique_strict", "range_agg", "range_intersect_agg",
]


@pytest.mark.parametrize("dialect", ["postgres", None])
@pytest.mark.parametrize("form", ["SELECT {f}(x) FROM users LIMIT 1", "SELECT (SELECT {f}(x) FROM users) LIMIT 1"])
@pytest.mark.parametrize("func", NEW_FOLDING)
def test_h2_row_folding_aggregates_are_blocked(func, form, dialect):
    v = check_sql(form.format(f=func), SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert "row-folding" in v.reason


@pytest.mark.parametrize("dialect", ["postgres", None])
@pytest.mark.parametrize("func", ["made_up_agg", "myagg", "x_agg_y", "MY_AGG"])
def test_h2_any_name_ending_in_agg_or_holding_underscore_agg_is_folding(func, dialect):
    v = check_sql(f"SELECT {func}(x) FROM users LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "row-folding" in v.reason


@pytest.mark.parametrize("dialect", ["postgres", None])
@pytest.mark.parametrize("expr", ["count(*)", "sum(x)", "avg(x)", "min(x)", "max(x)"])
def test_h2_ordinary_aggregates_stay_allowed(expr, dialect):
    v = check_sql(f"SELECT {expr} FROM users LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


# ---- H3: functions that run a table or a query given as text -----------------------------------------------------
TENANT = dict(allowed_tables=frozenset({"orders"}), require_filter_column="tenant_id")
TEXT_RUNNERS = [
    "table_to_xml_and_xmlschema('users', true, false, '')",
    "schema_to_xml_and_xmlschema('public', true, false, '')",
    "database_to_xml_and_xmlschema(true, false, '')",
    "table_to_xmlschema('users', true, false, '')",
    "schema_to_xmlschema('public', true, false, '')",
    "database_to_xmlschema(true, false, '')",
    "query_to_xmlschema('SELECT * FROM users', true, false, '')",
    "cursor_to_xmlschema('c', true, false, '')",
    "ts_rewrite('a'::tsquery, 'SELECT email::tsquery, ''x''::tsquery FROM users')",
    "ts_stat('SELECT to_tsvector(email) FROM users')",
]


@pytest.mark.parametrize("dialect", ["postgres", None])
@pytest.mark.parametrize("call", TEXT_RUNNERS)
def test_h3_text_running_functions_are_denied(call, dialect):
    v = check_sql(f"SELECT {call} FROM orders WHERE tenant_id = 1 LIMIT 1", SqlPolicy(dialect=dialect, **TENANT))
    assert v.allowed is False
    assert "denied function" in v.reason


@pytest.mark.parametrize("dialect", ["postgres", None])
def test_h3_ts_stat_in_from_is_denied(dialect):
    sql = "SELECT * FROM ts_stat('SELECT to_tsvector(email) FROM users') WHERE tenant_id = 1 LIMIT 1"
    v = check_sql(sql, SqlPolicy(dialect=dialect, **TENANT))
    assert v.allowed is False
    assert "denied function" in v.reason


# ---- M1: T-SQL FOR JSON / FOR XML, Oracle packages, DuckDB histogram and file paths ---------------------------
@pytest.mark.parametrize("sql", [
    "SELECT TOP 1 (SELECT * FROM users FOR JSON AUTO) AS x",
    "SELECT TOP 1 (SELECT email FROM users FOR XML PATH('')) AS x",
    "SELECT TOP 1 email FROM users FOR XML PATH('')",
])
def test_m1_tsql_for_json_and_for_xml_are_blocked(sql):
    v = check_sql(sql, SqlPolicy(dialect="tsql"))
    assert v.allowed is False
    assert "row-folding" in v.reason or "unparseable" in v.reason     # FOR JSON does not parse on sqlglot 28.x


@pytest.mark.parametrize("sql", [
    "SELECT CAST(COLLECT(email) AS sys.odcivarchar2list) FROM users FETCH FIRST 1 ROWS ONLY",
    "SELECT DBMS_XMLGEN.getxml('SELECT * FROM users') FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT DBMS_XMLQUERY.getxml('SELECT * FROM users') FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT dbms_xmlgen.getxmltype('SELECT * FROM users') FROM dual FETCH FIRST 1 ROWS ONLY",
])
def test_m1_oracle_collect_and_xml_packages_are_blocked(sql):
    assert check_sql(sql, SqlPolicy(dialect="oracle")).allowed is False


@pytest.mark.parametrize("sql", [
    # found while fixing M1: the package name sits outside the function in sqlglot's tree, so these packages,
    # already on the deny list, were not caught in their usual PACKAGE.function(...) form
    "SELECT UTL_HTTP.request('http://192.0.2.1/') FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT utl_file.fopen('d', 'f', 'r') FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT DBMS_PIPE.receive_message('p', 5) FROM dual FETCH FIRST 1 ROWS ONLY",
    "SELECT DBMS_LOCK.sleep(5) FROM dual FETCH FIRST 1 ROWS ONLY",
])
def test_m1_denied_oracle_packages_are_caught_in_package_function_form(sql):
    v = check_sql(sql, SqlPolicy(dialect="oracle"))
    assert v.allowed is False and "denied function" in v.reason


def test_m1_an_ordinary_qualified_function_stays_allowed():
    # Since the default allow-list (15 Nov 2026) the user names the function; the package/schema check of
    # this test must still not refuse it.
    v = check_sql("SELECT myschema.my_fn(id) FROM orders LIMIT 1",
                  SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"myschema.my_fn"})))
    assert v.allowed is True, v.reason


def test_m1_duckdb_histogram_is_row_folding():
    v = check_sql("SELECT histogram(email) FROM users LIMIT 1", SqlPolicy(dialect="duckdb"))
    assert v.allowed is False and "row-folding" in v.reason


@pytest.mark.parametrize("dialect", ["duckdb", None])
@pytest.mark.parametrize("source", ["'/etc/passwd'", "'data.csv'", "'C:\\x\\y.parquet'", "'s3://b/k.json'",
                                    "'*.csv'", "'~/notes.txt'"])
def test_m1_a_file_path_used_as_a_table_is_blocked(source, dialect):
    v = check_sql(f"SELECT * FROM {source} LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "file path" in v.reason


@pytest.mark.parametrize("sql, dialect", [
    ('SELECT * FROM "Orders" LIMIT 1', "postgres"),
    ("SELECT * FROM public.orders LIMIT 1", "postgres"),
    ("SELECT * FROM main.orders LIMIT 1", "duckdb"),
    ("SELECT * FROM `my-table` LIMIT 1", "mysql"),
])
def test_m1_ordinary_table_names_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


# ---- L1: anything unexpected inside the guard is a block, never an exception ------------------------------------
def test_l1_very_deep_nesting_is_blocked_without_an_exception():
    sql = "SELECT " + "(" * 3000 + "1" + ")" * 3000 + " LIMIT 1"
    v = check_sql(sql, SqlPolicy())
    assert v.allowed is False


@pytest.mark.parametrize("error", [RecursionError("deep"), RuntimeError("boom"), MemoryError()])
def test_l1_unexpected_error_becomes_query_too_complex(monkeypatch, error):
    def explode(*a, **k):
        raise error
    monkeypatch.setattr(sqlguard.sqlglot, "parse", explode)
    v = check_sql("SELECT 1 LIMIT 1", SqlPolicy())
    assert v.allowed is False
    assert v.reason == "query too complex (blocked, fail-closed)"


# ---- L2: notifications, statistics reset and T-SQL locking hints ------------------------------------------------
@pytest.mark.parametrize("call", ["pg_notify('ch', 'x')", "pg_stat_statements_reset()"])
def test_l2_more_denied_functions(call):
    v = check_sql(f"SELECT {call} LIMIT 1", SqlPolicy(dialect="postgres"))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("hints", ["UPDLOCK", "XLOCK", "HOLDLOCK", "TABLOCKX", "NOLOCK, UPDLOCK", "updlock"])
def test_l2_tsql_locking_hints_are_blocked(hints):
    v = check_sql(f"SELECT TOP 1 * FROM users WITH ({hints})", SqlPolicy(dialect="tsql"))
    assert v.allowed is False and "row-locking" in v.reason


def test_l2_a_non_locking_tsql_hint_stays_allowed():
    v = check_sql("SELECT TOP 1 * FROM users WITH (NOLOCK)", SqlPolicy(dialect="tsql"))
    assert v.allowed is True, v.reason


# ---- L4: library text does not name internal documents -----------------------------------------------------------
def test_l4_library_source_names_no_internal_document():
    hits = [str(p.relative_to(ROOT)) for p in (ROOT / "src").rglob("*.py")
            if "_HI.md" in p.read_text(encoding="utf-8")]
    assert hits == []


def test_sqlglot_version_is_reported():
    assert sqlglot.__version__
