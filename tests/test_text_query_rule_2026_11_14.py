"""Family rule (14 Nov 2026): a function argument that is SQL text ('SELECT ...') is refused in every dialect,
because several database functions run such text as a query (crosstab, query_to_xml, ts_stat, dblink, DuckDB query,
json_serialize_sql, and whatever a future version adds). Fail-closed; every query is synthetic."""
import pytest

from sangop import sqlguard
from sangop.sqlguard import SqlPolicy, check_sql

REASON = "query given as text blocked (fail-closed)"


@pytest.mark.parametrize("dialect", ["postgres", None])
@pytest.mark.parametrize("sql", [
    "SELECT * FROM crosstab('SELECT email, 1, email FROM t') AS x(a text, b text) LIMIT 5",
    "SELECT query_to_xml('select 1', true, true, '') LIMIT 1",
    "SELECT * FROM ts_stat('SELECT v FROM t') LIMIT 5",
    "SELECT * FROM query('WITH x AS (SELECT 1) SELECT * FROM x') LIMIT 1",
    "SELECT json_serialize_sql('SELECT 1') LIMIT 1",
    "SELECT * FROM dblink('conn', '  select 1') AS t(a int) LIMIT 1",
    "SELECT future_runner('SELECT email FROM users') LIMIT 1",
    "SELECT * FROM future_table_fn('(SELECT email FROM users)') LIMIT 1",
    "SELECT future_runner('VALUES (1)') LIMIT 1",
    "SELECT future_runner('delete from users') LIMIT 1",
])
def test_sql_text_in_a_function_argument_is_blocked(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert REASON in v.reason or "denied function" in v.reason


@pytest.mark.parametrize("dialect", ["postgres", None, "mysql", "tsql", "snowflake"])
def test_an_unknown_function_with_sql_text_gets_the_text_reason(dialect):
    v = check_sql("SELECT future_runner('SELECT email FROM users')" + ("" if dialect == "tsql" else " LIMIT 1"),
                  SqlPolicy(dialect=dialect))
    assert v.allowed is False and REASON in v.reason


@pytest.mark.parametrize("sql", [
    "SELECT * FROM query('WITH x AS (SELECT 1) SELECT * FROM x') LIMIT 1",
    "SELECT json_serialize_sql('SELECT 1') LIMIT 1",
    "SELECT * FROM query_table('SELECT 1') LIMIT 1",
])
def test_duckdb_query_text_is_blocked(sql):
    v = check_sql(sql, SqlPolicy(dialect="duckdb"))
    assert v.allowed is False


@pytest.mark.parametrize("dialect", ["postgres", None, "duckdb", "mysql"])
@pytest.mark.parametrize("sql", [
    "SELECT id FROM t WHERE note = 'select a plan' LIMIT 5",
    "SELECT lower('Selected') LIMIT 1",
    "SELECT concat('with', 'out') LIMIT 1",
    "SELECT replace(name, 'from', 'to') FROM t LIMIT 5",
    "SELECT position('values' IN s) FROM t LIMIT 5",
    "SELECT upper('select') LIMIT 1",
    "SELECT concat('select ', name) FROM t LIMIT 5",
    "SELECT id FROM t WHERE lower(note) LIKE 'select%' LIMIT 5",
    "SELECT CAST('2026-11-14' AS DATE) LIMIT 1",
])
def test_ordinary_text_arguments_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


# ---- 14 Nov 2026 follow-up: fewer false blocks; getenv; arg_max_null / arg_min_null -------------------------
@pytest.mark.parametrize("dialect", ["postgres", None, "duckdb", "mysql", "snowflake"])
@pytest.mark.parametrize("sql", [
    "SELECT coalesce(note, 'from Mumbai') FROM t LIMIT 5",
    "SELECT replace(s, 'table of contents', 'x') FROM t LIMIT 5",
    "SELECT concat('select ', name) FROM t LIMIT 5",
    "SELECT lower('WITH love') LIMIT 1",
    "SELECT position('values here' IN s) FROM t LIMIT 5",
    "SELECT split_part(addr, 'from Delhi', 1) FROM t LIMIT 5",
    "SELECT nullif(note, 'select all') FROM t LIMIT 5",
    "SELECT upper(trim('  from here ')) LIMIT 1",
    "SELECT concat_ws(' ', 'from', 'here', name) FROM t LIMIT 5",
    "SELECT regexp_replace(note, 'from [a-z]+', '') FROM t LIMIT 5",
])
def test_followup_common_string_functions_keep_plain_text(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("sql", [
    "SELECT ifnull(note, 'from Mumbai') FROM t LIMIT 5",
    "SELECT nvl(note, 'from Mumbai') FROM t LIMIT 5",
    "SELECT instr(note, 'from Mumbai') FROM t LIMIT 5",
    "SELECT substr('from Mumbai', 1, 4) LIMIT 1",
    "SELECT lpad(name, 20, 'with love ') FROM t LIMIT 5",
    "SELECT length('from Mumbai') LIMIT 1",
    "SELECT md5('select me') LIMIT 1",
    "SELECT starts_with(note, 'from Mumbai') FROM t LIMIT 5",
    "SELECT strftime(d, 'from %Y') FROM t LIMIT 5",
    "SELECT to_char(d, 'from YYYY') FROM t LIMIT 5",
    "SELECT greatest(a, 'from x') FROM t LIMIT 5",
])
@pytest.mark.parametrize("dialect", ["duckdb", None])
def test_followup_more_safe_functions(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", ["postgres", None, "duckdb"])
@pytest.mark.parametrize("sql", [
    "SELECT coalesce(future_runner('SELECT email FROM users'), 'x') LIMIT 1",
    "SELECT lower(future_runner('select email from users')) LIMIT 1",
    "SELECT concat('a', future_runner('WITH x AS (SELECT 1) SELECT * FROM x')) LIMIT 1",
])
def test_followup_unknown_function_inside_a_safe_one_is_still_blocked(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and REASON in v.reason


@pytest.mark.parametrize("dialect", ["duckdb", None])
def test_followup_duckdb_getenv_is_denied(dialect):
    v = check_sql("SELECT getenv('HOME') LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("dialect", ["duckdb", None])
@pytest.mark.parametrize("call", ["arg_max_null(email, id, 1000)", "arg_min_null(email, id, 5)"])
def test_followup_arg_max_null_with_a_count_is_row_folding(call, dialect):
    v = check_sql(f"SELECT {call} FROM users", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "row-folding" in v.reason


@pytest.mark.parametrize("call", ["arg_max_null(email, id)", "arg_min_null(email, id)"])
def test_followup_arg_max_null_one_value_stays_allowed(call):
    v = check_sql(f"SELECT {call} FROM users LIMIT 1", SqlPolicy(dialect="duckdb"))
    assert v.allowed is True, v.reason


# ---- 14 Nov 2026 second follow-up: more regexp/format functions; dollar-quoted text ----------------------------------------
@pytest.mark.parametrize("sql", [
    r"SELECT regexp_matches(s, 'with (\w+)') FROM t LIMIT 5",
    "SELECT regexp_split_to_array(s, 'from ') FROM t LIMIT 5",
    "SELECT regexp_split_to_array(s, 'from here') FROM t LIMIT 5",
    "SELECT * FROM regexp_split_to_table('from a to b', ' ') LIMIT 5",
    "SELECT regexp_match(s, 'select (\\d+)') FROM t LIMIT 5",
    "SELECT regexp_count(s, 'from x') FROM t LIMIT 5",
    "SELECT regexp_instr(s, 'from x') FROM t LIMIT 5",
    "SELECT regexp_substr(s, 'from x') FROM t LIMIT 5",
    "SELECT to_number(s, 'with 999') FROM t LIMIT 5",
    "SELECT format('select %s from %s', a, b) FROM t LIMIT 5",
    "SELECT coalesce(note, $$from Mumbai$$) FROM t LIMIT 5",
])
def test_followup2_regexp_and_format_keep_plain_text(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("sql", [
    "SELECT regexp_extract(s, 'from (x)') FROM t LIMIT 5",
    "SELECT similar_to(s, 'from x') FROM t LIMIT 5",
])
def test_followup2_more_safe_names(sql):
    v = check_sql(sql, SqlPolicy(dialect="duckdb"))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", ["postgres", "duckdb"])
@pytest.mark.parametrize("sql", [
    "SELECT unknownfn($$SELECT email FROM users$$) LIMIT 1",
    "SELECT unknownfn($tag$ select email from users $tag$) LIMIT 1",
    "SELECT * FROM unknown_table_fn($q$WITH x AS (SELECT 1) SELECT * FROM x$q$) LIMIT 1",
    "SELECT coalesce(unknownfn($$SELECT email FROM users$$), 'x') LIMIT 1",
])
def test_followup2_dollar_quoted_sql_text_is_blocked(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and REASON in v.reason


@pytest.mark.parametrize("sql", [
    "SELECT unknownfn('SELECT email FROM users'::text) LIMIT 1",
    "SELECT unknownfn(CAST('SELECT email FROM users' AS TEXT)) LIMIT 1",
    "SELECT unknownfn(('SELECT email FROM users')) LIMIT 1",
    "SELECT unknownfn($$SELECT email FROM users$$::text) LIMIT 1",
])
def test_followup2_sql_text_behind_a_cast_or_brackets_is_blocked(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is False and REASON in v.reason


# ---- 14 Nov 2026 third follow-up: every string-like node (E'...', N'...', X'...', B'...') -------------------------------
STRING_FORMS = [
    "SELECT unknownfn(E'SELECT email FROM users') LIMIT 1",
    "SELECT unknownfn(e'select email from users') LIMIT 1",
    "SELECT unknownfn(N'SELECT email FROM users') LIMIT 1",
    "SELECT unknownfn(X'53454C45435420656D61696C2046524F4D207573657273') LIMIT 1",
    "SELECT unknownfn(B'0101001101000101010011000100010101000011010101000010000001100101011011010110000101101001011011000010000001000110010100100100111101001101001000000111010101110011011001010111001001110011') LIMIT 1",
    "SELECT unknownfn(E'SELECT email FROM users'::text) LIMIT 1",
]


@pytest.mark.parametrize("sql", STRING_FORMS)
def test_followup3_string_like_nodes_are_checked_postgres(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is False and REASON in v.reason


@pytest.mark.parametrize("sql", STRING_FORMS)
def test_followup3_string_like_nodes_are_refused_with_dialect_none(sql):
    assert check_sql(sql, SqlPolicy(dialect=None)).allowed is False


@pytest.mark.parametrize("sql", [
    "SELECT coalesce(note, E'from Mumbai') FROM t LIMIT 5",
    "SELECT lower(N'With love') LIMIT 1",
    "SELECT unknownfn(X'0A0B') LIMIT 1",
    "SELECT unknownfn(B'0101') LIMIT 1",
    "SELECT unknownfn(E'from') LIMIT 1",
    "SELECT array_to_string(ARRAY['a', 'b'], ',') LIMIT 1",
])
def test_followup3_ordinary_string_forms_stay_allowed(sql):
    # unknownfn is named so that the default allow-list (15 Nov 2026) does not refuse it; the text rule is tested
    v = check_sql(sql, SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"unknownfn"})))
    assert v.allowed is True, v.reason


def test_followup3_every_string_node_class_is_covered():
    """Guard against a new sqlglot string-literal class: every non-function class whose name ends in 'String' must be
    read by the rule."""
    from sqlglot import exp
    for name in dir(exp):
        cls = getattr(exp, name)
        if (isinstance(cls, type) and issubclass(cls, exp.Expression) and name.endswith("String")
                and not issubclass(cls, exp.Func)):
            assert sqlguard._argument_text(cls(this="SELECT email FROM users")) is not None, name
