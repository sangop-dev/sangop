"""Messages name a function as the query wrote it, not by sqlglot's internal name (15 Nov 2026 follow-up): sqlglot
turns lpad into Pad, string_agg into GroupConcat, ifnull into Coalesce, instr into StrPosition, and so on.
The allow / refuse decisions stay as they were."""
import pytest

from sangop.sqlguard import SqlPolicy, check_sql


@pytest.mark.parametrize("sql, written, internal", [
    ("SELECT lpad('x', 100000000, 'y') LIMIT 1", "lpad", "'pad'"),
    ("SELECT rpad('x', 100000000) LIMIT 1", "rpad", "'pad'"),
    ("SELECT LPAD('x', 100000000, 'y') LIMIT 1", "lpad", "'pad'"),
])
@pytest.mark.parametrize("dialect", ["postgres", "sqlite", None])
def test_allow_list_message_uses_the_written_name(sql, written, internal, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert f"'{written}'" in v.reason and internal not in v.reason, v.reason


@pytest.mark.parametrize("sql, dialect, written", [
    ("SELECT string_agg(email, ',') FROM users LIMIT 1", "postgres", "string_agg"),
    ("SELECT STRING_AGG(DISTINCT email, ',') FROM users LIMIT 1", "postgres", "string_agg"),
    ("SELECT group_concat(email) FROM users LIMIT 1", "sqlite", "group_concat"),
    ("SELECT jsonb_object_agg(k, v) FROM t LIMIT 1", "postgres", "jsonb_object_agg"),
    ("SELECT json_object_agg(k, v) FROM t LIMIT 1", "postgres", "json_object_agg"),
    ("SELECT json_agg(u) FROM users u LIMIT 1", "postgres", "json_agg"),
    ("SELECT array_agg(email) FROM users LIMIT 1", "postgres", "array_agg"),
    ("SELECT json_group_array(email) FROM users LIMIT 1", "sqlite", "json_group_array"),
])
def test_row_folding_message_uses_the_written_name(sql, dialect, written):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "row-folding" in v.reason
    names = v.reason.split(":", 1)[1]
    assert written in names, v.reason
    for internal in ("groupconcat", "j_s_o", "jsonbobjectagg", "jsonobjectagg", "arrayagg"):
        assert internal not in names, v.reason


@pytest.mark.parametrize("sql, written, internal", [
    ("SELECT ifnull(a, 'x') FROM t LIMIT 5", "ifnull", "coalesce"),
    ("SELECT instr(a, 'b') FROM t LIMIT 5", "instr", "str_position"),
    ("SELECT strftime('%Y', d) FROM t LIMIT 5", "strftime", "time_to_str"),
])
def test_explicit_allow_list_message_uses_the_written_name(sql, written, internal):
    v = check_sql(sql, SqlPolicy(dialect="sqlite", allowed_functions=frozenset({"count"})))
    assert v.allowed is False and written in v.reason and internal not in v.reason, v.reason


@pytest.mark.parametrize("sql", ["SELECT ifnull(a, 'x'), instr(a, 'b') FROM t LIMIT 5",
                                 "SELECT lpad(code, 5, '0'), rpad(code, 8) FROM t LIMIT 5"])
@pytest.mark.parametrize("dialect", ["sqlite", "postgres", None])
def test_decisions_are_unchanged(sql, dialect):
    assert check_sql(sql, SqlPolicy(dialect=dialect)).allowed is True


def test_denied_and_text_query_messages_use_written_names():
    v = check_sql("SELECT PG_READ_FILE('x') LIMIT 1", SqlPolicy(dialect="postgres"))
    assert v.allowed is False and "pg_read_file" in v.reason
    v = check_sql("SELECT Some_Exec('SELECT email FROM users') LIMIT 1",
                  SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"some_exec"})))
    assert v.allowed is False and "some_exec" in v.reason


def test_a_name_with_a_schema_is_shown_with_it():
    v = check_sql("SELECT reporting.my_fn(a) FROM t LIMIT 5", SqlPolicy(dialect="postgres"))
    assert "'reporting.my_fn'" in v.reason
