"""Internal review 28 Oct 2026, finding A4-1 (HIGH): the LIMIT (bulk-extraction) guard could be bypassed by an aggregate hidden
in a scalar sub-query.

``_is_pure_aggregate`` treated a query as "returns one row" when every output column contained an aggregate ANYWHERE,
including inside a nested sub-query. ``SELECT (SELECT max(id) FROM t2) || email FROM users`` returns one row per user,
yet passed without a LIMIT. The fix counts an aggregate only when its nearest enclosing SELECT is the query itself.

Written before the fix (failing first). Synthetic table and column names only.
"""
import pytest

from sangop.sqlguard import SqlPolicy, check_sql

BLOCK = SqlPolicy(max_rows=100, dialect="postgres")
CLAMP = SqlPolicy(max_rows=100, dialect="postgres", rewrite_limit=True)

BYPASSES = [
    # the report's example and its single-column form
    "SELECT (SELECT max(id) FROM t2) || email FROM users",
    "SELECT (SELECT max(id) FROM t2) FROM users",
    # two columns, each with a hidden aggregate
    "SELECT (SELECT max(id) FROM t2) || email, (SELECT count(*) FROM t3) || phone FROM users",
    # aggregate hidden in a sub-query that reads a CTE
    "WITH m AS (SELECT id FROM t2) SELECT (SELECT max(id) FROM m) || email FROM users",
    # the outer rows come from a CTE
    "WITH u AS (SELECT email FROM users) SELECT (SELECT max(id) FROM t2) || email FROM u",
    # aggregate over a UNION inside the scalar sub-query
    "SELECT (SELECT max(x) FROM (SELECT id AS x FROM t2 UNION SELECT id FROM t3) s) || email FROM users",
    # aggregate over a derived table inside the scalar sub-query
    "SELECT (SELECT max(m) FROM (SELECT id AS m FROM t2) d) || email FROM users",
    # aggregate in a CASE / function around the sub-query
    "SELECT CASE WHEN (SELECT count(*) FROM t2) > 0 THEN email END FROM users",
    "SELECT coalesce((SELECT max(id) FROM t2), 0) || email FROM users",
    # outer rows from a derived table
    "SELECT (SELECT max(id) FROM t2) || e FROM (SELECT email AS e FROM users) d",
]


@pytest.mark.parametrize("sql", BYPASSES, ids=[f"bypass{i}" for i in range(len(BYPASSES))])
def test_hidden_aggregate_does_not_skip_the_limit_guard(sql):
    v = check_sql(sql, BLOCK)
    assert not v.allowed, (sql, v.reason)
    assert "LIMIT" in v.reason


@pytest.mark.parametrize("sql", BYPASSES, ids=[f"bypass{i}" for i in range(len(BYPASSES))])
def test_hidden_aggregate_gets_a_limit_when_rewriting(sql):
    v = check_sql(sql, CLAMP)
    assert v.allowed and "LIMIT 100" in v.sql, (sql, v.reason, v.sql)


@pytest.mark.parametrize("sql", BYPASSES, ids=[f"bypass{i}" for i in range(len(BYPASSES))])
def test_hidden_aggregate_with_a_small_limit_is_fine(sql):
    v = check_sql(sql + " LIMIT 5", BLOCK)
    assert v.allowed, (sql, v.reason)


# ---- real one-row aggregates keep working without a LIMIT --------------------------------------------------------

ONE_ROW = [
    "SELECT count(*) FROM users",
    "SELECT max(id) + 1 FROM users",
    "SELECT COUNT(*) FROM users",
    "SELECT count(*), max(id) FROM users",
    "SELECT count(*) FROM users WHERE id IN (SELECT id FROM t2)",
    "SELECT max(id) FROM (SELECT id FROM users) d",                      # aggregate in the query's own scope
    "WITH u AS (SELECT id FROM users) SELECT count(*) FROM u",
    "SELECT count(*) + (SELECT count(*) FROM t2) FROM users",            # own aggregate + a scalar sub-query
    "SELECT sum(amount) / nullif(count(*), 0) FROM orders",
]


@pytest.mark.parametrize("sql", ONE_ROW, ids=[f"one{i}" for i in range(len(ONE_ROW))])
def test_real_one_row_aggregates_still_need_no_limit(sql):
    v = check_sql(sql, BLOCK)
    assert v.allowed, (sql, v.reason)
    assert v.sql == sql                                                   # not rewritten


def test_group_by_and_window_still_need_a_limit():
    assert not check_sql("SELECT city, count(*) FROM users GROUP BY city", BLOCK).allowed
    assert not check_sql("SELECT count(*) OVER () FROM users", BLOCK).allowed


def test_tenant_filter_policy_still_blocks_the_attack():
    """With require_filter_column the attack was already blocked (no tenant filter); it must stay so."""
    pol = SqlPolicy(max_rows=100, dialect="postgres", require_filter_column="tenant_id")
    assert not check_sql("SELECT (SELECT max(id) FROM t2) || email FROM users", pol).allowed


@pytest.mark.parametrize("sql", ["SELECT (SELECT max(id) FROM t2)",
                                 "SELECT count(*), (SELECT max(id) FROM t2) FROM users"])
def test_stricter_on_purpose_one_row_queries_with_a_scalar_subquery_column(sql):
    """Documented side effect of the A4-1 fix (fail closed): these really return one row, but a column whose only
    aggregate is inside a sub-query no longer counts, so they need a LIMIT - or get one with rewrite_limit=True."""
    assert not check_sql(sql, BLOCK).allowed
    v = check_sql(sql, CLAMP)
    assert v.allowed and "LIMIT 100" in v.sql
