import pytest

from sangop.sqlguard import SqlPolicy, check_sql

P = SqlPolicy(max_rows=50, dialect="postgres")


def test_select_with_limit_allowed():
    assert check_sql("SELECT name FROM users WHERE id = 3 LIMIT 5", P).allowed


@pytest.mark.parametrize("sql", [
    "DELETE FROM users",
    "DROP TABLE users",
    "UPDATE users SET name = 'x'",
    "INSERT INTO users (name) VALUES ('x')",
    "TRUNCATE users",
    "ALTER TABLE users ADD COLUMN x INT",
    "SELECT * INTO backup FROM users",
    "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d LIMIT 1",
    "SELECT 1 LIMIT 1; DROP TABLE users",
    "this is not sql at all ((",
])
def test_dangerous_or_unparseable_blocked(sql):
    assert not check_sql(sql, P).allowed


def test_bulk_extraction_guard():
    assert not check_sql("SELECT * FROM users", P).allowed
    assert not check_sql("SELECT * FROM users LIMIT 10000", P).allowed
    v = check_sql("SELECT * FROM users", SqlPolicy(max_rows=50, rewrite_limit=True))
    assert v.allowed and "LIMIT 50" in v.sql


def test_pure_aggregate_needs_no_limit():
    assert check_sql("SELECT COUNT(*) FROM users", P).allowed
    assert not check_sql("SELECT city, COUNT(*) FROM users GROUP BY city", P).allowed


def test_tenant_filter():
    pol = SqlPolicy(max_rows=50, require_filter_column="tenant_id")
    assert check_sql("SELECT * FROM orders WHERE tenant_id = 9 LIMIT 5", pol).allowed
    assert not check_sql("SELECT * FROM orders WHERE id = 9 LIMIT 5", pol).allowed


def test_table_lists():
    pol = SqlPolicy(max_rows=50, denied_tables=frozenset({"secrets"}))
    assert not check_sql("SELECT * FROM secrets LIMIT 1", pol).allowed
    pol2 = SqlPolicy(max_rows=50, allowed_tables=frozenset({"orders"}))
    assert not check_sql("SELECT * FROM users LIMIT 1", pol2).allowed
    assert check_sql("SELECT * FROM orders LIMIT 1", pol2).allowed
