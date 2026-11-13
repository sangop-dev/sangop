"""Sangop's SQL guard on its own (no decorator, no database). Run: python examples/sql_guard_only.py"""
from sangop import SqlPolicy, check_sql

policy = SqlPolicy(max_rows=50, require_filter_column="tenant_id")
queries = [
    "SELECT id, total FROM orders WHERE tenant_id = 42 LIMIT 10",
    "SELECT * FROM orders",
    "DELETE FROM orders WHERE tenant_id = 42",
    "SELECT id FROM orders WHERE tenant_id = 42 LIMIT 5; DROP TABLE orders",
]
for sql in queries:
    verdict = check_sql(sql, policy)
    print("allowed" if verdict.allowed else "blocked", "|", verdict.reason, "|", sql)
