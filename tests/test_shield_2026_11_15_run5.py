"""Internal AI-assisted security review, 15 Nov 2026, second run ("review 5"): H1, M1, L1, L2, plus follow-ups.
Written before the fixes; every query is synthetic. H1 and M1 were confirmed by the reviewer on a throw-away local
PostgreSQL 16 / SQLite 3.53 (own sandbox only)."""
import pytest

from sangop.sqlguard import SqlPolicy, check_sql

STRICT = dict(require_filter_column="tenant_id", allowed_tables=frozenset({"users"}), max_rows=1)
PG_AND_NONE = ["postgres", None]


# ---- H1: the fraction of percentile_disc / percentile_cont must be one plain number --------------------------------------
H1 = [
    "SELECT percentile_disc('{0,0.5,1}'::float8[]) WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_disc('{0,0.01,1}'::float8[]) WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_disc(ARRAY[0,0.5,1]::float8[]) WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_disc(CAST('{0,0.5,1}' AS float8[])) WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_disc(regexp_split_to_array('0,0.5,1', ',')::float8[]) WITHIN GROUP (ORDER BY email) AS v "
    "FROM users LIMIT 1",
    "WITH f AS (SELECT '{0,0.5,1}'::float8[] AS a) SELECT percentile_disc((SELECT a FROM f)) WITHIN GROUP "
    "(ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_cont('{0,0.5,1}'::float8[]) WITHIN GROUP (ORDER BY id) AS v FROM users LIMIT 1",
    "SELECT percentile_cont(ARRAY[0.1,0.9]) WITHIN GROUP (ORDER BY id) AS v FROM users LIMIT 1",
    "SELECT percentile_disc(x) WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_disc('0.5') WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_disc(1.5) WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_disc(-0.5) WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
    "SELECT percentile_disc(0.5 + 0.1) WITHIN GROUP (ORDER BY email) AS v FROM users LIMIT 1",
]


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", H1)
def test_h1_percentile_fraction_must_be_one_plain_number(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "row-folding" in v.reason, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
def test_h1_strict_policy(dialect):
    v = check_sql("SELECT percentile_disc('{0,0.5,1}'::float8[]) WITHIN GROUP (ORDER BY email) AS v FROM users "
                  "WHERE tenant_id = 1 LIMIT 1", SqlPolicy(dialect=dialect, **STRICT))
    assert v.allowed is False and "row-folding" in v.reason, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY id) FROM users",
    "SELECT percentile_cont(0.9) WITHIN GROUP (ORDER BY total) FROM orders",
    "SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY total) FROM orders",
    "SELECT percentile_cont(0) WITHIN GROUP (ORDER BY total), percentile_cont(1) WITHIN GROUP (ORDER BY total) "
    "FROM orders",
    "SELECT percentile_cont((0.25)) WITHIN GROUP (ORDER BY total) FROM orders",
])
def test_h1_one_plain_fraction_stays_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_h1_placeholder_fraction_stays_allowed():
    v = check_sql("SELECT percentile_cont($1) WITHIN GROUP (ORDER BY total) FROM orders", SqlPolicy(dialect="postgres"))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("sql, ok", [
    ("SELECT quantile_cont(total, 0.5) FROM orders", True),
    ("SELECT quantile_disc(total, [0.1, 0.5]) FROM orders", False),
    ("SELECT quantile_cont(total, x) FROM orders", False),
    ("SELECT quantile(total, CAST(0.5 AS DOUBLE)) FROM orders", False),
    ("SELECT approx_quantile(total, 0.5) FROM orders", True),
    ("SELECT median(total) FROM orders", True),
])
def test_h1_duckdb_quantile_forms(sql, ok):
    v = check_sql(sql, SqlPolicy(dialect="duckdb"))
    assert v.allowed is ok, v.reason


# ---- M1: format() must not build a huge value --------------------------------------------------------------------------------
@pytest.mark.parametrize("dialect", ["postgres", "sqlite", None])
@pytest.mark.parametrize("sql", [
    "SELECT format('%*s', 900000000, 'x') AS v LIMIT 1",
    "SELECT format('%*s', 500000000, 'x') AS v LIMIT 1",
    "SELECT format('%900000000s', 'x') AS v LIMIT 1",
    "SELECT format('%500000000s', 'x') AS v LIMIT 1",
    "SELECT format('%-2000s', 'x') AS v LIMIT 1",
    "SELECT format('%1$*2$s', 'x', 900000000) AS v LIMIT 1",
    "SELECT format('%.900000000f', 1.5) AS v LIMIT 1",
    "SELECT format(fmt_col, a) FROM t LIMIT 5",
])
def test_m1_format_width_is_limited(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False
    if "fmt_col" not in sql:
        assert "format" in v.reason and "extra_allowed_functions" not in v.reason, v.reason


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", None])
@pytest.mark.parametrize("sql", [
    "SELECT format('%s from %s', a, b) FROM t LIMIT 5",
    "SELECT format('%5s', code) FROM t LIMIT 5",
    "SELECT format('%s-%s', id, tenant_id) AS v FROM users LIMIT 5",
    "SELECT format('%10s', name) FROM users LIMIT 5",
    "SELECT format('%1000s', name) FROM users LIMIT 5",
    "SELECT format('100%% of %s', name) FROM users LIMIT 5",
    "SELECT format('%s*%s', a, b) FROM t LIMIT 5",
])
def test_m1_ordinary_format_stays_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_m1_format_can_be_opened_by_the_user():
    v = check_sql("SELECT format(fmt_col, a) FROM t LIMIT 5",
                  SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"format"})))
    assert v.allowed is True, v.reason


# ---- follow-up 5: the lpad / rpad message ------------------------------------------------------------------------------------
@pytest.mark.parametrize("sql", ["SELECT lpad('x', 100000000, 'y') LIMIT 1", "SELECT rpad(code, n) FROM t LIMIT 1"])
def test_pad_length_message(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is False
    assert "lpad/rpad length must be a literal number up to 1000" in v.reason
    assert "extra_allowed_functions" not in v.reason and "add it" not in v.reason


# ---- L1: names are checked as the query wrote them -----------------------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT array_join(tags, ',') FROM posts LIMIT 5",
    "SELECT string(x) FROM t LIMIT 5",
    "SELECT year(created_at) FROM orders LIMIT 5",
    "SELECT ucase(name) FROM t LIMIT 5",
    "SELECT lcase(name) FROM t LIMIT 5",
    "SELECT len(name) FROM t LIMIT 5",
    "SELECT str_to_date(d, '%Y') FROM t LIMIT 5",
])
def test_l1_names_that_postgres_does_not_have_are_refused(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is False and "not in the default allow-list" in v.reason, v.reason


@pytest.mark.parametrize("sql, dialect", [
    ("SELECT extract(year FROM d) FROM t LIMIT 5", "postgres"),
    ("SELECT date_part('year', d) FROM t LIMIT 5", "postgres"),
    ("SELECT ifnull(a, 'x'), instr(a, 'b'), strftime('%Y', d) FROM t LIMIT 5", "sqlite"),
    ("SELECT lpad(x, 10), concat_ws(',', a, b), regexp_replace(a, 'x', 'y'), date_trunc('day', d) FROM t LIMIT 5",
     "postgres"),
    ("SELECT nvl(a, 0), ceiling(a), pow(a, 2), substr(a, 1, 2), char_length(a) FROM t LIMIT 5", None),
])
def test_l1_real_names_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


# ---- L2 / follow-up 4: functions that only expand one value or one row -------------------------------------------------
@pytest.mark.parametrize("call", [
    "array_length(tags, 1)", "array_upper(tags, 1)", "array_lower(tags, 1)", "array_ndims(tags)", "cardinality(tags)",
    "unnest(tags)", "string_to_array(tags_csv, ',')", "array_positions(tags, 'a')", "array_remove(tags, 'a')",
    "array_replace(tags, 'a', 'b')", "array_append(tags, 'a')", "array_prepend('a', tags)", "array_cat(tags, tags)",
    "json_array_elements(data::json)", "json_array_elements_text(data::json)", "jsonb_array_elements(data)",
    "jsonb_array_elements_text(data->'items')", "json_each(data::json)", "json_each_text(data::json)",
    "jsonb_each(data)", "jsonb_each_text(data)", "json_object_keys(data::json)", "jsonb_object_keys(data)",
])
def test_l2_postgres_expanding_functions_are_allowed(call):
    v = check_sql(f"SELECT {call} FROM posts LIMIT 5", SqlPolicy(dialect="postgres"))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", ["sqlite", None])
@pytest.mark.parametrize("sql", [
    "SELECT key, value FROM t, json_each(t.data) LIMIT 5",
    "SELECT value FROM json_each('[1,2,3]') LIMIT 5",
    "SELECT key, value FROM json_tree('{\"a\": 1}') LIMIT 5",
])
def test_l2_sqlite_json_each_and_tree_are_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT unnest(ARRAY(SELECT email FROM users)) LIMIT 5",
    "SELECT jsonb_array_elements((SELECT jsonb_agg(u) FROM users u)) LIMIT 5",
    "SELECT array_length(ARRAY(SELECT email FROM users), 1) LIMIT 5",
])
def test_l2_a_folding_subquery_inside_is_still_refused(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is False and "row-folding" in v.reason, v.reason


# ---- the review's false-positive list -------------------------------------------------------------------------------------
REVIEW5_PG = [
    "SELECT o.id, c.name, o.total FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.created_at >= now() - interval '7 days' LIMIT 100",
    "SELECT c.city, count(*) AS n, sum(o.total) AS revenue FROM orders o JOIN customers c ON c.id = o.customer_id GROUP BY c.city HAVING count(*) > 5 ORDER BY revenue DESC LIMIT 20",
    "SELECT date_trunc('month', created_at) AS m, count(*) FROM orders GROUP BY 1 ORDER BY 1 LIMIT 24",
    "SELECT id, total, rank() OVER (PARTITION BY customer_id ORDER BY total DESC) AS r FROM orders LIMIT 50",
    "SELECT id, sum(total) OVER (ORDER BY created_at ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS rolling FROM orders LIMIT 50",
    "WITH recent AS (SELECT * FROM orders WHERE created_at > current_date - 30) SELECT customer_id, avg(total) FROM recent GROUP BY customer_id LIMIT 20",
    "SELECT CASE WHEN total > 1000 THEN 'big' WHEN total > 100 THEN 'mid' ELSE 'small' END AS bucket, count(*) FROM orders GROUP BY 1 LIMIT 10",
    "SELECT id FROM orders WHERE status IN ('paid', 'shipped') AND city ILIKE 'raipur%' LIMIT 10",
    "SELECT extract(year FROM created_at) AS y, extract(month FROM created_at) AS mo, count(*) FROM orders GROUP BY 1, 2 LIMIT 50",
    "SELECT to_char(created_at, 'YYYY-MM-DD') AS d, count(*) FROM orders GROUP BY 1 ORDER BY 1 DESC LIMIT 30",
    "SELECT payload->>'source' AS src, count(*) FROM events GROUP BY 1 LIMIT 20",
    "SELECT payload #>> '{device,os}' AS os FROM events LIMIT 20",
    "SELECT jsonb_extract_path_text(payload, 'source') FROM events LIMIT 20",
    "SELECT coalesce(nullif(trim(name), ''), 'unknown') AS n FROM customers LIMIT 20",
    "SELECT lower(email) = lower('A@B.test') AS same FROM customers LIMIT 1",
    "SELECT round(avg(total)::numeric, 2) FROM orders",
    "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY total) FROM orders",
    "SELECT count(DISTINCT customer_id) FROM orders",
    "SELECT count(*) FILTER (WHERE status = 'paid') AS paid, count(*) AS total FROM orders",
    "SELECT id, lag(total) OVER (ORDER BY created_at) AS prev FROM orders LIMIT 20",
    "SELECT id, ntile(4) OVER (ORDER BY total) FROM orders LIMIT 20",
    "SELECT id, row_number() OVER () FROM orders LIMIT 20",
    "SELECT o.id FROM orders o WHERE NOT EXISTS (SELECT 1 FROM refunds r WHERE r.order_id = o.id) LIMIT 20",
    "SELECT id FROM orders UNION ALL SELECT id FROM archived_orders LIMIT 20",
    "SELECT age(now(), created_at) FROM orders LIMIT 5",
    "SELECT created_at::date, count(*) FROM orders GROUP BY 1 LIMIT 31",
    "SELECT split_part(email, '@', 2) AS domain, count(*) FROM customers GROUP BY 1 LIMIT 20",
    "SELECT substring(phone from 1 for 3) FROM customers LIMIT 5",
    "SELECT regexp_replace(name, '\\s+', ' ', 'g') FROM customers LIMIT 5",
    "SELECT concat(first_name, ' ', last_name) FROM customers LIMIT 5",
    "SELECT greatest(a, b), least(a, b) FROM metrics LIMIT 5",
    "SELECT abs(delta), ceil(x), floor(x), sqrt(x) FROM metrics LIMIT 5",
    "SELECT date_part('dow', created_at) AS dow, count(*) FROM orders GROUP BY 1 LIMIT 7",
    "SELECT generate_series(1, 12) AS m LIMIT 12",
    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 100",
    "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'orders' LIMIT 100",
    "SELECT id, total FROM orders ORDER BY total DESC NULLS LAST LIMIT 10 OFFSET 10",
    "SELECT id FROM orders WHERE created_at BETWEEN '2026-01-01' AND '2026-03-31' LIMIT 10",
    "SELECT stddev(total), variance(total) FROM orders",
    "SELECT max(total), min(total) FROM orders",
    "SELECT bool_or(is_vip) FROM customers",
    "SELECT length(name), upper(city), initcap(city) FROM customers LIMIT 5",
    "SELECT md5(email) FROM customers LIMIT 5",
    "SELECT to_timestamp(epoch) FROM events LIMIT 5",
    "SELECT id, first_value(total) OVER w, last_value(total) OVER w FROM orders WINDOW w AS (PARTITION BY customer_id ORDER BY created_at) LIMIT 10",
    "SELECT position('@' in email) FROM customers LIMIT 5",
    "SELECT left(name, 3), right(name, 3) FROM customers LIMIT 5",
    "SELECT replace(phone, '-', '') FROM customers LIMIT 5",
    "SELECT jsonb_array_length(items) FROM orders LIMIT 5",
    "SELECT payload ? 'source' FROM events LIMIT 5",
    "SELECT array_length(tags, 1) FROM posts LIMIT 5",
    "SELECT unnest(tags) FROM posts LIMIT 50",
    "SELECT cardinality(tags) FROM posts LIMIT 5",
    "SELECT date_trunc('week', created_at), sum(total) FROM orders GROUP BY 1 ORDER BY 1 LIMIT 52",
    "SELECT string_to_array(tags_csv, ',') FROM posts LIMIT 5",
    "SELECT trim(both ' ' from name) FROM customers LIMIT 5",
    "SELECT current_date - created_at::date AS days FROM orders LIMIT 5",
    "SELECT id FROM orders WHERE total::text LIKE '9%' LIMIT 5",
    "SELECT round(100.0 * count(*) FILTER (WHERE status='paid') / nullif(count(*),0), 1) FROM orders",
]
REVIEW5_SQLITE = [
    "SELECT strftime('%Y-%m', created_at) AS m, count(*) FROM orders GROUP BY 1 LIMIT 24",
    "SELECT ifnull(name, 'x'), substr(phone, 1, 3), instr(email, '@') FROM customers LIMIT 5",
    "SELECT json_extract(payload, '$.source') FROM events LIMIT 5",
    "SELECT name FROM sqlite_master WHERE type = 'table' LIMIT 50",
    "SELECT * FROM pragma_table_info('orders') LIMIT 50",
    "SELECT total(total), group_id FROM orders GROUP BY group_id LIMIT 10",
    "SELECT julianday('now') - julianday(created_at) FROM orders LIMIT 5",
    "SELECT cast(total AS integer) FROM orders LIMIT 5",
    "SELECT replace(phone, '-', ''), trim(name), upper(city) FROM customers LIMIT 5",
    "SELECT id, row_number() OVER (ORDER BY total) FROM orders LIMIT 5",
    "SELECT unixepoch(created_at) FROM orders LIMIT 5",
    "SELECT round(avg(total), 2) FROM orders",
    "SELECT iif(total > 100, 'big', 'small') FROM orders LIMIT 5",
    "SELECT value FROM json_each('[1,2,3]') LIMIT 5",
]


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", REVIEW5_PG)
def test_review5_postgres_queries_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", ["sqlite", None])
@pytest.mark.parametrize("sql", REVIEW5_SQLITE)
def test_review5_sqlite_queries_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_printf_stays_off_the_default_list():
    assert check_sql("SELECT printf('%.2f', total) FROM orders LIMIT 5", SqlPolicy(dialect="sqlite")).allowed is False


@pytest.mark.parametrize("dialect", PG_AND_NONE)
def test_json_array_of_values_is_allowed_but_of_a_query_is_not(dialect):
    assert check_sql("SELECT JSON_ARRAY((SELECT 1)) LIMIT 1", SqlPolicy(dialect=dialect)).allowed is True
    assert check_sql("SELECT JSON_ARRAY(id, total) FROM orders LIMIT 5", SqlPolicy(dialect=dialect)).allowed is True
    v = check_sql("SELECT JSON_ARRAY(SELECT email FROM users) LIMIT 1", SqlPolicy(dialect=dialect))
    assert v.allowed is False and "row-folding" in v.reason
