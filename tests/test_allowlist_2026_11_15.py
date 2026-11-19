"""Default function allow-list for PostgreSQL-like dialects, SQLite and dialect=None (15 Nov 2026), and the
large false-positive list that must stay allowed. Every query is synthetic.

The deny-list approach kept losing to new names (a new review found new ones each time), so for these dialects a
function that is not on a known-safe list is refused by default; users add names with extra_allowed_functions. The
backstop rules (deny-list, family rules, row-folding, text-query rule, U&, executable comments) still apply to every
name, also to names a user allows."""
import pytest

from sangop import sqlguard
from sangop.sqlguard import SqlPolicy, check_sql

ALLOWLIST_DIALECTS = ["postgres", "redshift", "materialize", "risingwave", "sqlite", None]
EXPERIMENTAL = ["mysql", "duckdb", "tsql", "snowflake", "bigquery", "oracle"]
NOT_LISTED = "not in the default allow-list"


# ---- A: the default allow-list -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("dialect", ALLOWLIST_DIALECTS)
def test_unknown_function_is_refused_with_a_helpful_message(dialect):
    v = check_sql("SELECT my_custom_fn(id) FROM t LIMIT 5", SqlPolicy(dialect=dialect))
    assert v.allowed is False
    assert NOT_LISTED in v.reason and "'my_custom_fn'" in v.reason
    assert "extra_allowed_functions" in v.reason


def test_message_names_the_dialect():
    v = check_sql("SELECT st_asmvt(t) FROM t LIMIT 5", SqlPolicy(dialect="postgres", allowed_tables=None))
    assert v.allowed is False
    v = check_sql("SELECT my_custom_fn(id) FROM t LIMIT 5", SqlPolicy(dialect="postgres"))
    assert "for postgres" in v.reason


@pytest.mark.parametrize("dialect", ALLOWLIST_DIALECTS)
def test_extra_allowed_functions_adds_a_name(dialect):
    v = check_sql("SELECT my_custom_fn(id) FROM t LIMIT 5",
                  SqlPolicy(dialect=dialect, extra_allowed_functions=frozenset({"my_custom_fn"})))
    assert v.allowed is True, v.reason


def test_extra_allowed_functions_is_case_insensitive():
    v = check_sql("SELECT My_Custom_Fn(id) FROM t LIMIT 5",
                  SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"MY_CUSTOM_FN"})))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", EXPERIMENTAL)
def test_experimental_dialects_keep_the_deny_list_behaviour(dialect):
    sql = "SELECT TOP 5 my_custom_fn(id) FROM t" if dialect == "tsql" else "SELECT my_custom_fn(id) FROM t LIMIT 5"
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_explicit_allowed_functions_replaces_the_default_list():
    p = SqlPolicy(dialect="postgres", allowed_functions=frozenset({"count"}))
    assert check_sql("SELECT count(*) FROM t", p).allowed is True
    v = check_sql("SELECT lower(name) FROM t LIMIT 5", p)
    assert v.allowed is False and "not in allow-list" in v.reason


def test_explicit_allowed_functions_plus_extra():
    p = SqlPolicy(dialect="mysql", allowed_functions=frozenset({"count"}), extra_allowed_functions=frozenset({"lower"}))
    assert check_sql("SELECT lower(name), count(*) FROM t GROUP BY 1 LIMIT 5", p).allowed is True


@pytest.mark.parametrize("sql", [
    "SELECT LOWER(name) FROM t LIMIT 5",
    'SELECT "lower"(name) FROM t LIMIT 5',
    "SELECT pg_catalog.lower(name) FROM t LIMIT 5",
    "SELECT Count(*) FROM t",
])
def test_names_match_in_any_case_and_with_pg_catalog(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("sql", [
    "SELECT public.lower(name) FROM t LIMIT 5",            # a user function that happens to be called lower
    "SELECT myschema.my_fn(name) FROM t LIMIT 5",
])
def test_a_schema_qualified_call_outside_pg_catalog_is_not_a_default_name(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres"))
    assert v.allowed is False and NOT_LISTED in v.reason


@pytest.mark.parametrize("extra", [{"myschema.my_fn"}, {"my_fn"}])
def test_a_schema_qualified_call_can_be_allowed(extra):
    v = check_sql("SELECT myschema.my_fn(name) FROM t LIMIT 5",
                  SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset(extra)))
    assert v.allowed is True, v.reason


def test_unicode_escaped_name_is_still_refused():
    v = check_sql('SELECT U&"\\0070g_sleep"(1) LIMIT 1', SqlPolicy(dialect="postgres"))
    assert v.allowed is False


@pytest.mark.parametrize("name", ["count", "sum", "avg", "lower", "coalesce", "row_number", "date_trunc", "now",
                                  "round", "regexp_replace", "json_extract_path_text"])
def test_core_names_are_on_the_postgres_list(name):
    assert name in sqlguard.default_allowed_functions("postgres")


@pytest.mark.parametrize("name", ["total", "strftime", "julianday", "json_extract", "quote", "unixepoch"])
def test_sqlite_names_are_on_the_sqlite_list(name):
    assert name in sqlguard.default_allowed_functions("sqlite")


@pytest.mark.parametrize("name", ["repeat", "printf", "randomblob", "zeroblob", "pg_sleep", "json_agg", "string_agg",
                                  "st_asmvt", "dblink", "lo_import", "query_to_xml"])
def test_dangerous_or_heavy_names_are_not_on_any_list(name):
    for d in ("postgres", "sqlite", None):
        assert name not in sqlguard.default_allowed_functions(d)


@pytest.mark.parametrize("sql", ["SELECT repeat('x', 100000000) LIMIT 1", "SELECT lpad('x', 100000000, 'y') LIMIT 1",
                                 "SELECT rpad('x', 100000000) LIMIT 1", "SELECT lpad(code, n, '0') FROM t LIMIT 1"])
def test_memory_heavy_string_builders_are_refused(sql):
    assert check_sql(sql, SqlPolicy(dialect="postgres")).allowed is False


@pytest.mark.parametrize("dialect", ["sqlite", None])
@pytest.mark.parametrize("sql", ["SELECT printf('%s', name) FROM t LIMIT 5", "SELECT randomblob(1000000000) LIMIT 1",
                                 "SELECT zeroblob(1000000000) LIMIT 1"])
def test_sqlite_memory_heavy_functions_are_refused(sql, dialect):
    assert check_sql(sql, SqlPolicy(dialect=dialect)).allowed is False


# ---- A4: the backstop stays on, whatever a user allows ---------------------------------------------------------------------
@pytest.mark.parametrize("dialect", ["postgres", None])
def test_backstop_deny_list_wins_over_extra_allowed(dialect):
    p = SqlPolicy(dialect=dialect, extra_allowed_functions=frozenset({"pg_sleep", "json_agg"}))
    v = check_sql("SELECT pg_sleep(10) LIMIT 1", p)
    assert v.allowed is False and "denied function" in v.reason
    assert "extra_allowed_functions" not in v.reason and "add it" not in v.reason
    v = check_sql("SELECT json_agg(u) FROM users u LIMIT 1", p)
    assert v.allowed is False and "row-folding" in v.reason
    assert "extra_allowed_functions" not in v.reason


@pytest.mark.parametrize("sql, extra, word", [
    ("SELECT pg_read_file('x') LIMIT 1", {"pg_read_file"}, "denied function"),
    ("SELECT lo_import('/etc/passwd') LIMIT 1", {"lo_import"}, "denied function"),
    ("SELECT dblink_exec('c', 'x') LIMIT 1", {"dblink_exec"}, "denied function"),
    ("SELECT http_get('http://x') LIMIT 1", {"http_get"}, "denied function"),
    ("SELECT some_exec('SELECT email FROM users') LIMIT 1", {"some_exec"}, "query given as text"),
    ("SELECT st_asmvt(t) FROM (SELECT email FROM users) t LIMIT 1", {"st_asmvt"}, "row-folding"),
    ("SELECT DropGeometryTable('users') LIMIT 1", {"dropgeometrytable"}, "denied function"),
    ("SELECT heap_force_kill('users'::regclass, ARRAY['(0,1)'::tid]) LIMIT 1", {"heap_force_kill"}, "denied function"),
])
def test_backstop_rules_win_over_extra_allowed(sql, extra, word):
    v = check_sql(sql, SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset(extra)))
    assert v.allowed is False and word in v.reason, v.reason
    assert "extra_allowed_functions" not in v.reason


@pytest.mark.parametrize("sql", ["SELECT sqlite_offset(id) FROM t LIMIT 1", "SELECT * FROM pragma_database_list LIMIT 5"])
def test_sqlite_family_wins_over_extra_allowed(sql):
    v = check_sql(sql, SqlPolicy(dialect="sqlite",
                                 extra_allowed_functions=frozenset({"sqlite_offset", "pragma_database_list"})))
    assert v.allowed is False and "denied" in v.reason


def test_executable_comment_and_unicode_escape_win_over_extra_allowed():
    p = SqlPolicy(dialect=None, extra_allowed_functions=frozenset({"anything"}))
    assert check_sql("SELECT id FROM t /*!50000 UNION SELECT 1 */ LIMIT 1", p).allowed is False
    assert check_sql("SELECT U&'\\0041' LIMIT 1", p).allowed is False


# ---- C: queries that must stay allowed -------------------------------------------------------------------------------------
ANALYTICS_61 = [
 "SELECT o.id, c.name, o.total FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.total > 100 ORDER BY o.total DESC LIMIT 50",
 "SELECT c.region, count(*) AS n, sum(o.total) AS revenue FROM orders o LEFT JOIN customers c ON c.id = o.customer_id GROUP BY c.region HAVING count(*) > 5 ORDER BY revenue DESC LIMIT 20",
 "SELECT id, total, row_number() OVER (PARTITION BY customer_id ORDER BY created_at) AS rn FROM orders LIMIT 100",
 "SELECT id, total, sum(total) OVER (ORDER BY created_at ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS rolling FROM orders LIMIT 100",
 "SELECT id, lag(total) OVER (ORDER BY created_at) AS prev, rank() OVER (ORDER BY total DESC) FROM orders LIMIT 100",
 "WITH monthly AS (SELECT date_trunc('month', created_at) AS m, sum(total) AS s FROM orders GROUP BY 1) SELECT m, s FROM monthly ORDER BY m LIMIT 24",
 "WITH a AS (SELECT customer_id, count(*) n FROM orders GROUP BY customer_id), b AS (SELECT * FROM a WHERE n > 3) SELECT * FROM b LIMIT 10",
 "SELECT id FROM orders WHERE created_at >= now() - interval '7 days' LIMIT 100",
 "SELECT id FROM orders WHERE created_at BETWEEN '2026-01-01' AND '2026-03-31' LIMIT 100",
 "SELECT extract(year FROM created_at) AS y, count(*) FROM orders GROUP BY 1 LIMIT 10",
 "SELECT to_char(created_at, 'YYYY-MM') AS ym, count(*) FROM orders GROUP BY 1 ORDER BY 1 LIMIT 24",
 "SELECT upper(name), lower(email), length(name), substring(name from 1 for 3), trim(name) FROM customers LIMIT 10",
 "SELECT name || ' (' || city || ')' AS label FROM customers LIMIT 10",
 "SELECT concat(first_name, ' ', last_name) AS full_name, coalesce(phone, 'n/a') FROM customers LIMIT 10",
 "SELECT replace(sku, '-', ''), split_part(sku, '-', 1) FROM products LIMIT 10",
 "SELECT data->>'status' AS status, (data->'amount')::numeric AS amt FROM events LIMIT 10",
 "SELECT json_extract_path_text(data::json, 'status') FROM events LIMIT 10",
 "SELECT id, CASE WHEN total > 1000 THEN 'big' WHEN total > 100 THEN 'mid' ELSE 'small' END AS bucket FROM orders LIMIT 100",
 "SELECT id FROM orders WHERE status IN ('paid', 'shipped', 'delivered') LIMIT 100",
 "SELECT id FROM customers WHERE name LIKE 'A%' OR email ILIKE '%@example.com' LIMIT 100",
 "SELECT id FROM orders WHERE customer_id IN (SELECT id FROM customers WHERE region = 'north') LIMIT 100",
 "SELECT id FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id) LIMIT 100",
 "SELECT count(*), avg(total), min(total), max(total), stddev(total) FROM orders",
 "SELECT count(DISTINCT customer_id) FROM orders",
 "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY total) FROM orders",
 "SELECT status, count(*) FILTER (WHERE total > 100) FROM orders GROUP BY status LIMIT 10",
 "SELECT id FROM orders ORDER BY created_at DESC NULLS LAST LIMIT 10 OFFSET 20",
 "SELECT DISTINCT region FROM customers LIMIT 50",
 "SELECT a.id FROM orders a UNION SELECT b.id FROM returns b LIMIT 100",
 "SELECT round(total * 1.18, 2) AS with_tax, abs(discount), ceil(total), floor(total) FROM orders LIMIT 10",
 "SELECT cast(total AS integer), total::text FROM orders LIMIT 10",
 "SELECT nullif(discount, 0), greatest(a, b), least(a, b) FROM orders LIMIT 10",
 "SELECT date_part('dow', created_at), date(created_at), current_date - created_at::date FROM orders LIMIT 10",
 "SELECT regexp_replace(phone, '[^0-9]', '', 'g') FROM customers LIMIT 10",
 "SELECT format('%s-%s', region, city) FROM customers LIMIT 10",
 "SELECT name FROM customers WHERE note = 'select the best plan for customers' LIMIT 10",
 "SELECT name FROM customers WHERE note LIKE 'from the north%' LIMIT 10",
 "SELECT name FROM customers WHERE status = 'update pending' LIMIT 10",
 "SELECT coalesce(note, 'Table 4 reserved') FROM bookings LIMIT 10",
 "SELECT position('select' in note) FROM customers LIMIT 10",
 "SELECT json_build_object('id', id, 'total', total) FROM orders LIMIT 10",
 "SELECT to_jsonb(o) FROM orders o LIMIT 10",
 "SELECT o.* FROM orders o JOIN LATERAL (SELECT 1) x ON true LIMIT 10",
 "SELECT * FROM generate_series(1, 10) LIMIT 10",
 "SELECT id, ntile(4) OVER (ORDER BY total) FROM orders LIMIT 100",
 "SELECT md5(email) FROM customers LIMIT 10",
 "SELECT strftime('%Y-%m', created_at), count(*) FROM orders GROUP BY 1 LIMIT 24",
 "SELECT ifnull(phone, ''), instr(email, '@') FROM customers LIMIT 10",
 "SELECT julianday('now') - julianday(created_at) FROM orders LIMIT 10",
 "SELECT json_extract(data, '$.status') FROM events LIMIT 10",
 "SELECT * FROM pragma_table_info('orders') LIMIT 50",
 "SELECT name FROM sqlite_master WHERE type = 'table' LIMIT 50",
 "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 100",
 "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'orders' LIMIT 100",
 "SELECT translate(name, 'abc', 'xyz'), initcap(name) FROM customers LIMIT 10",
 "SELECT starts_with(sku, 'A'), left(sku, 2), right(sku, 2), lpad(code, 5, '0') FROM products LIMIT 10",
 "SELECT to_date('2026-01-01', 'YYYY-MM-DD'), to_timestamp('2026-01-01 10:00', 'YYYY-MM-DD HH24:MI') LIMIT 1",
 "SELECT date_trunc('week', created_at) AS w, count(*) FROM orders GROUP BY w ORDER BY w LIMIT 52",
 "SELECT id, total FROM orders WHERE total > (SELECT avg(total) FROM orders) LIMIT 100",
 "SELECT bool_or(paid) FROM orders",
 "SELECT id FROM orders WHERE note IS NOT NULL AND note <> '' LIMIT 10",
]


def test_there_are_61_analytics_queries():
    assert len(ANALYTICS_61) == 61


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", None])
@pytest.mark.parametrize("sql", ANALYTICS_61)
def test_review4_analytics_queries_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


REQUESTED_FIVE_PG = [
    "SELECT status, COUNT(*) AS cnt, SUM(total_amount) AS rev, AVG(total_amount) FROM orders GROUP BY status "
    "ORDER BY rev DESC LIMIT 20",
    "SELECT DATE_TRUNC('month', created_at) AS m, COUNT(DISTINCT customer_id) FROM orders WHERE created_at >= "
    "CURRENT_DATE - INTERVAL '1 year' GROUP BY 1 ORDER BY 1 LIMIT 12",
    "WITH r AS (SELECT customer_id, total_amount, ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY total_amount "
    "DESC) AS rn FROM orders) SELECT customer_id, total_amount FROM r WHERE rn = 1 LIMIT 50",
    "SELECT LOWER(TRIM(COALESCE(country, 'unknown'))) AS c, COUNT(*) FROM customers GROUP BY 1 LIMIT 25",
    "SELECT c.id, COUNT(o.id), COALESCE(SUM(ROUND(o.total_amount, 2)), 0) AS ltv FROM customers c LEFT JOIN orders o "
    "ON c.id = o.customer_id GROUP BY c.id ORDER BY ltv DESC LIMIT 50",
]
SQLITE_ONE = ("SELECT strftime('%Y-%m', created_at) AS m, COUNT(*), ROUND(AVG(total_amount), 2) FROM orders "
              "GROUP BY m ORDER BY m DESC LIMIT 12")


@pytest.mark.parametrize("dialect", ["postgres", None])
@pytest.mark.parametrize("sql", REQUESTED_FIVE_PG)
def test_requested_examples_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", ["sqlite", None])
def test_requested_sqlite_example_stays_allowed(dialect):
    v = check_sql(SQLITE_ONE, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


SYNTAX_PG = [
    "SELECT CASE WHEN total > 100 THEN 'big' ELSE 'small' END FROM orders LIMIT 5",
    "SELECT CAST(total AS numeric), total::int, created_at::date FROM orders LIMIT 5",
    "SELECT EXTRACT(year FROM created_at), EXTRACT(epoch FROM created_at) FROM orders LIMIT 5",
    "SELECT created_at + INTERVAL '1 day', now() - interval '2 hours' FROM orders LIMIT 5",
    "SELECT data -> 'a', data ->> 'b', data #>> '{a,b}' FROM events LIMIT 5",
    "SELECT id FROM t WHERE name LIKE 'a%' OR name ILIKE 'b%' OR name NOT LIKE 'c%' LIMIT 5",
    "SELECT id FROM t WHERE status IN ('a', 'b') AND total BETWEEN 1 AND 9 LIMIT 5",
    "SELECT NULLIF(a, 0), GREATEST(a, b, 3), LEAST(a, b) FROM t LIMIT 5",
    "SELECT id FROM t WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '1 hour' AND d < CURRENT_DATE LIMIT 5",
    "SELECT date_part('hour', ts), age(ts), make_date(2026, 1, 1), to_number('12', '99') FROM t LIMIT 5",
    "SELECT percentile_disc(0.9) WITHIN GROUP (ORDER BY total), mode() WITHIN GROUP (ORDER BY status) FROM orders",
    "SELECT corr(a, b), covar_pop(a, b), regr_slope(a, b), var_samp(a), bool_and(paid), every(paid) FROM t LIMIT 1",
    "SELECT first_value(total) OVER w, last_value(total) OVER w, nth_value(total, 2) OVER w, dense_rank() OVER w, "
    "percent_rank() OVER w, cume_dist() OVER w, lead(total) OVER w FROM orders WINDOW w AS (ORDER BY id) LIMIT 5",
    "SELECT abs(a), ceiling(a), power(a, 2), sqrt(a), ln(a), log(10, a), mod(a, 3), sign(a), pi(), width_bucket(a, 0, 100, 10) FROM t LIMIT 5",
    "SELECT char_length(s), octet_length(s), ascii(s), chr(65), reverse(s), md5(s), strpos(s, 'a') FROM t LIMIT 5",
    "SELECT jsonb_extract_path_text(data, 'a'), json_typeof(data::json), jsonb_array_length(data->'xs') FROM t LIMIT 5",
    "SELECT date_trunc('day', ts), date_bin('15 minutes', ts, TIMESTAMP '2026-01-01') FROM t LIMIT 5",
    "SELECT justify_days(interval '35 days'), isfinite(ts), localtimestamp, current_time FROM t LIMIT 5",
    "SELECT pg_typeof(a), pg_size_pretty(1024::bigint), pg_column_size(a) FROM t LIMIT 5",
    "SELECT array_position(ARRAY['with gift', 'plain'], wrap) FROM orders LIMIT 10",
    "SELECT ARRAY['select a plan', 'x'] LIMIT 1",
    "SELECT count(*) FILTER (WHERE paid), any_value(status) FROM orders",
    "SELECT lpad(code, 5, '0'), rpad(code, 8) FROM products LIMIT 5",
]
SYNTAX_SQLITE = [
    "SELECT total(amount), date(ts), time(ts), datetime(ts, '+1 day'), julianday(ts), unixepoch(ts) FROM t LIMIT 5",
    "SELECT typeof(a), unicode(s), hex(s), quote(s), instr(s, 'a'), iif(a > 0, 'p', 'n') FROM t LIMIT 5",
    "SELECT json_extract(d, '$.a'), json_type(d), json_valid(d), json_array_length(d) FROM t LIMIT 5",
    "SELECT * FROM pragma_table_info('orders') LIMIT 50",
    "SELECT * FROM pragma_index_list('orders') LIMIT 50",
]


@pytest.mark.parametrize("dialect", ["postgres", None])
@pytest.mark.parametrize("sql", SYNTAX_PG)
def test_postgres_syntax_and_functions_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


@pytest.mark.parametrize("dialect", ["sqlite", None])
@pytest.mark.parametrize("sql", SYNTAX_SQLITE)
def test_sqlite_functions_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason
