"""Internal AI-assisted security review, 15 Nov 2026 ("review 4"): H1-H3, M1, M2, L1-L3. Written before the fixes;
every query is synthetic. H1-H3 and M2 were confirmed by the reviewer on a throw-away local PostgreSQL 16 (own
sandbox only). With the default allow-list most of these are refused because their names are unknown; the
tests also check the backstop, so the same names stay refused when a user allows them."""
import pytest

from sangop.sqlguard import SqlPolicy, check_sql

STRICT = dict(require_filter_column="tenant_id", allowed_tables=frozenset({"users"}), max_rows=1)
PG_AND_NONE = ["postgres", None]


# ---- H1: a function whose argument is a bare query folds the query's rows into one value ----------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT JSON_ARRAY(SELECT email FROM users) AS j LIMIT 1",
    "SELECT JSON_ARRAY(SELECT email FROM users UNION SELECT email FROM users) LIMIT 1",
    "SELECT ARRAY(SELECT email FROM users) LIMIT 1",
])
def test_h1_query_as_a_function_argument_is_row_folding(sql, dialect):
    for extra in (frozenset(), frozenset({"json_array"})):
        v = check_sql(sql, SqlPolicy(dialect=dialect, extra_allowed_functions=extra))
        assert v.allowed is False and "row-folding" in v.reason, v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
def test_h1_strict_policy(dialect):
    v = check_sql("SELECT JSON_ARRAY(SELECT email FROM users WHERE tenant_id = 1) AS j FROM users WHERE tenant_id = 1 "
                  "LIMIT 1", SqlPolicy(dialect=dialect, **STRICT))
    assert v.allowed is False and "row-folding" in v.reason


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT id FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.uid = u.id) LIMIT 5",
    "SELECT id FROM users WHERE id IN (SELECT uid FROM orders) LIMIT 5",
    "SELECT id FROM users WHERE id = ANY (SELECT uid FROM orders) LIMIT 5",
    "SELECT id FROM users WHERE total > ALL (SELECT total FROM orders) LIMIT 5",
    "SELECT id, total FROM orders WHERE total > (SELECT avg(total) FROM orders) LIMIT 100",
    "SELECT id, (SELECT max(total) FROM orders o WHERE o.uid = u.id) FROM users u LIMIT 5",
    "SELECT coalesce((SELECT max(total) FROM orders), 0) LIMIT 1",
])
def test_h1_ordinary_subqueries_stay_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_h1_json_array_of_a_bracketed_scalar_is_not_row_folding():
    v = check_sql("SELECT JSON_ARRAY((SELECT 1)) LIMIT 1", SqlPolicy(dialect="postgres"))
    assert "row-folding" not in v.reason          # refused only as an unknown name (default allow-list)
    v = check_sql("SELECT JSON_ARRAY((SELECT 1)) LIMIT 1",
                  SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"json_array"})))
    assert v.allowed is True, v.reason


# ---- H2: PostGIS aggregates that fold rows --------------------------------------------------------------------------------
H2 = [
    "SELECT ST_AsMVT(t) FROM (SELECT email, ST_AsMVTGeom(ST_MakePoint(1,1), ST_MakeEnvelope(0,0,4096,4096)) AS geom "
    "FROM users) t LIMIT 1",
    "SELECT ST_AsGeobuf(t) FROM (SELECT email, ST_MakePoint(1,1) AS geom FROM users) t LIMIT 1",
    "SELECT ST_AsFlatGeobuf(t) FROM (SELECT email, ST_MakePoint(1,1) AS geom FROM users) t LIMIT 1",
    "SELECT ST_AsText(ST_Collect(ST_MakePoint(id, tenant_id))) FROM users LIMIT 1",
    "SELECT ST_AsText(ST_MakeLine(ST_MakePoint(id, tenant_id))) FROM users LIMIT 1",
    "SELECT ST_Union(geom) FROM places LIMIT 1",
]


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", H2)
def test_h2_postgis_folding_is_refused_by_default(sql, dialect):
    assert check_sql(sql, SqlPolicy(dialect=dialect)).allowed is False


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", H2)
def test_h2_postgis_folding_stays_refused_when_postgis_is_allowed(sql, dialect):
    extra = frozenset({"st_asmvt", "st_asmvtgeom", "st_makepoint", "st_makeenvelope", "st_asgeobuf",
                       "st_asflatgeobuf", "st_astext", "st_collect", "st_makeline", "st_union"})
    v = check_sql(sql, SqlPolicy(dialect=dialect, extra_allowed_functions=extra))
    assert v.allowed is False and "row-folding" in v.reason, v.reason


def test_h2_strict_policy():
    v = check_sql("SELECT ST_AsMVT(t) FROM (SELECT email, ST_MakePoint(1,1) AS geom FROM users WHERE tenant_id = 1) t "
                  "WHERE tenant_id = 1 LIMIT 1", SqlPolicy(dialect="postgres", **STRICT))
    assert v.allowed is False


def test_h2_ordinary_postgis_works_once_allowed():
    v = check_sql("SELECT ST_AsText(geom), ST_Distance(geom, ST_MakePoint(0,0)) FROM places LIMIT 10",
                  SqlPolicy(dialect="postgres",
                            extra_allowed_functions=frozenset({"st_astext", "st_distance", "st_makepoint"})))
    assert v.allowed is True, v.reason


# ---- H3: PostGIS functions that change tables inside a SELECT --------------------------------------------------------------
H3 = ["SELECT DropGeometryTable('users') LIMIT 1", "SELECT DropGeometryColumn('users', 'geom') LIMIT 1",
      "SELECT AddGeometryColumn('users', 'geom', 4326, 'POINT', 2) LIMIT 1",
      "SELECT UpdateGeometrySRID('users', 'geom', 4326) LIMIT 1", "SELECT Populate_Geometry_Columns() LIMIT 1",
      "SELECT postgis_extensions_upgrade() LIMIT 1", "SELECT DropTopology('t') LIMIT 1",
      "SELECT AddRasterConstraints('r', 'rast') LIMIT 1"]


@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", H3)
def test_h3_table_changing_functions_are_refused(sql, dialect):
    assert check_sql(sql, SqlPolicy(dialect=dialect)).allowed is False
    assert check_sql(sql, SqlPolicy(dialect=dialect, **STRICT)).allowed is False


@pytest.mark.parametrize("sql", H3)
def test_h3_stays_refused_when_the_name_is_allowed(sql):
    name = sql.split("SELECT ")[1].split("(")[0].lower()
    v = check_sql(sql, SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({name})))
    assert v.allowed is False and "denied function" in v.reason, v.reason


# ---- M1: written forms of a query given as text ----------------------------------------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT * FROM some_exec('SELECT*FROM users') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('SELECT(email)FROM users') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('SELECT\"email\"FROM users') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('SELECT\temail FROM users') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('/*x*/ SELECT email FROM users') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('/*a*/ /*b*/SELECT email FROM users') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec(sql => 'SELECT email FROM users') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('EXPLAIN SELECT email FROM users') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('SHOW all') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('execute p1') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('prepare p1 AS SELECT 1') AS t(a text) LIMIT 1",
    "SELECT * FROM some_exec('DO $x$ BEGIN END $x$') AS t(a text) LIMIT 1",
])
def test_m1_text_forms_are_refused_as_text(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect, extra_allowed_functions=frozenset({"some_exec"})))
    assert v.allowed is False
    if dialect == "postgres":
        assert "query given as text" in v.reason, v.reason


def test_m1_dash_dash_comment_before_the_query():
    v = check_sql("SELECT * FROM some_exec(E'-- x\\nSELECT email FROM users') AS t(a text) LIMIT 1",
                  SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"some_exec"})))
    assert v.allowed is False and "query given as text" in v.reason, v.reason


@pytest.mark.parametrize("sql", [
    "SELECT some_fn('from') LIMIT 1", "SELECT some_fn('Selected') LIMIT 1", "SELECT some_fn('select') LIMIT 1",
    "SELECT some_fn('do it now please') LIMIT 1".replace("do it now please", "doing it"),
    "SELECT some_fn('showcase') LIMIT 1", "SELECT some_fn('executed') LIMIT 1", "SELECT some_fn('tablet') LIMIT 1",
])
def test_m1_single_words_and_longer_words_stay_allowed(sql):
    v = check_sql(sql, SqlPolicy(dialect="postgres", extra_allowed_functions=frozenset({"some_fn"})))
    assert v.allowed is True, v.reason


# ---- M2, L1, L2 ------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("call", ["heap_force_kill('users'::regclass, ARRAY['(0,1)'::tid])",
                                  "heap_force_freeze('users'::regclass, ARRAY['(0,1)'::tid])",
                                  "autoprewarm_dump_now()", "autoprewarm_start_worker()"])
def test_m2_l1_page_writers_are_denied_even_when_allowed(call, dialect):
    name = call.split("(")[0]
    v = check_sql(f"SELECT {call} LIMIT 1", SqlPolicy(dialect=dialect, extra_allowed_functions=frozenset({name})))
    assert v.allowed is False and "denied function" in v.reason


@pytest.mark.parametrize("dialect", ["sqlite", None])
@pytest.mark.parametrize("call", ["eval('SELECT email FROM users')", "eval('SELECT(email)FROM users')",
                                  "sha3_query('SELECT 1')"])
def test_l2_sqlite_text_runners_are_denied(call, dialect):
    name = call.split("(")[0]
    v = check_sql(f"SELECT {call} LIMIT 1", SqlPolicy(dialect=dialect, extra_allowed_functions=frozenset({name})))
    assert v.allowed is False and "denied function" in v.reason


# ---- L3: ordinary text in arrays, JSON objects and text search -------------------------------------------------------------
@pytest.mark.parametrize("dialect", PG_AND_NONE)
@pytest.mark.parametrize("sql", [
    "SELECT array_position(ARRAY['with gift', 'plain'], wrap) FROM orders LIMIT 10",
    "SELECT ARRAY['select a plan'] LIMIT 1",
    "SELECT count(*) FROM orders WHERE status = any(ARRAY['values set', 'x'])",
    "SELECT json_build_object('note', 'from the north office') FROM orders LIMIT 10",
    "SELECT jsonb_build_object('msg', 'Update available for you') LIMIT 1",
    "SELECT to_tsquery('english', 'select & plan') LIMIT 1",
    "SELECT plainto_tsquery('english', 'from delhi to mumbai') LIMIT 1",
])
def test_l3_ordinary_text_stays_allowed(sql, dialect):
    v = check_sql(sql, SqlPolicy(dialect=dialect))
    assert v.allowed is True, v.reason


def test_l3_websearch_to_tsquery_postgres():
    v = check_sql("SELECT id FROM docs WHERE to_tsvector('english', body) @@ websearch_to_tsquery('from delhi to mumbai') "
                  "LIMIT 5", SqlPolicy(dialect="postgres"))
    assert v.allowed is True, v.reason
