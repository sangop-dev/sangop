"""SQL AST guard built on sqlglot.

Fail-closed: anything that cannot be parsed, contains more than one statement, or makes the guard itself fail
(very deep nesting, an unexpected error) is blocked. A regular expression is used in exactly one place, and only to
BLOCK, never to allow: MySQL/MariaDB executable comments (``/*! ... */``, ``/*M! ... */``), whose text those
databases run but sqlglot drops as a comment (internal review 14 Nov 2026, H1). Everything else is judged on the AST.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import FrozenSet, Optional

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

# Functions that read files, reach other servers, change session state, take locks or burn CPU/time. Blocked in every
# dialect even inside a plain SELECT (audit finding H5). The database's own read-only user remains the real defence;
# this list is a second layer and cannot be complete - use ``allowed_functions`` for a strict allow-list.
DEFAULT_DENIED_FUNCTIONS = frozenset({
    # PostgreSQL
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_ls_logdir", "pg_ls_waldir", "pg_ls_tmpdir",
    "pg_ls_archive_statusdir", "pg_stat_file", "lo_import", "lo_export", "lo_get", "lo_put", "lo_from_bytea",
    "lo_create", "lo_unlink", "lo_open", "loread", "lowrite", "dblink", "dblink_exec", "dblink_connect",
    "dblink_send_query", "dblink_connect_u", "set_config", "nextval", "setval", "currval", "pg_sleep",
    "pg_sleep_for", "pg_sleep_until", "pg_advisory_lock", "pg_advisory_xact_lock", "pg_try_advisory_lock",
    "pg_advisory_lock_shared", "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile",
    "pg_switch_wal", "pg_create_restore_point", "pg_file_write", "pg_file_unlink", "pg_logdir_ls",
    "copy_from_program", "query_to_xml", "table_to_xml", "cursor_to_xml", "database_to_xml", "schema_to_xml",
    "query_to_xml_and_xmlschema", "pg_read_server_files",
    # SQLite
    "load_extension", "readfile", "writefile", "edit", "zeroblob", "randomblob", "fts3_tokenizer",
    # MySQL / MariaDB
    "load_file", "sleep", "benchmark", "get_lock", "release_lock", "release_all_locks", "master_pos_wait",
    "sys_exec", "sys_eval",
    # DuckDB / others that read files or URLs
    "read_csv", "read_csv_auto", "read_parquet", "read_json", "read_json_auto", "read_ndjson", "read_text",
    "read_blob", "glob", "parquet_scan", "csv_scan", "json_scan", "sniff_csv", "httpfs", "read_xlsx",
    # SQL Server / Oracle style
    "openrowset", "opendatasource", "openquery", "xp_cmdshell", "utl_http", "utl_file", "dbms_lock",
    "dbms_pipe", "waitfor",
    # configuration / credential reads (re-audit R3)
    "current_setting", "pg_current_logfile", "pg_conf_load_time", "pg_show_all_settings",
    "pg_show_all_file_settings", "pg_get_functiondef",
    # run a table, schema, database, cursor or a query given as TEXT, so the table checks never see it (14 Nov 2026, H3)
    "table_to_xml_and_xmlschema", "schema_to_xml_and_xmlschema", "database_to_xml_and_xmlschema",
    "table_to_xmlschema", "schema_to_xmlschema", "database_to_xmlschema", "query_to_xmlschema",
    "cursor_to_xmlschema", "ts_rewrite", "ts_stat",
    # Oracle packages that run a query given as text (14 Nov 2026, M1); package names are matched too, see below
    "dbms_xmlgen", "dbms_xmlquery",
    # side effects outside the query: notifications, statistics reset (14 Nov 2026, L2)
    "pg_notify", "pg_stat_statements_reset",
    # WRITE inside a plain SELECT: large objects, WAL messages, transaction ids (internal review 2, 14 Nov 2026, C1)
    "lo_creat", "lo_truncate", "lo_truncate64", "lo_lseek", "lo_lseek64", "lo_tell", "lo_close",
    "pg_logical_emit_message", "txid_current", "pg_current_xact_id",
    # more advisory locks (review 2, L2)
    "pg_try_advisory_xact_lock", "pg_advisory_xact_lock_shared", "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock_shared",
    # DuckDB: run a query or a table given as text (review 2, H6)
    "query", "query_table",
    # DuckDB: read files, other databases or file metadata (review 2, H7); see also the read_* / *_scan rule below
    "read_json_objects", "read_ndjson_objects", "read_json_objects_auto", "read_ndjson_auto", "sqlite_scan",
    "sqlite_attach", "parquet_metadata", "parquet_schema", "parquet_file_metadata", "parquet_kv_metadata",
    "iceberg_scan", "delta_scan", "st_read", "postgres_scan", "postgres_query", "mysql_query",
    # Oracle: network and metadata packages (review 2, M2)
    "httpuritype", "utl_inaddr", "dbms_ldap", "xmlgen", "dbms_metadata",
    # PostgreSQL extensions that schedule jobs, call the network or export to storage (review 2, M3)
    "cron", "aws_s3", "net", "http", "http_get", "http_post",
    # SQLite extensions that read files, archives or CSV (14 Nov 2026, G2)
    "fsdir", "zipfile", "csv", "lsmode",
})

# System catalogs that expose server configuration or credentials (re-audit R3). Matched on the bare table name,
# so ``pg_catalog.pg_settings`` is caught too.
DEFAULT_DENIED_TABLES = frozenset({
    "pg_settings", "pg_file_settings", "pg_hba_file_rules", "pg_ident_file_mappings", "pg_shadow", "pg_authid",
    "pg_user_mappings", "pg_stat_activity",
    "user_mapping_options",                           # shows foreign-server passwords (internal review 2, 14 Nov 2026, M3)
    "pg_stat_statements", "pg_stat_statements_info",  # other sessions' query texts (14 Nov 2026, D-115)
})

# Whole-family rules (14 Nov 2026, D-115). In PostgreSQL (and the generic reading, dialect=None) every function whose
# name starts with pg_, lo_, txid_ or dblink, and every table whose name starts with pg_, is denied - except the
# harmless ones named here. In SQLite (and dialect=None) the same holds for sqlite_*. New system functions are
# therefore blocked by default instead of waiting for someone to list them.
PG_FUNCTION_FAMILIES = ("pg_", "lo_", "txid_", "dblink")
PG_HARMLESS_FUNCTIONS = frozenset({"pg_typeof", "pg_size_pretty", "pg_column_size"})
PG_SCHEMA_TABLES = frozenset({"pg_tables", "pg_views", "pg_indexes", "pg_class", "pg_namespace", "pg_attribute",
                              "pg_type"})               # read to learn the schema
SQLITE_HARMLESS_FUNCTIONS = frozenset({"sqlite_version", "sqlite_source_id", "sqlite_compileoption_used"})
SQLITE_SCHEMA_TABLES = frozenset({"sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema"})
# SQLite pragma_* functions and tables are denied (14 Nov 2026, G2: pragma_integrity_check, pragma_database_list ...),
# except these, read to learn the schema. dbstat (page-level statistics) is denied as a table.
SQLITE_SCHEMA_PRAGMAS = frozenset({"pragma_table_info", "pragma_table_xinfo", "pragma_index_list", "pragma_index_info",
                                   "pragma_foreign_key_list"})
SQLITE_DENIED_TABLES = frozenset({"dbstat"})
# PostgreSQL extension families (14 Nov 2026, G4): postgres_fdw*, http, http_*
PG_EXTENSION_FAMILIES = ("postgres_fdw", "http_")

# Aggregates that fold many rows into ONE value: they would defeat the row-count (LIMIT) guard (audit finding H4).
CONCAT_AGGREGATES = frozenset({
    "string_agg", "group_concat", "listagg", "json_agg", "jsonb_agg", "json_object_agg", "jsonb_object_agg",
    "json_group_array", "json_group_object", "array_agg", "xmlagg", "collect_list", "collect_set", "list",
    "array_concat_agg", "string_agg_distinct", "wm_concat", "json_arrayagg", "json_objectagg", "any_value_list",
    # PostgreSQL variants that were missing (14 Nov 2026, H2)
    "json_agg_strict", "jsonb_agg_strict", "json_object_agg_strict", "jsonb_object_agg_strict",
    "json_object_agg_unique", "jsonb_object_agg_unique", "json_object_agg_unique_strict",
    "jsonb_object_agg_unique_strict", "range_agg", "range_intersect_agg",
    # Oracle COLLECT, DuckDB histogram (14 Nov 2026, M1)
    "collect", "histogram",
    # SQLite JSONB variants (14 Nov 2026, G1)
    "jsonb_group_array", "jsonb_group_object",
    # DuckDB approx_top_k (review 2, H5); Oracle CURSOR(SELECT ...) and MULTISET(SELECT ...) (review 2, M2)
    "approx_top_k", "approxtopk", "cursor", "multiset",
})


def _is_folding_attribute(name: str) -> bool:
    """PostgreSQL attribute notation: ``u.json_agg`` means ``json_agg(u)`` (review 2, H4). For a COLUMN name the
    rule is narrower than for functions: a listed name, or a name ending in "agg"; a column such as
    ``tag_aggregate_count`` is an ordinary column and stays allowed."""
    return name in CONCAT_AGGREGATES or name.endswith("agg")


_TOP_N_CLASSES = ("Max", "Min")                  # DuckDB max(x, n) / min(x, n): the n largest values (review 2, H5)
_ARG_CLASSES = ("ArgMax", "ArgMin")              # arg_max / max_by (x, y, n)
_MULTI_QUANTILE_CLASSES = ("PercentileDisc", "PercentileCont", "Quantile", "ApproxQuantile")


def _top_n_or_multi_value(stmt: exp.Expression) -> set:
    """Aggregates that return many rows' values in one cell (review 2, H5)."""
    found = set()
    for node in stmt.find_all(exp.Func):
        cls = type(node).__name__
        if cls in _TOP_N_CLASSES and (node.args.get("expressions") or node.args.get("count")):
            found.add(f"{cls.lower()}(x, n)")
        elif cls in _ARG_CLASSES and node.args.get("count"):
            found.add(f"{_func_name(node)}(x, y, n)")
        elif cls in _MULTI_QUANTILE_CLASSES or (isinstance(node, exp.Anonymous)
                                                and ("quantile" in _func_name(node) or "percentile" in _func_name(node))):
            for arg in node.iter_expressions():
                if isinstance(arg, (exp.Array, exp.List)):
                    found.add(f"{_func_name(node)}(array)")
                    break
    return found


def _folding_attributes(stmt: exp.Expression) -> set:
    names = set()
    for col in stmt.find_all(exp.Column):
        if col.table and _is_folding_attribute(col.name.lower()):
            names.add(col.name.lower())
    for dot in stmt.find_all(exp.Dot):
        last = dot.expression
        if isinstance(last, exp.Identifier) and _is_folding_attribute(str(last.this).lower()):
            names.add(str(last.this).lower())
    return names


def _is_folding_name(name: str) -> bool:
    """Fail-closed naming rule (14 Nov 2026, H2): a function whose name ends in "agg" or contains "_agg" is treated as
    row-folding, listed or not. "avg" does not match. SQLite style names ending in "_group_array" or
    "_group_object" are row-folding too (G1)."""
    return (name.endswith("agg") or "_agg" in name
            or name.endswith("_group_array") or name.endswith("_group_object"))


# MySQL / MariaDB executable comments: the server runs their text (14 Nov 2026, H1). Checked on the raw SQL text,
# before parsing, in every dialect; the marker inside a string literal is blocked too (accepted, fail-closed).
_EXECUTABLE_COMMENT = re.compile(r"/\*[Mm]?!")

# PostgreSQL unicode escapes U&"..." / U&'...' can spell any name, e.g. U&"pg\005fsleep" is pg_sleep (14 Nov 2026,
# G3). Checked on the raw text before parsing, in every dialect; blocked outright (fail-closed).
_UNICODE_ESCAPE = re.compile(r"[Uu]&['\"]")

# T-SQL table hints that take or keep locks (14 Nov 2026, L2)
_LOCKING_TABLE_HINTS = frozenset({"UPDLOCK", "XLOCK", "HOLDLOCK", "TABLOCKX",
                                  "PAGLOCK", "TABLOCK", "SERIALIZABLE", "REPEATABLEREAD"})   # review 2, L2

# Longer SQL is refused before parsing (review 2, L1): parsing megabytes takes seconds.
MAX_SQL_BYTES = 100 * 1024

# MySQL reads "--x" as minus-minus-x, not as a comment, and does not nest /* */ comments (review 2, M1). "--" without a
# following space is blocked for dialect=None and "mysql" (also used for MariaDB; founder's decision, 14 Nov 2026);
# a nested comment for dialect=None.
_DASH_DASH_NO_SPACE = re.compile(r"--(?=\S)")

# A table "name" with one of these characters is a file path or URL (DuckDB: SELECT * FROM '/etc/passwd') (M1)
_PATH_CHARS = frozenset("/\\.:")   # "*", "?" and "~" removed: BigQuery wildcard tables `events_*` (review 2 false positive)

_STRUCTURAL_FUNCS = ("Cast", "TryCast", "Paren")

_WRITE_NODES = (
    exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Drop, exp.Create,
    exp.Alter, exp.TruncateTable, exp.Command, exp.Grant,
)


@dataclass(frozen=True)
class SqlPolicy:
    read_only: bool = True
    max_rows: Optional[int] = 100          # None = no LIMIT requirement
    rewrite_limit: bool = False            # add/clamp LIMIT instead of blocking
    require_filter_column: Optional[str] = None   # e.g. "tenant_id"
    denied_tables: FrozenSet[str] = field(default_factory=frozenset)
    allowed_tables: Optional[FrozenSet[str]] = None
    dialect: Optional[str] = None          # "postgres", "sqlite", "mysql", ...
    extra_denied_functions: FrozenSet[str] = field(default_factory=frozenset)
    allowed_functions: Optional[FrozenSet[str]] = None   # strict allow-list of function names (None = deny-list only)
    allow_recursive: bool = False          # WITH RECURSIVE can run for ever / eat memory: blocked unless you opt in


@dataclass(frozen=True)
class SqlVerdict:
    allowed: bool
    reason: str
    sql: str                               # possibly rewritten SQL
    statement_type: str = ""


def _own_aggregate(projection: exp.Expression, select: exp.Select) -> bool:
    """Does this output column contain an aggregate that belongs to ``select`` itself?

    An aggregate inside a nested sub-query (``(SELECT max(id) FROM t2)``), a CTE, a UNION or a derived table belongs
    to THAT inner query: it says nothing about how many rows ``select`` returns (internal review 28 Oct 2026, finding A4-1)."""
    for agg in projection.find_all(exp.AggFunc):
        if agg.find_ancestor(exp.Select) is select:
            return True
    return False


def _is_pure_aggregate(select: exp.Select) -> bool:
    """True only when the query returns exactly one row: no GROUP BY, no window function, and every output column
    has an aggregate of this query's OWN scope (aggregates hidden in sub-queries do not count, A4-1)."""
    if select.args.get("group") or select.find(exp.Window) is not None:
        return False
    projections = select.expressions
    return bool(projections) and all(_own_aggregate(p, select) for p in projections)


def _func_name(node: exp.Expression) -> str:
    if isinstance(node, exp.Anonymous):
        this = node.this
        return str(this.name if isinstance(this, exp.Expression) else this).lower()
    try:
        return node.sql_name().lower()
    except Exception:  # pragma: no cover - defensive
        return type(node).__name__.lower()


def _function_qualifiers(stmt: exp.Expression) -> set:
    """Package / schema names written in front of a function call: ``UTL_HTTP.request(...)`` gives {"utl_http"}.

    sqlglot keeps such a call as Dot(qualifier, function); the guard checked just the function's own name, so a
    denied PACKAGE slipped through (found while fixing M1, 14 Nov 2026). Used for the deny list, not the allow-list."""
    names = set()
    for node in stmt.find_all(exp.Func):
        parent = node.parent
        if isinstance(parent, exp.Dot) and parent.expression is node:
            for part in parent.this.find_all(exp.Identifier):
                names.add(str(part.this).lower())
    return names


def _family_denied_functions(funcs: set, dialect: Optional[str]) -> set:
    """Fail-closed rules for whole families of names, by dialect (``None`` = the generic reading, so every family).

    DuckDB: any name starting with ``read_`` or ending in ``_scan`` reads files or other databases (review 2, H7).
    PostgreSQL: pg_* / lo_* / txid_* / dblink* except PG_HARMLESS_FUNCTIONS. SQLite: sqlite_* except
    SQLITE_HARMLESS_FUNCTIONS (D-115)."""
    d = (dialect or "").lower()
    found = set()
    if d in ("", "duckdb"):
        found |= {n for n in funcs if n.startswith("read_") or n.endswith("_scan")}
    if d in ("", "postgres", "postgresql"):
        found |= {n for n in funcs if n.startswith(PG_FUNCTION_FAMILIES) and n not in PG_HARMLESS_FUNCTIONS}
        found |= {n for n in funcs if n == "http" or n.startswith(PG_EXTENSION_FAMILIES)}         # G4
    if d in ("", "sqlite"):
        found |= {n for n in funcs if n.startswith("sqlite_") and n not in SQLITE_HARMLESS_FUNCTIONS}
        found |= {n for n in funcs if n.startswith("pragma_") and n not in SQLITE_SCHEMA_PRAGMAS}  # G2
    return found


def _family_denied_tables(refs: list, dialect: Optional[str]) -> set:
    """pg_* tables (PostgreSQL) and sqlite_* tables (SQLite) are denied except the schema tables named above (D-115)."""
    d = (dialect or "").lower()
    found = set()
    for ref in refs:
        name = ref[2]
        if d in ("", "postgres", "postgresql") and name.startswith("pg_") and name not in PG_SCHEMA_TABLES:
            found.add(".".join(x for x in ref if x))
        if d in ("", "sqlite") and name.startswith("sqlite_") and name not in SQLITE_SCHEMA_TABLES:
            found.add(".".join(x for x in ref if x))
        if d in ("", "sqlite") and ((name.startswith("pragma_") and name not in SQLITE_SCHEMA_PRAGMAS)
                                    or name in SQLITE_DENIED_TABLES):                             # G2
            found.add(".".join(x for x in ref if x))
    return found


def _function_names(stmt: exp.Expression) -> set:
    names = set()
    for node in stmt.find_all(exp.Func):
        if type(node).__name__ in _STRUCTURAL_FUNCS:
            continue
        names.add(_func_name(node))
        # sqlglot may map some aggregates to dedicated classes; also record the class name for them
        names.add(type(node).__name__.lower())
    return names


def _const_like(node: Optional[exp.Expression]) -> bool:
    """A literal, a bind placeholder, or a cast/negation of one - never a column or a sub-query."""
    while isinstance(node, (exp.Cast, exp.TryCast, exp.Paren, exp.Neg)):
        node = node.this
    return isinstance(node, (exp.Literal, exp.Placeholder, exp.Parameter, exp.Null)) and not isinstance(node, exp.Null)


def _tenant_column(node: Optional[exp.Expression], column: str) -> Optional[exp.Column]:
    if isinstance(node, exp.Column) and node.name.lower() == column.lower():
        return node
    return None


def _guarantees(cond: Optional[exp.Expression], column: str, qualifier: Optional[str]) -> bool:
    """True only if EVERY row that passes ``cond`` must have ``column`` compared to a constant/placeholder.

    AND needs one guaranteeing side, OR needs all sides, NOT / <> / ranges / column-to-column never count.
    ``qualifier`` (alias or table name) is required to match when given; None accepts an unqualified column.
    """
    if cond is None:
        return False
    if isinstance(cond, exp.Paren):
        return _guarantees(cond.this, column, qualifier)
    if isinstance(cond, exp.And):
        return _guarantees(cond.left, column, qualifier) or _guarantees(cond.right, column, qualifier)
    if isinstance(cond, exp.Or):
        return _guarantees(cond.left, column, qualifier) and _guarantees(cond.right, column, qualifier)

    def _qual_ok(col: exp.Column) -> bool:
        if qualifier is None:
            return True
        return col.table.lower() == qualifier.lower() if col.table else False

    if isinstance(cond, exp.EQ):
        for a, b in ((cond.left, cond.right), (cond.right, cond.left)):
            col = _tenant_column(a, column)
            if col is not None and _qual_ok(col) and _const_like(b):
                return True
        return False
    if isinstance(cond, exp.In):
        col = _tenant_column(cond.this, column)
        items = cond.expressions
        return (col is not None and _qual_ok(col) and cond.args.get("query") is None and not cond.args.get("unnest")
                and bool(items) and all(_const_like(i) for i in items))
    return False


def _direct_tables(select: exp.Select) -> list:
    sources = []
    frm = select.args.get("from_") or select.args.get("from")
    if frm is not None:
        sources.append(frm.this)
    for j in select.args.get("joins") or []:
        sources.append(j.this)
    return [s for s in sources if isinstance(s, exp.Table)]


def _limit_value(node: Optional[exp.Expression]) -> Optional[int]:
    """Value of a plain non-negative integer literal; anything else (expression, ALL, NULL, -1, sub-query) is None."""
    if isinstance(node, exp.Literal) and not node.is_string:
        try:
            return int(node.this)
        except ValueError:
            return None
    return None


def _row_cap(stmt: exp.Expression) -> Optional[int]:
    """Largest number of rows the statement can return, or None if unbounded/unknown (fail-closed)."""
    caps = []
    for key in ("limit", "fetch"):
        node = stmt.args.get(key)
        if node is None:
            continue
        if isinstance(node, exp.Fetch):          # FETCH FIRST n ROWS ONLY (sqlglot stores it under "limit")
            opts = node.args.get("limit_options")
            if node.args.get("percent") or (opts is not None and (opts.args.get("percent") or opts.args.get("with_ties"))):
                return None
            v = _limit_value(node.args.get("count"))
        else:
            v = _limit_value(node.expression)
        if v is None:
            return None
        caps.append(v)
    return min(caps) if caps else None


_DEFAULT_SCHEMAS = {
    "postgres": {"", "public"}, "redshift": {"", "public"}, "sqlite": {"", "main"}, "duckdb": {"", "main"},
    "tsql": {"", "dbo"}, "fabric": {"", "dbo"},
}


def _entry_matches(entry: str, ref: tuple, dialect: Optional[str], bare_any: bool) -> bool:
    """Does a policy entry ("orders", "sales.orders", "db.sales.orders") name the table ``ref`` = (catalog, schema, name)?

    Deny lists (``bare_any=True``): a bare name matches that table in EVERY schema (strict).
    Allow lists (``bare_any=False``): a bare name means the DEFAULT schema only (``public``/``main``/``dbo`` or no
    prefix); to allow another schema write ``schema.table``. A catalog prefix in the query is ignored unless the
    entry has one. Which schema an unqualified name really reaches depends on the database's search_path: keep that
    pinned on the database account too.
    """
    parts = [p.strip().strip('"').strip("`") for p in entry.split(".")]
    cat = db = ""
    if len(parts) == 1:
        name = parts[0]
    elif len(parts) == 2:
        db, name = parts
    else:
        cat, db, name = parts[-3], parts[-2], parts[-1]
    if name != ref[2]:
        return False
    if cat and cat != ref[0]:
        return False
    if db:
        return db == ref[1]
    if bare_any:
        return True
    defaults = _DEFAULT_SCHEMAS.get(dialect or "", {"", "public", "main"})
    return ref[1] in defaults


def check_sql(sql: str, policy: SqlPolicy = SqlPolicy()) -> SqlVerdict:
    """Judge one SQL statement against ``policy``. Never raises: any failure inside the guard is a block (L1)."""
    try:
        return _check_sql(sql, policy)
    except Exception:            # RecursionError on very deep nesting, MemoryError, or anything unexpected
        return SqlVerdict(False, "query too complex (blocked, fail-closed)", sql)


def _nested_block_comment(sql: str) -> bool:
    """True when a /* ... */ comment holds another "/*" (PostgreSQL nests comments, MySQL does not)."""
    start = sql.find("/*")
    while start != -1:
        end = sql.find("*/", start + 2)
        inner = sql.find("/*", start + 2)
        if end == -1 or (inner != -1 and inner < end):
            return end != -1
        start = sql.find("/*", end + 2)
    return False


def _check_sql(sql: str, policy: SqlPolicy) -> SqlVerdict:
    if len(sql) > MAX_SQL_BYTES or len(sql.encode("utf-8")) > MAX_SQL_BYTES:
        return SqlVerdict(False, "query too long (blocked)", sql)
    if _EXECUTABLE_COMMENT.search(sql):
        return SqlVerdict(False, "MySQL/MariaDB executable comment /*! */ blocked (fail-closed)", sql)
    if _UNICODE_ESCAPE.search(sql):
        return SqlVerdict(False, "unicode-escaped identifier/string blocked (fail-closed)", sql)
    if (policy.dialect or "").lower() in ("", "mysql") and _DASH_DASH_NO_SPACE.search(sql):
        # MySQL/MariaDB read "--x" as minus-minus-x, not as a comment (founder's decision, 14 Nov 2026: mysql too)
        return SqlVerdict(False, "'--' without a following space is read differently by MySQL (blocked; set "
                                 "SqlPolicy(dialect=...) to your database)", sql)
    if policy.dialect is None:
        if _nested_block_comment(sql):
            return SqlVerdict(False, "nested /* */ comment is read differently by MySQL and PostgreSQL (blocked; set "
                                     "SqlPolicy(dialect=...) to your database)", sql)
    try:
        statements = [s for s in sqlglot.parse(sql, read=policy.dialect) if s is not None]
    except ParseError as e:
        return SqlVerdict(False, f"unparseable SQL (blocked, fail-closed): {str(e).splitlines()[0]}", sql)
    if len(statements) != 1:
        return SqlVerdict(False, f"expected exactly 1 statement, got {len(statements)}", sql)
    stmt = statements[0]
    stype = type(stmt).__name__.upper()

    if policy.read_only:
        if isinstance(stmt, _WRITE_NODES) or any(stmt.find_all(*_WRITE_NODES)):
            return SqlVerdict(False, f"write/DDL statement blocked by read-only policy ({stype})", sql, stype)
        if stmt.find(exp.Into) is not None:
            return SqlVerdict(False, "SELECT ... INTO blocked by read-only policy", sql, stype)
        if not isinstance(stmt, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
            return SqlVerdict(False, f"only SELECT is allowed in read-only mode (got {stype})", sql, stype)
        if stmt.find(exp.Lock) is not None:
            return SqlVerdict(False, "row-locking SELECT (FOR UPDATE/SHARE) blocked by read-only policy", sql, stype)
        hint_cls = getattr(exp, "WithTableHint", None)
        if hint_cls is not None:
            for hint in stmt.find_all(hint_cls):
                locking = sorted({h.name.upper() for h in hint.expressions} & _LOCKING_TABLE_HINTS)
                if locking:
                    return SqlVerdict(False, f"row-locking table hint blocked by read-only policy: {', '.join(locking)}",
                                      sql, stype)
        # old T-SQL form without WITH: "FROM users (UPDLOCK)" - sqlglot 28.x reads it as a call users(UPDLOCK)
        for table in stmt.find_all(exp.Table):
            if isinstance(table.this, exp.Anonymous):
                args = {a.name.upper() for a in table.this.expressions if isinstance(a, (exp.Column, exp.Var))}
                locking = sorted(args & _LOCKING_TABLE_HINTS)
                if locking:
                    return SqlVerdict(False, f"row-locking table hint blocked by read-only policy: {', '.join(locking)}",
                                      sql, stype)

    funcs = _function_names(stmt)
    bad_agg = funcs & CONCAT_AGGREGATES
    if not bad_agg:
        bad_agg = {n for n in funcs if _is_folding_name(n)}
    if not bad_agg:
        bad_agg = _folding_attributes(stmt) | _top_n_or_multi_value(stmt)
    if not bad_agg:
        # T-SQL FOR JSON / FOR XML turn a whole result into one value (14 Nov 2026, M1)
        for select in stmt.find_all(exp.Select):
            if select.args.get("for_") or select.args.get("for"):
                bad_agg = {"for json/xml"}
                break
    if not bad_agg:
        for node in stmt.find_all(exp.AggFunc):
            cname = type(node).__name__.lower()
            if cname.endswith("agg") or isinstance(node, exp.GroupConcat):
                bad_agg = {cname}
                break
    if not bad_agg:
        # ARRAY(SELECT ...) folds the rows of a sub-query into one value (re-audit R2)
        for node in stmt.find_all(exp.Array):
            if any(isinstance(x, (exp.Select, exp.Subquery, exp.Union, exp.Intersect, exp.Except))
                   for x in node.expressions):
                bad_agg = {"array(subquery)"}
                break
    if bad_agg:
        return SqlVerdict(False, f"row-folding aggregate blocked (bulk extraction guard): {', '.join(sorted(bad_agg))}",
                          sql, stype)
    denied_f = ((funcs | _function_qualifiers(stmt)) & (DEFAULT_DENIED_FUNCTIONS
                                                        | {f.lower() for f in policy.extra_denied_functions})
                | _family_denied_functions(funcs, policy.dialect))
    if denied_f:
        return SqlVerdict(False, f"denied function(s): {', '.join(sorted(denied_f))}", sql, stype)
    if policy.allowed_functions is not None:
        allow = {f.lower() for f in policy.allowed_functions}
        extra = {n for n in funcs if n not in allow}
        if extra:
            return SqlVerdict(False, f"function(s) not in allow-list: {', '.join(sorted(extra))}", sql, stype)

    if not policy.allow_recursive:
        for w in stmt.find_all(exp.With):
            if w.args.get("recursive"):
                return SqlVerdict(False, "WITH RECURSIVE blocked (can run without end); set allow_recursive=True "
                                         "and a database statement_timeout if you need it", sql, stype)

    ctes = {c.alias.lower() for c in stmt.find_all(exp.CTE) if c.alias}
    refs = []                                   # (catalog, schema, name) of every real table, lower case
    for t in stmt.find_all(exp.Table):
        if isinstance(t.this, exp.Identifier) and set(t.name) & _PATH_CHARS:
            return SqlVerdict(False, f"file path used as a table blocked: {t.name!r}", sql, stype)
        ref = ((t.catalog or "").lower(), (t.db or "").lower(), t.name.lower())
        if not ref[0] and not ref[1] and ref[2] in ctes:
            continue                            # a CTE name, not a table
        refs.append(ref)
    deny = {t.lower() for t in policy.denied_tables} | DEFAULT_DENIED_TABLES
    denied = sorted({".".join(x for x in r if x) for r in refs if any(_entry_matches(e, r, dialect=None, bare_any=True)
                                                                         for e in deny)}
                    | _family_denied_tables(refs, policy.dialect))
    if denied:
        return SqlVerdict(False, f"denied table(s): {', '.join(denied)}", sql, stype)
    if policy.allowed_tables is not None:
        allow = {t.lower() for t in policy.allowed_tables}
        extra = sorted({".".join(x for x in r if x) for r in refs
                        if not any(_entry_matches(e, r, dialect=policy.dialect, bare_any=False) for e in allow)})
        if extra:
            return SqlVerdict(False, f"table(s) not in allow-list: {', '.join(extra)}", sql, stype)

    if policy.require_filter_column:
        col = policy.require_filter_column
        for select in stmt.find_all(exp.Select):
            direct = _direct_tables(select)
            has_func_source = any(not isinstance(t.this, exp.Identifier) for t in direct)
            if not direct:
                # sources are sub-queries / nothing: their own SELECTs are checked as part of this loop
                continue
            where = select.args.get("where")
            where = where.this if where is not None else None
            if len(direct) == 1 and not has_func_source:
                ok = _guarantees(where, col, None)
            else:
                ok = not has_func_source and all(
                    _guarantees(where, col, t.alias_or_name) for t in direct)
            if not ok:
                return SqlVerdict(False, f"missing required filter: WHERE {col} = <value> on every table "
                                         f"(OR / NOT / column-to-column / ranges do not count)", sql, stype)

    if policy.max_rows is not None and isinstance(stmt, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
        if not (isinstance(stmt, exp.Select) and _is_pure_aggregate(stmt)):
            current = _row_cap(stmt)
            if current is None or current > policy.max_rows:
                if policy.rewrite_limit:
                    new = stmt.copy()
                    new.set("fetch", None)
                    new = new.limit(policy.max_rows, copy=False)
                    return SqlVerdict(True, f"LIMIT clamped to {policy.max_rows}", new.sql(dialect=policy.dialect), stype)
                return SqlVerdict(False, f"query must have a plain integer LIMIT <= {policy.max_rows} "
                                         f"(bulk extraction guard)", sql, stype)

    return SqlVerdict(True, "ok", sql, stype)
