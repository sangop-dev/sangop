"""SQL AST guard built on sqlglot.

Fail-closed: anything that cannot be parsed, or contains more than one
statement, is blocked. Regex is never used to judge SQL safety.
"""

from __future__ import annotations

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
})

# System catalogs that expose server configuration or credentials (re-audit R3). Matched on the bare table name,
# so ``pg_catalog.pg_settings`` is caught too.
DEFAULT_DENIED_TABLES = frozenset({
    "pg_settings", "pg_file_settings", "pg_hba_file_rules", "pg_ident_file_mappings", "pg_shadow", "pg_authid",
    "pg_user_mappings", "pg_stat_activity",
})

# Aggregates that fold many rows into ONE value: they would defeat the row-count (LIMIT) guard (audit finding H4).
CONCAT_AGGREGATES = frozenset({
    "string_agg", "group_concat", "listagg", "json_agg", "jsonb_agg", "json_object_agg", "jsonb_object_agg",
    "json_group_array", "json_group_object", "array_agg", "xmlagg", "collect_list", "collect_set", "list",
    "array_concat_agg", "string_agg_distinct", "wm_concat", "json_arrayagg", "json_objectagg", "any_value_list",
})

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

    funcs = _function_names(stmt)
    bad_agg = funcs & CONCAT_AGGREGATES
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
    denied_f = funcs & (DEFAULT_DENIED_FUNCTIONS | {f.lower() for f in policy.extra_denied_functions})
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
        ref = ((t.catalog or "").lower(), (t.db or "").lower(), t.name.lower())
        if not ref[0] and not ref[1] and ref[2] in ctes:
            continue                            # a CTE name, not a table
        refs.append(ref)
    deny = {t.lower() for t in policy.denied_tables} | DEFAULT_DENIED_TABLES
    denied = sorted({".".join(x for x in r if x) for r in refs if any(_entry_matches(e, r, dialect=None, bare_any=True)
                                                                         for e in deny)})
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
