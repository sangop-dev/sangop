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
    # PostgreSQL contrib functions that run a query or a table given as text (review 3, 14 Nov 2026, N1); see also
    # the crosstab* family rule below
    "crosstab", "crosstab2", "crosstab3", "crosstab4", "crosstab_hash", "connectby", "xpath_table", "xslt_process",
    # DuckDB serialized-SQL execution (review 3, N2); see also the *execute* / *serialize* rule below
    "json_execute_serialized_sql", "json_serialize_sql", "json_deserialize_sql", "json_serialize_plan",
    # PostgreSQL page inspection and index maintenance (review 3, M2)
    "get_raw_page", "bt_page_items", "bt_metap", "heap_page_items", "page_header", "pgstattuple",
    "pgstattuple_approx", "pgstatindex", "pgrowlocks", "brin_summarize_new_values", "brin_summarize_range",
    "brin_desummarize_range", "gin_clean_pending_list",
    # T-SQL: other sessions' SQL text, as a table-valued function (review 3, M3; also a denied table)
    "dm_exec_sql_text",
    # DuckDB secrets and settings (review 3, L1); MySQL replication waits (review 3, L2)
    "duckdb_secrets", "duckdb_settings", "which_secret",
    "source_pos_wait", "wait_for_executed_gtid_set", "wait_until_sql_thread_after_gtids",
    # review 4 (15 Nov 2026): functions that change tables or pages inside a SELECT (H3, M2, L1); also refused when a
    # user adds the name to extra_allowed_functions
    "dropgeometrytable", "dropgeometrycolumn", "addgeometrycolumn", "updategeometrysrid", "populate_geometry_columns",
    "postgis_extensions_upgrade", "droptopology", "createtopology", "addtopogeometrycolumn", "addrasterconstraints",
    "droprasterconstraints", "heap_force_kill", "heap_force_freeze", "autoprewarm_dump_now",
    "autoprewarm_start_worker",
})

# System catalogs that expose server configuration or credentials (re-audit R3). Matched on the bare table name,
# so ``pg_catalog.pg_settings`` is caught too.
DEFAULT_DENIED_TABLES = frozenset({
    "pg_settings", "pg_file_settings", "pg_hba_file_rules", "pg_ident_file_mappings", "pg_shadow", "pg_authid",
    "pg_user_mappings", "pg_stat_activity",
    "user_mapping_options",                           # shows foreign-server passwords (internal review 2, 14 Nov 2026, M3)
    "pg_stat_statements", "pg_stat_statements_info",  # other sessions' query texts (14 Nov 2026, D-115)
    # MySQL / SQL Server views with other sessions' SQL text or credentials (review 3, 14 Nov 2026, M3).
    # "user" only as mysql.user: a bare "user" is a common application table name.
    "processlist", "events_statements_current", "events_statements_history", "events_statements_history_long",
    "statement_analysis", "mysql.user", "sql_logins", "sysxlogins", "dm_exec_sql_text", "dm_exec_requests",
    "dm_exec_sessions",
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
PG_EXTENSION_FAMILIES = ("postgres_fdw", "http_", "crosstab")      # crosstab*: review 3, N1
# The PostgreSQL rules apply to these dialects; the "--" rule to the MySQL-family ones ("" = dialect None)
# (review 3, 14 Nov 2026, M1).
PG_LIKE_DIALECTS = ("", "postgres", "postgresql", "redshift", "materialize", "risingwave")
MYSQL_LIKE_DIALECTS = ("", "mysql", "doris", "starrocks", "singlestore")

# Aggregates that fold many rows into ONE value: they would defeat the row-count (LIMIT) guard (audit finding H4).
CONCAT_AGGREGATES = frozenset({
    # review 4 (15 Nov 2026, H2): aggregates that fold whole rows or many rows' locations into one value
    "st_asmvt", "st_asgeobuf", "st_asflatgeobuf", "st_collect", "st_makeline", "st_union", "st_memunion",
    "st_polygonize", "st_clusterintersecting", "st_clusterwithin", "st_coverageunion",
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
_ARG_NULL_NAMES = frozenset({"arg_max_null", "arg_min_null"})   # DuckDB, sqlglot keeps them as Anonymous
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
        elif (isinstance(node, exp.Anonymous) and _func_name(node) in _ARG_NULL_NAMES
              and len(node.expressions) >= 3):                                     # 14 Nov 2026 follow-up
            found.add(f"{_func_name(node)}(x, y, n)")
        elif cls in _MULTI_QUANTILE_CLASSES or (isinstance(node, exp.Anonymous)
                                                and ("quantile" in _func_name(node) or "percentile" in _func_name(node))):
            # The fraction must be ONE plain number from 0 to 1 (or a bind placeholder): an array, a cast, a string,
            # a column, a sub-query or an expression can hold many fractions, one row's value each (review 5, H1).
            fraction = _quantile_fraction(node)
            if fraction is not None and not _plain_fraction(fraction):
                found.add(f"{_func_name(node)}(array)")
    return found


def _quantile_fraction(node: exp.Func) -> Optional[exp.Expression]:
    if isinstance(node, exp.Anonymous):
        return node.expressions[-1] if node.expressions else None
    if node.args.get("quantile") is not None:
        return node.args["quantile"]
    if node.args.get("expression") is not None:          # DuckDB percentile_cont(x, 0.5)
        return node.args["expression"]
    return node.this                                      # percentile_cont(0.5) WITHIN GROUP (ORDER BY x)


def _plain_fraction(arg: exp.Expression) -> bool:
    while isinstance(arg, exp.Paren):
        arg = arg.this
    if isinstance(arg, (exp.Placeholder, exp.Parameter)):
        return True
    if isinstance(arg, exp.Literal) and not arg.is_string:
        try:
            return 0 <= float(str(arg.this)) <= 1
        except ValueError:
            return False
    return False


# Common string / date functions that never run a text argument as a query: plain text in their arguments is not
# refused by the text-query rule (14 Nov 2026, D-117). Matched by the name as written (unknown functions) and by the
# node sqlglot builds for it (it turns many of them into typed nodes: ifnull/nvl -> Coalesce, instr -> StrPosition).
# A function nested inside one of these is still checked on its own.
SAFE_TEXT_ARG_FUNCTIONS = frozenset({
    "coalesce", "nullif", "greatest", "least", "concat", "concat_ws", "replace", "translate", "lower", "upper",
    "initcap", "trim", "btrim", "ltrim", "rtrim", "substring", "substr", "left", "right", "position", "strpos", "instr",
    "split_part", "starts_with", "length", "char_length", "octet_length", "lpad", "rpad", "reverse", "md5", "encode",
    "decode", "to_char", "to_date", "to_timestamp", "format_date", "strftime", "date", "datetime", "json_extract",
    "json_extract_path_text", "jsonb_extract_path_text", "regexp_replace", "regexp_like", "like", "ilike", "ifnull",
    "iif", "nvl", "nvl2", "case",
    # second follow-up, 14 Nov 2026
    "regexp_match", "regexp_matches", "regexp_split_to_array", "regexp_split_to_table", "regexp_count",
    "regexp_instr", "regexp_substr", "regexp_extract", "similar_to", "to_number", "format",
    # review 4 (15 Nov 2026, L3): array constructors, JSON object builders and text search parse text, never run it
    "array", "json_build_object", "jsonb_build_object", "to_tsquery", "plainto_tsquery", "phraseto_tsquery",
    "websearch_to_tsquery", "to_tsvector",
})
_SAFE_TEXT_ARG_CLASSES = frozenset({
    "coalesce", "nullif", "greatest", "least", "concat", "concatws", "replace", "translate", "lower", "upper",
    "initcap", "trim", "substring", "left", "right", "strposition", "splitpart", "startswith", "length", "pad",
    "reverse", "md5", "md5digest", "encode", "decode", "decodecase", "timetostr", "tochar", "strtodate",
    "tsordstodate", "strtotime", "date", "datefromparts", "timestampfromparts", "jsonextract", "jsonextractscalar",
    "regexpreplace", "regexplike", "if", "nvl2", "case",
    "regexpcount", "regexpinstr", "regexpsubstr", "regexpextract", "tonumber", "format", "numbertostr",
    "array", "jsonobject",
})
# String nodes whose text is checked (D-117 follow-ups): quoted literals, and every other string-literal node sqlglot
# has - RawString (PostgreSQL / DuckDB $$...$$, $tag$...$tag$), ByteString (E'...'), National (N'...'),
# UnicodeString (U&'...'), HexString (X'...'), BitString (B'...') and any future non-function class whose name ends
# in "String" - also behind CAST, TRY_CAST, :: or brackets. Hex and bit strings are decoded before the check.
_STRING_NODES = tuple(c for c in (exp.RawString, getattr(exp, "National", None)) if c is not None)


def _decoded(arg, text: str) -> str:
    name = type(arg).__name__
    try:
        if name == "HexString":
            return bytes.fromhex(text).decode("utf-8", "replace")
        if name == "BitString" and text and len(text) % 8 == 0 and set(text) <= {"0", "1"}:
            return bytes(int(text[i:i + 8], 2) for i in range(0, len(text), 8)).decode("utf-8", "replace")
    except ValueError:
        pass
    return text


def _argument_text(arg) -> Optional[str]:
    while isinstance(arg, (exp.Cast, exp.TryCast, exp.Paren, exp.Kwarg, exp.PropertyEQ)):
        arg = arg.expression if isinstance(arg, (exp.Kwarg, exp.PropertyEQ)) else arg.this
    if isinstance(arg, exp.Literal):
        return str(arg.this) if arg.is_string else None
    if (isinstance(arg, exp.Expression) and not isinstance(arg, exp.Func) and isinstance(arg.this, str)
            and (isinstance(arg, _STRING_NODES) or type(arg).__name__.endswith("String"))):
        return _decoded(arg, arg.this)
    return None


def _keeps_plain_text(node: exp.Func) -> bool:
    if isinstance(node, exp.Anonymous):
        return node.name.lower() in SAFE_TEXT_ARG_FUNCTIONS
    if type(node).__name__.lower() in _SAFE_TEXT_ARG_CLASSES:
        return True
    return any(n.lower() in SAFE_TEXT_ARG_FUNCTIONS for n in type(node).sql_names())


def _sql_text_arguments(stmt: exp.Expression) -> list:
    """Names of functions (table-functions and unknown functions included) that get SQL text as a string argument.
    Several database functions run such text as a query (crosstab, query_to_xml, ts_stat, dblink, DuckDB query,
    json_serialize_sql, ...); new ones appear with new versions, so the shape is refused, fail-closed (D-117).
    CAST / TRY_CAST are skipped: they convert a value and never run it (text behind one, passed on to another
    function, is still checked)."""
    found = []
    for node in stmt.find_all(exp.Func):
        if isinstance(node, (exp.Cast, exp.TryCast)) or _keeps_plain_text(node):
            continue
        for value in node.args.values():
            for arg in (value if isinstance(value, list) else [value]):
                text = _argument_text(arg)
                if text is not None and _looks_like_sql(text):
                    found.append(node.name.lower() if isinstance(node, exp.Anonymous) else node.sql_name().lower())
    return found


def _has_dynamic_pivot(stmt: exp.Expression) -> bool:
    """A PIVOT whose output columns come from the data folds a whole column into one row (review 3, N3): DuckDB
    "ON col" without IN, Snowflake "IN (ANY ...)" or "IN (SELECT ...)". A PIVOT that lists its values as literals or
    names (T-SQL "IN ([a],[b])", "IN ('a','b')") is allowed; UNPIVOT is allowed."""
    for pivot in stmt.find_all(exp.Pivot):
        if pivot.args.get("unpivot"):
            continue
        fields = pivot.args.get("fields") or pivot.expressions        # DuckDB keeps its ON part in expressions
        if not fields:
            return True
        for field in fields:
            if not isinstance(field, exp.In) or field.args.get("query") or not field.expressions:
                return True
            for value in field.expressions:
                if isinstance(value, exp.Alias):
                    value = value.this
                if not isinstance(value, (exp.Literal, exp.Identifier, exp.Column)) or value.find(exp.Select):
                    return True
    return False


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
# A string argument that reads as SQL: a statement keyword as a whole word, then more text (D-117)
# The keyword may be followed by whitespace and more text, or directly by * ( " ` [ (review 4, M1: 'SELECT*FROM t',
# 'SELECT(email)FROM t'); a single word ('from', 'select') or a longer word ('selected', 'showcase') is plain text.
_SQL_TEXT_ARGUMENT = re.compile(
    r"(select|with|values|table|from|insert|update|delete|merge|copy|call|exec|execute|pivot|unpivot"
    r"|explain|show|prepare|do)(?:\s+\S|[*(\"`\[])",
    re.IGNORECASE)


def _looks_like_sql(text: str) -> bool:
    """Leading /* ... */ and -- comments are removed first (review 4, M1). Backslash escapes (E'...\\n...', which
    sqlglot 28.5 keeps as written) are also read decoded."""
    if "\\" in text:
        try:
            decoded = text.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except (UnicodeDecodeError, ValueError):
            decoded = text
        if decoded != text and _looks_like_sql(decoded.replace("\\", "")):
            return True
    i, n = 0, len(text)
    while i < n:                                         # linear scan: no regex backtracking on long input
        if text[i].isspace() or text[i] == "(":
            i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif text.startswith("--", i):
            end = text.find("\n", i + 2)
            i = n if end < 0 else end + 1
        else:
            break
    return bool(_SQL_TEXT_ARGUMENT.match(text, i))

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
    allowed_functions: Optional[FrozenSet[str]] = None   # your own full allow-list (None = the default, see below)
    extra_allowed_functions: FrozenSet[str] = field(default_factory=frozenset)   # names added to the allow-list
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
        found |= {n for n in funcs if "execute" in n or "serialize" in n}                       # review 3, N2
        found |= {n for n in funcs if n == "getenv"}                                             # 14 Nov 2026 follow-up
    if d in PG_LIKE_DIALECTS:
        found |= {n for n in funcs if n.startswith(PG_FUNCTION_FAMILIES) and n not in PG_HARMLESS_FUNCTIONS}
        found |= {n for n in funcs if n == "http" or n.startswith(PG_EXTENSION_FAMILIES)}         # G4
    if d in ("", "sqlite"):
        found |= {n for n in funcs if n.startswith("sqlite_") and n not in SQLITE_HARMLESS_FUNCTIONS}
        found |= {n for n in funcs if n.startswith("pragma_") and n not in SQLITE_SCHEMA_PRAGMAS}  # G2
        found |= {n for n in funcs if n in ("eval", "sha3_query")}                  # review 4, L2: run text as SQL
    return found


def _family_denied_tables(refs: list, dialect: Optional[str]) -> set:
    """pg_* tables (PostgreSQL) and sqlite_* tables (SQLite) are denied except the schema tables named above (D-115)."""
    d = (dialect or "").lower()
    found = set()
    for ref in refs:
        name = ref[2]
        if d in PG_LIKE_DIALECTS and name.startswith("pg_") and name not in PG_SCHEMA_TABLES:
            found.add(".".join(x for x in ref if x))
        if d in ("", "sqlite") and name.startswith("sqlite_") and name not in SQLITE_SCHEMA_TABLES:
            found.add(".".join(x for x in ref if x))
        if d in ("", "sqlite") and ((name.startswith("pragma_") and name not in SQLITE_SCHEMA_PRAGMAS)
                                    or name in SQLITE_DENIED_TABLES):                             # G2
            found.add(".".join(x for x in ref if x))
    return found


# ---- Default function allow-list (15 Nov 2026, D-119) --------------------------------------------------------------------
# PostgreSQL-like dialects, SQLite and dialect=None: a function that is not on this list is refused. A deny-list kept
# losing to new names (every security review found new ones), so the default is now "known safe names only"; add your
# own with SqlPolicy(extra_allowed_functions=...). The deny-list, the family rules, the row-folding rules, the
# text-query rule and the raw-text checks still run first, on every name, also on names you allow.
ALLOWLIST_DIALECTS = PG_LIKE_DIALECTS + ("sqlite",)

_ALLOWED_SHARED = frozenset({
    # aggregates (max / min with one argument; the many-value forms are row-folding, see above)
    "count", "sum", "avg", "min", "max", "bool_and", "bool_or", "every", "stddev", "stddev_samp", "stddev_pop",
    "variance", "var_samp", "var_pop", "corr", "covar_pop", "covar_samp", "regr_avgx", "regr_avgy", "regr_count",
    "regr_intercept", "regr_r2", "regr_slope", "regr_sxx", "regr_sxy", "regr_syy", "percentile_cont",
    "percentile_disc", "mode", "any_value",
    # window functions
    "row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile", "lag", "lead", "first_value",
    "last_value", "nth_value",
    # conditionals
    "coalesce", "nullif", "greatest", "least", "ifnull", "iif", "nvl",
    # math
    "abs", "ceil", "ceiling", "floor", "round", "trunc", "mod", "power", "pow", "sqrt", "cbrt", "exp", "ln", "log",
    "log10", "log2", "sign", "div", "pi", "degrees", "radians", "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
    "width_bucket",
    # strings (repeat, printf, randomblob and zeroblob are not here: they build large values; lpad / rpad only with a
    # literal length up to _MAX_PAD_LENGTH)
    "lower", "upper", "initcap", "trim", "btrim", "ltrim", "rtrim", "length", "char_length", "character_length",
    "octet_length", "bit_length", "substring", "substr", "left", "right", "position", "strpos", "instr", "replace",
    "translate", "split_part", "concat", "concat_ws", "starts_with", "ascii", "chr", "md5", "encode", "decode",
    "reverse", "format", "regexp_match", "regexp_matches", "regexp_replace", "regexp_like", "regexp_count",
    "regexp_instr", "regexp_substr", "regexp_split_to_array", "similar_to", "lpad", "rpad",
    # date / time
    "now", "current_date", "current_time", "current_timestamp", "localtime", "localtimestamp", "date_trunc",
    "date_part", "extract", "to_char", "to_date", "to_timestamp", "to_number", "date", "time", "datetime",
    "julianday", "strftime",
    # JSON: reading values out, and building one object per row
    "json_extract_path_text", "jsonb_extract_path_text", "json_extract_path", "jsonb_extract_path", "json_typeof",
    "jsonb_typeof", "json_array_length", "jsonb_array_length", "json_extract", "json_build_object",
    "jsonb_build_object", "to_jsonb", "json_object",
    # rows from a range (heavy ranges need a database statement_timeout, see Known limits)
    "generate_series",
    # found common while testing (15 Nov 2026): arrays to text, splitting text into rows
    "array_to_string", "regexp_split_to_table",
}) | PG_HARMLESS_FUNCTIONS | SQLITE_HARMLESS_FUNCTIONS | SQLITE_SCHEMA_PRAGMAS
_ALLOWED_PG_ONLY = frozenset({
    # arrays and JSON: these expand one value or one row, they never fold rows (review 5, L2; a folding sub-query
    # inside is still refused by the row-folding rules)
    "array_length", "array_upper", "array_lower", "array_ndims", "cardinality", "unnest", "string_to_array",
    "array_positions", "array_remove", "array_replace", "array_append", "array_prepend", "array_cat",
    "json_array_elements", "json_array_elements_text", "jsonb_array_elements", "jsonb_array_elements_text",
    "json_each", "json_each_text", "jsonb_each", "jsonb_each_text", "json_object_keys", "jsonb_object_keys",
    "sha224", "sha256", "sha384", "sha512",                                      # review 6, L2: one value each
    "json_array",                    # PostgreSQL 16 JSON_ARRAY(a, b): JSON_ARRAY(SELECT ...) stays row-folding (run4 H1)
    "date_bin", "age", "make_date", "make_time", "make_timestamp", "make_timestamptz", "make_interval", "isfinite",
    "justify_days", "justify_hours", "justify_interval", "array_position", "to_tsvector", "to_tsquery",
    "plainto_tsquery", "phraseto_tsquery", "websearch_to_tsquery",
})
_ALLOWED_SQLITE_ONLY = frozenset({
    "json_each", "json_tree",                                                     # review 5, L2
    "total", "quote", "typeof", "unicode", "hex", "unixepoch", "timediff", "json_type", "json_valid",
})
# The names sqlglot gives to the functions above (it turns many calls into its own nodes: ifnull / nvl -> coalesce,
# instr / strpos -> str_position, strftime -> time_to_str, lpad / rpad -> pad, ...); measured on sqlglot 28.5 and
# 30.31 (15 Nov 2026). Used only when the name a call was written with cannot be found in the query text: a written
# name must itself be on the list (review 5, L1: ucase, year, array_join are sqlglot names, not PostgreSQL ones).
_ALLOWED_SQLGLOT_NAMES = frozenset({
    "anyvalue", "arrayposition", "bitlength", "booland_agg", "boolor_agg", "cast", "char", "concatws", "covarpop",
    "covarsamp", "cumedist", "currentdate", "currenttime", "currenttimestamp", "current_version", "currentversion", "datebin", "datetrunc", "decode_case",
    "decodecase", "denserank", "exploding_generate_series", "explodinggenerateseries", "firstvalue",
    "generateseries", "if", "json_extract_scalar", "jsonextract", "jsonextractscalar", "jsontype", "justifydays",
    "justifyhours", "justifyinterval", "lastvalue", "lcase", "len", "logical_and", "logical_or", "logicaland",
    "logicalor", "makeinterval", "nthvalue", "pad", "percentilecont", "percentiledisc", "percentrank", "regexpcount",
    "regexpinstr", "regexplike", "regexpreplace", "regexpsubstr", "regravgx", "regravgy", "regrcount",
    "regrintercept", "regrr2", "regrslope", "regrsxx", "regrsxy", "regrsyy", "rownumber", "signum", "splitpart",
    "startswith", "stddevpop", "stddevsamp", "stdev", "str_position", "str_to_date", "str_to_time", "strposition",
    "strtodate", "strtotime", "time_from_parts", "time_to_str", "timefromparts", "timestamp_from_parts",
    "timestamp_trunc", "timestampfromparts", "timestamptrunc", "timetostr", "tochar", "tonumber", "truncate",
    "ts_or_ds_to_timestamp", "tsordstotimestamp", "ucase", "unix_to_time", "unixtotime", "variance_pop",
    "variance_samp", "variancepop", "widthbucket",
})
# sqlglot keeps some syntax as function nodes; these are syntax, not function calls: CAST, CASE, IF, EXTRACT,
# INTERVAL, the ARRAY[...] constructor, CURRENT_DATE / CURRENT_TIME / CURRENT_TIMESTAMP, and every operator node
# (AND, OR, ->, ->>, @>, ~, ...). BETWEEN, IN, LIKE and ILIKE are not function nodes in sqlglot.
_SYNTAX_FUNCS = ("Cast", "TryCast", "Paren", "Case", "If", "Extract", "Interval", "Array", "Distinct", "MatchAgainst",
                 "CurrentDate", "CurrentTime", "CurrentTimestamp", "Between", "In", "Like", "ILike", "Collate")
_OPERATOR_FUNCS = tuple(c for c in (getattr(exp, n, None) for n in ("Binary", "Connector", "Unary", "Predicate",
                                                                    "SubqueryPredicate")) if c is not None)
_MAX_PAD_LENGTH = 1000


def default_allowed_functions(dialect: Optional[str]) -> Optional[FrozenSet[str]]:
    """The default function allow-list for ``dialect``, or None where the default is the deny-list only
    (experimental dialects: MySQL, DuckDB, SQL Server, Oracle, ...)."""
    d = (dialect or "").lower()
    if d not in ALLOWLIST_DIALECTS:
        return None
    names = _ALLOWED_SHARED
    if d in PG_LIKE_DIALECTS:
        names |= _ALLOWED_PG_ONLY
    if d in ("", "sqlite"):
        names |= _ALLOWED_SQLITE_ONLY
    return names


def _node_names(node: exp.Func) -> set:
    if isinstance(node, exp.Anonymous):
        return {_func_name(node)}
    names = {_func_name(node), type(node).__name__.lower()}
    try:
        names |= {n.lower() for n in type(node).sql_names()}
    except Exception:  # nosec B110 # pragma: no cover - the written name and class name above are still checked
        pass
    return names


def _qualifier(node: exp.Func) -> Optional[str]:
    parent = node.parent
    if isinstance(parent, exp.Dot) and parent.expression is node:
        return ".".join(str(p.this).lower() for p in parent.this.find_all(exp.Identifier)) or None
    return None


_MAX_REPARSED_CALLS = 200


def _strip_builtin_schema(stmt: exp.Expression, dialect: Optional[str]) -> exp.Expression:
    """Remove a pg_catalog. qualifier (main. for SQLite) from function calls, so that every rule - deny-list,
    family rules, row-folding, text-query, size limits, allow-list - sees the plain name (review 6, M1:
    pg_catalog.lpad('x', 260000000) passed the lpad length limit). Another schema stays: it is the user's own."""
    d = (dialect or "").lower()
    builtin = ({"pg_catalog"} if d in PG_LIKE_DIALECTS else set()) | ({"main"} if d in ("", "sqlite") else set())
    if not builtin:
        return stmt

    budget = [_MAX_REPARSED_CALLS]

    def plain(func: exp.Expression) -> exp.Expression:
        if not isinstance(func, exp.Anonymous):
            return func
        name = _func_name(func)
        node: exp.Expression = exp.Anonymous(this=name, expressions=list(func.expressions))
        budget[0] -= 1
        try:                                       # the node sqlglot builds for the plain name (Pad, Format, ...)
            if budget[0] < 0:                      # past the budget the plain unknown call is kept (each rule
                raise ValueError("budget")         # also reads names); this only avoids re-parsing work
            args = ", ".join(a.sql(dialect=dialect) for a in func.expressions)
            parsed = sqlglot.parse_one(f"{name}({args})", read=dialect)
            if isinstance(parsed, exp.Func):
                node = parsed
        except Exception:  # nosec B110 # keeps the plain unknown call, which every rule still reads by name
            pass
        for part in node.walk():                    # positions would point into another text
            for key in ("line", "col", "start", "end"):
                part.meta.pop(key, None)
        node.meta[_WRITTEN_KEY] = name
        return node

    for _ in range(5):                              # a re-parsed call can hold another qualified call
        if not _strip_once(stmt, builtin, plain):
            break
    return stmt


def _strip_once(stmt: exp.Expression, builtin: set, plain) -> bool:
    swaps = []                                      # (old node, new node); applied per parent list in one go
    for dot in list(stmt.find_all(exp.Dot)):
        qual = dot.this
        last = qual.name if isinstance(qual, (exp.Identifier, exp.Dot)) else None
        if last and last.lower() in builtin and isinstance(dot.expression, exp.Func):
            swaps.append((dot, plain(dot.expression)))
    for col in list(stmt.find_all(exp.Column)):
        table = col.args.get("table")
        inner = col.this
        if (isinstance(table, exp.Identifier) and table.name.lower() in builtin
                and isinstance(inner, exp.Expression) and not isinstance(inner, exp.Identifier)):
            if isinstance(inner, exp.Anonymous):
                inner = plain(inner)
            elif isinstance(inner.args.get("this"), exp.Anonymous):     # pg_catalog.f(...) WITHIN GROUP / OVER
                inner.set("this", plain(inner.this))
            swaps.append((col, inner))
    if not swaps or any(old is stmt for old, _ in swaps):
        return False
    # node.replace() re-parents the whole sibling list each time (quadratic on thousands of calls), so each
    # parent's argument is rebuilt once
    by_slot: dict = {}
    for old, new in swaps:
        by_slot.setdefault((id(old.parent), old.arg_key), (old.parent, old.arg_key, {}))[2][id(old)] = new
    for parent, key, news in by_slot.values():
        value = parent.args.get(key)
        if isinstance(value, list):
            parent.set(key, [news.get(id(item), item) for item in value])
        elif value is not None and id(value) in news:
            parent.set(key, news[id(value)])
    return True


def _pad_too_long(node: exp.Func) -> bool:
    if isinstance(node, exp.Anonymous):                # lpad(text, length[, fill]) kept as an unknown call
        length = node.expressions[1] if len(node.expressions) > 1 else None
    else:
        length = node.args.get("expression")
    if isinstance(length, exp.Literal) and not length.is_string:
        try:
            return int(str(length.this)) > _MAX_PAD_LENGTH
        except ValueError:
            return True
    return True                                        # a column or an expression: size unknown, refuse


def _written_name(node: exp.Func, dialect: Optional[str]) -> Optional[str]:
    """The name as the dialect writes the call (JSONObject -> json_object), for typed nodes; None if unknown."""
    try:
        text = node.sql(dialect=dialect)
    except Exception:  # pragma: no cover - defensive
        return None
    head = text.split("(", 1)[0].strip().lower()
    return head if head and "(" in text and re.fullmatch(r"[a-z_][a-z0-9_]*", head) else None


_IDENT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_$")


def _clean_ident(text: str) -> Optional[str]:
    text = text.strip().strip('"`[]').lower()
    return text if text and all(c in _IDENT_CHARS for c in text) else None


def _written_in_sql(node: exp.Func, sql: Optional[str], dialect: Optional[str]) -> str:
    """The function name as the query wrote it (lpad, not pad; string_agg, not group_concat), for messages.

    sqlglot records where most names stand in the text (node.meta start / end); when it does not, the name is read
    just before the bracket that opens the call; failing that, the name the dialect would write."""
    if isinstance(node, exp.Anonymous):
        return _func_name(node)
    return _written_from_text(node, sql) or _written_name(node, dialect) or _func_name(node)


_WRITTEN_KEY = "sangop_written_name"


def _written_from_text(node: exp.Func, sql: Optional[str]) -> Optional[str]:
    """The name of a typed call as it stands in the query text, or None when it cannot be found there."""
    if isinstance(node, exp.Anonymous):
        return _func_name(node)
    if node.meta and node.meta.get(_WRITTEN_KEY):           # set when a pg_catalog. / main. prefix was removed
        return node.meta[_WRITTEN_KEY]
    if sql:
        meta = node.meta or {}
        start, end = meta.get("start"), meta.get("end")
        if isinstance(start, int) and isinstance(end, int) and 0 <= start <= end < len(sql):
            name = _clean_ident(sql[start:end + 1])
            if name:
                return name
        firsts = [n.meta.get("start") for n in node.walk() if n is not node and n.meta
                  and isinstance(n.meta.get("start"), int)]
        if firsts:
            bracket = sql.rfind("(", 0, min(firsts))
            i = bracket - 1
            while i >= 0 and sql[i].isspace():
                i -= 1
            j = i
            while j >= 0 and (sql[j].lower() in _IDENT_CHARS or sql[j] in '"`'):
                j -= 1
            if bracket > 0 and i > j:
                name = _clean_ident(sql[j + 1:i + 1])
                if name:
                    return name
    return None


def _written_map(stmt: exp.Expression, sql: Optional[str], dialect: Optional[str]) -> dict:
    """sqlglot's names for each call (node names, class name) -> the name the query wrote."""
    names = {}
    for node in stmt.find_all(exp.Func):
        if type(node).__name__ in _SYNTAX_FUNCS or isinstance(node, _OPERATOR_FUNCS):
            continue
        written = _written_in_sql(node, sql, dialect)
        for key in _node_names(node) | {type(node).__name__.lower()}:
            names.setdefault(key, written)
    return names


def _as_written(names, stmt: exp.Expression, sql: Optional[str], dialect: Optional[str]) -> str:
    wmap = _written_map(stmt, sql, dialect)
    shown = []
    for name in sorted(names):
        head, bracket, rest = name.partition("(")
        out = wmap.get(name) or (wmap[head] + bracket + rest if bracket and head in wmap else name)
        if out not in shown:
            shown.append(out)
    return ", ".join(shown)


_FORMAT_SPEC = re.compile(r"%(?:\d+\$)?[-+ #0',!]*(\*(?:\d+\$)?|\d+)?(?:\.(\*(?:\d+\$)?|\d+))?")


def _format_too_big(first: Optional[exp.Expression]) -> bool:
    """format(): the format must be written in the query, with no '*' width / precision and none above
    _MAX_PAD_LENGTH; otherwise one call can build a value of hundreds of megabytes (review 5, M1)."""
    text = _argument_text(first) if first is not None else None
    if text is None:
        return True                                      # format taken from a column or an expression
    i = 0
    while True:
        i = text.find("%", i)
        if i < 0:
            return False
        if text.startswith("%%", i):
            i += 2
            continue
        spec = _FORMAT_SPEC.match(text, i)
        for part in (spec.group(1), spec.group(2)) if spec else ():
            if part and (part.startswith("*") or int(part) > _MAX_PAD_LENGTH):
                return True
        i += 1


def _size_refusal(stmt: exp.Expression, extra: set, sql: Optional[str], dialect: Optional[str]) -> Optional[str]:
    """Allowed functions whose arguments can build a huge value (default allow-list only; a name the user adds to
    extra_allowed_functions is the user's call)."""
    for node in stmt.find_all(exp.Func):
        if type(node).__name__ in _SYNTAX_FUNCS or isinstance(node, _OPERATOR_FUNCS):
            continue
        names = _node_names(node) | {_written_in_sql(node, sql, dialect)}
        if names & extra:
            continue
        if names & {"pad", "lpad", "rpad"} and _pad_too_long(node):
            return "lpad/rpad length must be a literal number up to 1000 (blocked: a longer value uses a lot of memory)"
        if type(node).__name__ == "Format" or (isinstance(node, exp.Anonymous) and _func_name(node) == "format"):
            first = (node.expressions[0] if node.expressions else None) if isinstance(node, exp.Anonymous) else node.this
            if _format_too_big(first):
                return ("format width too large / dynamic width blocked: format() needs its format written in the "
                        "query, with no '*' and no width or precision above 1000")
    return None


def _functions_outside(stmt: exp.Expression, allow: set, extra: set,
                       dialect: Optional[str] = None, sql: Optional[str] = None,
                       node_names: FrozenSet[str] = frozenset()) -> list:
    """Function calls that are not on ``allow``, in the order they appear (each name once, at most five)."""
    refused = []
    for node in stmt.find_all(exp.Func):
        if type(node).__name__ in _SYNTAX_FUNCS or isinstance(node, _OPERATOR_FUNCS):
            continue
        names = _node_names(node)
        qual = _qualifier(node)
        shown = _func_name(node)
        written = None if isinstance(node, exp.Anonymous) else _written_from_text(node, sql)
        if qual and qual != "pg_catalog":
            ok = f"{qual}.{shown}" in allow or bool(names & extra)
            shown = f"{qual}.{shown}"
        elif written:
            # the name as written decides (review 5, L1): sqlglot turns names a database may not have (array_join,
            # year, ucase, ...) into nodes whose own names are on the list
            ok = written in allow
        elif isinstance(node, exp.Anonymous):
            ok = bool(names & allow)              # sqlglot's own names are never written names (review 6)
        else:
            ok = bool(names & (allow | node_names))
            if not ok:
                rendered = _written_name(node, dialect)  # sqlglot's own name can differ (j_s_o_n_object)
                ok = bool(rendered) and rendered in allow
        if not ok and not qual:
            shown = _written_in_sql(node, sql, dialect)      # the name as the query wrote it
        if not ok and shown not in refused:
            refused.append(shown)
            if len(refused) >= 5:
                break
    return refused


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
    if (policy.dialect or "").lower() in MYSQL_LIKE_DIALECTS and _DASH_DASH_NO_SPACE.search(sql):
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
    stmt = _strip_builtin_schema(statements[0], policy.dialect)
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
    if not bad_agg and _has_dynamic_pivot(stmt):
        bad_agg = {"pivot (dynamic)"}
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
    if not bad_agg:
        # A function whose argument is a bare query folds that query's rows into one value: PostgreSQL 16
        # JSON_ARRAY(SELECT ...) (review 4, H1). EXISTS / IN / ANY / ALL and a bracketed scalar sub-query are fine.
        for node in stmt.find_all(exp.Func):
            if isinstance(node, (exp.Exists, exp.Any, exp.All)) or isinstance(node, _OPERATOR_FUNCS):
                continue
            for value in node.args.values():
                for arg in (value if isinstance(value, list) else [value]):
                    if isinstance(arg, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
                        bad_agg = {f"{_func_name(node)}(query)"}
                        break
                if bad_agg:
                    break
            if bad_agg:
                break
    if bad_agg:
        return SqlVerdict(False, "row-folding aggregate blocked (bulk extraction guard): "
                                 f"{_as_written(bad_agg, stmt, sql, policy.dialect)}", sql, stype)
    denied_f = ((funcs | _function_qualifiers(stmt)) & (DEFAULT_DENIED_FUNCTIONS
                                                        | {f.lower() for f in policy.extra_denied_functions})
                | _family_denied_functions(funcs, policy.dialect))
    if denied_f:
        return SqlVerdict(False, f"denied function(s): {_as_written(denied_f, stmt, sql, policy.dialect)}", sql, stype)
    text_query = _sql_text_arguments(stmt)
    if text_query:
        return SqlVerdict(False, "query given as text blocked (fail-closed): "
                                 f"{_as_written(set(text_query), stmt, sql, policy.dialect)}", sql, stype)
    extra_allow = {f.lower() for f in policy.extra_allowed_functions}
    if policy.allowed_functions is not None:
        base = {f.lower() for f in policy.allowed_functions}
    else:
        base = default_allowed_functions(policy.dialect)
    if policy.allowed_functions is None and base is not None:
        too_big = _size_refusal(stmt, extra_allow, sql, policy.dialect)
        if too_big:
            return SqlVerdict(False, too_big, sql, stype)
    if base is not None:
        refused = _functions_outside(stmt, base | extra_allow, extra_allow,
                                     dialect=policy.dialect, sql=sql,
                                     node_names=_ALLOWED_SQLGLOT_NAMES if policy.allowed_functions is None
                                     else frozenset())
        if refused:
            names = ", ".join(f"'{n}'" for n in refused)
            if policy.allowed_functions is not None:
                return SqlVerdict(False, f"function(s) not in allow-list: {', '.join(refused)}", sql, stype)
            word = "function" if len(refused) == 1 else "functions"
            verb = "is" if len(refused) == 1 else "are"
            return SqlVerdict(False, f"{word} {names} {verb} not in the default allow-list for "
                                     f"{policy.dialect or 'dialect=None'}; if it is safe for your database, add it with "
                                     f"SqlPolicy(extra_allowed_functions={{...}})", sql, stype)

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
