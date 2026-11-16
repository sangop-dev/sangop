"""The @guard decorator: one line to protect an MCP tool (or any function).

    from fastmcp import FastMCP
    import sangop

    mcp = FastMCP("support")

    @mcp.tool
    @sangop.guard(purpose="support", sql_param="query")
    def run_query(query: str) -> list[dict]:
        ...

Flow per call:
  1. SQL argument (if any) is checked by the AST guard -> blocked = SangopBlocked. A SQL argument that is not a
     string or None is blocked too (F6); None means "no SQL" and is not checked.
  2. Arguments named in ``detokenize_params`` get real values back (JIT). If that changed the SQL argument, it is
     checked again with the real values before the tool sees it (F3).
  3. The function runs.
  4. Its output is scrubbed (tokenize / redact / shadow) before the model sees it.
  5. One audit event is appended (no raw PII).
"""

from __future__ import annotations

import collections.abc
import functools
import inspect
import secrets as _secrets
import string
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Union

from .audit import AuditLedger
from . import plugins as _plugins
from .detectors import known_kinds, rules_info, verhoeff_check_digit
from .sqlguard import SqlPolicy, check_sql
from .tokenizer import MEDIA_MODES, MODES, Vault, detokenize_obj, scrub_obj, scrub_text


class SangopBlocked(Exception):
    """Raised when a call is blocked by policy. The message is safe to show the model."""


class SangopToolError(Exception):
    """Raised instead of the original exception when a guarded tool fails (audit finding H2).

    Database and library errors often quote the offending row ("duplicate key ... (email)=(<the e-mail address>)"). The text
    here has been scrubbed with the guard's own PII mode and the original exception is NOT chained, so neither
    message nor traceback can carry the raw value to the model. The original exception type name is in
    ``error_type`` and in the audit ledger. In ``pii_mode="shadow"`` (observe only) the original exception is
    re-raised unchanged.
    """

    def __init__(self, message: str, error_type: str = "Exception") -> None:
        super().__init__(message)
        self.error_type = error_type


@dataclass
class _State:
    vault: Vault
    ledger: Optional[AuditLedger]
    selftest_done: bool = False
    media_mode: str = "block"


_STATE = _State(vault=Vault(), ledger=None)
_MISSING = object()
# BaseException subclasses that are control flow of the interpreter itself: re-raised untouched.
_PASS_THROUGH = (GeneratorExit,)


def configure(
    ledger_path: Optional[str] = ".sangop/audit.db",
    session_key: Optional[bytes] = None,
    run_selftest: bool = True,
    ledger_key: Optional[bytes] = None,
    media_mode: str = "block",
    **plugin_options: Any,
) -> None:
    """Set the audit ledger location and (optionally) a session key.

    ledger_path=None disables the ledger (not recommended).

    ledger_key (or the SANGOP_LEDGER_KEY environment variable, >= 16 characters, stored OUTSIDE the ledger) makes the
    ledger an HMAC chain; without it the chain is unkeyed and ``verify`` says so.

    media_mode (D-078) is the default for every ``@guard`` that does not set its own: ``"block"`` (default) replaces
    images, PDFs, Office files, archives and audio in a tool result with ``[SANGOP_BLOCKED: media <kind> not
    scanned]`` and writes ``media_blocked``; ``"allow"`` passes them on UNSCANNED and writes ``media_unscanned``
    (Sangop does not read the content of media). Choosing "allow" is written to the ledger (``media_allow_default``).

    Any other keyword is an option of an installed rules plugin (see ``sangop.plugins``); a keyword that no installed
    plugin accepts raises ``TypeError``. Plugins receive their options on every ``configure()`` call, so an option
    that is not passed goes back to the plugin's default.
    """
    if media_mode not in MEDIA_MODES:
        raise ValueError(f"media_mode must be one of {MEDIA_MODES}")
    unknown = sorted(set(plugin_options) - _plugins.accepted_configure_keys())
    if unknown:
        raise TypeError(f"configure() got an unexpected keyword argument {unknown[0]!r} "
                        f"(no installed Sangop rules plugin accepts it; active rules: {rules_info()['name']})")
    if _STATE.ledger is not None:
        _STATE.ledger.close()
    _STATE.vault = Vault(session_key)
    _STATE.ledger = AuditLedger(ledger_path, key=ledger_key) if ledger_path else None
    _STATE.selftest_done = False
    _STATE.media_mode = media_mode
    if media_mode == "allow":
        _log("media_allow_default", {
            "media_mode": "allow",
            "warning": "images, PDFs, Office files and audio pass through UNSCANNED unless a tool sets media_mode='block'",
        })
    _plugins.run_configure_hooks(plugin_options, _log)
    if run_selftest:
        selftest()


def get_vault() -> Vault:
    return _STATE.vault


def get_ledger() -> Optional[AuditLedger]:
    return _STATE.ledger


def _effective_kinds(kinds: Optional[tuple]) -> Optional[tuple]:
    """Apply the installed plugins' kinds filters to a guard's ``kinds`` filter (read at call time)."""
    return _plugins.filter_kinds(kinds)


def _log(event: str, record: dict) -> None:
    if _STATE.ledger is not None:
        _STATE.ledger.append(event, record)


def selftest() -> dict:
    """Canary test: proves the filters are live. Uses synthetic values only."""
    canary_aadhaar = "999941057058"           # UIDAI's published test UID, not a person's number
    az = string.ascii_uppercase               # PAN-shaped canary is made at run time, never written in the file
    canary_pan = (_secrets.choice(az) + _secrets.choice(az) + _secrets.choice(az) + "P" + _secrets.choice(az)
                  + str(_secrets.randbelow(9000) + 1000) + _secrets.choice(az))
    probe = f"canary {canary_aadhaar} {canary_pan}"
    tmp = Vault()
    out, counts = scrub_text(probe, tmp, "tokenize")
    sql_blocked = not check_sql("DROP TABLE users").allowed
    ok = (canary_aadhaar not in out) and (canary_pan not in out) and sql_blocked
    result = {"ok": ok, "pii_kinds": sorted(counts), "sql_drop_blocked": sql_blocked, "rules": rules_info()["name"]}
    _log("selftest", result)
    _STATE.selftest_done = True
    if not ok:
        raise RuntimeError("Sangop selftest FAILED - filters are not working; refusing to continue")
    return result


def guard(
    purpose: str,
    pii_mode: str = "tokenize",
    sql_param: Optional[str] = None,
    sql_policy: SqlPolicy = SqlPolicy(),
    sql_mode: str = "enforce",
    detokenize_params: Iterable[str] = (),
    kinds: Optional[Iterable[str]] = None,
    detokenize_kinds: Union[None, str, Iterable[str]] = None,
    media_mode: Optional[str] = None,
) -> Callable:
    """Wrap a tool function with PII scrubbing, SQL guarding and audit logging.

    pii_mode : "tokenize" (reversible, default) | "redact" | "shadow" (log only)
    sql_mode : "enforce" (block, default) | "shadow" (log only)
    detokenize_params : names of arguments whose tokens get their real value back inside this trusted tool.
    detokenize_kinds : REQUIRED with ``detokenize_params`` (D-054): the token kinds that may be revealed, e.g.
        ``("PHONE_IN",)``; other tokens stay tokens. ``"*"`` reveals every kind and is marked in the ledger.
        Every reveal writes a ``detokenize`` event (counts by kind, never the values).
    media_mode : "block" | "allow" | None (default: the ``configure(media_mode=...)`` value, itself "block").
        Media (images, PDFs, Office files, archives, audio) is never scanned for personal data (D-078). "block"
        replaces it and writes ``media_blocked``; "allow" passes it unchanged and writes ``media_unscanned``.
    """
    if media_mode is not None and media_mode not in MEDIA_MODES:
        raise ValueError(f"media_mode must be one of {MEDIA_MODES} or None")
    if pii_mode not in MODES:
        raise ValueError(f"pii_mode must be one of {MODES}")
    if sql_mode not in ("enforce", "shadow"):
        raise ValueError("sql_mode must be 'enforce' or 'shadow'")
    detok = tuple(detokenize_params)
    detok_all = detokenize_kinds == "*"
    if detok:
        if detokenize_kinds is None or (not detok_all and isinstance(detokenize_kinds, str)):
            raise ValueError("detokenize_params needs detokenize_kinds=(...) naming the token kinds that may be "
                             "revealed, or detokenize_kinds='*' for all kinds (not recommended)")
        detok_kinds = None if detok_all else tuple(detokenize_kinds)
        if detok_kinds is not None:
            known = known_kinds()
            bad = [k for k in detok_kinds if k not in known]
            if bad or not detok_kinds:
                raise ValueError(f"detokenize_kinds must be a non-empty subset of the known kinds; got {list(detokenize_kinds)}")
    else:
        detok_kinds = None
    kinds_t = tuple(kinds) if kinds is not None else None

    def decorator(fn: Callable) -> Callable:
        sig = inspect.signature(fn)
        tool = fn.__name__
        varkw = next((p.name for p in sig.parameters.values() if p.kind is inspect.Parameter.VAR_KEYWORD), None)
        if sql_param is not None and sql_param not in sig.parameters and varkw is None:
            # F6: a misspelt sql_param used to switch the SQL check off silently
            raise ValueError(f"sql_param={sql_param!r} is not a parameter of {tool}{sig}")

        def _sql_get(bound: inspect.BoundArguments) -> Any:
            if sql_param in sig.parameters:
                return bound.arguments.get(sql_param, _MISSING)
            return bound.arguments.get(varkw, {}).get(sql_param, _MISSING)

        def _sql_set(bound: inspect.BoundArguments, value: str) -> None:
            if sql_param in sig.parameters:
                bound.arguments[sql_param] = value
            else:
                bound.arguments[varkw][sql_param] = value

        def _sql_gate(bound: inspect.BoundArguments, record: dict, revealed: bool) -> None:
            """Check the SQL argument; block (enforce) or log (shadow). ``revealed``: tokens in it were just turned
            back into real values, so its text is not logged and the message to the model names no detail."""
            value = _sql_get(bound)
            if value is _MISSING:
                return
            if value is None:
                # R-1 (11 Nov 2026): None (not given, default None, or passed as None) means "no SQL": nothing to
                # check, the tool runs as before F6; the ledger says so
                record["sql_after_detokenize" if revealed else "sql"] = {"present": False, "note": "no SQL given (None)"}
                return
            if isinstance(value, str):
                verdict = check_sql(value, sql_policy)
                allowed, reason, stype, sql_out = verdict.allowed, verdict.reason, verdict.statement_type, verdict.sql
            else:                                                        # F6: fail closed on bytes, lists, numbers ...
                allowed, stype, sql_out = False, None, None
                reason = f"the SQL argument {sql_param!r} is not a string ({type(value).__name__})"
            if revealed:
                entry = {"allowed": allowed, "reason": scrub_text(reason, Vault(), "redact")[0], "type": stype,
                         "text": "(not logged: contains revealed values)"}
                record["sql_after_detokenize"] = entry
            else:
                entry = {"allowed": allowed, "reason": reason, "type": stype,
                         "text": scrub_text(sql_out, Vault(), "redact")[0][:2000] if sql_out is not None else ""}
                record["sql"] = entry
            if not allowed:
                entry["mode"] = sql_mode
                if sql_mode == "enforce":
                    record["outcome"] = "blocked"
                    _log("tool_call", record)
                    if revealed:
                        raise SangopBlocked("Sangop blocked this query: with its tokens revealed it does not pass the "
                                            "SQL check (details in the audit log)")
                    raise SangopBlocked(f"Sangop blocked this query: {reason}")
            elif sql_out is not None:
                _sql_set(bound, sql_out)

        def _before(args: tuple, kwargs: dict) -> tuple:
            if not _STATE.selftest_done:
                selftest()
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            record: dict = {"tool": tool, "purpose": purpose, "pii_mode": pii_mode}
            if sql_param:
                _sql_gate(bound, record, revealed=False)
            sql_before = _sql_get(bound) if sql_param else _MISSING
            revealed: Counter = Counter()
            for name in detok:
                if name in bound.arguments:
                    bound.arguments[name] = detokenize_obj(bound.arguments[name], _STATE.vault, detok_kinds, revealed)
            if sql_param and _sql_get(bound) is not sql_before and _sql_get(bound) != sql_before:
                # F3: the tool must never receive SQL the guard has not checked in that exact form
                _sql_gate(bound, record, revealed=True)
            if revealed:
                record["detokenized"] = dict(revealed)
                _log("detokenize", {"tool": tool, "purpose": purpose, "params": list(detok),
                                    "kinds_allowed": "*" if detok_all else list(detok_kinds or ()),
                                    "unrestricted": detok_all, "revealed": dict(revealed)})
            return bound, record

        def _finish(record: dict, counts: Counter, outcome: str, t0: float, error_type: Optional[str] = None,
                    items: Optional[int] = None) -> None:
            record["pii_found"] = dict(counts)
            _plugins.apply_record_hooks(record)
            record["outcome"] = outcome
            if error_type:
                record["error_type"] = error_type
            if items is not None:
                record["items"] = items
            record["overhead_note"] = "duration includes tool runtime"
            record["duration_ms"] = round((time.perf_counter() - t0) * 1000, 3)
            _log("tool_call", record)

        def _scrub(value: Any, counts: Counter, record: Optional[dict] = None) -> Any:
            k = _effective_kinds(kinds_t)
            if k is not None and record and record.get("detokenized"):
                # L1: a value this call revealed must be masked again on the way out, whatever the ``kinds`` filter says
                k = tuple(sorted(set(k) | set(record["detokenized"])))
            events: list = []
            stats: dict = {}
            media_events: list = []
            mm = media_mode or _STATE.media_mode
            key = getattr(_STATE.ledger, "_key", None) if _STATE.ledger is not None else None
            scrubbed, c = scrub_obj(value, _STATE.vault, pii_mode, k, Counter(), _events=events, _stats=stats,
                                    media_mode=mm, _media_events=media_events, _media_key=key)
            counts.update(c)
            for ev in media_events:
                # D-078: one event per media item; kind, MIME types, size, never the content
                name = ev.pop("event")
                field = "media_blocked" if name == "media_blocked" else "media_unscanned"
                if record is not None:
                    record[field] = record.get(field, 0) + 1
                _log(name, {"tool": tool, "purpose": purpose, "pii_mode": pii_mode, "media_mode": mm, **ev})
            if record is not None:
                # F1 (D-075): nested lazy iterables are read and scrubbed; blocked ones are logged, never their values
                if stats.get("lazy_iterables_read"):
                    record["lazy_iterables_read"] = record.get("lazy_iterables_read", 0) + stats["lazy_iterables_read"]
                if events:
                    record["nested_iterables_blocked"] = record.get("nested_iterables_blocked", 0) + len(events)
                    for ev in events:
                        _log("nested_iterable_blocked", {"tool": record.get("tool"), "purpose": record.get("purpose"),
                                                         "pii_mode": pii_mode, **ev})
            return scrubbed

        def _scrub_in_place(exc: BaseException) -> BaseException:
            """F7: a BaseException that is not an Exception (KeyboardInterrupt, SystemExit, CancelledError, a library's
            own) keeps its type, so the interpreter still treats it the same way; its message, arguments and
            attributes are scrubbed and chained exceptions are dropped."""
            k = _effective_kinds(kinds_t)

            def s(v: Any) -> Any:
                if isinstance(v, str):
                    return scrub_text(v, _STATE.vault, pii_mode, k)[0]
                if v is None or isinstance(v, (bool, int, float)):
                    return v
                return scrub_obj(v, _STATE.vault, pii_mode, k, Counter())[0]

            try:
                exc.args = tuple(s(a) for a in exc.args)
            except Exception:  # noqa: BLE001
                exc.args = ()
            if isinstance(exc, SystemExit) and isinstance(exc.code, str):
                exc.code = s(exc.code)
            for name, value in list(getattr(exc, "__dict__", {}).items()):
                try:
                    setattr(exc, name, s(value))
                except Exception:  # noqa: BLE001
                    # a read-only attribute (or a value that cannot be scrubbed): drop the raw value, fail closed
                    # (bandit B110, 16 Nov 2026: this `pass` used to leave the unscrubbed value in __dict__)
                    exc.__dict__.pop(name, None)
            exc.__cause__ = None
            exc.__context__ = None
            exc.__suppress_context__ = True
            return exc

        def _error_for(exc: BaseException) -> BaseException:
            """The exception to raise to the caller: the original in shadow mode, else a scrubbed SangopToolError
            (or, for a BaseException that is not an Exception, the same exception scrubbed in place)."""
            if pii_mode == "shadow" or isinstance(exc, (SangopBlocked, SangopToolError) + _PASS_THROUGH):
                return exc
            if not isinstance(exc, Exception):
                return _scrub_in_place(exc)
            text, _ = scrub_text(f"{exc}", _STATE.vault, pii_mode, _effective_kinds(kinds_t))
            etype = type(exc).__name__
            return SangopToolError(f"tool '{tool}' failed ({etype}): {text}"[:2000], etype)

        def _fail(exc: BaseException, record: dict, counts: Counter, t0: float) -> BaseException:
            _finish(record, counts, "error", t0, error_type=type(exc).__name__)
            return _error_for(exc)

        def _iter_scrub(it: Any, record: dict, t0: float):
            counts: Counter = Counter()
            outcome, err, n = "incomplete", None, 0
            try:
                for item in it:
                    out = _scrub(item, counts, record)
                    n += 1
                    yield out
                outcome = "ok"
            except _PASS_THROUGH:
                raise
            except BaseException as e:               # noqa: BLE001 - re-raised below, outside the except block (F7)
                err = e
            finally:
                if err is not None:
                    _finish(record, counts, "error", t0, error_type=type(err).__name__, items=n)
                else:
                    _finish(record, counts, outcome, t0, items=n)
            if err is not None:
                raise _error_for(err)

        async def _aiter_scrub(it: Any, record: dict, t0: float):
            counts: Counter = Counter()
            outcome, err, n = "incomplete", None, 0
            try:
                async for item in it:
                    out = _scrub(item, counts, record)
                    n += 1
                    yield out
                outcome = "ok"
            except _PASS_THROUGH:
                raise
            except BaseException as e:               # noqa: BLE001 (F7)
                err = e
            finally:
                if err is not None:
                    _finish(record, counts, "error", t0, error_type=type(err).__name__, items=n)
                else:
                    _finish(record, counts, outcome, t0, items=n)
            if err is not None:
                raise _error_for(err)

        def _after(result: Any, record: dict, t0: float) -> Any:
            # Lazy results are wrapped so every item is scrubbed (audit finding H3).
            if isinstance(result, collections.abc.AsyncIterator):
                return _aiter_scrub(result, record, t0)
            if isinstance(result, collections.abc.Iterator):
                return _iter_scrub(result, record, t0)
            counts: Counter = Counter()
            scrubbed = _scrub(result, counts, record)
            _finish(record, counts, "ok", t0)
            return scrubbed

        if inspect.isasyncgenfunction(fn):
            @functools.wraps(fn)
            def asyncgen_wrapper(*args: Any, **kwargs: Any) -> Any:
                t0 = time.perf_counter()
                bound, record = _before(args, kwargs)
                return _aiter_scrub(fn(*bound.args, **bound.kwargs), record, t0)
            return asyncgen_wrapper

        if inspect.isgeneratorfunction(fn):
            @functools.wraps(fn)
            def gen_wrapper(*args: Any, **kwargs: Any) -> Any:
                t0 = time.perf_counter()
                bound, record = _before(args, kwargs)
                return _iter_scrub(fn(*bound.args, **bound.kwargs), record, t0)
            return gen_wrapper

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                t0 = time.perf_counter()
                bound, record = _before(args, kwargs)
                err: Optional[BaseException] = None
                try:
                    result = await fn(*bound.args, **bound.kwargs)
                except BaseException as e:           # noqa: BLE001 - handled below, outside the except block (F7)
                    err = e
                if err is not None:
                    raise _fail(err, record, Counter(), t0)
                return _after(result, record, t0)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            t0 = time.perf_counter()
            bound, record = _before(args, kwargs)
            err: Optional[BaseException] = None
            try:
                result = fn(*bound.args, **bound.kwargs)
            except BaseException as e:               # noqa: BLE001 (F7)
                err = e
            if err is not None:
                raise _fail(err, record, Counter(), t0)
            return _after(result, record, t0)
        return wrapper

    return decorator
