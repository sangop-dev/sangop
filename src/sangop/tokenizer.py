"""Reversible, session-scoped PII tokenization.

The real value never leaves the process: the model sees ``[PII_PAN_1a2b3c4d5e6f7a8b]``
and only a trusted tool that explicitly asks for it gets the real value back
(Just-in-Time detokenization).

The token -> value map lives in process memory only. It is never written to
disk or to the audit ledger.
"""

from __future__ import annotations

import collections
import collections.abc
import copy
import dataclasses
import decimal
import enum
import hashlib
import hmac
import itertools
import json
import re
import secrets
import threading
from collections import Counter
from typing import Any, Dict, Iterable, Optional, Tuple

from . import media as _media
from .detectors import find_all

try:  # sqlite3 is in the standard library but may be missing in stripped builds
    import sqlite3
except Exception:  # pragma: no cover
    sqlite3 = None  # type: ignore

TOKEN_RE = re.compile(r"\[PII_([A-Z_]+)_([0-9a-f]{16,64})\]")      # 64 bit; longer only after a collision

MODES = ("tokenize", "redact", "shadow")
_EMPTY: Counter = Counter()


class Vault:
    """In-memory token store for one process/session."""

    def __init__(self, session_key: Optional[bytes] = None) -> None:
        self._key = session_key or secrets.token_bytes(32)
        self._map: Dict[str, str] = {}
        self._rev: Dict[Tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def _hex(self, kind: str, value: str) -> str:
        return hmac.new(self._key, f"{kind}\x00{value}".encode(), hashlib.sha256).hexdigest()

    def token_for(self, kind: str, value: str) -> str:
        cached = self._rev.get((kind, value))
        if cached is not None:
            return cached
        full = self._hex(kind, value)
        with self._lock:
            cached = self._rev.get((kind, value))
            if cached is not None:
                return cached
            # 64-bit token; if a different value already owns it (probability ~ n^2 / 2^65) use a longer prefix of
            # the same digest, so two values never share a token (audit finding M5).
            for n in range(16, len(full) + 1, 4):
                token = f"[PII_{kind}_{full[:n]}]"
                if token not in self._map or self._map[token] == value:
                    break
            else:  # pragma: no cover - needs a full 256-bit collision
                raise RuntimeError("token space exhausted")
            self._map[token] = value
            self._rev[(kind, value)] = token
        return token

    def reveal(self, token: str) -> Optional[str]:
        with self._lock:
            return self._map.get(token)

    def clear(self) -> None:
        with self._lock:
            self._map.clear()
            self._rev.clear()

    def __len__(self) -> int:
        return len(self._map)


def scrub_text(
    text: str,
    vault: Vault,
    mode: str = "tokenize",
    kinds: Optional[Iterable[str]] = None,
) -> Tuple[str, Counter]:
    """Return (new_text, counts_by_kind). Shadow mode returns text unchanged."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    findings = find_all(text, kinds)
    if not findings:
        return text, _EMPTY
    counts: Counter = Counter(f.kind for f in findings)
    if mode == "shadow":
        return text, counts
    out, last = [], 0
    for f in findings:
        out.append(text[last:f.start])
        out.append(vault.token_for(f.kind, f.value) if mode == "tokenize" else f"[REDACTED_{f.kind}]")
        last = f.end
    out.append(text[last:])
    return "".join(out), counts


_MAX_DEPTH = 40
_SCALAR_NO_PII = (bool, type(None), complex)

# Internal review (26 Oct 2026), F1 (D-075): a lazy iterable nested inside a result (generator, map, zip, filter, iter, chain, ...) is
# read into a list - at most this many items - and scrubbed like a list. A longer one, an async iterable (it cannot
# be read here) or one that raises is replaced by a placeholder (fail closed) and reported as an event.
MAX_LAZY_ITEMS = 10_000


MEDIA_MODES = ("block", "allow")


class _Ctx:
    __slots__ = ("events", "lazy_read", "shadow_rebuilt", "media_mode", "media_events", "media_key")

    def __init__(self, media_mode: str = "block", media_key: Optional[bytes] = None) -> None:
        self.events: list = []          # one dict per blocked nested iterable (no values, only reason/type/counts)
        self.lazy_read = 0              # nested lazy iterables read and scrubbed
        self.shadow_rebuilt = False     # shadow mode had to read an iterator, so the original object is now spent
        self.media_mode = media_mode    # D-078: "block" (default) or "allow"
        self.media_events: list = []    # one dict per media item seen (never its content)
        self.media_key = media_key      # ledger key: if set, events carry an HMAC fingerprint of the media


def _media_placeholder(kind: str) -> str:
    return f"[SANGOP_BLOCKED: media {kind} not scanned]"


def _media_decision(ctx: _Ctx, mode: str, *, kind: str, sniffed_mime: Optional[str], claimed_mime: Optional[str],
                    size: Optional[int], raw: Optional[bytes], reason: Optional[str] = None) -> bool:
    """Record one media item and return True when it must be replaced (D-078).

    block mode, or any decoding/sniffing error (fail closed, even in allow mode) -> replaced, ``media_blocked``.
    allow mode -> passed unchanged, ``media_unscanned``. pii_mode="shadow" -> never replaced; the event says what
    would have happened. The event never holds the content or a plain hash; with a ledger key it holds an HMAC.
    """
    block = ctx.media_mode == "block" or reason is not None
    ev: dict = {"event": "media_blocked" if block else "media_unscanned", "kind": kind,
                "sniffed_mime": sniffed_mime, "claimed_mime": claimed_mime, "size_bytes": size}
    if reason:
        ev["reason"] = reason
    if mode == "shadow":
        ev["shadow"] = True
    if ctx.media_key and raw is not None:
        ev["content_hmac"] = hmac.new(ctx.media_key, raw, hashlib.sha256).hexdigest()
    ctx.media_events.append(ev)
    return block and mode != "shadow"


def _media_bytes(obj: Any, mode: str, ctx: _Ctx) -> Any:
    """bytes / bytearray / memoryview: media -> placeholder or unchanged; ``_NOT_MEDIA`` if it is not media."""
    try:
        raw = obj.tobytes() if isinstance(obj, memoryview) else bytes(obj)
        hit = _media.sniff(raw)
    except Exception:                                            # noqa: BLE001 - fail closed
        if _media_decision(ctx, mode, kind="unknown", sniffed_mime=None, claimed_mime=None,
                           size=getattr(obj, "nbytes", None) if isinstance(obj, memoryview) else len(obj),
                           raw=None, reason="error"):
            return _media_placeholder("unknown")
        return obj
    if hit is None:
        return _NOT_MEDIA
    kind, mime = hit
    if _media_decision(ctx, mode, kind=kind, sniffed_mime=mime, claimed_mime=None, size=len(raw), raw=raw):
        return _media_placeholder(kind)
    return obj


def _media_b64(b64: str, claimed: Optional[str], mode: str, ctx: _Ctx, *, hint: Optional[Tuple[str, str]] = None
               ) -> Tuple[bool, str]:
    """Decode base64 media fully; record it; return (replace?, kind). Decoding errors fail closed."""
    try:
        raw = _media.b64_decode_full(b64) if b64 else b""
    except Exception:                                            # noqa: BLE001 - fail closed
        kind = hint[0] if hint else _media.kind_from_mime(claimed)
        return _media_decision(ctx, mode, kind=kind, sniffed_mime=hint[1] if hint else None, claimed_mime=claimed,
                               size=None, raw=None, reason="decode_error"), kind
    if claimed is not None and not raw:
        kind = _media.kind_from_mime(claimed)
        return _media_decision(ctx, mode, kind=kind, sniffed_mime=None, claimed_mime=claimed, size=0, raw=raw,
                               reason="decode_error"), kind
    try:
        hit = _media.sniff(raw)
    except Exception:                                            # noqa: BLE001 - fail closed
        return _media_decision(ctx, mode, kind="unknown", sniffed_mime=None, claimed_mime=claimed, size=len(raw),
                               raw=None, reason="error"), "unknown"
    kind = hit[0] if hit else _media.kind_from_mime(claimed)
    return _media_decision(ctx, mode, kind=kind, sniffed_mime=hit[1] if hit else None, claimed_mime=claimed,
                           size=len(raw), raw=raw), kind


def _data_uri_media(m: "re.Match[str]", mode: str, ctx: _Ctx) -> Optional[Tuple[bool, str]]:
    """M0-2: every ``;base64`` data URI is decoded and sniffed, whatever MIME type it claims. A media MIME type
    (image/audio/video/pdf/octet-stream) is media even if the bytes are not recognised (and fails closed if they
    cannot be decoded); any other claimed type is media only when the decoded bytes are. None = not media."""
    claimed = (m.group("mime") or "").lower() or None
    b64 = m.group("b64")
    if _media.is_media_mime(claimed):
        return _media_b64(b64, claimed, mode, ctx)
    try:
        raw = _media.b64_decode_full(b64) if b64 else b""
    except Exception:                                            # noqa: BLE001 - not media, stays text
        return None
    try:
        hit = _media.sniff(raw)
    except Exception:                                            # noqa: BLE001 - fail closed
        return _media_decision(ctx, mode, kind="unknown", sniffed_mime=None, claimed_mime=claimed, size=len(raw),
                               raw=None, reason="error"), "unknown"
    if hit is None:
        return None
    return _media_decision(ctx, mode, kind=hit[0], sniffed_mime=hit[1], claimed_mime=claimed, size=len(raw),
                           raw=raw), hit[0]


def _media_str(text: str, vault: Vault, mode: str, kinds: Optional[tuple], counts: Counter, ctx: _Ctx) -> Any:
    """A string that IS long base64 media, or that CONTAINS data: URIs or base64 media pieces (M0-1).
    ``_NOT_MEDIA`` if none. Text around a media piece is still scanned for PII; the piece itself never is."""
    if len(text) >= _media.MIN_B64_CHARS and len(text) <= 64 * 1024 * 1024:
        # the whole string is base64 (line-wrapped base64 included)
        try:
            hit = _media.b64_media_candidate(text)
        except Exception:                                        # noqa: BLE001 - fail closed
            if _media_decision(ctx, mode, kind="unknown", sniffed_mime=None, claimed_mime=None, size=None,
                               raw=None, reason="error"):
                return _media_placeholder("unknown")
            return text
        if hit is not None:
            replace, kind = _media_b64(text, None, mode, ctx, hint=hit)
            return _media_placeholder(kind) if replace else text
    pieces: list = []                                            # (start, end, replace?, kind)
    if "ata:" in text or "ATA:" in text:
        for m in _media.DATA_URI_RE.finditer(text):
            got = _data_uri_media(m, mode, ctx)
            if got is not None:
                pieces.append((m.start(), m.end(), got[0], got[1]))
    if len(text) >= _media.MIN_B64_CHARS:
        taken = [(a, b) for a, b, _, _ in pieces]
        for m in _media.B64_RUN_RE.finditer(text):
            if any(a < m.end() and m.start() < b for a, b in taken):
                continue                                         # already handled as part of a data: URI
            run = m.group(0)
            try:
                hit = _media.b64_run_media(run)
            except Exception:                                    # noqa: BLE001 - fail closed
                pieces.append((m.start(), m.end(), _media_decision(
                    ctx, mode, kind="unknown", sniffed_mime=None, claimed_mime=None, size=None, raw=None,
                    reason="error"), "unknown"))
                continue
            if hit is None:
                continue
            off, kind, mime = hit
            replace, kind = _media_b64(run[off:], None, mode, ctx, hint=(kind, mime))
            pieces.append((m.start(), m.end(), replace, kind))
    if not pieces:
        return _NOT_MEDIA
    pieces.sort()
    parts, last = [], 0
    for start, end, replace, kind in pieces:
        new, c = scrub_text(text[last:start], vault, mode, kinds)
        if c:
            counts.update(c)
        parts.append(new)
        parts.append(_media_placeholder(kind) if replace else text[start:end])
        last = end
    new, c = scrub_text(text[last:], vault, mode, kinds)
    if c:
        counts.update(c)
    parts.append(new)
    return text if mode == "shadow" else "".join(parts)


def _media_mcp(obj: Any, mode: str, ctx: _Ctx) -> Any:
    """MCP ImageContent / AudioContent / EmbeddedResource(blob) / BlobResourceContents. ``_NOT_MEDIA`` otherwise."""
    try:
        info = _media.mcp_media(obj)
    except Exception:                                            # noqa: BLE001 - treat as not MCP media
        info = None
    if info is None:
        return _NOT_MEDIA
    form, claimed, data = info
    replace, kind = _media_b64(data if isinstance(data, str) else "", claimed, mode, ctx)
    if not replace:
        return obj
    return _media.mcp_text_replacement(obj, form, _media_placeholder(kind))


_NOT_MEDIA = object()


def _blocked_text(reason: str) -> str:
    return f"[SANGOP_BLOCKED: {reason}]"


def _replay(items: list, exc: BaseException):
    """Shadow mode: give back what an iterator produced, then fail the way it failed (observe only)."""
    yield from items
    raise exc


def _is_lazy_iterable(obj: Any) -> bool:
    if isinstance(obj, (str, bytes, bytearray, type, collections.abc.Mapping)):
        return False
    if isinstance(obj, collections.abc.Iterator):
        return True
    return isinstance(obj, collections.abc.Iterable) and not hasattr(obj, "__len__")


def _is_async_iterable(obj: Any) -> bool:
    return not isinstance(obj, type) and isinstance(obj, (collections.abc.AsyncIterator, collections.abc.AsyncIterable))


def _number_text(obj: Any) -> Optional[str]:
    """Digits of a big number (Aadhaar/phone stored as int/float/Decimal), else None."""
    try:
        if isinstance(obj, int):
            return str(obj) if abs(obj) >= 10**9 else None
        if isinstance(obj, float):
            if obj != obj or obj in (float("inf"), float("-inf")) or abs(obj) < 10**9:
                return None
            return f"{obj:.0f}"
        if isinstance(obj, decimal.Decimal):
            if not obj.is_finite() or abs(obj) < 10**9:
                return None
            return format(obj, "f")
    except Exception:  # pragma: no cover - defensive
        return None
    return None


def _new_like(obj: Any, items: Any) -> Any:
    """Rebuild a tuple/list/set-like container of the same type from scrubbed items."""
    if isinstance(obj, tuple) and hasattr(obj, "_fields"):          # namedtuple
        return type(obj)(*items)
    try:
        return type(obj)(items)
    except Exception:
        return list(items)


def _set_attr(target: Any, name: str, value: Any) -> None:
    try:
        object.__setattr__(target, name, value)
    except Exception:
        setattr(target, name, value)


def _walk(obj: Any, vault: Vault, mode: str, kinds: Optional[tuple], counts: Counter, depth: int, seen: set,
          ctx: _Ctx) -> Any:
    if isinstance(obj, str):
        found = _media_str(obj, vault, mode, kinds, counts, ctx)          # D-078: before any text scan
        if found is not _NOT_MEDIA:
            return found
        new, c = scrub_text(obj, vault, mode, kinds)
        if c:
            counts.update(c)
        return new
    if isinstance(obj, _SCALAR_NO_PII):
        return obj
    num = _number_text(obj)
    if num is not None:
        new, c = scrub_text(num, vault, mode, kinds)
        if c:
            counts.update(c)
            return new if mode != "shadow" else obj
        return obj
    if isinstance(obj, (int, float, decimal.Decimal)):
        return obj
    if depth > _MAX_DEPTH or id(obj) in seen:
        # too deep or a reference cycle: fail closed by returning only the scrubbed text form
        text, c = scrub_text(f"<{type(obj).__name__}>", vault, mode, kinds)
        return text
    seen = seen | {id(obj)}

    def rec(v: Any) -> Any:
        return _walk(v, vault, mode, kinds, counts, depth + 1, seen, ctx)

    if isinstance(obj, (bytes, bytearray, memoryview)):
        found = _media_bytes(obj, mode, ctx)                               # D-078: media is never text-decoded
        if found is not _NOT_MEDIA:
            return found
    found = _media_mcp(obj, mode, ctx)
    if found is not _NOT_MEDIA:
        return found
    if isinstance(obj, (bytes, bytearray)):
        text = bytes(obj).decode("utf-8", "replace")
        new, c = scrub_text(text, vault, mode, kinds)
        if not c:
            return obj
        counts.update(c)
        if mode == "shadow":
            return obj
        enc = new.encode("utf-8")
        return bytearray(enc) if isinstance(obj, bytearray) else enc
    if isinstance(obj, memoryview):
        # F8: read like bytes (not as a list of byte numbers); a clean view is returned unchanged
        try:
            raw = obj.tobytes()
        except Exception:
            return obj if mode == "shadow" else _blocked_text("memoryview could not be read")
        new, c = scrub_text(raw.decode("utf-8", "replace"), vault, mode, kinds)
        if not c:
            return obj
        counts.update(c)
        return obj if mode == "shadow" else new.encode("utf-8")
    if isinstance(obj, enum.Enum):
        # N2-enum: an Enum member is shared by the whole process and must never be changed; with personal data in
        # its value, the scrubbed value is returned in its place
        before = sum(counts.values())
        value = rec(obj.value)
        return obj if mode == "shadow" or sum(counts.values()) == before else value
    if isinstance(obj, collections.abc.Mapping):
        out = {rec(k): rec(v) for k, v in obj.items()}
        if isinstance(obj, dict):
            try:
                clone = copy.copy(obj)
                clone.clear()
                clone.update(out)
                return clone
            except Exception:
                return out
        return out
    if isinstance(obj, (list, tuple, set, frozenset, collections.deque)):
        return _new_like(obj, [rec(v) for v in obj])
    if isinstance(obj, (collections.abc.KeysView, collections.abc.ValuesView, collections.abc.ItemsView)):
        return [rec(v) for v in obj]
    if sqlite3 is not None and isinstance(obj, sqlite3.Row):
        return tuple(rec(v) for v in tuple(obj))
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        before = sum(counts.values())
        clone = copy.copy(obj)
        if clone is obj:                                                  # N2: never change a shared object
            return _unshared(obj, [f.name for f in dataclasses.fields(obj)], rec, vault, mode, kinds, counts, before)
        for f in dataclasses.fields(obj):
            if hasattr(obj, f.name):
                _set_attr(clone, f.name, rec(getattr(obj, f.name)))
        return _verified(clone, obj, vault, mode, kinds, counts, before)
    if hasattr(obj, "model_copy") and hasattr(type(obj), "model_fields"):          # pydantic v2
        before = sum(counts.values())
        update = {name: rec(getattr(obj, name)) for name in type(obj).model_fields if hasattr(obj, name)}
        clone = obj.model_copy(update=update)
        extra = getattr(obj, "__pydantic_extra__", None)
        if extra:
            clone.__pydantic_extra__ = {k: rec(v) for k, v in extra.items()}
        done = _verified(clone, obj, vault, mode, kinds, counts, before)
        if done is clone:
            # N2-pyd: a custom serializer (e.g. one that reads a PrivateAttr) can put data in the JSON form that no
            # field shows; frameworks serialize with it, so that form is checked too
            try:
                dumped = clone.model_dump(mode="json")
                found = scrub_text(json.dumps(dumped, default=str, ensure_ascii=False), vault, mode, kinds)[1]
            except Exception:
                dumped, found = None, None
            if found:
                if mode == "shadow":
                    counts.update(found)
                    return obj
                return rec(dumped)
        return done
    if _is_async_iterable(obj):
        # cannot be read synchronously here; a serializer may still drain it later -> fail closed
        ctx.events.append({"reason": "async_iterable", "type": type(obj).__name__})
        return obj if mode == "shadow" else _blocked_text("nested async iterable not read")
    if _is_lazy_iterable(obj):
        return _read_lazy(obj, mode, ctx, rec)
    if not callable(obj) and not isinstance(obj, type):
        slots = _slot_names(type(obj))
        if hasattr(obj, "__dict__") or slots:
            try:
                before = sum(counts.values())
                clone = copy.copy(obj)
                if clone is obj:                                          # N2: never change a shared object
                    names = list(vars(obj)) if hasattr(obj, "__dict__") else []
                    return _unshared(obj, names + [n for n in slots if n not in names], rec, vault, mode, kinds,
                                     counts, before)
                if hasattr(obj, "__dict__"):
                    for name, value in list(vars(obj).items()):
                        _set_attr(clone, name, rec(value))
                for name in slots:
                    if hasattr(obj, name):
                        _set_attr(clone, name, rec(getattr(obj, name)))
                return _verified(clone, obj, vault, mode, kinds, counts, before)
            except Exception:  # nosec B110 # falls through to the fail-closed text-form check just below
                pass
    # Unknown type: fail closed through its text forms. Clean objects (dates, UUIDs, ...) are returned unchanged.
    done = _verified(obj, obj, vault, mode, kinds, counts)
    if done is not obj:
        return done
    if hasattr(obj, "__iter__") and hasattr(obj, "__len__"):
        try:
            return [rec(v) for v in obj]
        except Exception:
            return obj
    return obj


def _unshared(obj: Any, names: list, rec: Any, vault: Vault, mode: str, kinds: Optional[tuple], counts: Counter,
              before: int) -> Any:
    """An object whose copy is the object itself (a singleton) is never changed: with personal data in its
    attributes a scrubbed dict of them is returned instead; a clean one is returned as it is."""
    out = {}
    for name in names:
        if hasattr(obj, name):
            out[name] = rec(getattr(obj, name))
    if sum(counts.values()) > before:
        return obj if mode == "shadow" else out
    return _verified(obj, obj, vault, mode, kinds, counts)


def _read_lazy(obj: Any, mode: str, ctx: _Ctx, rec: Any) -> Any:
    """Read a nested lazy iterable (at most MAX_LAZY_ITEMS + 1 items) and scrub it as a list (F1)."""
    it = iter(obj)
    items: list = []
    try:
        for item in itertools.islice(it, MAX_LAZY_ITEMS + 1):
            items.append(item)
    except Exception as exc:                                     # noqa: BLE001 - reported, never re-raised here
        ctx.events.append({"reason": "error", "type": type(obj).__name__, "error_type": type(exc).__name__,
                           "items_read": len(items)})
        if mode == "shadow":
            for v in items:
                rec(v)                                           # count only
            ctx.shadow_rebuilt = True
            return _replay(items, exc)
        return _blocked_text(f"nested iterable raised {type(exc).__name__}")
    if len(items) > MAX_LAZY_ITEMS:
        ctx.events.append({"reason": "too_many_items", "type": type(obj).__name__, "limit": MAX_LAZY_ITEMS})
        if mode == "shadow":
            for v in items[:MAX_LAZY_ITEMS]:
                rec(v)                                           # count only (first MAX_LAZY_ITEMS)
            ctx.shadow_rebuilt = True
            return itertools.chain(items, it)                    # unchanged values, still lazy
        return _blocked_text(f"nested iterable longer than {MAX_LAZY_ITEMS} items")
    ctx.lazy_read += 1
    if mode == "shadow":
        for v in items:
            rec(v)
        ctx.shadow_rebuilt = True
        return items                                             # original values; the iterator itself is spent
    return [rec(v) for v in items]


def _slot_names(cls: type) -> list:
    names: list = []
    for klass in cls.__mro__:
        sl = klass.__dict__.get("__slots__", ())
        for n in ([sl] if isinstance(sl, str) else sl):
            if n not in ("__dict__", "__weakref__") and n not in names:
                names.append(n)
    return names


def _verified(clone: Any, original: Any, vault: Vault, mode: str, kinds: Optional[tuple], counts: Counter,
              before: int = -1) -> Any:
    """Re-audit R1: after attributes are scrubbed, the object's own ``str()`` / ``repr()`` (which a framework or a
    logger will print) must be clean too. If a text form still shows PII, the object is replaced by its scrubbed
    text. Shadow mode only counts (and does not count again what the attributes already showed)."""
    if mode == "shadow" and before >= 0 and sum(counts.values()) > before:
        return original
    for fn in (str, repr):
        try:
            text = fn(clone)
        except Exception:
            text = ""
        new, c = scrub_text(text, vault, mode, kinds)
        if c:
            counts.update(c)
            return new if mode != "shadow" else original
    return clone


def scrub_obj(
    obj: Any,
    vault: Vault,
    mode: str = "tokenize",
    kinds: Optional[Iterable[str]] = None,
    _counts: Optional[Counter] = None,
    _events: Optional[list] = None,
    _stats: Optional[dict] = None,
    media_mode: str = "block",
    _media_events: Optional[list] = None,
    _media_key: Optional[bytes] = None,
) -> Tuple[Any, Counter]:
    """Recursively scrub every string-like value inside ``obj`` (audit finding H1).

    Handled: str, bytes/bytearray, big int/float/Decimal numbers, dict keys AND values, list/tuple/namedtuple/set/
    frozenset/deque, dict views, sqlite3.Row, dataclasses, pydantic models, plain objects with attributes, and
    lazy iterables nested anywhere inside (generator, map, zip, filter, iter, chain, ...: read into a list of at most
    ``MAX_LAZY_ITEMS`` items; longer, async or failing ones become a ``[SANGOP_BLOCKED: ...]`` placeholder and an
    entry in ``_events``). Any other type is checked through ``str(obj)`` (fail-closed).

    Media (D-078, see ``sangop.media``): images, PDFs, Office files, archives and audio are recognised by magic bytes
    (raw bytes, ``data:`` URIs, long base64 strings, MCP Image/Audio/EmbeddedResource blobs) and are NEVER text-scanned.
    ``media_mode="block"`` (default) replaces each with ``[SANGOP_BLOCKED: media <kind> not scanned]`` (an MCP content
    block becomes a TextContent); ``"allow"`` returns it unchanged. A decoding or sniffing error always blocks. One
    entry per media item goes to ``_media_events`` (kind, MIME types, size; never the content; an HMAC fingerprint
    only when ``_media_key`` is given).

    Shadow mode only counts and returns ``obj`` itself - except when a nested iterator had to be read: then a copy
    with the ORIGINAL values (the iterator as a list) is returned, because the original iterator is spent.
    ``_stats`` (optional dict) receives ``lazy_iterables_read``.
    """
    if media_mode not in MEDIA_MODES:
        raise ValueError(f"media_mode must be one of {MEDIA_MODES}")
    counts = _counts if _counts is not None else Counter()
    kinds_t = tuple(kinds) if kinds is not None else None
    ctx = _Ctx(media_mode, _media_key)
    new = _walk(obj, vault, mode, kinds_t, counts, 0, frozenset(), ctx)
    if _events is not None:
        _events.extend(ctx.events)
    if _media_events is not None:
        _media_events.extend(ctx.media_events)
    if _stats is not None:
        _stats["lazy_iterables_read"] = _stats.get("lazy_iterables_read", 0) + ctx.lazy_read
    if mode == "shadow" and not ctx.shadow_rebuilt:
        return obj, counts
    return new, counts


def detokenize_text(text: str, vault: Vault, kinds: Optional[Iterable[str]] = None,
                    counts: Optional[Counter] = None) -> str:
    """Replace known tokens with their real values; unknown tokens stay.

    ``kinds`` (optional) limits which token kinds may be turned back: a token of any other kind stays a token.
    ``counts`` (optional) receives how many values of each kind were revealed (never the values).
    """
    allowed = None if kinds is None else frozenset(kinds)

    def _sub(m: "re.Match[str]") -> str:
        if allowed is not None and m.group(1) not in allowed:
            return m.group(0)
        real = vault.reveal(m.group(0))
        if real is None:
            return m.group(0)
        if counts is not None:
            counts[m.group(1)] += 1
        return real
    return TOKEN_RE.sub(_sub, text)


def detokenize_obj(obj: Any, vault: Vault, kinds: Optional[Iterable[str]] = None,
                   counts: Optional[Counter] = None) -> Any:
    allowed = None if kinds is None else frozenset(kinds)
    if isinstance(obj, str):
        return detokenize_text(obj, vault, allowed, counts)
    if isinstance(obj, dict):
        return {k: detokenize_obj(v, vault, allowed, counts) for k, v in obj.items()}
    if isinstance(obj, list):
        return [detokenize_obj(v, vault, allowed, counts) for v in obj]
    if isinstance(obj, tuple):
        return tuple(detokenize_obj(v, vault, allowed, counts) for v in obj)
    return obj
