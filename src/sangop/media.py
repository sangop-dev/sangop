"""Media recognition for Media M0 (D-078): "No media leaves silently."

Sangop does not read images, PDFs, Office files or audio (no OCR, no parsing). This module only RECOGNISES them, so
that the guard can block them (default) or pass them on with an audit event, instead of letting them through
silently or decoding their bytes as text.

Recognition uses magic bytes at the start of the data (standard library only, no new dependency):

    png, jpeg, gif, webp, bmp, tiff, heic, heif, avif      images
    pdf                                                     PDF
    office (OOXML / ODF inside a ZIP), zip, ole             Office files and archives (OLE = old .doc/.xls/.msg)
    wav, ogg, flac, mp3 (ID3), mp4, avi                     audio / video containers

Where media can hide in a tool result: raw ``bytes`` / ``bytearray`` / ``memoryview``; a ``data:...;base64,`` URI
anywhere inside a string (decoded and sniffed whatever MIME type it claims; ``image/*``, ``audio/*``, ``video/*``,
``application/pdf`` and ``application/octet-stream`` count as media even when the bytes are not recognised); a long
(>= ``MIN_B64_CHARS``) base64 string, or a base64 piece of that length inside longer text, whose decoded first bytes
carry one of the magic numbers; and the MCP content blocks ``ImageContent``, ``AudioContent`` and
``EmbeddedResource`` / ``BlobResourceContents`` (blob). A PDF is also recognised when ``%PDF-`` appears in its first
1024 bytes after a BOM or other junk, if a PDF object (``<n> <n> obj``) follows (a mere mention of "%PDF-" is not).
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
from typing import Any, Optional, Tuple

MIN_B64_CHARS = 256           # shorter base64 strings (JWT parts, ids, tokens) are never treated as media
_PREFIX_CHARS = 2048          # base64 characters decoded to look for a magic number (1536 bytes; covers the PDF window)
PDF_WINDOW = 1024             # "%PDF-" may start anywhere in the first 1024 bytes (as PDF readers accept)
_PDF_HEADER = re.compile(rb"%PDF-\d\.\d")
_PDF_OBJECT = re.compile(rb"\d+\s+\d+\s+obj\b")

_FTYP_BRANDS = {
    b"heic": ("heic", "image/heic"), b"heix": ("heic", "image/heic"), b"heim": ("heic", "image/heic"),
    b"heis": ("heic", "image/heic"), b"hevc": ("heic", "image/heic"), b"hevx": ("heic", "image/heic"),
    b"mif1": ("heif", "image/heif"), b"msf1": ("heif", "image/heif"),
    b"avif": ("avif", "image/avif"), b"avis": ("avif", "image/avif"),
}

_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def sniff(data: bytes) -> Optional[Tuple[str, str]]:
    """Return ``(kind, mime)`` when ``data`` starts like a known media file, else ``None``."""
    d = bytes(data[:64])
    if len(d) < 4:
        return None
    if d.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "image/png"
    if d.startswith(b"\xff\xd8\xff"):
        return "jpeg", "image/jpeg"
    if d.startswith((b"GIF87a", b"GIF89a")):
        return "gif", "image/gif"
    if d.startswith(b"RIFF") and len(d) >= 12:
        sub = d[8:12]
        if sub == b"WEBP":
            return "webp", "image/webp"
        if sub == b"WAVE":
            return "wav", "audio/wav"
        if sub == b"AVI ":
            return "avi", "video/x-msvideo"
    if _is_bmp(d):
        return "bmp", "image/bmp"
    if d.startswith((b"II*\x00", b"MM\x00*")):
        return "tiff", "image/tiff"
    if len(d) >= 12 and d[4:8] == b"ftyp":
        return _FTYP_BRANDS.get(d[8:12], ("mp4", "video/mp4"))
    if d.startswith(b"%PDF-"):
        return "pdf", "application/pdf"
    if d.startswith(b"PK\x03\x04"):
        return _zip_kind(bytes(data[:200]))
    if d.startswith(_OLE):
        return "ole", "application/x-ole-storage"
    if d.startswith(b"OggS"):
        return "ogg", "audio/ogg"
    if d.startswith(b"fLaC"):
        return "flac", "audio/flac"
    if d.startswith(b"ID3") and len(d) >= 10 and d[3] in (2, 3, 4):
        return "mp3", "audio/mpeg"
    if _pdf_after_junk(data):
        return "pdf", "application/pdf"
    return None


def _pdf_after_junk(data: bytes) -> bool:
    """M0-3: '%PDF-<d>.<d>' within the first 1024 bytes (after a BOM, blank lines or junk) AND a PDF object
    ('1 0 obj') after it. Text that merely mentions '%PDF-1.7' has no object and is not treated as a PDF."""
    head = bytes(data[:PDF_WINDOW + 8])
    m = _PDF_HEADER.search(head)
    if m is None or m.start() >= PDF_WINDOW:
        return False
    return _PDF_OBJECT.search(bytes(data[m.end():m.end() + 4096])) is not None


def _is_bmp(d: bytes) -> bool:
    """'BM' alone is too weak (b'BMW ...'): also need zero reserved fields and a known DIB header size."""
    if not d.startswith(b"BM") or len(d) < 18:
        return False
    if d[6:10] != b"\x00\x00\x00\x00":
        return False
    offset, dib = struct.unpack("<II", d[10:18])
    return dib in (12, 40, 52, 56, 64, 108, 124) and 14 + dib <= offset < (1 << 30)


def _zip_kind(d: bytes) -> Tuple[str, str]:
    """A ZIP whose first entry is the OOXML or ODF marker is an Office file; anything else is a plain ZIP."""
    try:
        name_len = struct.unpack("<H", d[26:28])[0]
        name = d[30:30 + name_len]
    except Exception:
        name = b""
    if name == b"[Content_Types].xml" or name.startswith((b"word/", b"xl/", b"ppt/", b"_rels/")):
        return "office", "application/vnd.openxmlformats-officedocument"
    if name == b"mimetype" and b"application/vnd.oasis.opendocument" in d:
        return "office", "application/vnd.oasis.opendocument"
    return "zip", "application/zip"


# ---- base64 -------------------------------------------------------------------------------------------------------

_B64_CHARS = re.compile(r"[A-Za-z0-9+/=\-_\s]+")
_WS = re.compile(r"\s+")


def _b64_decode(s: str, full: bool, prefix_chars: int = _PREFIX_CHARS) -> bytes:
    """Decode standard or URL-safe base64 (whitespace ignored). ``full=False`` decodes only a prefix."""
    if not full:
        s = s[:prefix_chars * 2]                   # never touch more than needed (a piece can be megabytes long)
    s = _WS.sub("", s)
    if "-" in s or "_" in s:
        if "+" in s or "/" in s:
            raise binascii.Error("mixed base64 alphabets")
        s = s.replace("-", "+").replace("_", "/")
    if not full:
        s = s[:prefix_chars].rstrip("=")
        s = s[:len(s) - len(s) % 4]                # a whole number of 4-character groups: no padding needed
    else:
        s = s + "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True)


def b64_media_candidate(s: str) -> Optional[Tuple[str, str]]:
    """``(kind, mime)`` if the WHOLE string looks like long base64 of a media file (decoded prefix has a magic
    number), else None. Only the prefix is decoded here; :func:`b64_decode_full` checks the rest."""
    t = s.strip()
    if len(t) < MIN_B64_CHARS or not _B64_CHARS.fullmatch(t[:128]):       # cheap check; full check later
        return None
    try:
        head = _b64_decode(t, full=False, prefix_chars=64)       # 48 bytes: every fixed magic number
    except (binascii.Error, ValueError):
        return None
    hit = sniff(head)
    if hit is not None:
        return hit
    if _maybe_pdf_b64(t):
        try:
            if _pdf_after_junk(_b64_decode(t, full=False)):
                return "pdf", "application/pdf"
        except (binascii.Error, ValueError):
            return None
    return None


def b64_decode_full(s: str) -> bytes:
    """Strict decode of a base64 string (raises ``binascii.Error`` / ``ValueError`` on any bad character)."""
    t = s.strip()
    if not _B64_CHARS.fullmatch(t):
        raise binascii.Error("not base64")
    return _b64_decode(t, full=True)


# ---- data: URIs ---------------------------------------------------------------------------------------------------

# M0-2/M0-4: any MIME type (or none), optional parameters, spaces allowed around ";" and ",".
DATA_URI_RE = re.compile(
    r"data:(?P<mime>[A-Za-z0-9.+\-]+/[A-Za-z0-9.+\-]+)?"
    r"(?P<params>(?:\s*;\s*[A-Za-z0-9.+\-]+=[^;,\s]+)*)\s*;\s*base64\s*,\s*(?P<b64>[^\s\"'<>()\[\]{},;]*)",
    re.IGNORECASE)


def is_media_mime(mime: Optional[str]) -> bool:
    """MIME types that are media even when their bytes are not recognised."""
    if not mime:
        return False
    m = mime.lower()
    return m.startswith(("image/", "audio/", "video/")) or m in ("application/pdf", "application/octet-stream")


def _pdf_b64_markers() -> Tuple[str, ...]:
    """The base64 text of '%PDF-' at each of the three byte alignments (only the characters that do not depend on
    the neighbouring bytes), so the long decode is done only when a PDF header can be in the first 1024 bytes."""
    out = []
    for k in range(3):
        a = base64.b64encode(b"\x00" * k + b"%PDF-" + b"\x00\x00").decode()
        b = base64.b64encode(b"\xff" * k + b"%PDF-" + b"\xff\xff").decode()
        common = "".join(x if x == y else "\n" for x, y in zip(a, b))
        out.append(max(common.split("\n"), key=len))
    return tuple(out)


_PDF_B64 = _pdf_b64_markers()
_PDF_B64_WINDOW = (PDF_WINDOW // 3 + 2) * 4


def _maybe_pdf_b64(s: str) -> bool:
    head = s[:_PDF_B64_WINDOW + 16]
    return any(mk in head for mk in _PDF_B64)


# M0-1: a base64 piece of MIN_B64_CHARS+ characters inside longer text ("img=<b64>", "image: <b64>").
B64_RUN_RE = re.compile(r"[A-Za-z0-9+/\-_]{%d,}={0,2}" % MIN_B64_CHARS)


def b64_run_media(run: str) -> Optional[Tuple[int, str, str]]:
    """``(offset, kind, mime)`` if the piece, read from offset 0-3 (letters glued in front, e.g. 'imgiVBOR...'),
    decodes to bytes that start like a media file; else None. Only a prefix is decoded here."""
    for off in range(4):
        try:
            head = _b64_decode(run[off:], full=False, prefix_chars=64)      # 48 bytes: every fixed magic number
        except (binascii.Error, ValueError):
            continue
        hit = sniff(head)
        if hit is not None:
            return off, hit[0], hit[1]
    try:                                                     # PDF after a BOM/junk needs a longer look (offset 0)
        if _maybe_pdf_b64(run) and _pdf_after_junk(_b64_decode(run, full=False)):
            return 0, "pdf", "application/pdf"
    except (binascii.Error, ValueError):
        pass
    return None


# ---- MCP content blocks -------------------------------------------------------------------------------------------

def _mime_of(obj: Any) -> Optional[str]:
    return getattr(obj, "mime_type", None) or getattr(obj, "mimeType", None)


def mcp_media(obj: Any) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
    """For an MCP content block that carries binary media, return ``(form, claimed_mime, base64_data)``.

    form: ``"content"`` (ImageContent / AudioContent / EmbeddedResource with a blob) or ``"blob"`` (a bare
    BlobResourceContents). Duck-typed on the class name and fields, so it works without importing ``mcp``."""
    name = type(obj).__name__
    if name in ("ImageContent", "AudioContent") and hasattr(obj, "data"):
        return "content", _mime_of(obj), getattr(obj, "data", None)
    if name == "EmbeddedResource":
        res = getattr(obj, "resource", None)
        blob = getattr(res, "blob", None)
        if blob is not None:
            return "content", _mime_of(res), blob
        return None
    if name == "BlobResourceContents" and getattr(obj, "blob", None) is not None:
        return "blob", _mime_of(obj), obj.blob
    return None


def mcp_text_replacement(obj: Any, form: str, text: str) -> Any:
    """A TextContent (or TextResourceContents for a bare blob) carrying ``text``; a plain string if ``mcp`` is absent."""
    try:
        import mcp.types as mt
    except Exception:
        return text
    try:
        if form == "blob":
            return mt.TextResourceContents(uri=getattr(obj, "uri"), mimeType="text/plain", text=text)
        return mt.TextContent(type="text", text=text)
    except Exception:
        return text


def kind_from_mime(mime: Optional[str]) -> str:
    """A short kind name from a claimed MIME type (used when the bytes could not be sniffed)."""
    if not mime:
        return "unknown"
    sub = mime.split("/", 1)[-1].split(";")[0].strip().lower()
    return {"jpg": "jpeg", "pjpeg": "jpeg", "x-ms-bmp": "bmp", "octet-stream": "binary", "mpeg": "mp3",
            "x-wav": "wav", "wave": "wav"}.get(sub, re.sub(r"[^a-z0-9.+\-]", "", sub) or "unknown")
