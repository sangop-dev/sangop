"""Media M0: "No media leaves silently."

Before M0, an MCP ImageContent / AudioContent / EmbeddedResource(blob), a ``data:image/...;base64,...`` URI or a long
base64 image string left a guarded tool unchanged (``pii_found: {}``), and raw PNG/JPEG bytes were decoded as text,
scanned, and re-encoded (which can break the image while the pixels - a photographed Aadhaar - are never checked).

M0 does not read images. It recognises media by magic bytes (no new dependency) and, by default
(``media_mode="block"``), replaces it with ``[SANGOP_BLOCKED: media <kind> not scanned]`` and writes a
``media_blocked`` ledger event (kind, sniffed and claimed MIME type, size, tool, purpose; never the content, never a
plain hash; an HMAC only when a ledger key is set). ``media_mode="allow"`` passes media unchanged and writes
``media_unscanned``. ``pii_mode="shadow"`` never changes anything; it only counts and logs.

Written before the code (failing first). Synthetic bytes only.
"""
import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import struct
import zlib

import pytest
from conftest import PAN, PHONE

import sangop
from sangop.tokenizer import Vault, scrub_obj

BLOCK_RE = "[SANGOP_BLOCKED: media "


# ---- synthetic media ----------------------------------------------------------------------------------------------

def _png(text_chunk: bytes = b"") -> bytes:
    """A real 1x1 PNG (stdlib zlib only); an optional tEXt chunk carries text inside the file."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    body = chunk(b"IHDR", ihdr)
    if text_chunk:
        body += chunk(b"tEXt", b"Comment\x00" + text_chunk)
    body += chunk(b"IDAT", zlib.compress(b"\x00\x7f")) + chunk(b"IEND", b"")
    return b"\x89PNG\r\n\x1a\n" + body


PAD = bytes(range(256)) * 2          # filler after the magic bytes (512 bytes, not text)

MEDIA = {
    "png": _png(text_chunk=b"synthetic test image, no personal data " * 6),   # > 192 bytes -> > 256 base64 chars
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + PAD,
    "gif": b"GIF89a\x01\x00\x01\x00\x80\x00\x00" + PAD,
    "webp": b"RIFF" + struct.pack("<I", 4 + len(PAD)) + b"WEBPVP8 " + PAD,
    "bmp": b"BM" + struct.pack("<I", 54 + len(PAD)) + b"\x00\x00\x00\x00" + struct.pack("<II", 54, 40) + PAD,
    "tiff": b"II*\x00\x08\x00\x00\x00" + PAD,
    "tiff_be": b"MM\x00*\x00\x00\x00\x08" + PAD,
    "heic": b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00" + PAD,
    "heix": b"\x00\x00\x00\x18ftypheix\x00\x00\x00\x00" + PAD,
    "mif1": b"\x00\x00\x00\x18ftypmif1\x00\x00\x00\x00" + PAD,
    "avif": b"\x00\x00\x00\x1cftypavif\x00\x00\x00\x00" + PAD,
    "pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + PAD,
    "zip": b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + PAD,
    "ole": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + PAD,
}


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _blocked(v) -> bool:
    return isinstance(v, str) and v.startswith(BLOCK_RE) and v.endswith(" not scanned]")


def _events(name):
    return [r["record"] for r in sangop.get_ledger().tail(500) if r["event"] == name]


def _json(obj) -> str:
    import pydantic_core
    return pydantic_core.to_json(obj, fallback=repr).decode("utf-8", "replace")


# ---- 1. recognition: raw bytes, bytearray, memoryview ------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(MEDIA))
@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview])
def test_raw_media_is_blocked_by_magic_bytes(name, wrap):
    out, counts = scrub_obj({"file": wrap(MEDIA[name])}, Vault(), "tokenize")
    assert _blocked(out["file"]), (name, wrap, type(out["file"]))
    assert not counts


@pytest.mark.parametrize("name,kind", [("png", "png"), ("jpeg", "jpeg"), ("pdf", "pdf"), ("ole", "ole"),
                                       ("heic", "heic"), ("avif", "avif"), ("tiff_be", "tiff")])
def test_placeholder_names_the_sniffed_kind(name, kind):
    out, _ = scrub_obj(MEDIA[name], Vault(), "tokenize")
    assert out == f"[SANGOP_BLOCKED: media {kind} not scanned]"


def test_sniff_helper():
    from sangop.media import sniff
    for name, raw in MEDIA.items():
        assert sniff(raw) is not None, name
    assert sniff(b"hello world, this is plain text") is None
    assert sniff(b"") is None


# ---- 2. data: URIs and long base64 strings -----------------------------------------------------------------------

@pytest.mark.parametrize("mime,raw", [("image/png", MEDIA["png"]), ("image/jpeg", MEDIA["jpeg"]),
                                      ("application/pdf", MEDIA["pdf"]), ("application/octet-stream", MEDIA["zip"])])
def test_data_uri_is_blocked(mime, raw):
    uri = f"data:{mime};base64,{_b64(raw)}"
    out, _ = scrub_obj({"img": uri}, Vault(), "tokenize")
    assert _blocked(out["img"]) and "base64," not in out["img"]


def test_data_uri_inside_longer_text_is_cut_out_and_the_rest_is_still_scanned():
    uri = f"data:image/png;base64,{_b64(MEDIA['png'])}"
    html = f'<p>PAN {PAN}</p><img src="{uri}"/><p>call {PHONE}</p>'
    out, counts = scrub_obj(html, Vault(), "redact")
    assert "base64," not in out and BLOCK_RE in out
    assert PAN not in out and PHONE not in out and counts["PAN"] == 1 and counts["PHONE_IN"] == 1
    assert out.startswith("<p>PAN [REDACTED_PAN]</p><img src=\"")


@pytest.mark.parametrize("name", ["png", "jpeg", "pdf", "gif", "webp", "zip"])
def test_long_base64_media_string_in_a_dict_or_list_is_blocked(name):
    s = _b64(MEDIA[name])
    assert len(s) >= 256
    out, _ = scrub_obj({"blob": s, "list": [s]}, Vault(), "tokenize")
    assert _blocked(out["blob"]) and _blocked(out["list"][0]), name


def test_urlsafe_and_wrapped_base64_media_is_blocked():
    raw = MEDIA["png"] + PAD
    urlsafe = base64.urlsafe_b64encode(raw).decode()
    wrapped = "\n".join(_b64(raw)[i:i + 76] for i in range(0, len(_b64(raw)), 76))
    for s in (urlsafe, wrapped):
        out, _ = scrub_obj([s], Vault(), "tokenize")
        assert _blocked(out[0])


# ---- 3. MCP content blocks ---------------------------------------------------------------------------------------

mcp_types = pytest.importorskip("mcp.types")


def test_mcp_image_audio_and_blob_resource_become_text_content():
    img = mcp_types.ImageContent(type="image", data=_b64(MEDIA["png"]), mimeType="image/png")
    aud = mcp_types.AudioContent(type="audio", data=_b64(b"RIFF\x24\x00\x00\x00WAVEfmt " + PAD), mimeType="audio/wav")
    res = mcp_types.EmbeddedResource(type="resource", resource=mcp_types.BlobResourceContents(
        uri="file:///scan.pdf", mimeType="application/pdf", blob=_b64(MEDIA["pdf"])))
    out, _ = scrub_obj([img, aud, res], Vault(), "tokenize")
    for o in out:
        assert isinstance(o, mcp_types.TextContent), type(o)
        assert _blocked(o.text)
    assert "png" in out[0].text and "pdf" in out[2].text


def test_mcp_text_resource_is_scanned_as_text_not_blocked():
    res = mcp_types.EmbeddedResource(type="resource", resource=mcp_types.TextResourceContents(
        uri="file:///a.txt", mimeType="text/plain", text=f"PAN {PAN}"))
    out, counts = scrub_obj(res, Vault(), "redact")
    assert isinstance(out, mcp_types.EmbeddedResource) and PAN not in out.resource.text and counts["PAN"] == 1


def test_mcp_image_with_short_or_non_media_data_is_still_blocked():
    """A content block that CLAIMS to be an image is media whatever its data looks like."""
    img = mcp_types.ImageContent(type="image", data=_b64(b"tiny"), mimeType="image/png")
    out, _ = scrub_obj(img, Vault(), "tokenize")
    assert isinstance(out, mcp_types.TextContent) and _blocked(out.text)


# ---- 4. nested ---------------------------------------------------------------------------------------------------

@dataclasses.dataclass
class Report:
    title: str
    scan: bytes


def test_nested_media_in_dict_list_generator_pydantic_and_dataclass():
    import pydantic

    class Model(pydantic.BaseModel):
        name: str
        photo: str

    payload = {
        "a": [{"b": MEDIA["jpeg"]}],
        "gen": (x for x in [MEDIA["png"], "ok"]),
        "model": Model(name="x", photo=_b64(MEDIA["png"])),
        "dc": Report(title=f"PAN {PAN}", scan=MEDIA["pdf"]),
        "content": [mcp_types.ImageContent(type="image", data=_b64(MEDIA["gif"]), mimeType="image/gif")],
    }
    out, counts = scrub_obj(payload, Vault(), "redact")
    assert _blocked(out["a"][0]["b"])
    assert _blocked(out["gen"][0]) and out["gen"][1] == "ok"
    assert _blocked(out["model"].photo) and out["model"].name == "x"
    assert _blocked(out["dc"].scan) and PAN not in out["dc"].title
    assert isinstance(out["content"][0], mcp_types.TextContent)
    assert counts["PAN"] == 1
    text = _json(out)
    for raw in (MEDIA["jpeg"], MEDIA["png"], MEDIA["pdf"], MEDIA["gif"]):
        assert _b64(raw) not in text


# ---- 5. raw image bytes are no longer decoded as text ------------------------------------------------------------

def test_png_with_text_inside_is_not_rewritten_as_text():
    png = _png(text_chunk=f"PAN {PAN} phone {PHONE}".encode())
    out, counts = scrub_obj(png, Vault(), "redact")
    assert _blocked(out)
    assert not counts              # media is not text-scanned: no PII counts from inside the file


# ---- 6. through @guard: modes and ledger -------------------------------------------------------------------------

def test_guard_blocks_by_default_and_logs_without_content():
    raw = MEDIA["png"]

    @sangop.guard(purpose="kyc")
    def tool():
        return {"photo": raw, "note": f"PAN {PAN}"}
    out = tool()
    assert _blocked(out["photo"]) and PAN not in out["note"]
    ev = _events("media_blocked")
    assert len(ev) == 1
    e = ev[0]
    assert e["kind"] == "png" and e["sniffed_mime"] == "image/png" and e["size_bytes"] == len(raw)
    assert e["tool"] == "tool" and e["purpose"] == "kyc"
    dump = json.dumps(e)
    assert _b64(raw)[:40] not in dump
    assert hashlib.sha256(raw).hexdigest() not in dump and hashlib.md5(raw).hexdigest() not in dump
    assert "content_hmac" not in e                 # no ledger key -> no fingerprint at all
    call = _events("tool_call")[0]
    assert call["media_blocked"] == 1 and call["pii_found"] == {"PAN": 1}


def test_ledger_key_gives_an_hmac_fingerprint_not_a_plain_hash(tmp_path):
    key = b"k" * 8 + b"Q7r8s9t0u1v2w3x4y5z6A7B8C9D0E1F2"
    sangop.configure(ledger_path=str(tmp_path / "keyed.db"), ledger_key=key)
    raw = MEDIA["pdf"]

    @sangop.guard(purpose="t")
    def tool():
        return raw
    assert _blocked(tool())
    e = _events("media_blocked")[0]
    assert e["content_hmac"] == hmac.new(key, raw, hashlib.sha256).hexdigest()
    assert hashlib.sha256(raw).hexdigest() not in json.dumps(e)


def test_claimed_mime_is_logged_for_data_uri_and_mcp_blocks():
    @sangop.guard(purpose="t")
    def tool():
        return [f"data:image/jpeg;base64,{_b64(MEDIA['png'])}",
                mcp_types.ImageContent(type="image", data=_b64(MEDIA["png"]), mimeType="image/webp")]
    tool()
    ev = _events("media_blocked")
    assert sorted(e["claimed_mime"] for e in ev) == ["image/jpeg", "image/webp"]
    assert all(e["sniffed_mime"] == "image/png" for e in ev)


def test_allow_mode_passes_media_unchanged_and_logs_media_unscanned():
    raw = MEDIA["png"]
    img = mcp_types.ImageContent(type="image", data=_b64(raw), mimeType="image/png")

    @sangop.guard(purpose="t", media_mode="allow")
    def tool():
        return {"photo": raw, "img": img, "note": f"PAN {PAN}"}
    out = tool()
    assert out["photo"] == raw and isinstance(out["photo"], bytes)       # byte-identical, not text-decoded
    assert isinstance(out["img"], mcp_types.ImageContent) and out["img"].data == _b64(raw)
    assert PAN not in out["note"]
    ev = _events("media_unscanned")
    assert len(ev) == 2 and not _events("media_blocked")
    assert {e["kind"] for e in ev} == {"png"}


def test_configure_sets_the_default_and_guard_overrides_it(tmp_path):
    sangop.configure(ledger_path=str(tmp_path / "c.db"), media_mode="allow")

    @sangop.guard(purpose="t")
    def follows_default():
        return MEDIA["jpeg"]

    @sangop.guard(purpose="t", media_mode="block")
    def strict():
        return MEDIA["jpeg"]
    assert follows_default() == MEDIA["jpeg"]
    assert _blocked(strict())
    sangop.configure(ledger_path=str(tmp_path / "d.db"))          # back to the default
    assert _blocked(follows_default())


def test_media_mode_is_validated():
    with pytest.raises(ValueError):
        sangop.guard(purpose="t", media_mode="scan")
    with pytest.raises(ValueError):
        sangop.configure(ledger_path=None, run_selftest=False, media_mode="maybe")


def test_shadow_mode_changes_nothing_and_logs():
    raw = MEDIA["png"]

    @sangop.guard(purpose="t", pii_mode="shadow")
    def tool():
        return {"photo": raw}
    out = tool()
    assert out["photo"] is raw
    ev = _events("media_blocked")
    assert len(ev) == 1 and ev[0]["shadow"] is True


def test_generator_tool_items_are_checked_too():
    @sangop.guard(purpose="t")
    def tool():
        yield MEDIA["png"]
        yield "fine"
    items = list(tool())
    assert _blocked(items[0]) and items[1] == "fine"
    assert len(_events("media_blocked")) == 1


# ---- 7. fail closed ----------------------------------------------------------------------------------------------

def test_undecodable_claimed_media_is_blocked_even_in_allow_mode():
    img = mcp_types.ImageContent(type="image", data="!!not base64!!" * 30, mimeType="image/png")

    @sangop.guard(purpose="t", media_mode="allow")
    def tool():
        return [img, f"data:image/png;base64,{'@@@@' * 80}"]
    out = tool()
    assert isinstance(out[0], mcp_types.TextContent) and _blocked(out[0].text)
    assert _blocked(out[1])
    ev = _events("media_blocked")
    assert len(ev) == 2 and all(e["reason"] == "decode_error" for e in ev)


def test_corrupt_long_base64_with_media_magic_is_blocked_in_allow_mode():
    s = _b64(MEDIA["png"] + PAD)
    s = s[:200] + "!!!!" + s[204:]

    @sangop.guard(purpose="t", media_mode="allow")
    def tool():
        return {"blob": s}
    assert _blocked(tool()["blob"])
    assert _events("media_blocked")[0]["reason"] == "decode_error"


def test_error_inside_the_sniffer_blocks(monkeypatch):
    import sangop.media as media

    def boom(*a, **k):
        raise RuntimeError("sniffer bug")
    monkeypatch.setattr(media, "sniff", boom)

    @sangop.guard(purpose="t", media_mode="allow")
    def tool():
        return {"photo": MEDIA["png"]}
    out = tool()
    assert _blocked(out["photo"])
    assert _events("media_blocked")[0]["reason"] == "error"


# ---- 8. decoys: not media ----------------------------------------------------------------------------------------

DECOYS = [
    "The report is attached as %PDF-1.7 in the mail, see PNG and JPEG versions too.",
    "data: none; base64 is an encoding",
    "Header 'PNG' and 'GIF89a' and 'RIFF WEBP' mentioned in text only",
    "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxIn0" + ".c2lnbmF0dXJl",   # short JWT-like token (built at runtime)
    _b64(MEDIA["png"])[:120],                                         # short base64 (< 256) of a PNG header
    _b64(bytes(range(256)) * 2),                                       # long base64 that is NOT media
    "QUJD" * 100,                                                      # long base64 of "ABC..." text
    "[PII_PAN_1a2b3c4d5e6f7a8b] and [PII_PHONE_IN_0011223344556677]",
    "A" * 400,                                                         # long, base64 alphabet, decodes to zeros
]


@pytest.mark.parametrize("text", DECOYS, ids=[f"decoy{i}" for i in range(len(DECOYS))])
def test_decoys_are_not_blocked(text):
    """Not media. (A JWT-shaped token can still be masked as SECRET_JWT; it must just not be treated as media.)"""
    out, _ = scrub_obj({"v": text}, Vault(), "tokenize")
    assert BLOCK_RE not in out["v"]
    out2, counts = scrub_obj({"v": text}, Vault(), "shadow")
    assert out2["v"] == text


@pytest.mark.parametrize("raw", [b"Report: %PDF-1.4 is mentioned mid-text, not at the start", b"BMW car parked in bay 4",
                                 b"PK is a country code", b"plain text bytes", b"GIF8 almost"])
def test_byte_decoys_are_not_blocked(raw):
    out, _ = scrub_obj(raw, Vault(), "tokenize")
    assert out == raw


def test_plain_bytes_with_pii_are_still_scrubbed_as_text():
    out, counts = scrub_obj(f"PAN {PAN}".encode(), Vault(), "redact")
    assert out == b"PAN [REDACTED_PAN]" and counts["PAN"] == 1


def test_no_media_event_for_clean_calls():
    @sangop.guard(purpose="t")
    def tool():
        return {"text": "hello", "n": 1}
    tool()
    assert not _events("media_blocked") and not _events("media_unscanned")
    assert "media_blocked" not in _events("tool_call")[0]


# ---- 9. official MCP Python SDK server, in memory ----------------------------------------------------------------

def _serve(media_mode):
    pytest.importorskip("mcp.server.mcpserver")
    from mcp.client import Client
    from mcp.server.mcpserver import MCPServer

    srv = MCPServer("media")
    png = _png(text_chunk=f"Aadhaar card scan {PAN}".encode())

    @srv.tool()
    @sangop.guard(purpose="kyc", media_mode=media_mode)
    def photo() -> list:
        """Returns an image."""
        return [mcp_types.ImageContent(type="image", data=_b64(png), mimeType="image/png")]

    async def go():
        async with Client(srv) as c:
            r = await c.call_tool("photo", {})
            return r
    return asyncio.run(go()), png


def test_official_mcpserver_block_mode_no_image_reaches_the_client():
    r, png = _serve("block")
    assert not r.is_error
    assert not [x for x in r.content if getattr(x, "type", None) == "image"]
    text = "".join(getattr(x, "text", "") or "" for x in r.content)
    assert BLOCK_RE in text and _b64(png) not in _json(r)
    assert _events("media_blocked")


def test_official_mcpserver_allow_mode_image_reaches_the_client_and_is_logged():
    r, png = _serve("allow")
    assert not r.is_error
    imgs = [x for x in r.content if getattr(x, "type", None) == "image"]
    assert len(imgs) == 1 and base64.b64decode(imgs[0].data) == png
    assert _events("media_unscanned")
