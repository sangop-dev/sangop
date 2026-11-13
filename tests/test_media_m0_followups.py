"""Media M0 follow-ups from the internal review of 27 Oct 2026 (M0-1 ... M0-4; M0-5 is a README limit).

M0-1  a base64 piece of 256+ characters INSIDE longer text ("img=<b64>", "image: <b64>") is decoded and sniffed;
      if it is media only that piece is replaced, and the rest of the text is still scanned for PII.
M0-2  every ";base64" data: URI is decoded and sniffed, whatever MIME type it claims (text/plain, ...).
M0-3  a PDF is recognised when "%PDF-" appears in the first 1024 bytes (after a BOM or junk), not only at byte 0.
M0-4  "data:image/png ; base64 , ..." (spaces around ";" and ",") is still a data URI.
Plus: the decoys stay unblocked, and a 20 MB string is handled in under 2 seconds.

Written before the fix (failing first). Synthetic bytes only.
"""
import base64
import struct
import time
import zlib

import pytest
from conftest import PAN, PHONE

import sangop
from sangop.tokenizer import Vault, scrub_obj

BLOCK = "[SANGOP_BLOCKED: media "


def _png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    body = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    body += chunk(b"tEXt", b"Comment\x00" + b"synthetic test image, no personal data " * 6)
    body += chunk(b"IDAT", zlib.compress(b"\x00\x7f")) + chunk(b"IEND", b"")
    return b"\x89PNG\r\n\x1a\n" + body


PNG = _png()
PDF = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF\n" + bytes(range(256))
B64_PNG = base64.b64encode(PNG).decode()
B64_PDF = base64.b64encode(PDF).decode()
assert len(B64_PNG) >= 256 and len(B64_PDF) >= 256


def _events(name):
    return [r["record"] for r in sangop.get_ledger().tail(500) if r["event"] == name]


# ---- M0-1: base64 media inside longer text -----------------------------------------------------------------------

@pytest.mark.parametrize("template", [
    "img={b} done",
    "image: {b}",
    "Attached photo (base64) {b}\nThanks",
    '{{"note": "see attachment", "file": "{b}"}}',
    "prefix text|{b}|suffix text",
])
def test_base64_media_piece_inside_text_is_replaced(template):
    text = f"PAN {PAN}. " + template.format(b=B64_PNG) + f" call {PHONE}"
    out, counts = scrub_obj(text, Vault(), "redact")
    assert B64_PNG not in out and B64_PNG[:60] not in out
    assert out.count(BLOCK) == 1 and "media png not scanned" in out
    assert PAN not in out and PHONE not in out and counts["PAN"] == 1 and counts["PHONE_IN"] == 1


def test_two_media_pieces_in_one_text():
    text = f"a={B64_PNG} b={B64_PDF} end"
    out, _ = scrub_obj(text, Vault(), "tokenize")
    assert out.count(BLOCK) == 2 and "media png" in out and "media pdf" in out
    assert out.startswith("a=[SANGOP_BLOCKED") and out.endswith(" end")


def test_base64_piece_in_text_allow_mode_unchanged_and_logged():
    @sangop.guard(purpose="t", media_mode="allow")
    def tool():
        return f"img={B64_PNG} PAN {PAN}"
    out = tool()
    assert B64_PNG in out and PAN not in out
    ev = _events("media_unscanned")
    assert len(ev) == 1 and ev[0]["kind"] == "png"


def test_corrupt_base64_media_piece_in_text_is_blocked_in_allow_mode():
    """A piece that starts like a PNG but cannot be decoded (one character too many) fails closed."""
    core = B64_PNG.rstrip("=")
    bad = core + "A" * ((1 - len(core)) % 4)                # length = 1 more than a multiple of 4: not decodable
    assert len(bad) % 4 == 1

    @sangop.guard(purpose="t", media_mode="allow")
    def tool():
        return f"x={bad} y"
    out = tool()
    assert BLOCK in out and bad not in out
    assert _events("media_blocked")[0]["reason"] == "decode_error"


# ---- M0-2: data URI with a non-media MIME is still sniffed --------------------------------------------------------

@pytest.mark.parametrize("mime", ["text/plain", "application/json", "text/html", "application/x-anything", ""])
def test_data_uri_with_any_claimed_mime_is_decoded_and_sniffed(mime):
    uri = f"data:{mime};base64,{B64_PNG}"
    out, _ = scrub_obj({"v": f"see {uri} ok"}, Vault(), "tokenize")
    assert B64_PNG not in out["v"] and BLOCK in out["v"] and out["v"].endswith(" ok")


def test_data_uri_with_text_mime_and_text_payload_is_not_blocked():
    payload = base64.b64encode(b"hello, this is just text " * 20).decode()
    s = f"data:text/plain;base64,{payload}"
    out, _ = scrub_obj({"v": s}, Vault(), "tokenize")
    assert out["v"] == s


def test_claimed_mime_is_logged_when_it_lies():
    @sangop.guard(purpose="t")
    def tool():
        return f"data:text/plain;base64,{B64_PNG}"
    tool()
    e = _events("media_blocked")[0]
    assert e["claimed_mime"] == "text/plain" and e["sniffed_mime"] == "image/png" and e["kind"] == "png"


# ---- M0-3: %PDF- after a BOM or junk -----------------------------------------------------------------------------

@pytest.mark.parametrize("lead", [b"\xef\xbb\xbf", b"\r\n\r\n", b"junk header line\n", b"\x00" * 300, b"x" * 1000])
def test_pdf_header_within_first_1024_bytes_is_recognised(lead):
    raw = lead + PDF
    assert len(lead) + 5 <= 1024
    out, _ = scrub_obj({"f": raw}, Vault(), "tokenize")
    assert isinstance(out["f"], str) and out["f"] == "[SANGOP_BLOCKED: media pdf not scanned]"
    out2, _ = scrub_obj({"f": base64.b64encode(raw).decode()}, Vault(), "tokenize")
    assert out2["f"] == "[SANGOP_BLOCKED: media pdf not scanned]"


def test_pdf_header_after_1024_bytes_is_not_assumed():
    raw = b"x" * 1100 + PDF
    out, _ = scrub_obj(raw, Vault(), "tokenize")
    assert out == raw


@pytest.mark.parametrize("raw", [
    b"Report: %PDF-1.4 is mentioned mid-text, not at the start",
    b"notes\nThe spec says files begin with %PDF-1.7 and end with %%EOF\n",
])
def test_text_that_only_mentions_pdf_is_not_blocked(raw):
    out, _ = scrub_obj(raw, Vault(), "tokenize")
    assert out == raw


# ---- M0-4: spaces inside the data URI ----------------------------------------------------------------------------

@pytest.mark.parametrize("form", [
    "data:image/png ; base64 , {b}",
    "data:image/png;base64, {b}",
    "data:image/png ;base64,{b}",
    "DATA:IMAGE/PNG; BASE64,{b}",
])
def test_data_uri_with_spaces_is_still_a_data_uri(form):
    s = "src " + form.format(b=B64_PNG) + " end"
    out, _ = scrub_obj(s, Vault(), "tokenize")
    assert B64_PNG not in out and BLOCK in out and out.endswith(" end")


# ---- decoys ------------------------------------------------------------------------------------------------------

DECOYS = [
    "Normal sentence about images, PDFs and base64 encoding with no data at all.",
    "token=" + "ab12" * 30,                                                       # short (< 256)
    "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxIn0" + ".c2lnbmF0dXJl",
    "blob=" + base64.b64encode(bytes(range(256)) * 3).decode() + " end",        # long, not media
    "hash " + "A" * 600,
    "words " + "abcdefgh" * 80,                                                  # long letters only
    "[PII_PAN_1a2b3c4d5e6f7a8b] and [PII_PHONE_IN_0011223344556677]",
    "data:text/plain;base64," + base64.b64encode(b"plain words " * 40).decode(),
]


@pytest.mark.parametrize("text", DECOYS, ids=[f"d{i}" for i in range(len(DECOYS))])
def test_decoys_are_not_media(text):
    out, _ = scrub_obj({"v": text}, Vault(), "shadow")
    assert out["v"] == text
    out2, _ = scrub_obj({"v": text}, Vault(), "tokenize")
    assert BLOCK not in out2["v"]


# ---- DoS: large input must not blow up ---------------------------------------------------------------------------
# L-1 (internal review 27 Oct 2026): a fixed "20 MB < 2 s" limit is flaky on a slower machine. The meaning of the check stays the
# same - 20 MB must fit in the 2-second budget measured on the development machine - but the budget is CALIBRATED to
# the machine running the tests: a reference workload that uses no Sangop code (regex + a Python loop + encode) is
# timed, and the 2 s budget is scaled by how much slower this machine is than the development machine (never made
# tighter than 2 s on a faster one). A Sangop slowdown therefore cannot hide inside the calibration.
# Two more checks: the time must grow about linearly from 2 MB to 20 MB, and the strict absolute "under 2 s" check
# is kept, marked ``slow`` (run it on the development machine with ``pytest -m slow``).

DEV_REFERENCE_SECONDS = 0.062     # best of 7 runs of _reference_workload() on the development machine, 28 Oct 2026
BUDGET_SECONDS = 2.0              # 20 MB budget on the development machine (measured worst case 1.7 s, 27 Oct 2026)
MAX_GROWTH = 25.0                 # 2 MB -> 20 MB: linear is ~10x; a quadratic blow-up is ~100x
DOS_KINDS = ["text", "base64_not_media", "many_small_pieces", "media_inside_text"]


def _reference_workload() -> float:
    import re
    s = "Order 1234 shipped to 560001 on 27/10/2026; ref ab12cd34. " * 40000
    t = time.perf_counter()
    n = len(re.findall(r"\d{4}", s))
    n += sum(1 for c in s[:600000] if c.isdigit())
    s.encode().decode()
    return time.perf_counter() - t


def _reference_median() -> float:
    runs = sorted(_reference_workload() for _ in range(5))
    return runs[len(runs) // 2]


def _machine_factor(before: float, after: float) -> float:
    """How much slower than the development machine, from the reference timed just before AND just after the
    measured run (the slower of the two, so load that changes during the run is covered); never below 1."""
    return max(1.0, max(before, after) / DEV_REFERENCE_SECONDS)


def _big(kind, n):
    if kind == "text":
        return ("Customer note about refund and delivery. " * (n // 40 + 1))[:n]
    if kind == "base64_not_media":
        return "QUJD" * (n // 4)
    if kind == "many_small_pieces":
        piece = "id=" + base64.b64encode(bytes(range(256)) * 2).decode() + " "
    else:
        piece = "img=" + B64_PNG + " note "
    return (piece * (n // len(piece) + 1))[:n]


def _best_time(s, repeat):
    best, out = None, None
    for _ in range(repeat):
        t = time.perf_counter()
        out, _ = scrub_obj(s, Vault(), "tokenize")
        took = time.perf_counter() - t
        best = took if best is None else min(best, took)
    return best, out


def _no_leak(kind, out):
    if kind == "media_inside_text":
        leaked = B64_PNG in out                  # a bool, so a failure does not make pytest diff 20 MB strings
        assert not leaked


@pytest.mark.parametrize("kind", DOS_KINDS)
def test_20_mb_within_the_machine_calibrated_budget(kind):
    big = _big(kind, 20_000_000)
    before = _reference_median()
    took, out = _best_time(big, repeat=2)
    factor = _machine_factor(before, _reference_median())
    assert took < BUDGET_SECONDS * factor, (kind, round(took, 2), "budget", round(BUDGET_SECONDS * factor, 2),
                                            "machine factor", round(factor, 2))
    _no_leak(kind, out)


@pytest.mark.parametrize("kind", DOS_KINDS)
def test_large_input_time_grows_linearly(kind):
    small, _ = _best_time(_big(kind, 2_000_000), repeat=3)
    large, out = _best_time(_big(kind, 20_000_000), repeat=2)
    growth = large / max(small, 1e-3)
    assert growth < MAX_GROWTH, (kind, round(small, 3), round(large, 3), round(growth, 1))
    _no_leak(kind, out)


@pytest.mark.slow
@pytest.mark.parametrize("kind", DOS_KINDS)
def test_20_mb_string_under_2_seconds(kind):
    """The strict absolute limit, for the development machine (run with ``pytest -m slow``)."""
    took, out = _best_time(_big(kind, 20_000_000), repeat=1)
    assert took < BUDGET_SECONDS, (kind, round(took, 2))
    _no_leak(kind, out)


# ---- documented limits (README Known limits, M0-5): still NOT recognised as media --------------------------------

@pytest.mark.parametrize("name", ["hex_string", "list_of_ints", "tuple_of_ints", "wrapped_base64_inside_text",
                                  "pdf_header_after_1024_bytes"])
def test_forms_listed_in_known_limits_are_still_not_recognised(name):
    """If one of these starts being recognised, update README Known limits and this list together."""
    value = {
        "hex_string": PNG.hex(),
        "list_of_ints": list(PNG),
        "tuple_of_ints": tuple(PNG),
        "wrapped_base64_inside_text": "img:\n" + "\n".join(B64_PNG[i:i + 76] for i in range(0, len(B64_PNG), 76)) + "\nend",
        "pdf_header_after_1024_bytes": b"x" * 1100 + PDF,
    }[name]
    out, _ = scrub_obj({"v": value}, Vault(), "tokenize")
    assert BLOCK not in str(out["v"]), name


def test_gzip_compressed_media_in_base64_is_not_recognised_documented_limit():
    """Internal review 28 Oct 2026 (M0-x, LOW): gzip has no media magic number, so a PNG gzip-compressed and then base64-encoded is
    not recognised. README Known limits; if this ever changes, update the README too."""
    import gzip
    s = base64.b64encode(gzip.compress(PNG + bytes(range(256)) * 4)).decode()
    assert len(s) >= 256                         # long enough that only the gzip wrapper hides it
    for v in (s, "img=" + s + " end"):
        out, _ = scrub_obj({"v": v}, Vault(), "tokenize")
        assert BLOCK not in out["v"]
