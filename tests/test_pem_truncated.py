"""N1-PEM (internal review 5 Nov 2026, MEDIUM): a PEM private key block that is cut off before its END line (tool
output limited in length, pagination) was not masked, so the key material after the BEGIN header left unmasked.

Written test-first. Fake key text only: the lines are pseudo-random base64 made at runtime, not a real key, and the
header is assembled by concatenation so that no file contains a literal key header.
"""
import random
import sys
import time

import pytest
from conftest import PAN

import sangop
from sangop import find_all

DASH = "-" * 5


def header(kind=""):
    return DASH + "BEGIN " + (kind + " " if kind else "") + "PRIVATE" + " KEY" + DASH


def footer(kind=""):
    return DASH + "END " + (kind + " " if kind else "") + "PRIVATE" + " KEY" + DASH


def body_lines(n=12, seed=7, width=64):
    rnd = random.Random(seed)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    lines = ["".join(rnd.choice(alphabet) for _ in range(width)) for _ in range(n)]
    lines.append("".join(rnd.choice(alphabet) for _ in range(20)) + "==")
    return lines


def secret_spans(text):
    return [(f.start, f.end) for f in find_all(text) if f.kind == "SECRET_PRIVATE_KEY"]


def assert_no_fragment(out: str, lines):
    for ln in lines:
        for i in range(0, len(ln) - 11, 6):            # any 12-character piece of any key line
            assert ln[i:i + 12] not in out, "key material left unmasked"


# ---- (a) truncated block: masked from the header to the end of the key lines ------------------------------------

@pytest.mark.parametrize("cut", [1, 5, 12])
def test_truncated_block_is_masked_from_the_header(cut):
    lines = body_lines()
    text = "result:\n" + header() + "\n" + "\n".join(lines[:cut])
    spans = secret_spans(text)
    assert spans and spans[0][0] == text.index(DASH + "BEGIN") and spans[0][1] == len(text)


def test_truncated_block_cut_inside_a_line_is_masked_to_the_end_of_text():
    lines = body_lines()
    text = header("RSA") + "\n" + "\n".join(lines[:4]) + "\n" + lines[4][:9]      # cut 9 characters into a line
    assert secret_spans(text) == [(0, len(text))]


def test_truncated_block_followed_by_ordinary_text_stops_at_the_key_lines():
    lines = body_lines()
    key = header() + "\n" + "\n".join(lines[:5])
    text = key + "\n[output truncated at 4 KB]\nNext row: status ok"
    spans = secret_spans(text)
    assert spans == [(0, len(key))]
    assert "Next row: status ok" in text[spans[0][1]:]


def test_truncated_block_through_guard_leaves_no_fragment_in_output_or_ledger(tmp_path):
    lines = body_lines()
    sangop.configure(ledger_path=str(tmp_path / "a.db"))

    @sangop.guard(purpose="test")
    def read_file() -> str:
        return "config:\n" + header("EC") + "\n" + "\n".join(lines[:6]) + "\n" + lines[6][:30]

    out = read_file()
    assert_no_fragment(out, lines[:7])
    assert "[SECRET_SECRET_PRIVATE_KEY" in out or "SECRET_PRIVATE_KEY" in out
    led = str(sangop.get_ledger().tail(50))
    assert_no_fragment(led, lines[:7])


def test_truncated_block_inside_json_text_with_escaped_newlines():
    lines = body_lines()
    text = '{"file": "' + header() + "\\n" + "\\n".join(lines[:3]) + '", "size": 4096}'
    spans = secret_spans(text)
    assert spans
    covered = text[spans[0][0]:spans[0][1]]
    assert all(ln in covered for ln in lines[:3]) and '"size"' not in covered


# ---- (b) complete block: unchanged ------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["", "RSA", "EC", "OPENSSH", "ENCRYPTED", "DSA"])
def test_complete_block_is_masked_whole_as_before(kind):
    lines = body_lines()
    block = header(kind) + "\n" + "\n".join(lines) + "\n" + footer(kind)
    text = "key:\n" + block + "\nafter"
    assert secret_spans(text) == [(5, 5 + len(block))]


def test_complete_block_with_any_body_is_still_masked():
    """As before: a complete BEGIN ... END block is masked whatever its body looks like (docs-style '...')."""
    block = header() + "\n...\n" + footer()
    assert secret_spans("x " + block) == [(2, 2 + len(block))]


def test_two_complete_blocks_are_two_findings():
    a = header("RSA") + "\n" + "\n".join(body_lines(seed=1)) + "\n" + footer("RSA")
    b = header("EC") + "\n" + "\n".join(body_lines(seed=2)) + "\n" + footer("EC")
    assert len(secret_spans(a + "\n\n" + b)) == 2


# ---- (c) RSA / EC / OPENSSH / ENCRYPTED forms, truncated ---------------------------------------------------------

@pytest.mark.parametrize("kind", ["RSA", "EC", "OPENSSH", "ENCRYPTED", "DSA"])
def test_every_kind_truncated(kind):
    lines = body_lines(width=70 if kind == "OPENSSH" else 64)
    text = header(kind) + "\n" + "\n".join(lines[:3])
    assert secret_spans(text) == [(0, len(text))]


def test_legacy_encrypted_pem_headers_are_part_of_the_block():
    lines = body_lines()
    text = (header("RSA") + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0A1B2C3D4E5F60718293A4B5C6D7E8F9\n\n"
            + "\n".join(lines[:4]))
    assert secret_spans(text) == [(0, len(text))]


# ---- (d) inside dict / list ---------------------------------------------------------------------------------------

def test_truncated_block_inside_dict_and_list_through_guard(tmp_path):
    lines = body_lines()
    sangop.configure(ledger_path=str(tmp_path / "b.db"))

    @sangop.guard(purpose="test")
    def tool() -> dict:
        return {"files": [{"name": "id_rsa", "content": header("OPENSSH") + "\n" + "\n".join(lines[:5])}],
                "pan": PAN}

    out = tool()
    assert_no_fragment(repr(out), lines[:5])
    assert PAN not in repr(out) and out["files"][0]["name"] == "id_rsa"


# ---- (e) the word BEGIN in ordinary text: no new false positives ---------------------------------------------------

@pytest.mark.parametrize("text", [
    "Paste the key that starts with " + header() + " into the box.",
    "A PEM file begins with " + DASH + "BEGIN and ends with " + DASH + "END lines.",
    header() + "\n",                                                   # header only, cut right after it
    "Docs: " + header() + "\n(your key here)\n",
    header() + "\nThe key was removed from this example for safety reasons.",
])
def test_begin_in_ordinary_text_is_not_a_finding(text):
    assert secret_spans(text) == []


# ---- no ReDoS -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("make", [
    lambda: header() + "\n" + "\n".join(body_lines(n=16000, width=64)),           # one 1 MB truncated block
    lambda: (header() + "\n") * 36000,                                            # 1 MB of headers, no body, no END
    lambda: (header() + " " + "A" * 20 + " ") * 20000,                            # many short truncated blocks
    lambda: header() + "\n" + ("A" * 63 + "\n-----x\n") * 15000,                  # dashes that are not END
])
def test_one_megabyte_inputs_are_fast(make):
    text = make()
    assert len(text) >= 900_000
    t0 = time.perf_counter()
    find_all(text)
    # Windows CI and laptops are much slower; the Linux limit stays the real gate.
    limit = 2.0 * (3 if sys.platform == "win32" else 1)
    assert time.perf_counter() - t0 < limit
