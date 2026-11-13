from conftest import AADHAAR, EMAIL, PAN, PHONE

from sangop.tokenizer import Vault, detokenize_obj, detokenize_text, scrub_obj, scrub_text


def test_roundtrip_and_determinism():
    v = Vault()
    text = f"Customer PAN {PAN}, phone {PHONE}; again {PAN}"
    out, counts = scrub_text(text, v)
    assert PAN not in out and PHONE not in out
    assert counts["PAN"] == 2 and counts["PHONE_IN"] == 1
    tokens = [t for t in out.split() if t.startswith("[PII_PAN_")]
    assert len(set(t.rstrip(";,") for t in tokens)) == 1   # same value -> same token
    assert detokenize_text(out, v) == text


def test_different_sessions_give_different_tokens():
    a, _ = scrub_text(PAN, Vault())
    b, _ = scrub_text(PAN, Vault())
    assert a != b


def test_redact_and_shadow():
    v = Vault()
    red, _ = scrub_text(f"aadhaar {AADHAAR}", v, "redact")
    assert red == "aadhaar [REDACTED_AADHAAR]" and len(v) == 0
    sh, counts = scrub_text(f"aadhaar {AADHAAR}", v, "shadow")
    assert AADHAAR in sh and counts["AADHAAR"] == 1


def test_nested_structures_and_int_ids():
    v = Vault()
    rows = [{"id": 7, "email": EMAIL, "notes": f"my aadhaar is {AADHAAR}"},
            {"id": 8, "aadhaar_num": int(AADHAAR), "tags": ("vip", PAN)}]
    out, counts = scrub_obj(rows, v)
    flat = repr(out)
    assert EMAIL not in flat and AADHAAR not in flat and PAN not in flat
    assert out[0]["id"] == 7
    assert counts["AADHAAR"] == 2
    assert detokenize_obj(out, v)[0]["email"] == EMAIL


def test_unknown_token_left_alone():
    assert detokenize_text("[PII_PAN_deadbeef]", Vault()) == "[PII_PAN_deadbeef]"
