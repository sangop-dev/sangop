from conftest import (AADHAAR, AADHAAR_BAD, AADHAAR_SPACED, AWS_KEY, CARD, EMAIL,
                      GITHUB_TOKEN, GSTIN, IFSC, PAN, PHONE, UPI)

from sangop.detectors import find_all, gstin_valid, mask_value, verhoeff_valid


def kinds(text):
    return [f.kind for f in find_all(text)]


def test_aadhaar_checksum():
    assert verhoeff_valid(AADHAAR)
    assert not verhoeff_valid(AADHAAR_BAD)
    assert kinds(f"id {AADHAAR}") == ["AADHAAR"]
    assert kinds(f"id {AADHAAR_SPACED}") == ["AADHAAR"]
    assert "AADHAAR" not in kinds(f"id {AADHAAR_BAD}")


def test_aadhaar_cannot_start_with_0_or_1():
    assert "AADHAAR" not in kinds("order 123456789012")


def test_pan_gstin_ifsc():
    assert kinds(f"PAN {PAN}") == ["PAN"]
    assert gstin_valid(GSTIN)
    assert kinds(f"GST {GSTIN}") == ["GSTIN"]          # not double-counted as PAN
    assert not gstin_valid(GSTIN[:-1] + ("A" if GSTIN[-1] != "A" else "B"))
    assert kinds(f"IFSC {IFSC}") == ["IFSC"]


def test_contact_and_payment():
    assert kinds(f"call {PHONE}") == ["PHONE_IN"]
    assert kinds(f"call +91 {PHONE}") == ["PHONE_IN"]
    assert kinds(f"mail {EMAIL}") == ["EMAIL"]
    assert kinds(f"pay {UPI}") == ["UPI"]
    assert kinds(f"card {CARD}") == ["CARD"]


def test_secrets():
    assert kinds(f"token={GITHUB_TOKEN}") == ["SECRET_GITHUB"]
    assert kinds(f"aws {AWS_KEY}") == ["SECRET_AWS_ACCESS_KEY"]
    anthropic = "sk-" + "ant-" + "x" * 30
    assert kinds(anthropic) == ["SECRET_ANTHROPIC"]
    tg = "123456789:" + "AA" + "b" * 33
    assert kinds(f"bot {tg}") == ["SECRET_TELEGRAM_BOT"]


def test_plain_text_has_no_findings():
    text = "Order 4521 shipped on 2026-10-21, total Rs 1,299. Ticket #88213."
    assert find_all(text) == []


def test_mask_never_shows_full_value():
    assert mask_value(PAN) == "AB******4F"
    assert PAN not in mask_value(PAN)
