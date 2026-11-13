"""Regression tests for the four limits recorded after holdout 1 (fixed in Sangop 0.1.2). Synthetic values only.

Sangop 0.1.3 (D-037) changed two of the 0.1.2 behaviours on purpose; those tests are updated below and the
new behaviour is tested in test_detectors_v013.py."""
import pytest

from sangop.detectors import find_all, luhn_valid, verhoeff_check_digit, verhoeff_valid


def kinds(text):
    return [f.kind for f in find_all(text)]


def aadhaar12(prefix="23456789012"):
    return prefix + verhoeff_check_digit(prefix)


def ref16_verhoeff_prefix_luhn_fail():
    """16 digits: first 12 pass Verhoeff, the whole fails Luhn (a reference number, not a card)."""
    a = aadhaar12()
    for tail in range(10000):
        d = a + f"{tail:04d}"
        if not luhn_valid(d):
            return d
    raise AssertionError


def isbn13(body9="123456789"):
    d12 = "978" + body9
    chk = str((10 - sum(int(c) * (1 if i % 2 == 0 else 3) for i, c in enumerate(d12)) % 10) % 10)
    return d12 + chk


def luhn_run(n=16, body="999877665544332"):
    body = body[: n - 1]
    for c in "0123456789":
        if luhn_valid(body + c):
            return body + c


# 1) a 4-4-4-4 reference number is not an Aadhaar --------------------------------------------------


def test_aadhaar_followed_by_text_or_punctuation_is_still_found():
    a = aadhaar12()
    g = f"{a[:4]} {a[4:8]} {a[8:]}"
    assert kinds(f"Aadhaar {g}.") == ["AADHAAR"]
    assert kinds(f"Aadhaar {g}, pincode 560001") == ["AADHAAR"]
    assert kinds(f"Aadhaar {g} and mobile 98765 43210") == ["AADHAAR", "PHONE_IN"]


# 2) ISBN-13 is not a card ---------------------------------------------------------------------------
def test_isbn13_is_not_a_card_even_when_luhn_passes_by_chance():
    found_luhn_valid = False
    for i in range(300):
        d = isbn13(f"{i:09d}")
        found_luhn_valid |= luhn_valid(d)
        for text in (d, f"{d[:3]}-{d[3]}-{d[4:6]}-{d[6:12]}-{d[12]}", f"{d[:3]} {d[3]} {d[4:6]} {d[6:12]} {d[12]}"):
            assert "CARD" not in kinds(f"ISBN {text}"), text
    assert found_luhn_valid, "test needs at least one Luhn-valid ISBN to be meaningful"


def test_real_13_digit_card_prefix_not_978_still_a_card():
    for body in range(100000, 100200):
        d = "4" + f"{body:011d}"
        for c in "0123456789":
            if luhn_valid(d + c):
                assert kinds(f"card {d + c}") == ["CARD"]
                return
    raise AssertionError


# 3) digits glued to letters inside hashes / ids / tokens ------------------------------------------------
def test_digit_runs_inside_hex_hashes_uuids_and_ids_are_not_cards():
    run = luhn_run(16)
    assert luhn_valid(run)
    assert "CARD" not in kinds(f"commit ab{run}cd ok")
    assert "CARD" not in kinds(f"trace f{run[:8]}-{run[8:12]}-{run[12:]}e")
    assert "CARD" not in kinds(f"tok_xyz{run}abc")
    assert kinds(f"card {run}") == ["CARD"]                       # the same digits alone are still a card
    assert kinds(f"card:{run}.") == ["CARD"]


# 4) dotted Aadhaar ------------------------------------------------------------------------------------------


def test_dotted_lookalikes_are_not_aadhaar():
    assert kinds("server 10.12.104.200 version 3.14.159.2653") == []
    assert kinds("dated 21.10.2026") == []
    bad = "1" + "2345678901"
    bad += verhoeff_check_digit(bad)                                # Verhoeff-valid but starts with 1
    assert "AADHAAR" not in kinds(f"{bad[:4]}.{bad[4:8]}.{bad[8:]}")


def test_plain_and_spaced_aadhaar_unchanged():
    a = aadhaar12()
    assert kinds(f"id {a}") == ["AADHAAR"]
    assert kinds(f"id {a[:4]} {a[4:8]} {a[8:]}") == ["AADHAAR"]
    assert kinds(f"id {a[:4]}-{a[4:8]}-{a[8:]}") == ["AADHAAR"]
