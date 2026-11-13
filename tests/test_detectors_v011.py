"""Regression tests for the six weaknesses found by the benchmark in Sangop 0.1.0 (fixed in 0.1.1).

All values are synthetic. Check digits are computed at runtime so no real number appears here.
"""
import pytest

from sangop.detectors import UPI_HANDLES, find_all, luhn_valid, verhoeff_check_digit, verhoeff_valid

DEV = str.maketrans("0123456789", "०१२३४५६७८९")
BEN = str.maketrans("0123456789", "০১২৩৪৫৬৭৮৯")


def kinds(text):
    return [f.kind for f in find_all(text)]


def aadhaar12(prefix="23456789012"):
    return prefix + verhoeff_check_digit(prefix)


def mobile_with_verhoeff_12():
    """A '91'+mobile 12-digit string that also passes Verhoeff (the ambiguous case)."""
    for n in range(9876543210, 9876543210 + 500):
        s = "91" + str(n)
        if verhoeff_valid(s):
            return str(n)
    raise AssertionError("not found")


def card_with_verhoeff_first12():
    """Synthetic 16-digit, Luhn-valid number whose first 12 digits also pass Verhoeff."""
    for i in range(100000):
        d15 = "9998" + f"{i:07d}" + f"{i % 10000:04d}"
        for last in "0123456789":
            d = d15 + last
            if luhn_valid(d) and verhoeff_valid(d[:12]):
                return d
    raise AssertionError("not found")


# 1) other digit scripts ---------------------------------------------------


def test_other_script_digits_still_obey_the_rules():
    bad_prefix = "1" + "2345678901"
    bad = bad_prefix + verhoeff_check_digit(bad_prefix)      # Verhoeff-valid but starts with 1
    assert "AADHAAR" not in kinds(bad.translate(DEV))
    assert "PHONE_IN" not in kinds("मोबाइल " + "1234567890".translate(DEV))   # mobiles start 6-9
    flipped = aadhaar12()[:-1] + ("0" if aadhaar12()[-1] != "0" else "1")
    assert "AADHAAR" not in kinds(flipped.translate(DEV))


# 2) + 6) UPI at the end of a sentence -------------------------------------
@pytest.mark.parametrize("end", [".", "!", "?", ",", ";", ")"])
def test_upi_before_sentence_punctuation(end):
    assert kinds(f"pay to asha.test@oksbi{end}") == ["UPI"]
    assert kinds(f"pay to 9876543210@ybl{end}") == ["UPI"]          # phone-style local part: UPI, not PHONE


def test_upi_not_confused_with_email_domains():
    assert kinds("mail asha@example.com.") == ["EMAIL"]
    assert kinds("mail asha@oksbi.example.com") == ["EMAIL"]


# 3) hostnames after @ are not UPI ------------------------------------------
@pytest.mark.parametrize("text", ["ssh deploy@localhost", "run as ci@internal", "build@staging failed", "react@latest",
                                  "deploy@bastion", "UPI listener started by build@localhost"])
def test_hostnames_and_package_tags_are_not_upi(text):
    assert "UPI" not in kinds(text)


def test_known_psp_handles_are_upi_case_insensitive():
    assert {"ybl", "oksbi", "okaxis", "paytm", "ibl", "axl"} <= UPI_HANDLES
    assert kinds("pay asha.test@YBL") == ["UPI"]


def test_unknown_handle_needs_a_upi_or_vpa_hint_nearby():
    assert "UPI" not in kinds("note: shop77@zenpay")
    assert kinds("UPI: shop77@zenpay") == ["UPI"]
    assert kinds("my VPA is shop77@zenpay") == ["UPI"]
    assert kinds("मेरी UPI आईडी shop77@zenpay है") == ["UPI"]


# 4) grouped 16-digit card beats an Aadhaar-shaped prefix --------------------
def test_grouped_card_wins_over_aadhaar_prefix():
    d = card_with_verhoeff_first12()
    assert verhoeff_valid(d[:12]) and luhn_valid(d)
    for sep in (" ", "-"):
        grouped = sep.join(d[i:i + 4] for i in range(0, 16, 4))
        assert kinds(f"card {grouped}") == ["CARD"]


def test_plain_aadhaar_next_to_a_short_group_is_still_aadhaar():
    a = aadhaar12()
    assert kinds(f"Aadhaar {a[:4]} {a[4:8]} {a[8:]} and pincode 560001") == ["AADHAAR"]


# 5) +91 mobile without separators beats an Aadhaar-shaped digit run ---------
def test_compact_plus91_mobile_is_a_phone():
    n = mobile_with_verhoeff_12()
    assert kinds(f"call +91{n}") == ["PHONE_IN"]
    assert kinds(f"call +91 {n}") == ["PHONE_IN"]


# nothing else moved --------------------------------------------------------
def test_plain_12_digit_valid_aadhaar_still_detected():
    assert kinds(f"id {aadhaar12()}") == ["AADHAAR"]


def test_email_and_secret_priorities_unchanged():
    assert kinds("write to asha@example.com") == ["EMAIL"]
    assert kinds("key=AKIA" + "ABCDEFGHIJKLMNOP") == ["SECRET_AWS_ACCESS_KEY"]
