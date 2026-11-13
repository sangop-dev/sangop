"""Synthetic test values only. Built at runtime; never real people's data.

Secrets are assembled by concatenation so that the repository itself never
contains a literal that secret scanners (e.g. GitHub push protection) flag.
"""

import pytest

import sangop
from sangop.detectors import gstin_check_char, verhoeff_check_digit

AADHAAR_BASE = "23456789012"
AADHAAR = AADHAAR_BASE + verhoeff_check_digit(AADHAAR_BASE)
AADHAAR_SPACED = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"
AADHAAR_BAD = AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10)
PAN = "ABCPE1234F"
GSTIN = "27" + PAN + "1Z" + gstin_check_char("27" + PAN + "1Z")
IFSC = "SBIN0001234"
PHONE = "9876543210"
EMAIL = "asha.test@example.com"
UPI = "asha.test@okaxis"
CARD = "4111 1111 1111 1111"
GITHUB_TOKEN = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
AWS_KEY = "AK" + "IA" + "ABCDEFGHIJKLMNOP"


@pytest.fixture(autouse=True)
def fresh_state(tmp_path):
    sangop.configure(ledger_path=str(tmp_path / "audit.db"))
    yield
    sangop.configure(ledger_path=None, run_selftest=False)
