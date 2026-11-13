"""A weak SANGOP_LEDGER_KEY (short, few distinct characters, repeated block, simple sequence) gives a warning; a strong one does not.
The weak key is still accepted if it meets the 16-character minimum (the warning is advice, not a block)."""
import secrets
import warnings

import pytest

from sangop.audit import AuditLedger, weak_key_reason

WEAK = [
    "a" * 16, "a" * 40, "abababababababababababababababab", "1234567890123456", "12345678901234567890123456789012345",
    "passwordpasswordpasswordpassword", "abcdefghijklmnopqrstuvwxyzabcdef", "Short16CharsKey!!",
    "0000111100001111000011110000111100001111",
]
STRONG = [secrets.token_hex(32), secrets.token_urlsafe(40), "k7Qz-9mX2vLp_4RtYb8NfWc3HgJs6DuE1aOi5Zx0"]


@pytest.mark.parametrize("key", WEAK)
def test_weak_keys_are_flagged(key):
    assert weak_key_reason(key.encode()) is not None, key


@pytest.mark.parametrize("key", STRONG)
def test_strong_keys_are_not_flagged(key):
    assert weak_key_reason(key.encode()) is None, key


@pytest.mark.parametrize("key", WEAK[:3])
def test_ledger_warns_but_still_works_with_a_weak_key(key, tmp_path):
    with pytest.warns(UserWarning, match="SANGOP_LEDGER_KEY|ledger key"):
        led = AuditLedger(str(tmp_path / "w.db"), key=key)
    led.append("e", {"a": 1})
    assert led.verify_report()["ok"] and led.key_warning


def test_strong_key_gives_no_warning(tmp_path):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        led = AuditLedger(str(tmp_path / "s.db"), key=secrets.token_hex(32))
    assert led.key_warning is None


def test_unkeyed_ledger_gives_no_key_warning(tmp_path, monkeypatch):
    monkeypatch.delenv("SANGOP_LEDGER_KEY", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        led = AuditLedger(str(tmp_path / "u.db"))
    assert led.key_warning is None


def test_too_short_still_raises():
    with pytest.raises(ValueError):
        AuditLedger(":memory:", key="short")
