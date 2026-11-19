"""Open core and the rules-plugin hook.

Written before the split (failing first): the open core runs a basic rule set (ASCII digits only) when no rules
plugin is installed, reports which rule set is active, rejects plugin options it does not know, and fails closed
when an installed plugin cannot load. Synthetic values only.
"""
import re

import pytest

import sangop
from sangop import detectors as D
from sangop import plugins
from sangop.detectors import find_all, verhoeff_check_digit

AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")
BASIC_KINDS = {
    "AADHAAR", "PAN", "GSTIN", "IFSC", "CARD", "EMAIL", "UPI", "PHONE_IN",
    "SECRET_PRIVATE_KEY", "SECRET_ANTHROPIC", "SECRET_OPENAI", "SECRET_GITHUB", "SECRET_AWS_ACCESS_KEY",
    "SECRET_GOOGLE_API", "SECRET_SLACK", "SECRET_TELEGRAM_BOT", "SECRET_JWT",
}


@pytest.fixture
def core_only():
    """The open core exactly as it runs when no rules plugin is installed."""
    plugins._load_for_tests([])
    sangop.configure(ledger_path=None, run_selftest=False)
    yield
    plugins._load_for_tests(None)          # back to whatever is really installed
    sangop.configure(ledger_path=None, run_selftest=False)


def _kinds(text):
    return [(f.kind, text[f.start:f.end]) for f in find_all(text)]


def test_basic_rule_set_is_active_without_plugins(core_only):
    assert D.rules_info()["name"] == "basic"
    assert set(D.known_kinds()) == BASIC_KINDS
    assert set(D.DEFAULT_KINDS) == BASIC_KINDS          # the old module attribute still works
    assert plugins.loaded_plugins() == []


@pytest.mark.parametrize("text,kind,value", [
    (f"Aadhaar {AADHAAR} ok", "AADHAAR", AADHAAR),
    (f"id {AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]} ok", "AADHAAR", f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"),
    (f"id {AADHAAR[:4]}-{AADHAAR[4:8]}-{AADHAAR[8:]} ok", "AADHAAR", f"{AADHAAR[:4]}-{AADHAAR[4:8]}-{AADHAAR[8:]}"),
    ("PAN ABCPE1234F filed", "PAN", "ABCPE1234F"),
    ("IFSC SBIN0001234 branch", "IFSC", "SBIN0001234"),
    ("call 9876543210 now", "PHONE_IN", "9876543210"),
    ("call +91 98765 43210 now", "PHONE_IN", "+91 98765 43210"),
    ("call 98765-43210 now", "PHONE_IN", "98765-43210"),
    ("call 09876543210 now", "PHONE_IN", "09876543210"),
    ("mail asha.test@example.com today", "EMAIL", "asha.test@example.com"),
    ("pay asha.test@okaxis now", "UPI", "asha.test@okaxis"),
    ("pay via UPI asha.test@newbank now", "UPI", "asha.test@newbank"),
    ("card 4111 1111 1111 1111 exp", "CARD", "4111 1111 1111 1111"),
    ("card 4111-1111-1111-1111 exp", "CARD", "4111-1111-1111-1111"),
])
def test_basic_rules_find_the_common_ascii_forms(core_only, text, kind, value):
    assert (kind, value) in _kinds(text)


def test_basic_rules_keep_the_checksums(core_only):
    bad = AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10)
    assert not [k for k in _kinds(f"id {bad} ok") if k[0] == "AADHAAR"]
    assert not [k for k in _kinds("card 4111 1111 1111 1112 exp") if k[0] == "CARD"]
    assert not [k for k in _kinds("isbn 9780306406157 ok") if k[0] == "CARD"]
    assert not [k for k in _kinds("call 5876543210 now") if k[0] == "PHONE_IN"]     # mobiles start 6-9
    assert not [k for k in _kinds("host user@localhost ok") if k[0] == "UPI"]


def test_open_core_reads_ascii_digits_only(core_only):
    """Honest limit of the open core (README Known limits): digits written in another script are not read."""
    deva = AADHAAR.translate(str.maketrans("0123456789", "०१२३४५६७८९"))
    assert _kinds(f"id {deva} ok") == []
    assert all(r"\d" not in d.pattern.pattern for d in D.BASIC_DETECTORS)


def test_selftest_reports_the_active_rule_set(core_only):
    result = sangop.selftest()
    assert result["ok"] is True and result["rules"] == "basic"


def test_unknown_configure_option_is_a_type_error(core_only):
    with pytest.raises(TypeError, match="not_a_real_option"):
        sangop.configure(ledger_path=None, run_selftest=False, not_a_real_option=True)


# ---- a fake plugin, to test the hook itself ----

def _fake_register(api):
    det = D.Detector("TICKET", "pii", re.compile(r"\bTKT-[0-9]{6}\b"), priority=40)
    seen = {}

    def hook(options, log):
        seen["opts"] = dict(options)
        if options.get("tickets_off"):
            log("tickets_off", {"tickets_off": True})

    api.set_detectors(D.BASIC_DETECTORS + (det,), name="fake_rules", version="9.9")
    api.add_configure_hook(("tickets_off",), hook)
    api.add_kinds_filter(lambda kinds: kinds)
    api.add_call_record_hook(lambda record: record.__setitem__("fake_flag", True))
    _fake_register.seen = seen


@pytest.fixture
def fake_plugin(tmp_path):
    plugins._load_for_tests([("fake", _fake_register)])
    yield tmp_path
    plugins._load_for_tests(None)
    sangop.configure(ledger_path=None, run_selftest=False)


def test_plugin_can_replace_the_rule_set_and_take_options(fake_plugin):
    assert D.rules_info() == {"name": "fake_rules", "version": "9.9"}
    assert ("TICKET", "TKT-123456") in _kinds("ref TKT-123456 open")
    sangop.configure(ledger_path=str(fake_plugin / "a.db"), run_selftest=False, tickets_off=True)
    assert _fake_register.seen["opts"] == {"tickets_off": True}
    assert [r["event"] for r in sangop.get_ledger().tail(10)] == ["tickets_off"]   # the plugin logged its option
    sangop.configure(ledger_path=str(fake_plugin / "b.db"), run_selftest=False)
    assert _fake_register.seen["opts"] == {}                       # not passed -> the plugin applies its default
    assert sangop.get_ledger().tail(10) == []


def test_plugin_record_hook_reaches_the_ledger(fake_plugin):
    sangop.configure(ledger_path=str(fake_plugin / "c.db"), run_selftest=False)

    @sangop.guard(purpose="t")
    def tool() -> str:
        return "nothing here"

    assert tool() == "nothing here"
    calls = [r for r in sangop.get_ledger().tail(10) if r["event"] == "tool_call"]
    assert len(calls) == 1 and calls[0]["record"]["fake_flag"] is True
    ok, n, _ = sangop.get_ledger().verify()
    assert ok and n >= 2


def test_only_one_plugin_may_replace_the_rule_set():
    def second(api):
        api.set_detectors(D.BASIC_DETECTORS, name="second_rules")

    plugins._load_for_tests([("fake", _fake_register), ("second", second)])
    try:
        with pytest.raises(RuntimeError, match="second"):
            find_all("call 9876543210 now")
    finally:
        plugins._load_for_tests(None)


def test_a_broken_plugin_fails_closed_and_never_falls_back_to_basic():
    def broken(api):
        raise ImportError("compiled module missing")

    plugins._load_for_tests([("broken", broken)])
    try:
        for call in (lambda: find_all("call 9876543210 now"), D.known_kinds, D.rules_info, sangop.selftest):
            with pytest.raises(RuntimeError, match="broken"):
                call()
    finally:
        plugins._load_for_tests(None)
    assert find_all("call 9876543210 now")          # recovered once the plugin set is valid again


def test_no_thread_runs_with_basic_rules_while_a_plugin_is_still_loading(monkeypatch):
    """Two tools called at the same moment on first use: the second call must wait for the plugin, not run with the
    weaker basic rules while the first call is still loading it (found in review, 5 Nov 2026)."""
    import threading
    import time

    started = threading.Event()

    def slow_register(api):
        started.set()
        time.sleep(0.4)                        # e.g. a compiled module that takes a moment to import
        _fake_register(api)

    monkeypatch.setattr(plugins, "_discover", lambda: [("slow", slow_register)])
    plugins._STATE.update(loaded=False, loading=False, error=None)
    plugins._reset()
    results = {}

    def first():
        results["first"] = find_all("ref TKT-123456 open")

    def second():
        started.wait(5)
        results["second"] = find_all("ref TKT-654321 open")

    t1, t2 = threading.Thread(target=first), threading.Thread(target=second)
    t1.start(); t2.start(); t1.join(10); t2.join(10)
    try:
        assert [f.kind for f in results["first"]] == ["TICKET"]
        assert [f.kind for f in results["second"]] == ["TICKET"]       # not basic rules while loading
    finally:
        monkeypatch.undo()
        plugins._load_for_tests(None)
