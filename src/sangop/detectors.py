"""Deterministic detectors for Indian + global PII and secrets (open core).

Design rules (see docs/LEGAL_SAFETY_HI.md):
- Pure Python, no network, no ML model in the hot path.
- Structured identifiers are validated with checksums where one exists
  (Aadhaar -> Verhoeff, GSTIN -> base-36 check char, cards -> Luhn) to keep
  false positives low.
- Detectors never store or print raw values; callers decide what to do.

The open core ships a basic rule set: ASCII digits (0-9) only, and the common written forms of each identifier.
An installed rules plugin (entry-point group ``sangop.plugins``, see ``sangop.plugins``) may replace the active rule
set; ``rules_info()`` and ``sangop.selftest()`` report which set is active.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple, Union

# --------------------------------------------------------------------------
# Checksum helpers
# --------------------------------------------------------------------------

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(digits: str) -> bool:
    """True if the digit string passes the Verhoeff checksum."""
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(digits: str) -> str:
    """Return the Verhoeff check digit to append to ``digits``.

    Used only to build *synthetic* test values at runtime.
    """
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_B36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_check_char(first14: str) -> str:
    total = 0
    for i, ch in enumerate(first14):
        product = _B36.index(ch) * (1 if i % 2 == 0 else 2)
        total += product // 36 + product % 36
    return _B36[(36 - total % 36) % 36]


def gstin_valid(value: str) -> bool:
    v = value.upper()
    return len(v) == 15 and gstin_check_char(v[:14]) == v[14]


# --------------------------------------------------------------------------
# Detector types
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Detector:
    kind: str                      # e.g. "AADHAAR", "PAN", "SECRET_GITHUB"
    category: str                  # "pii" or "secret"
    pattern: "re.Pattern[str]"
    validator: Optional[Callable[[str], bool]] = None
    priority: int = 50             # higher wins when matches overlap
    hint: Optional[str] = None     # cheap pre-check: substring that must be present
    needs_digit: bool = False      # cheap pre-check: text must contain a run of 4 digits
    # optional check that also sees the surrounding text: (text, start, end) -> bool
    ctx_validator: Optional[Callable[[str, int, int], bool]] = None


@dataclass(frozen=True)
class Finding:
    kind: str
    category: str
    start: int
    end: int
    value: str                     # raw value: callers must never log it

    def masked(self) -> str:
        return mask_value(self.value)


def mask_value(value: str) -> str:
    """Human-safe preview: keep at most 2 leading and 2 trailing chars."""
    v = value.strip()
    if len(v) <= 6:
        return "*" * len(v)
    return f"{v[:2]}{'*' * (len(v) - 4)}{v[-2:]}"


# --------------------------------------------------------------------------
# Basic rules (open core): ASCII digits only
# --------------------------------------------------------------------------


def _digits(s: str) -> str:
    """The ASCII digits 0-9 of ``s``, in order."""
    return "".join(c for c in s if "0" <= c <= "9")


def _aadhaar_ok(s: str) -> bool:
    d = _digits(s)
    return len(d) == 12 and d[0] not in "01" and verhoeff_valid(d)


def _card_ok(s: str) -> bool:
    d = _digits(s)
    if len(d) == 13 and d[:3] in ("978", "979"):
        return False            # ISBN-13 ("Bookland" prefix); no payment card has this form
    return 13 <= len(d) <= 19 and luhn_valid(d)


def _phone_ok(s: str) -> bool:
    """Indian mobile: 10 digits starting 6-9, optionally with +91 / 91 / 0 in front."""
    d = _digits(s)
    if len(d) == 12 and d.startswith("91"):
        d = d[2:]
    elif len(d) == 11 and d[0] == "0":
        d = d[1:]
    return len(d) == 10 and d[0] in "6789"


# UPI handles (the part after "@"). The first group is taken from the NPCI-sourced list of approved
# handles that a public broker page republishes (data as of 2022-10-03); the second group are other
# widely used handles added from general knowledge and NOT verified against an official list. The list
# is not exhaustive and changes over time: a handle that is not here is still caught when the text
# just before it says "UPI" or "VPA" (see _upi_ok). Handles are matched case-insensitively.
UPI_HANDLES = frozenset({
    # from the republished NPCI list
    "barodampay", "rbl", "idbi", "upi", "aubank", "axisbank", "bandhan", "dlb", "indus", "kbl",
    "federal", "sbi", "uco", "yesbank", "citi", "citigold", "dbs", "freecharge", "okhdfcbank",
    "okaxis", "oksbi", "okicici", "hsbc", "icici", "indianbank", "allbank", "kotak", "ikwik",
    "unionbankofindia", "uboi", "unionbank", "paytm", "ybl", "axl", "ibl", "sib",
    # extras, unverified
    "apl", "fbl", "ptsbi", "pthdfc", "ptyes", "ptaxis", "airtel", "postbank", "pnb", "cnrb", "boi",
})
# Words after "@" that are hostnames / package tags, never a payment handle, even next to "UPI".
NOT_A_HANDLE = frozenset({"localhost", "local", "internal", "example", "test", "staging", "prod",
                          "dev", "host", "latest", "next", "stable", "beta", "canary", "main"})
_UPI_WORD = re.compile(r"\b(?:upi|vpa)\b", re.I | re.A)


def _upi_ok(text: str, start: int, end: int) -> bool:
    handle = text[start:end].rpartition("@")[2].lower()
    if handle in UPI_HANDLES:
        return True
    if handle in NOT_A_HANDLE:
        return False
    return _UPI_WORD.search(text, max(0, start - 40), start) is not None


# PEM private key blocks. A complete block: the body never contains "-----", so each header scans at most up to the
# next "-----" (linear time, also for many headers without END). A truncated block (no END line): the header plus
# the lines that look like key material - base64 runs of 16+ characters, or the legacy "Proc-Type:" / "DEK-Info:" /
# "Comment:" lines - separated by whitespace or escaped newlines (JSON text), plus a last short piece when the text
# ends (or a quote, bracket or "..." follows) right after it. Ordinary words after a header are never key lines.
_PEM_HEAD = r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
_PEM_SEP = r"(?:[ \t\r\n]|\\[rn])+"
_PEM_LINE = r"(?:[A-Za-z0-9+/=]{16,}|(?:Proc-Type|DEK-Info|Comment):[^\r\n\\]*)"
_PEM_KEY = re.compile(
    _PEM_HEAD + r"(?:"
    r"(?:[^-]|-(?!----))+-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
    r"|" + _PEM_SEP + _PEM_LINE + r"(?:" + _PEM_SEP + _PEM_LINE + r")*"
    r"(?:(?:" + _PEM_SEP + r")?[A-Za-z0-9+/=]{1,15}(?=\s*(?:\Z|[\"'\]}\\]|\.\.\.|\u2026)))?"
    r")"
)

_NB = r"(?<![A-Za-z0-9])"   # left boundary
_NA = r"(?![A-Za-z0-9])"    # right boundary
_G = r"[ \-]"               # one space or one hyphen between digit groups

BASIC_DETECTORS: Tuple[Detector, ...] = (
    # ---- secrets (highest priority: a leaked key is the worst case) ----
    # PEM private key: a complete BEGIN ... END block, or (N1-PEM, 5 Nov 2026) a block cut off before its END line
    # (tool output limited in length, pagination), masked from the header to the end of its key lines.
    Detector("SECRET_PRIVATE_KEY", "secret", _PEM_KEY, hint="PRIVATE KEY-----", priority=100),
    Detector("SECRET_ANTHROPIC", "secret",
             re.compile(_NB + r"sk-ant-[A-Za-z0-9_\-]{20,}"), hint="sk-ant-", priority=95),
    Detector("SECRET_OPENAI", "secret",
             re.compile(_NB + r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"), hint="sk-", priority=90),
    Detector("SECRET_GITHUB", "secret",
             re.compile(_NB + r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"), hint="g", priority=95),
    Detector("SECRET_AWS_ACCESS_KEY", "secret",
             re.compile(_NB + r"(?:AKIA|ASIA)[0-9A-Z]{16}" + _NA), hint="A", priority=95),
    Detector("SECRET_GOOGLE_API", "secret",
             re.compile(_NB + r"AIza[0-9A-Za-z_\-]{35}" + _NA), hint="AIza", priority=95),
    Detector("SECRET_SLACK", "secret",
             re.compile(_NB + r"xox[abprs]-[A-Za-z0-9\-]{10,}"), hint="xox", priority=95),
    Detector("SECRET_TELEGRAM_BOT", "secret",
             re.compile(_NB + r"[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}" + _NA), hint=":AA", priority=95),
    Detector("SECRET_JWT", "secret",
             re.compile(_NB + r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), hint="eyJ", priority=85),
    # ---- Indian identifiers ----
    # Aadhaar: 4-4-4 digits, with one space or hyphen between groups or none. It must not touch letters, digits or a
    # leading "+" (+91... is a phone number) and must not be part of a longer grouped number (4-4-4-4 is a card or a
    # reference number).
    Detector("AADHAAR", "pii",
             re.compile(r"(?<![A-Za-z0-9+])(?<![0-9]{4}[ \-])[0-9]{4}" + _G + r"?[0-9]{4}" + _G + r"?[0-9]{4}"
                        r"(?![A-Za-z0-9])(?!" + _G + r"[0-9]{4}(?![0-9]))"),
             validator=_aadhaar_ok, needs_digit=True, priority=80),
    Detector("GSTIN", "pii",
             re.compile(_NB + r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]" + _NA),
             validator=gstin_valid, needs_digit=True, priority=78),
    Detector("PAN", "pii",
             re.compile(_NB + r"[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z]" + _NA), needs_digit=True, priority=75),
    Detector("IFSC", "pii",
             re.compile(_NB + r"[A-Z]{4}0[A-Z0-9]{6}" + _NA), hint="0", priority=60),
    Detector("CARD", "pii",
             re.compile(r"(?<![A-Za-z0-9])(?:[0-9]" + _G + r"?){12,18}[0-9](?![A-Za-z0-9])"),
             validator=_card_ok, needs_digit=True, priority=82),
    Detector("EMAIL", "pii",
             re.compile(_NB + r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}" + _NA),
             hint="@", priority=65),
    Detector("UPI", "pii",
             re.compile(_NB + r"[A-Za-z0-9.\-_]{2,256}@[A-Za-z]{2,64}(?!\.[A-Za-z0-9]|[A-Za-z0-9@])"),
             ctx_validator=_upi_ok, hint="@", priority=55),
    # Indian mobile: 10 digits as 5-5 (one space or hyphen, or none), optionally after +91 / 91 / 0.
    Detector("PHONE_IN", "pii",
             re.compile(r"(?<![A-Za-z0-9+])(?:\+91" + _G + r"?|91" + _G + r"?|0)?[0-9]{5}" + _G
                        + r"?[0-9]{5}(?![A-Za-z0-9])"),
             validator=_phone_ok, needs_digit=True, priority=50),
)
_BASIC_DIGIT_RUN = re.compile(r"[0-9]{4}")


# --------------------------------------------------------------------------
# Active rule set (basic unless a plugin installs another one; see sangop.plugins)
# --------------------------------------------------------------------------

DetectorSource = Union[Tuple[Detector, ...], Callable[[], Iterable[Detector]]]

_RULES: dict = {}


def _install(source: DetectorSource, name: str, version: str, digit_run: "re.Pattern[str]") -> None:
    _RULES.clear()
    _RULES.update(source=source, name=name, version=version, digit_run=digit_run)


def _install_basic() -> None:
    _install(BASIC_DETECTORS, "basic", "", _BASIC_DIGIT_RUN)


_install_basic()
_PLUGINS = None


def _ensure_plugins() -> None:
    global _PLUGINS
    if _PLUGINS is None:
        from . import plugins as _p
        _PLUGINS = _p
    _PLUGINS.ensure_loaded()


def _active() -> Tuple[Detector, ...]:
    src = _RULES["source"]
    return tuple(src()) if callable(src) else src


def rules_info() -> dict:
    """Which rule set is active: ``{"name": "basic" | <plugin rule-set name>, "version": ...}``."""
    _ensure_plugins()
    return {"name": _RULES["name"], "version": _RULES["version"]}


def known_kinds() -> frozenset:
    """Every kind the active rule set can report."""
    _ensure_plugins()
    return frozenset(d.kind for d in _active())


def __getattr__(name: str):
    # ``DEFAULT_KINDS`` is kept as a module attribute for compatibility; it follows the active rule set.
    if name == "DEFAULT_KINDS":
        return known_kinds()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def find_all(text: str, kinds: Optional[Iterable[str]] = None) -> List[Finding]:
    """Return non-overlapping findings in ``text`` (left-to-right)."""
    if not text or len(text) < 6:
        return []
    _ensure_plugins()
    active = _active()
    wanted = frozenset(d.kind for d in active) if kinds is None else frozenset(kinds)
    has_digit = _RULES["digit_run"].search(text) is not None
    candidates: List[tuple] = []
    for det in active:
        if (det.needs_digit and not has_digit) or (det.hint is not None and det.hint not in text):
            continue
        if det.kind not in wanted:
            continue
        for m in det.pattern.finditer(text):
            raw = m.group(0)
            if det.validator is not None and not det.validator(raw):
                continue
            if det.ctx_validator is not None and not det.ctx_validator(text, m.start(), m.end()):
                continue
            candidates.append((det.priority, m.end() - m.start(), m.start(), m.end(), det, raw))
    # Highest priority first, then longest; greedily keep non-overlapping.
    candidates.sort(key=lambda c: (-c[0], -c[1], c[2]))
    # The kept findings never overlap, so they stay sorted by start in ``starts``/``taken``; a new candidate can only
    # collide with its immediate left and right neighbours (bisect, O(log n) per candidate; the old "compare with
    # every kept finding" loop was O(n^2): ~9 s for 20,000 phone numbers).
    taken: List[Finding] = []
    starts: List[int] = []
    for _, _, start, end, det, raw in candidates:
        i = bisect_left(starts, start)
        if i > 0 and taken[i - 1].end > start:
            continue
        if i < len(taken) and taken[i].start < end:
            continue
        starts.insert(i, start)
        taken.insert(i, Finding(det.kind, det.category, start, end, raw))
    return taken
