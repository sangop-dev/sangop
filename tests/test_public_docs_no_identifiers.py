"""Public pages people read (README, public changelog, examples) must not show a whole identifier-shaped value:
no full PAN, Indian mobile, checksum-valid Aadhaar or Luhn-valid card number. Show a masked form (first 2 and last 2
characters, X in between), a Sangop token, or words instead (TASK-041). The one allowed exception is UIDAI's own
published test UID. This test contains no identifier-shaped value itself.
"""
import importlib.util
import re
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UIDAI_TEST_UID = "9999" + "4105" + "7058"          # UIDAI's published test UID, not a person's number
SEP = r"[ .\- \t]?"

_PAN = re.compile(r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z] ?[0-9]{4}[A-Z](?![A-Z0-9])")
_MOBILE = re.compile(r"(?<![0-9])[6-9](?:" + SEP + r"[0-9]){9}(?![0-9])")
_TWELVE = re.compile(r"(?<![0-9])[2-9](?:" + SEP + r"[0-9]){11}(?![0-9])")
_CARD = re.compile(r"(?<![0-9])[0-9](?:" + SEP + r"[0-9]){12,18}(?![0-9])")

_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 8, 5]]


def _verhoeff(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0 and len(set(digits)) > 1


def _public_files() -> list:
    # private repo: CHANGELOG_PUBLIC.md; in the public export it is renamed CHANGELOG.md. Read whichever exists.
    changelog = [p for p in (ROOT / "CHANGELOG_PUBLIC.md", ROOT / "CHANGELOG.md") if p.exists()]
    assert changelog, "no public changelog found (CHANGELOG_PUBLIC.md or CHANGELOG.md)"
    files = [ROOT / "README.md", changelog[0]]
    files +=[p for p in sorted((ROOT / "examples").rglob("*"))
              if p.is_file() and p.suffix in {".py", ".md", ".json", ".txt", ".yaml", ".yml"}]
    files += sorted((ROOT / "src" / "sangop").rglob("*.py"))
    files += _bench_files()
    return files


def _bench_files() -> list:
    """The text files of bench/ that are published (TASK-045). In the private repository the private benchmark sets
    sit in the same folder, so only the files of the export plan are read there; in the export, every text file."""
    script = ROOT / "scripts" / "make_public_export.py"
    if script.is_file():
        spec = importlib.util.spec_from_file_location("_export_plan_for_bench", script)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out = [ROOT / src for src, dst in mod.plan(ROOT) if dst.startswith("bench/")]
    else:
        out = list((ROOT / "bench").rglob("*"))
    files = sorted(p for p in out if p.is_file() and p.suffix in {".py", ".md", ".json", ".txt", ".yaml", ".yml"})
    assert any(p.name == "bench.py" for p in files), "bench/bench.py not found"
    return files


def _normalise(text: str) -> str:
    """Read text the way a person would: full-width forms, Indian-script digits and JSON \\u escapes become ASCII."""
    text = re.sub(r"\\u00([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    text = unicodedata.normalize("NFKC", text)
    return "".join(str(unicodedata.decimal(ch)) if ch.isdecimal() and not ch.isascii() else ch for ch in text)


def _found(text: str) -> list:
    text = re.sub(r"(?<![0-9A-Fa-f])[0-9a-f]{64}(?![0-9A-Fa-f])", " ", _normalise(text))   # a sha256 is not an identifier
    hits = [("PAN", m.group(0)) for m in _PAN.finditer(text.upper())]
    hits += [("MOBILE", m.group(0)) for m in _MOBILE.finditer(text)]
    for m in _TWELVE.finditer(text):
        d = re.sub(r"\D", "", m.group(0))
        if _verhoeff(d) and d != UIDAI_TEST_UID:
            hits.append(("AADHAAR", m.group(0)))
    for m in _CARD.finditer(text):
        if _luhn(re.sub(r"\D", "", m.group(0))):
            hits.append(("CARD", m.group(0)))
    return hits


def test_the_checker_finds_what_it_should():
    pan = "ab" + "cpe" + "12" + "34f"
    mobile = "98" + "765" + " " + "432" + "10"
    base = "2345" + "6789" + "012"
    aadhaar = next(base + str(d) for d in range(10) if _verhoeff(base + str(d)))
    card = "41" + "11" * 7
    sample = f"x {pan} y {mobile} z {aadhaar} w {card} and \\u0039{mobile[1:]}"
    kinds = sorted({k for k, _ in _found(sample)})
    assert kinds == ["AADHAAR", "CARD", "MOBILE", "PAN"]
    assert _found("masked: 98XXXXXX10 ABXXXXXX4F 99XXXXXXXX58 " + UIDAI_TEST_UID) == []
    assert _found("sha256 " + "ab" + "6713407631" + "c" * 52) == []                  # a hash with a digit run inside


def test_public_docs_and_examples_show_no_identifier_shaped_value():
    bad = []
    for path in _public_files():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for kind, value in _found(line):
                bad.append(f"{path.relative_to(ROOT).as_posix()}:{n}: {kind} {value[:2]}...{value[-2:]}")
    assert not bad, "identifier-shaped values on public pages:\n" + "\n".join(bad)
