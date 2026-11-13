#!/usr/bin/env python3
"""Pre-publish safety check for the Sangop repository.   Read-only: it changes nothing.

    python scripts/prepublish_check.py            # from the repo root
    python scripts/prepublish_check.py --root .   # same

It looks only at files that WOULD be published and fails if it finds: private/internal files, secrets, internal
names or paths, risky legal claims, a missing licence/notice/security/contributing file, or a Pro rule or a private
benchmark file.

Which files: in the maintainers' private repository (it has scripts/make_public_export.py) the check builds the
public export (an explicit allow-list) in a temporary folder and checks THAT. The maintainers' private lists are
plain-text files next to this script and are never published:
  scripts/pro_markers.txt          names and pattern fragments of the Pro rules
  scripts/private_strings.txt      internal names and paths that must never appear in a public file
  scripts/private_check_files.txt  unpublished texts that must pass the risky-claims check too
  scripts/private_checks.py        extra checks of the maintainers (a run(root) function returning results)
When a list is missing it is treated as empty and the remaining checks still run. The extra checks run whenever
their file is present; --skip-private-checks (or SANGOP_SKIP_PRIVATE_CHECKS=1) skips them, and a file that fails
to load counts as a FAIL. In a public checkout the script
checks git's view (or a simple .gitignore reading).

It is a safety net, not a promise: a human still reads the maintainers' pre-publish checklist.
Exit code 0 = no FAIL, 1 = at least one FAIL.
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

REQUIRED = ["LICENSE", "NOTICE", "README.md", "SECURITY.md", "CONTRIBUTING.md", "SHARED_RESPONSIBILITY.md", "pyproject.toml",
            "TRADEMARKS.md", "CODE_OF_CONDUCT.md"]
FORBIDDEN_DIRS = {"private", "research", "policies", ".sangop", ".venv", "tools-venv", ".git"}
FORBIDDEN_GLOBS = ["*_HI.md", "dataset_*.jsonl", "holdout*_*.jsonl", "*.db", "*.db-wal", "*.db-shm", "*.sqlite", "*.pem", "*.key", "id_rsa*", ".env", ".env.*"]
ALLOW = "prepublish-allow"  # a line containing this marker is skipped (used only for this tool's own pattern lists)
CLAIMS = [  # prepublish-allow
    r"dpdp[- ]compliant", r"fully compliant",  # prepublish-allow
    r"100% (?:secure|safe)", r"guaranteed? compliance",  # prepublish-allow
    r"we guarantee", r"\bcertified\b", r"consent manager",  # prepublish-allow
    r"bullet-?proof", r"unhackable", r"military-grade",  # prepublish-allow
    r"\b100\s?%", r"hack-?proof", r"\bstops? all\b", r"\bcatch(?:es)? (?:all|everything)\b",  # prepublish-allow
    r"\bthe only\b", r"\bonly (?:tool|solution|product|one)\b",  # prepublish-allow
    r"\b(?:india|world)'?s first\b", r"\bfirst (?:in india|of its kind)\b",  # prepublish-allow
    r"\bguarantee", r"\bcompliant\b",  # prepublish-allow
]
NEGATION = re.compile(r"\b(not|no|never|without|nor|cannot|does not|doesn't|isn't|neither)\b", re.I)
TEXT_SUFFIXES = {".py", ".md", ".txt", ".toml", ".yaml", ".yml", ".json", ".jsonl", ".cfg", ".ini", ".sh", ""}
MAX_BYTES = 2_000_000
# Private benchmark material: generators, holdout sets and the per-set reports stay private.
PRIVATE_BENCH_GLOBS = ["generate*.py", "*holdout*", "BASELINE_*", "AFTER_*", "CANDIDATES_*", "RESULTS_*", "ANALYSIS_*",
                       "*_checks.py", "_*.py"]
MARKERS_FILE = Path("scripts") / "pro_markers.txt"
PRIVATE_STRINGS_FILE = Path("scripts") / "private_strings.txt"
CHECK_FILES_FILE = Path("scripts") / "private_check_files.txt"
PRIVATE_CHECKS_FILE = Path("scripts") / "private_checks.py"

Result = Tuple[str, str, str]  # (status, check, message)


def _gitignore_patterns(root: Path) -> List[str]:
    gi = root / ".gitignore"
    if not gi.is_file():
        return []
    return [ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]


def _ignored(rel: str, patterns: List[str]) -> bool:
    parts = rel.split("/")
    for pat in patterns:
        p = pat.rstrip("/")
        anchored = "/" in p.rstrip("/")
        p = p.lstrip("/")
        if pat.endswith("/") and not anchored:
            if p in parts[:-1]:
                return True
        elif anchored:
            if fnmatch.fnmatch(rel, p) or rel.startswith(p + "/"):
                return True
        elif any(fnmatch.fnmatch(part, p) for part in parts):
            return True
    return False


def public_files(root: Path) -> Tuple[List[str], str]:
    """Files that would be published, plus a note on how they were found."""
    if (root / ".git").exists():
        try:
            out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=root, capture_output=True, text=True, check=True)
            return sorted(x for x in out.stdout.splitlines() if x and (root / x).is_file()), "git ls-files (exact)"
        except (OSError, subprocess.CalledProcessError):
            pass
    pats = _gitignore_patterns(root)
    files = []
    for p in root.rglob("*"):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            if "__pycache__" in rel.split("/") or rel.endswith(".pyc") or _ignored(rel, pats):
                continue
            files.append(rel)
    return sorted(files), "simple .gitignore reading (no .git folder: run `git init` for an exact check)"


def _read_text(root: Path, rel: str):
    p = root / rel
    if p.suffix.lower() not in TEXT_SUFFIXES or p.stat().st_size > MAX_BYTES:
        return None
    try:
        return p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def load_markers(path: Path) -> List[str]:
    """One entry per line; blank lines and lines starting with '#' are ignored. A missing file = empty list."""
    if not path.is_file():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def check_files(root: Path) -> List[Path]:
    """Unpublished texts to run the claims check on, from the private list (paths relative to ``root``)."""
    return [(root / rel).resolve() for rel in load_markers(root / CHECK_FILES_FILE)]


def claim_lines(text: str) -> List[int]:
    """Line numbers (1-based) with a risky claim that is not negated on the same line."""
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if ALLOW in line or NEGATION.search(line):
            continue
        if any(re.search(c, line, re.I) for c in CLAIMS):
            hits.append(i)
    return hits


PRE_RELEASE_NOTE = "<!-- pre-release-note -->"   # marks the README line that must be removed on release day


def run_checks(root: Path, markers: Iterable[str] = None, extra_claim_files: Iterable[Path] = (),
               private_strings: Iterable[str] = None, release_day: bool = False) -> List[Result]:
    res: List[Result] = []
    markers = list(load_markers(root / MARKERS_FILE) if markers is None else markers)
    private_strings = list(load_markers(root / PRIVATE_STRINGS_FILE) if private_strings is None else private_strings)
    files, how = public_files(root)
    res.append(("INFO", "file list", f"{len(files)} files would be published; found via {how}"))

    missing = [f for f in REQUIRED if f not in files]
    res.append(("FAIL" if missing else "PASS", "required files", f"missing: {missing}" if missing else "LICENSE, NOTICE, README, SECURITY, CONTRIBUTING, SHARED_RESPONSIBILITY, TRADEMARKS, CODE_OF_CONDUCT, pyproject present"))

    bad = []
    for f in files:
        parts = f.split("/")
        name = parts[-1]
        if any(p in FORBIDDEN_DIRS for p in parts[:-1]) or any(fnmatch.fnmatch(name, g) for g in FORBIDDEN_GLOBS):
            bad.append(f)
    res.append(("FAIL" if bad else "PASS", "private/internal files", f"would be published: {bad}" if bad else "no internal (_HI), policy, data, key or environment files in the public set"))

    big = [f for f in files if (root / f).stat().st_size > MAX_BYTES]
    res.append(("FAIL" if big else "PASS", "file size", f"over {MAX_BYTES // 1000} KB: {big}" if big else "no large files"))

    leaks, claims, secrets, pii = [], [], [], 0
    finder = None
    try:
        sys.path.insert(0, str(root / "src"))
        from sangop import find_all as finder  # type: ignore
    except Exception:  # sangop deps missing: fall back to a small built-in pattern list
        finder = None
    secret_re = re.compile(r"(sk-ant-[A-Za-z0-9_\-]{20,}|sk-(?:proj-)?[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|AIza[0-9A-Za-z_\-]{35}|xox[abprs]-[0-9]{6,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
    for f in files:
        txt = _read_text(root, f)
        if txt is None:
            continue
        for i, s in enumerate(private_strings):
            if s in txt:
                leaks.append(f"{f}: private string #{i + 1}")
        if f.endswith((".md", ".toml", ".py")) and not f.startswith("tests/"):
            claims += [f"{f}:{i}" for i in claim_lines(txt)]
        if secret_re.search(txt):
            secrets.append(f)
        elif finder is not None and len(txt) < 400_000:
            for fd in finder(txt):
                if fd.category == "secret":
                    secrets.append(f)
                    break
                pii += 1
    pro = [f for f in files if f.startswith("bench/") and not f.endswith(".sha256")   # sha256 files are public
           and any(fnmatch.fnmatch(f.split("/")[-1], g) for g in PRIVATE_BENCH_GLOBS)]
    for f in files:
        txt = _read_text(root, f)
        if txt is not None:
            pro += [f"{f}: marker #{i + 1}" for i, m in enumerate(markers) if m in txt]
    res.append(("FAIL" if pro else "PASS", "Pro rules / private benchmark",
                f"would be published: {pro[:8]}" if pro else
                f"no Pro rule marker ({len(markers)} checked) and no private benchmark file in the public set"))
    res.append(("FAIL" if leaks else "PASS", "personal paths/e-mail/internal names",
                "; ".join(leaks[:8]) if leaks else f"none found in public files ({len(private_strings)} private strings checked)"))
    for extra in extra_claim_files or ():
        extra = Path(extra)
        if extra.is_file():
            claims += [f"{extra.name} (not published, checked too):{i}" for i in claim_lines(extra.read_text(encoding="utf-8"))]
    res.append(("FAIL" if claims else "PASS", "risky legal claims", f"check wording at: {claims[:10]}" if claims else "no 'compliant/guaranteed/certified' style claims outside negations"))
    res.append(("FAIL" if secrets else "PASS", "secrets", f"secret-shaped text in: {sorted(set(secrets))}" if secrets else "no secret-shaped text in public files"))
    res.append(("INFO", "synthetic identifiers", f"{pii} PII-shaped strings in public files (expected: tests/examples use synthetic values only; skim them once)" if finder else "sangop not importable, PII-shaped scan skipped"))

    readme = (root / "README.md").read_text(encoding="utf-8") if "README.md" in files else ""
    if "pip install sangop" not in readme:
        res.append(("FAIL", "install line", "README has no `pip install sangop` line"))
    elif PRE_RELEASE_NOTE in readme and release_day:
        res.append(("FAIL", "install line", "release day: remove the README line marked " + PRE_RELEASE_NOTE))
    elif PRE_RELEASE_NOTE in readme:
        res.append(("PASS", "install line", "`pip install sangop` present; pre-release note still in place (remove on release day)"))
    else:
        res.append(("PASS", "install line", "`pip install sangop` present, no pre-release note"))
    ok = "not legal advice" in readme.lower() and "known limits" in readme.lower()
    res.append(("PASS" if ok else "FAIL", "README honesty", "disclaimer and Known limits present" if ok else "README must contain 'not legal advice' and a 'Known limits' section"))

    contrib = (root / "CONTRIBUTING.md").read_text(encoding="utf-8") if "CONTRIBUTING.md" in files else ""
    res.append(("PASS" if "Signed-off-by" in contrib else "FAIL", "DCO rule", "sign-off rule present" if "Signed-off-by" in contrib else "CONTRIBUTING.md has no DCO sign-off rule"))

    pyproj = (root / "pyproject.toml").read_text(encoding="utf-8") if "pyproject.toml" in files else ""
    res.append(("PASS" if "Apache-2.0" in pyproj else "FAIL", "licence in metadata", "Apache-2.0" if "Apache-2.0" in pyproj else "pyproject.toml does not declare Apache-2.0"))

    res.append(("MANUAL", "gates", "trademark search clear? domain obtainable? only the open part published? maintainer approval given?"))
    return res


def private_check_results(root: Path) -> List[Result]:
    """Results of the maintainers' extra checks, if their file is present; a file that cannot run is a FAIL."""
    path = root / PRIVATE_CHECKS_FILE
    if not path.is_file():
        return []
    try:
        spec = importlib.util.spec_from_file_location("sangop_private_checks", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return [tuple(r) for r in mod.run(root)]
    except Exception as exc:  # fail closed: a broken extra check never passes silently
        return [("FAIL", "maintainers' extra checks", f"{PRIVATE_CHECKS_FILE.as_posix()} could not run: {exc!r}")]


def main(argv: Iterable[str] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--no-export", action="store_true", help="check the folder itself, not the public export built from it")
    ap.add_argument("--skip-private-checks", action="store_true", help="do not run scripts/private_checks.py")
    ap.add_argument("--release-day", action="store_true",
                    help="the release is being published now: the README's pre-release install note must be gone")
    a = ap.parse_args(list(argv) if argv is not None else None)
    root = a.root.resolve()
    exporter = root / "scripts" / "make_public_export.py"
    if exporter.is_file() and not a.no_export:
        import importlib.util
        import tempfile
        spec = importlib.util.spec_from_file_location("make_public_export", exporter)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "public"
            try:
                mod.build(root, out)
            except (RuntimeError, FileNotFoundError, ValueError) as exc:   # the export itself refused to build
                print(f"[FAIL  ] public export  {exc}")
                print("\nNOT READY: the public export could not be built")
                return 1
            print(f"Checking the public export built from {root.name} (allow-list in scripts/make_public_export.py)")
            results = run_checks(out, markers=load_markers(root / MARKERS_FILE),
                                 extra_claim_files=check_files(root),
                                 private_strings=load_markers(root / PRIVATE_STRINGS_FILE),
                                 release_day=a.release_day)
    else:
        results = run_checks(root, extra_claim_files=check_files(root), release_day=a.release_day)
    if not (a.skip_private_checks or os.environ.get("SANGOP_SKIP_PRIVATE_CHECKS") == "1"):
        results += private_check_results(root)
    width = max(len(r[1]) for r in results)
    for status, name, msg in results:
        print(f"[{status:6}] {name:<{width}}  {msg}")
    fails = sum(1 for r in results if r[0] == "FAIL")
    print(f"\n{'NOT READY: ' + str(fails) + ' check(s) failed' if fails else 'No automatic check failed. Now go through the pre-publish checklist by hand.'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
