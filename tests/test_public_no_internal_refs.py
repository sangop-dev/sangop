"""Public files must not carry internal decision numbers (TASK-045).

Numbers such as the ones the private decision log uses mean nothing to outside readers and point at a private
document. Every public text file (.py .md .yml .toml .txt) must be free of them. In the private repository the
files are those of the export plan; in the exported copy they are every text file of the tree.
The pattern is assembled from pieces so that this file does not match itself.
"""
import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERN = re.compile(r"\b" + "D" + "-" + r"\d{3}\b")
SUFFIXES = {".py", ".md", ".yml", ".toml", ".txt"}
SKIP_DIRS = {".git", ".venv", "dist", "build", "__pycache__", ".pytest_cache"}


def _export_plan_files():
    script = ROOT / "scripts" / "make_public_export.py"
    if not script.is_file():
        return None                                              # the exported copy has no export script
    spec = importlib.util.spec_from_file_location("_export_plan_for_test", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [(ROOT / src, dst) for src, dst in mod.plan(ROOT)]


def _public_text_files():
    planned = _export_plan_files()
    if planned is None:
        return [(p, p.relative_to(ROOT).as_posix()) for p in sorted(ROOT.rglob("*"))
                if p.is_file() and p.suffix in SUFFIXES and not (set(p.relative_to(ROOT).parts) & SKIP_DIRS)]
    return [(src, dst) for src, dst in planned if Path(dst).suffix in SUFFIXES]


def test_the_pattern_finds_what_it_should():
    assert PATTERN.search("# " + "D" + "-" + "078 reason")
    assert not PATTERN.search("D-12 or AD-123 or D-1234")


def test_public_files_have_no_internal_decision_numbers():
    files = _public_text_files()
    assert len(files) > 20, "the list of public files looks wrong"
    bad = []
    for src, dst in files:
        for n, line in enumerate(src.read_text(encoding="utf-8").splitlines(), 1):
            if PATTERN.search(line):
                bad.append(f"{dst}:{n}")
    assert not bad, "internal decision numbers in public files:\n" + "\n".join(bad)
