"""The README "Tested on" line must match the CI matrix (os and Python versions), so it cannot go stale again."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
CANDIDATES = [ROOT / ".github" / "workflows" / "ci.yml", ROOT / "github_drafts" / "workflows" / "ci.yml.disabled"]


def _ci_text():
    for p in CANDIDATES:
        if p.is_file():
            return p.read_text(encoding="utf-8")
    pytest.skip("no CI workflow file in this tree")


def _tested_on():
    text = README.read_text(encoding="utf-8")
    m = re.search(r"\*\*Tested on:\*\*(.*?)(?:\n\s*\n|\Z)", text, re.DOTALL)
    assert m, "README has no 'Tested on' line"
    return " ".join(m.group(1).split())


def _matrix():
    ci = _ci_text()
    os_m = re.search(r"^\s*os:\s*\[([^\]]*)\]", ci, re.MULTILINE)
    py_m = re.search(r"^\s*python-version:\s*\[([^\]]*)\]", ci, re.MULTILINE)
    assert os_m and py_m, "matrix not found in ci.yml"
    oses = [s.strip().strip("\"'") for s in os_m.group(1).split(",")]
    pys = [s.strip().strip("\"'") for s in py_m.group(1).split(",")]
    return oses, pys


def test_tested_on_python_versions_match_ci_matrix():
    _, pys = _matrix()
    line = _tested_on()
    listed = re.findall(r"\b3\.\d{1,2}\b", line)
    assert sorted(set(listed), key=lambda v: int(v.split(".")[1])) == sorted(pys, key=lambda v: int(v.split(".")[1]))


def test_tested_on_os_match_ci_matrix():
    oses, _ = _matrix()
    line = _tested_on()
    names = {"ubuntu": "Linux", "windows": "Windows", "macos": "macOS"}
    for o in oses:
        assert names[o.split("-")[0]] in line, o
    for key, name in names.items():
        if not any(o.startswith(key) for o in oses):
            assert name not in line, name
    assert "not in automated CI" not in line
