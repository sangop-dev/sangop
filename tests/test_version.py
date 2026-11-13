"""The package version is written in two places (pyproject.toml and sangop.__version__); they must agree.
Found by the 26 Oct 2026 check: pyproject said 0.1.3 while the code said 0.1.4."""
import re
from pathlib import Path

import pytest

import sangop

ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^\[project\][^\[]*?^version\s*=\s*"([^"]+)"', text)
    assert m, "no version in [project]"
    return m.group(1)


def test_pyproject_and_package_versions_agree():
    assert _pyproject_version() == sangop.__version__


def test_version_is_calver_2026_11_0():
    """D-102 (5 Nov 2026): date-based versions, YYYY.MM.PATCH; the first public release is 2026.11.0."""
    assert sangop.__version__ == "2026.11.0"
    assert re.fullmatch(r"20\d\d\.(?:[1-9]|1[0-2])\.\d+", sangop.__version__)


def test_changelog_mentions_the_version():
    assert f"## {sangop.__version__}" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_public_changelog_mentions_the_version():
    """In the private repository the public changelog is CHANGELOG_PUBLIC.md; in a public export it has become
    CHANGELOG.md (checked by the test above)."""
    public = ROOT / "CHANGELOG_PUBLIC.md"
    if not public.exists():
        pytest.skip("public export: CHANGELOG.md is the public changelog")
    assert f"## {sangop.__version__}" in public.read_text(encoding="utf-8")


def test_readme_names_both_versions():
    year_month = ".".join(sangop.__version__.split(".")[:2])
    line = (f"**Sangop open core {year_month} · Sangop Pro {year_month} (separate add-on with tuned Indian rules; "
            f"not yet publicly available)**")
    assert line in (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_never_suggests_pro_can_be_obtained_today():
    """LEGAL_SAFETY rule 3 (honesty): every README paragraph that names Sangop Pro's extra coverage says it is not
    publicly available yet."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for para in text.split("\n\n"):
        flat = " ".join(para.split())
        if "Sangop Pro" in flat and ("covers" in flat or "add-on" in flat):
            assert "not yet publicly available" in flat or "not publicly available yet" in flat, flat[:120]


def test_notice_names_the_owner_in_full():
    """One owner name everywhere, the same as on trademark application 8094683 (D-106, 5 Nov 2026)."""
    text = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "Copyright 2026 Arvind Kumar" in text
