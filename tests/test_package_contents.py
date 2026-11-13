"""What would be published must not contain internal, closed or generated files (needs `hatchling`, skipped if absent)."""
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("hatchling")
ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN = ("_HI.md", "policies/", "private/", ".jsonl", ".env", ".db", "TRADEMARK", "INVENTION", "DOMAIN_BRAND")
PUBLIC_POLICY = "TRADEMARKS.md"      # the public trademark policy at the top level is allowed (14 Nov 2026)


def _forbidden(name: str) -> bool:
    return name != PUBLIC_POLICY and any(f in name for f in FORBIDDEN)


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    for target in ("wheel", "sdist"):
        r = subprocess.run([sys.executable, "-m", "hatchling", "build", "-t", target, "-d", str(out)],
                           cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr[-600:]
    return out


def test_wheel_has_only_the_library_and_the_example_pack(built):
    whl = next(built.glob("*.whl"))
    names = zipfile.ZipFile(whl).namelist()
    code = [n for n in names if ".dist-info/" not in n]
    assert code and all(n.startswith("sangop/") for n in code)
    assert any(n.startswith("sangop/example_policy/") for n in code)
    for n in names:
        assert not _forbidden(n), n


def test_sdist_has_no_internal_or_generated_files(built):
    sd = next(built.glob("*.tar.gz"))
    names = [n.split("/", 1)[1] for n in tarfile.open(sd).getnames() if "/" in n]
    assert "CHANGELOG.md" in names and "LICENSE" in names and "NOTICE" in names
    for n in names:
        assert not _forbidden(n), n
