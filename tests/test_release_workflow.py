"""The PyPI release workflow (inactive until the maintainer renames it to release.yml) must build from the public
repository it runs in, refuse packages that carry a private file, wait for a human approval and use trusted
publishing (no token). Written first, 13 Nov 2026. Synthetic packages only; nothing is built or uploaded."""
import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parent.parent
CANDIDATES = [ROOT / ".github" / "workflows" / "release.yml.disabled",
              ROOT / "github_drafts" / "workflows" / "release.yml.disabled"]
WORKFLOW = next((p for p in CANDIDATES if p.is_file()), None)
pytestmark = pytest.mark.skipif(WORKFLOW is None, reason="release workflow file not found")


def _wf():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _step(job, name):
    return next(s for s in _wf()["jobs"][job]["steps"] if s.get("name") == name)


def _package_check_script() -> str:
    run = _step("build", "Nothing private in the packages")["run"]
    lines = run.splitlines()
    start = next(i for i, ln in enumerate(lines) if "<<'PY'" in ln)
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "PY")
    return "\n".join(lines[start + 1:end])


def _make_dist(folder: Path, extra: str = None):
    dist = folder / "dist"
    dist.mkdir()
    with zipfile.ZipFile(dist / "sangop-2026.11.0-py3-none-any.whl", "w") as z:
        z.writestr("sangop/__init__.py", "x = 1\n")
        z.writestr("sangop-2026.11.0.dist-info/METADATA", "Name: sangop\n")
    with tarfile.open(dist / "sangop-2026.11.0.tar.gz", "w:gz") as t:
        for rel in ["src/sangop/__init__.py", "README.md", "scripts/prepublish_check.py",
                    "bench/india_pii/dataset_v0_1.sha256"] + ([extra] if extra else []):
            data = b"x\n"
            info = tarfile.TarInfo("sangop-2026.11.0/" + rel)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


def _run_check(folder: Path) -> int:
    return subprocess.run([sys.executable, "-c", _package_check_script()], cwd=folder,
                          capture_output=True, text=True).returncode


def test_clean_packages_pass(tmp_path):
    _make_dist(tmp_path)
    assert _run_check(tmp_path) == 0


@pytest.mark.parametrize("private", [
    "scripts/private_checks.py", "scripts/private_strings.txt", "scripts/private_check_files.txt",
    "scripts/pro_markers.txt", "scripts/make_public_export.py", "docs/NOTES_HI.md",
    "bench/india_pii/holdout9_v0_1.jsonl", "bench/other.jsonl",
])
def test_a_private_file_in_the_packages_fails_the_release(tmp_path, private):
    _make_dist(tmp_path, extra=private)
    assert _run_check(tmp_path) == 1


def test_build_uses_this_repository_and_checks_after_building():
    steps = _wf()["jobs"]["build"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    checkout = steps[uses.index(next(u for u in uses if u.startswith("actions/checkout@")))]
    assert "repository" not in (checkout.get("with") or {}), "the build must use the repository it runs in"
    names = [s.get("name") for s in steps]
    assert names.index("Build sdist and wheel") < names.index("Nothing private in the packages")


def test_publish_waits_for_approval_and_uses_trusted_publishing():
    wf = _wf()
    pub = wf["jobs"]["publish"]
    assert pub["needs"] == "build"
    assert pub["environment"]["name"] == "pypi"
    assert pub["permissions"] == {"id-token": "write"}
    step = next(s for s in pub["steps"] if str(s.get("uses", "")).startswith("pypa/gh-action-pypi-publish@"))
    assert not {"password", "user", "api-token"} & set((step.get("with") or {}))
    assert "secrets." not in WORKFLOW.read_text(encoding="utf-8")
    trigger = wf[True] if True in wf else wf["on"]          # YAML 1.1 reads the key `on` as True
    assert trigger == {"push": {"tags": ["v*"]}}


def test_only_ci_is_active():
    """Private repository: nothing in the drafts folder is active and there is no live .github folder.
    Public repository: .github/workflows holds the active ci.yml and the still-disabled release workflow only,
    and no .github/README.md (GitHub would show it instead of README.md)."""
    drafts = ROOT / "github_drafts" / "workflows"
    if drafts.is_dir():
        assert not list(drafts.glob("*.yml")) and not list(drafts.glob("*.yaml"))
        assert (drafts / "ci.yml.disabled").exists()
        assert not (ROOT / ".github").exists()
    else:
        wf = ROOT / ".github" / "workflows"
        assert sorted(p.name for p in wf.iterdir() if p.suffix in (".yml", ".yaml")) == ["ci.yml"]
        assert (wf / "release.yml.disabled").exists()
        assert not (ROOT / ".github" / "README.md").exists()
