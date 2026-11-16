"""GitHub Actions hardening (16 Nov 2026): every action pinned to a full commit SHA with its version in a comment,
checkout keeps no credentials, every workflow and job declares minimal permissions, CI runs pinned pip-audit and
bandit, and Dependabot watches pip and github-actions. Works in the private drafts and in the public .github/."""
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parent.parent


def _workflow_files():
    pub = ROOT / ".github" / "workflows"
    drafts = ROOT / "github_drafts" / "workflows"
    if pub.is_dir():
        return sorted(p for p in pub.iterdir() if p.suffix in (".yml", ".yaml"))
    if drafts.is_dir():
        return sorted(drafts.glob("*.yml.disabled"))
    return []


WORKFLOWS = _workflow_files()
DEPENDABOT = next((p for p in (ROOT / ".github" / "dependabot.yml", ROOT / "github_drafts" / "dependabot.yml")
                   if p.is_file()), None)
pytestmark = pytest.mark.skipif(not WORKFLOWS, reason="workflow files not found")

USES_LINE = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$")
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"#\s*v\d+(\.\d+)*\s*$")


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _steps(wf):
    for name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            yield name, step


def test_both_workflows_are_checked():
    names = {p.name.split(".")[0] for p in WORKFLOWS}
    assert {"ci", "release"} <= names


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_uses_is_pinned_to_a_full_sha_with_a_version_comment(path):
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if USES_LINE.match(ln)]
    assert lines, "no uses: lines found"
    for ln in lines:
        ref, rest = USES_LINE.match(ln).groups()
        assert PINNED.match(ref), f"not pinned to a 40-hex commit SHA: {ln.strip()}"
        assert VERSION_COMMENT.search(rest), f"no version comment such as '# v4.2.2': {ln.strip()}"
    # the YAML view agrees with the text view
    uses = [s["uses"] for _, s in _steps(_load(path)) if "uses" in s]
    assert len(uses) == len(lines) and all(PINNED.match(u) for u in uses)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkout_keeps_no_credentials(path):
    checkouts = [s for _, s in _steps(_load(path)) if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert checkouts
    for s in checkouts:
        assert (s.get("with") or {}).get("persist-credentials") is False


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_and_every_job_declare_minimal_permissions(path):
    wf = _load(path)
    assert wf.get("permissions") == {"contents": "read"}
    for name, job in wf["jobs"].items():
        perms = job.get("permissions")
        assert isinstance(perms, dict) and perms, f"job {name} has no permissions"
        assert not [k for k, v in perms.items() if v == "write" and k != "id-token"], f"job {name} writes"
        assert "write-all" not in str(perms)


def test_only_the_publish_job_gets_an_id_token():
    for path in WORKFLOWS:
        for name, job in _load(path)["jobs"].items():
            if job.get("permissions", {}).get("id-token") == "write":
                assert (path.name.startswith("release"), name) == (True, "publish")


def test_ci_runs_pinned_pip_audit_and_bandit():
    ci = next(p for p in WORKFLOWS if p.name.startswith("ci."))
    sec = _load(ci)["jobs"]["security"]
    text = "\n".join(s.get("run", "") for s in sec["steps"])
    assert re.search(r'"pip-audit==\d+\.\d+\.\d+"', text)
    assert re.search(r'"bandit==\d+\.\d+\.\d+"', text)
    assert "pip_audit" in text
    assert re.search(r"bandit -r src\b", text)


def test_dependabot_watches_pip_and_actions_weekly_with_a_small_pr_limit():
    assert DEPENDABOT is not None
    cfg = _load(DEPENDABOT)
    assert cfg["version"] == 2
    by_eco = {u["package-ecosystem"]: u for u in cfg["updates"]}
    assert set(by_eco) == {"pip", "github-actions"}
    for u in by_eco.values():
        assert u["schedule"]["interval"] == "weekly"
        assert 1 <= u["open-pull-requests-limit"] <= 5


def test_dependabot_has_no_labels_and_ignores_major_versions():
    assert DEPENDABOT is not None
    for u in _load(DEPENDABOT)["updates"]:
        assert "labels" not in u
        assert {"dependency-name": "*", "update-types": ["version-update:semver-major"]} in u.get("ignore", [])


EXPORT_SCRIPT = ROOT / "scripts" / "make_public_export.py"


@pytest.mark.skipif(not EXPORT_SCRIPT.is_file(), reason="private repository only")
def test_export_publishes_dependabot_under_dot_github():
    import importlib.util
    spec = importlib.util.spec_from_file_location("make_public_export", EXPORT_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    published = dict((dst, src) for src, dst in mod.plan(ROOT))
    assert published.get(".github/dependabot.yml") == "github_drafts/dependabot.yml"
