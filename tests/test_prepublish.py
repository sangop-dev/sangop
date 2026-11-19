"""scripts/prepublish_check.py must catch the mistakes it exists to catch (synthetic trees only)."""
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "prepublish_check.py"
spec = importlib.util.spec_from_file_location("prepublish_check", SCRIPT)
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)

GOOD = {
    "LICENSE": "Apache License text",
    "NOTICE": "Sangop\nThis is not legal advice.\n",
    "README.md": "# Sangop\n```bash\npip install sangop\n```\nThis is not legal advice.\n## Known limits\n- many\n",
    "SECURITY.md": "Report privately.\n",
    "CONTRIBUTING.md": "Add `Signed-off-by: A <a@example.com>` to commits.\n",
    "SHARED_RESPONSIBILITY.md": "Your duties.\n",
    "TRADEMARKS.md": "Trademark policy.\n",
    "CODE_OF_CONDUCT.md": "Be kind.\n",
    "pyproject.toml": 'license = "Apache-2.0"\n',
    ".gitignore": "docs/*_HI.md\npolicies/\ndataset_*.jsonl\n.env\n",
    "src/sangop/__init__.py": "x = 1\n",
}


def make(tmp_path, extra=None, drop=()):
    tmp_path = tmp_path / "repo"  # sub-folder: the autouse fixture keeps an audit.db in tmp_path itself
    for rel, txt in {**GOOD, **(extra or {})}.items():
        if rel in drop:
            continue
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")
    return tmp_path


def status(results, name):
    return next(s for s, n, _ in results if n == name)


def test_clean_tree_passes(tmp_path):
    res = pc.run_checks(make(tmp_path))
    assert not [r for r in res if r[0] == "FAIL"], res


def test_ignored_internal_files_are_not_flagged(tmp_path):
    res = pc.run_checks(make(tmp_path, {"docs/NOTES_HI.md": "internal", "policies/dpdp/a.yaml": "x", "dataset_v0_1.jsonl": "{}"}))
    assert status(res, "private/internal files") == "PASS"


def test_unignored_internal_file_fails(tmp_path):
    res = pc.run_checks(make(tmp_path, {"notes_HI.md": "internal", "keys/server.pem": "k"}))
    assert status(res, "private/internal files") == "FAIL"


def test_missing_required_file_fails(tmp_path):
    assert status(pc.run_checks(make(tmp_path, drop=("SECURITY.md",))), "required files") == "FAIL"


FAKE_PRIVATE = ["PRIVATE_DIR_X", "someone@example.com"]


def test_private_string_in_a_public_file_fails(tmp_path):
    root = make(tmp_path, {"docs/guide.md": "see PRIVATE_DIR_X\\notes and mail someone@example.com\n"})
    assert status(pc.run_checks(root, private_strings=FAKE_PRIVATE), "personal paths/e-mail/internal names") == "FAIL"


def test_private_strings_are_read_from_the_private_list(tmp_path):
    root = make(tmp_path, {"docs/guide.md": "see PRIVATE_DIR_X\n", "scripts/private_strings.txt": "# list\nPRIVATE_DIR_X\n"})
    assert status(pc.run_checks(root), "personal paths/e-mail/internal names") == "FAIL"


def test_missing_private_list_means_empty_and_checks_still_run(tmp_path):
    res = pc.run_checks(make(tmp_path, {"docs/guide.md": "see PRIVATE_DIR_X\n"}))
    assert status(res, "personal paths/e-mail/internal names") == "PASS"
    assert status(res, "required files") == "PASS" and status(res, "risky legal claims") == "PASS"


def test_extra_claim_files_come_from_the_private_list(tmp_path):
    root = make(tmp_path, {"scripts/private_check_files.txt": "# list\n../outside.md\nmissing.md\n"})
    (root.parent / "outside.md").write_text("x\n", encoding="utf-8")
    got = pc.check_files(root)
    assert [p.name for p in got] == ["outside.md", "missing.md"]
    assert pc.run_checks(root, extra_claim_files=got)   # a missing file is skipped, not an error


def test_claims_fail_but_negated_claims_pass(tmp_path):
    bad = pc.run_checks(make(tmp_path / "a", {"docs/x.md": "Sangop makes you " + "DPDP " + "compliant.\n"}))
    assert status(bad, "risky legal claims") == "FAIL"
    ok = pc.run_checks(make(tmp_path / "b", {"docs/x.md": "Sangop does not make you " + "compliant; no " + "certified status.\n"}))
    assert status(ok, "risky legal claims") == "PASS"


def test_secret_shaped_text_fails(tmp_path):
    fake = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
    assert status(pc.run_checks(make(tmp_path, {"examples/e.py": f"KEY = '{fake}'\n"})), "secrets") == "FAIL"


def test_readme_must_be_honest_and_dco_present(tmp_path):
    res = pc.run_checks(make(tmp_path, {"README.md": "# Sangop\nBest tool ever.\n", "CONTRIBUTING.md": "Send PRs.\n"}))
    assert status(res, "README honesty") == "FAIL" and status(res, "DCO rule") == "FAIL"


def test_large_file_fails(tmp_path):
    res = pc.run_checks(make(tmp_path, {"data/big.txt": "x" * 2_100_000}))
    assert status(res, "file size") == "FAIL"


def test_exit_code(tmp_path):
    assert pc.main(["--root", str(make(tmp_path / "ok"))]) == 0
    assert pc.main(["--root", str(make(tmp_path / "bad", drop=("NOTICE",)))]) == 1


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_uses_git_view_when_available(tmp_path):
    root = make(tmp_path)
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs" / "SECRET_HI.md").write_text("internal", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    files, how = pc.public_files(root)
    assert "git ls-files" in how and "docs/SECRET_HI.md" not in files and "README.md" in files


def test_real_repo_passes_its_own_check():
    """The way the script is really run: in the private repository it checks the public export built from it;
    in a public checkout it checks the checkout itself."""
    root = SCRIPT.parent.parent
    assert pc.main(["--root", str(root), "--skip-private-checks"]) == 0     # the maintainers' extra checks run tests


STUB = """from pathlib import Path


def run(root):
    (Path(root) / "ran.txt").write_text("yes", encoding="utf-8")
    return [("{status}", "stub extra check", "from the stub")]
"""


@pytest.mark.parametrize("stub_status, code", [("PASS", 0), ("FAIL", 1)])
def test_maintainers_extra_checks_run_when_present(tmp_path, monkeypatch, stub_status, code):
    monkeypatch.delenv("SANGOP_SKIP_PRIVATE_CHECKS", raising=False)   # set when the maintainers' check runs this suite
    root = make(tmp_path, {"scripts/private_checks.py": STUB.format(status=stub_status)})
    assert pc.main(["--root", str(root)]) == code
    assert (root / "ran.txt").read_text(encoding="utf-8") == "yes"


def test_extra_checks_can_be_skipped(tmp_path, monkeypatch):
    monkeypatch.delenv("SANGOP_SKIP_PRIVATE_CHECKS", raising=False)
    root = make(tmp_path, {"scripts/private_checks.py": STUB.format(status="FAIL")})
    assert pc.main(["--root", str(root), "--skip-private-checks"]) == 0
    monkeypatch.setenv("SANGOP_SKIP_PRIVATE_CHECKS", "1")
    assert pc.main(["--root", str(root)]) == 0
    assert not (root / "ran.txt").exists()


def test_a_broken_extra_check_file_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("SANGOP_SKIP_PRIVATE_CHECKS", raising=False)
    root = make(tmp_path, {"scripts/private_checks.py": "raise RuntimeError('broken')\n"})
    assert pc.main(["--root", str(root)]) == 1


def test_no_extra_check_file_changes_nothing(tmp_path):
    assert pc.main(["--root", str(make(tmp_path))]) == 0


# ---- Pro rules and the private benchmark must never reach a public export (5 Nov 2026) ----

def test_pro_rule_marker_in_a_public_file_fails(tmp_path):
    root = make(tmp_path, {"src/sangop/extra.py": "RULE = _PRIVATE_TUNED_RULE_X\n"})
    res = pc.run_checks(root, markers=["_PRIVATE_TUNED_RULE_X"])
    assert status(res, "Pro rules / private benchmark") == "FAIL"


def test_private_benchmark_files_fail(tmp_path):
    for rel in ("bench/india_pii/generate_set9.py", "bench/india_pii/BASELINE_X.md",
                "bench/india_pii/AFTER_D999.md", "bench/india_pii/holdout9_v0_1.jsonl"):
        res = pc.run_checks(make(tmp_path / rel.replace("/", "_"), {rel: "x\n"}), markers=[])
        assert status(res, "Pro rules / private benchmark") == "FAIL", rel


def test_clean_tree_passes_the_pro_check(tmp_path):
    res = pc.run_checks(make(tmp_path), markers=["_PRIVATE_TUNED_RULE_X"])
    assert status(res, "Pro rules / private benchmark") == "PASS"


def test_published_sha256_of_private_sets_are_allowed(tmp_path):
    """The sha256 of every private set is public (it proves the sets were not changed later)."""
    res = pc.run_checks(make(tmp_path, {"bench/india_pii/holdout9_v0_1.sha256": "ab  holdout9_v0_1.jsonl\n"}), markers=[])
    assert status(res, "Pro rules / private benchmark") == "PASS"


# ---- the honesty rule on every public sentence, also for Sangop Pro (5 Nov 2026) ----

@pytest.mark.parametrize("line", [
    "Sangop Pro catches everything.", "It stops all leaks.", "Hack-proof by design.", "The only tool you need.",
    "India's first agent firewall.", "100% local and private.", "We guarantee your data is safe.",
    "Makes you DPDP compliant.", "Certified secure.",
])
def test_risky_claims_fail(tmp_path, line):
    res = pc.run_checks(make(tmp_path, {"README.md": GOOD["README.md"] + line + "\n"}), markers=[])
    assert status(res, "risky legal claims") == "FAIL", line


@pytest.mark.parametrize("line", [
    "Sangop Pro covers more written forms.", "Recognised by their first bytes only.", "Only plain integer limits count.",
    "It does not make anyone compliant.", "Not a guarantee.",
])
def test_ordinary_wording_passes(tmp_path, line):
    res = pc.run_checks(make(tmp_path, {"README.md": GOOD["README.md"] + line + "\n"}), markers=[])
    assert status(res, "risky legal claims") == "PASS", line


def test_extra_files_are_checked_for_claims(tmp_path):
    """The Pro README and the changelogs are checked too, although they are not part of the public export."""
    root = make(tmp_path)
    pro = tmp_path / "pro_README.md"
    pro.write_text("Sangop Pro catches everything.\n", encoding="utf-8")
    assert status(pc.run_checks(root, markers=[], extra_claim_files=[pro]), "risky legal claims") == "FAIL"
    pro.write_text("Sangop Pro covers more written forms.\n", encoding="utf-8")
    assert status(pc.run_checks(root, markers=[], extra_claim_files=[pro]), "risky legal claims") == "PASS"


# ---- the install line (Builder 19): `pip install sangop` on top; a pre-release note that must go on release day ----

NOTE = "<!-- pre-release-note -->"


def test_readme_without_pip_install_line_fails(tmp_path):
    root = make(tmp_path, {"README.md": "# Sangop\nThis is not legal advice.\n## Known limits\n"})
    assert status(pc.run_checks(root, markers=[]), "install line") == "FAIL"


def test_pre_release_note_passes_before_release_and_fails_on_release_day(tmp_path):
    readme = GOOD["README.md"] + NOTE + " Until the first PyPI release, install from source.\n"
    root = make(tmp_path, {"README.md": readme})
    assert status(pc.run_checks(root, markers=[]), "install line") == "PASS"
    assert status(pc.run_checks(root, markers=[], release_day=True), "install line") == "FAIL"
    assert pc.main(["--root", str(root), "--release-day"]) == 1


def test_release_day_passes_once_the_note_is_gone(tmp_path):
    assert status(pc.run_checks(make(tmp_path), markers=[], release_day=True), "install line") == "PASS"


# ---- release day (14 Nov 2026): the trademark policy and the code of conduct are part of every public tree ------
@pytest.mark.parametrize("name", ["TRADEMARKS.md", "CODE_OF_CONDUCT.md"])
def test_trademark_policy_and_code_of_conduct_are_required(tmp_path, name):
    assert name in pc.REQUIRED
    res = pc.run_checks(make(tmp_path, drop=(name,)), markers=[])
    assert status(res, "required files") == "FAIL"
