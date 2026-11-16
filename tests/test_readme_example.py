"""The first example in the README must be true: this test runs its code and its CLI step and compares the output with
the output printed in the README. Token hex values and the ledger anchor change on every run and are normalised.
Synthetic values only.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def _block(text: str, marker: str) -> str:
    m = re.search(r"<!-- " + re.escape(marker) + r" -->\s*```[a-z]*\n(.*?)```", text, re.S)
    assert m, f"README has no block marked {marker}"
    return m.group(1)


def _norm(text: str) -> str:
    text = re.sub(r"\[(PII|SECRET)_([A-Z_]+?)_[0-9a-f]{16}\]", r"[\1_\2_<hex>]", text)
    text = re.sub(r"anchor: \d+:[0-9a-f]{64}", "anchor: <n>:<hash>", text)
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


def test_readme_example_output_is_what_the_code_prints(tmp_path):
    text = README.read_text(encoding="utf-8")
    code = _block(text, "readme-example:code")
    shown = _block(text, "readme-example:output")
    (tmp_path / "example.py").write_text(code, encoding="utf-8")
    env_cmd = [sys.executable, str(tmp_path / "example.py")]
    out = subprocess.run(env_cmd, cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    cli = subprocess.run([sys.executable, "-c", "import sys; from sangop.cli import main; sys.exit(main(sys.argv[1:]))",
                          "audit", "verify", "--db", "demo_audit.db"],
                         cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert cli.returncode == 0, cli.stderr
    got = out.stdout + "$ sangop audit verify --db demo_audit.db\n" + cli.stdout
    assert _norm(got) == _norm(shown)


def test_readme_example_is_short_and_synthetic():
    code = _block(README.read_text(encoding="utf-8"), "readme-example:code")
    assert len(code.strip().splitlines()) <= 15
    assert "999941057058" in code and "UIDAI's published test UID" in code   # not a person's number (TASK-041)
