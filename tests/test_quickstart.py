"""The quickstart (examples/quickstart) must run, show masking, and never print raw synthetic values where
a token is expected. Synthetic data only."""
import asyncio
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastmcp")

ROOT = Path(__file__).resolve().parent.parent
QS = ROOT / "examples" / "quickstart"
sys.path.insert(0, str(QS))

import tools  # noqa: E402

import sangop  # noqa: E402


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setenv("SANGOP_QS_DB", str(tmp_path / "qs.db"))
    yield
    sangop.configure(ledger_path=None, run_selftest=False)


def _call(mcp, name, args):
    from fastmcp import Client

    async def go():
        async with Client(mcp) as c:
            r = await c.call_tool(name, args, raise_on_error=False)
            return r.is_error, (r.content[0].text if r.content else "")
    return asyncio.run(go())


def test_enforce_masks_everything_that_is_raw_without_sangop(tmp_path):
    off = tools.build_server("off")
    _, raw = _call(off, "lookup_customer", {"customer_id": 7})
    aad = tools.fake_aadhaar(7)
    assert aad in raw and "ABCPE1234F" in raw
    enf = tools.build_server("enforce", ledger_path=str(tmp_path / "a.db"))
    err, text = _call(enf, "lookup_customer", {"customer_id": 7})
    assert not err and aad not in text and "ABCPE1234F" not in text and "9876500007" not in text
    assert "[PII_AADHAAR_" in text and "[PII_PAN_" in text
    err, note = _call(enf, "read_note", {"note_id": 1})
    assert tools.FAKE_KEY not in note and "[PII_SECRET_GITHUB_" in note


def test_enforce_blocks_bad_sql_and_shadow_blocks_nothing(tmp_path):
    enf = tools.build_server("enforce", ledger_path=str(tmp_path / "e.db"))
    for q in ("DROP TABLE customers", "SELECT * FROM customers"):
        err, text = _call(enf, "run_query", {"query": q})
        assert err and "blocked" in text.lower()
    sh = tools.build_server("shadow", ledger_path=str(tmp_path / "s.db"))
    err, text = _call(sh, "run_query", {"query": "SELECT * FROM customers"})
    assert not err and "Test Customer 1" in text            # nothing blocked
    err, text = _call(sh, "lookup_customer", {"customer_id": 3})
    assert tools.fake_aadhaar(3) in text                    # nothing masked either
    events = sangop.get_ledger().tail(20)
    assert any(e["record"].get("sql", {}).get("allowed") is False for e in events)   # but it was seen
    assert tools.fake_aadhaar(3) not in str(events)                                  # and no raw value logged


def test_no_key_shaped_literal_in_quickstart_files():
    for p in QS.iterdir():
        if p.is_file():
            txt = p.read_text(encoding="utf-8")
            assert not re.search(r"gh[pousr]_[A-Za-z0-9]{36}", txt), p.name
            assert not re.search(r"AKIA[0-9A-Z]{16}", txt), p.name


def test_config_example_is_valid_json_with_placeholders_only():
    import json
    d = json.loads((QS / "claude_desktop_config.example.json").read_text(encoding="utf-8"))
    text = json.dumps(d)
    assert "<PATH-TO-PYTHON>" in text and "<PATH-TO-SANGOP>" in text
    assert not re.search(r"[A-Za-z]:\\\\|/home/|/Users/", text)


def test_client_demo_runs_from_a_clean_directory_and_is_clean(tmp_path):
    env = dict(os.environ, SANGOP_QS_DB=str(tmp_path / "d.db"), PYTHONIOENCODING="ascii")
    r = subprocess.run([sys.executable, str(QS / "client_demo.py")], cwd=tmp_path, env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-800:]
    out = r.stdout
    assert "Traceback" not in out and "Traceback" not in r.stderr
    assert "[PII_AADHAAR_" in out and "blocked" in out.lower() and "shadow log: would mask" in out
    enforce_lines = [l for l in out.splitlines() if l.strip().startswith("Sangop enforce")]
    assert enforce_lines and not any(tools.fake_aadhaar(7) in l or tools.FAKE_KEY in l for l in enforce_lines)
    v = subprocess.run([sys.executable, "-m", "sangop.cli", "audit", "verify", "--db", ".sangop/quickstart_enforce.db"],
                       cwd=tmp_path, env=dict(env, PYTHONPATH=str(ROOT / "src")), capture_output=True, text=True)
    assert v.returncode == 0 and "OK" in v.stdout


def test_readme_quickstart_commands_point_at_real_files():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    sec = readme[readme.index("## Quickstart (5 minutes)"):readme.index("## Protect an MCP tool")]
    for rel in re.findall(r"examples[/\\]quickstart[/\\][\w.\-]+", sec):
        assert (ROOT / rel.replace("\\", "/")).exists(), rel
    assert "examples/quickstart/ladder.md" in sec
