"""Dependency floors in pyproject.toml must be versions the test suite really passes on.

Why the sqlglot floor is 28.5: with sqlglot 28.0.0 to 28.4.0 the postgres dialect let `json_agg` through,
with or without a LIMIT (for example `SELECT json_agg(u) FROM users u LIMIT 10` was allowed, i.e.
fail-open: one row can carry the whole table); from 28.5.0 it is blocked. That case is pinned directly by
`test_h4b_row_folding_aggregate_blocked_with_limit` in test_security_regressions.py.
A separate finding (weekly maintenance check, 11 Nov 2026): on older sqlglot versions (checked: 25.34.1,
27.0.0) a `%s` placeholder query (`SELECT * FROM orders WHERE tenant_id = %s LIMIT 10`) was blocked;
that was fail-closed (too strict, not a leak) and is not the reason for the floor.
Written test-first. No third-party packages are needed to read the file.
"""
import re
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _project() -> dict:
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        import tomllib                                    # Python 3.11+
        return tomllib.loads(text)["project"]
    except ModuleNotFoundError:                           # Python 3.10: read the two lists this test needs
        deps = re.search(r'^dependencies\s*=\s*\[(.*?)\]', text, re.M | re.S).group(1)
        dev = re.search(r'^dev\s*=\s*\[(.*?)\]', text, re.M | re.S).group(1)
        return {"dependencies": re.findall(r'"([^"]+)"', deps),
                "optional-dependencies": {"dev": re.findall(r'"([^"]+)"', dev)}}


def _floor(reqs, name):
    for r in reqs:
        m = re.fullmatch(rf"{re.escape(name)}\s*>=\s*([0-9][0-9.]*)(?:\s*,.*)?", r.strip())
        if m:
            return tuple(int(p) for p in m.group(1).split("."))
    raise AssertionError(f"no '{name}>=' requirement in {reqs}")


def _pad(v, n=3):
    return v + (0,) * (n - len(v))


def test_sqlglot_floor_is_at_least_28_5():
    assert _pad(_floor(_project()["dependencies"], "sqlglot")) >= (28, 5, 0)


def test_dev_extra_has_httpx_so_the_mcp_compat_tests_run():
    dev = _project()["optional-dependencies"]["dev"]
    assert _pad(_floor(dev, "httpx")) >= (0, 28, 0)


def test_the_installed_sqlglot_meets_the_floor():
    import sqlglot
    installed = tuple(int(p) for p in re.findall(r"\d+", sqlglot.__version__)[:3])
    assert _pad(installed) >= _pad(_floor(_project()["dependencies"], "sqlglot"))
