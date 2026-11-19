"""sangop command line.

  sangop scan PATH [--fail-on secret|pii|any|none] [--json]
  sangop sql-check "SQL" [--max-rows N] [--dialect postgres] [--allow-write]
  sangop audit verify [--db .sangop/audit.db] [--anchor ID:HASH]   (key: env SANGOP_LEDGER_KEY)
  sangop audit tail   [--db .sangop/audit.db] [-n 20]
  sangop keygen                       (prints a random ledger key; writes no file)
  sangop selftest
  sangop version

`scan` is meant for files YOU own or are authorised to inspect. It reads
local files only and never uploads anything. Values are always printed masked.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from typing import Iterator, List

from . import __version__
from .audit import AuditLedger
from .detectors import find_all
from .sqlguard import SqlPolicy, check_sql

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
             ".pytest_cache", "dist", "build", ".sangop", ".idea", ".tox"}
MAX_BYTES = 2 * 1024 * 1024


def _iter_files(root: str) -> Iterator[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _read_text(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None                     # binary
    return data.decode("utf-8", errors="replace")


def cmd_scan(args: argparse.Namespace) -> int:
    results: List[dict] = []
    files = 0
    for path in _iter_files(args.path):
        text = _read_text(path)
        if text is None:
            continue
        files += 1
        for f in find_all(text):
            line = text.count("\n", 0, f.start) + 1
            results.append({"file": path, "line": line, "kind": f.kind,
                            "category": f.category, "preview": f.masked()})
    secrets_n = sum(r["category"] == "secret" for r in results)
    pii_n = sum(r["category"] == "pii" for r in results)
    if args.json:
        print(json.dumps({"files_scanned": files, "secrets": secrets_n, "pii": pii_n,
                          "findings": results}, indent=2))
    else:
        for r in results:
            tag = "SECRET" if r["category"] == "secret" else "PII   "
            print(f"[{tag}] {r['file']}:{r['line']}  {r['kind']:<22} {r['preview']}")
        print(f"\nScanned {files} file(s): {secrets_n} secret(s), {pii_n} PII value(s). "
              "Values shown masked. Local scan only - nothing was uploaded.")
    fail = {"secret": secrets_n > 0, "pii": pii_n > 0,
            "any": (secrets_n + pii_n) > 0, "none": False}[args.fail_on]
    return 1 if fail else 0


def cmd_sql_check(args: argparse.Namespace) -> int:
    policy = SqlPolicy(read_only=not args.allow_write, max_rows=args.max_rows,
                       rewrite_limit=args.rewrite_limit, dialect=args.dialect,
                       require_filter_column=args.require_filter)
    v = check_sql(args.sql, policy)
    print(json.dumps({"allowed": v.allowed, "reason": v.reason, "type": v.statement_type,
                      "sql": v.sql}, indent=2))
    return 0 if v.allowed else 2


def cmd_audit(args: argparse.Namespace) -> int:
    if not os.path.exists(args.db):
        print(f"No ledger at {args.db}")
        return 1
    led = AuditLedger(args.db)
    try:
        if args.action == "verify":
            rep = led.verify_report(anchor=args.anchor)
            print(f"{'OK' if rep['ok'] else 'TAMPERED'} ({rep['mode']}): {rep['message']}")
            if rep["anchor"]:
                print(f"anchor: {rep['anchor']}")
                print("(keep a copy of the anchor where the ledger's writer cannot change it; pass it as --anchor next time)")
            return 0 if rep["ok"] else 3
        for row in led.tail(args.n):
            print(json.dumps(row, ensure_ascii=False))
        return 0
    finally:
        led.close()


KEYGEN_NOTE = ("Keep this key in a password manager. Never put it in git, chat or screenshots. "
               "Set it as SANGOP_LEDGER_KEY in the environment of the process that writes the ledger.")


def cmd_keygen(_: argparse.Namespace) -> int:
    """Print one random 32-byte key (64 hex characters) on stdout. Nothing is written to any file."""
    print(secrets.token_hex(32))
    print(KEYGEN_NOTE, file=sys.stderr)
    return 0


def cmd_selftest(_: argparse.Namespace) -> int:
    from .guard import _STATE, selftest
    _STATE.ledger = None
    print(json.dumps(selftest(), indent=2))
    return 0


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sangop", description="Sangop local safety tools (no network).")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan your own files for secrets and PII (masked output)")
    s.add_argument("path")
    s.add_argument("--fail-on", choices=["secret", "pii", "any", "none"], default="secret")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    q = sub.add_parser("sql-check", help="check one SQL statement against the policy")
    q.add_argument("sql")
    q.add_argument("--max-rows", type=int, default=100)
    q.add_argument("--rewrite-limit", action="store_true")
    q.add_argument("--dialect", default=None)
    q.add_argument("--require-filter", default=None, metavar="COLUMN")
    q.add_argument("--allow-write", action="store_true")
    q.set_defaults(func=cmd_sql_check)

    a = sub.add_parser("audit", help="verify or view the audit ledger")
    a.add_argument("action", choices=["verify", "tail"])
    a.add_argument("--db", default=".sangop/audit.db")
    a.add_argument("--anchor", default=None, help="'<id>:<hash>' printed by an earlier verify; detects cut-off rows")
    a.add_argument("-n", type=int, default=20)
    a.set_defaults(func=cmd_audit)

    k = sub.add_parser("keygen", help="print a random ledger key for SANGOP_LEDGER_KEY (writes no file)")
    k.set_defaults(func=cmd_keygen)

    t = sub.add_parser("selftest", help="canary test with synthetic values")
    t.set_defaults(func=cmd_selftest)

    v = sub.add_parser("version")
    v.set_defaults(func=lambda _: print(__version__) or 0)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
