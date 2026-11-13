"""Helper for tests/test_mcp_compat.py: runs the quickstart tools as a stateless streamable-HTTP MCP server on
127.0.0.1 (loopback only). Not a test file. Synthetic data only.

    python compat_server.py PORT LEDGER_PATH
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples" / "quickstart"))

import tools  # noqa: E402

if __name__ == "__main__":
    port, ledger = int(sys.argv[1]), sys.argv[2]
    tools.build_server("enforce", ledger_path=ledger).run(
        transport="http", host="127.0.0.1", port=port, stateless_http=True, show_banner=False)
