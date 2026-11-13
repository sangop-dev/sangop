"""Quickstart MCP server (stdio). SYNTHETIC data only.

    python examples/quickstart/server.py              # enforce (default)
    python examples/quickstart/server.py shadow       # log only, nothing masked or blocked
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tools import build_server  # noqa: E402

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "enforce"
    build_server(mode).run()
