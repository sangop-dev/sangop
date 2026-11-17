"""Sangop - deterministic PII/secret scrubbing, SQL guarding and
tamper-evident audit logging for AI agent tools (MCP / FastMCP).

Runs locally, in-process; designed to make no network connections and send no telemetry
(checked by tests/test_no_network.py).
Engineering aid only - not legal advice and not a compliance guarantee.
"""

from .audit import AuditLedger
from .detectors import Finding, find_all, mask_value
from .guard import SangopBlocked, SangopToolError, configure, get_ledger, get_vault, guard, selftest
from .policy import PolicyError, PolicyPack, example_pack_path, load_pack
from .sqlguard import SqlPolicy, SqlVerdict, check_sql
from .tokenizer import Vault, detokenize_obj, detokenize_text, scrub_obj, scrub_text

__version__ = "2026.11.1"

__all__ = [
    "AuditLedger", "Finding", "PolicyError", "PolicyPack", "SangopBlocked", "SangopToolError", "SqlPolicy", "SqlVerdict", "Vault",
    "check_sql", "configure", "detokenize_obj", "detokenize_text", "example_pack_path", "find_all",
    "get_ledger", "get_vault", "guard", "load_pack", "mask_value", "scrub_obj", "scrub_text",
    "selftest", "__version__",
]
