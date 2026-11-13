# MCP compatibility notes (spec 2026-07-28)

Status of this page: **tested on 23 Oct 2026 and re-checked on 25 Oct 2026** (both are the newest releases on PyPI that day: mcp 2.3.0, fastmcp 4.1.3; plus the SDK's own `MCPServer` class, added on 25 Oct) against the versions listed below, on synthetic data. It describes what we ran, not a promise for other versions. Spec facts come from the official changelog: <https://modelcontextprotocol.io/specification/2026-07-28/changelog>. Sangop is a library (`@sangop.guard`) that wraps a tool function; it does not speak MCP itself, so most protocol changes reach it only through the MCP SDK you use.

## What we ran

| Setup | Versions | Result |
|---|---|---|
| FastMCP over stdio | fastmcp 4.1.3, mcp 2.3.0 | masking and SQL blocking work |
| **The SDK's own server class `mcp.server.mcpserver.MCPServer`** (the SDK's own high-level server class in mcp 2.x), in-memory with the official `mcp.client.Client`: sync tool, async tool, SQL guard block and allow, a tool that raises | mcp 2.3.0 | masking works for sync and async tools; `DELETE` is blocked as an error result; an exception message carrying a PAN comes back scrubbed (`tests/test_mcp_sdk_server_compat.py`) |
| `MCPServer` over stdio (a subprocess server, official client) | mcp 2.3.0 | masking works |
| FastMCP streamable HTTP, `stateless_http=True`, three separate connections | same | works |
| Raw 2026-07-28 JSON-RPC over HTTP: no `initialize`, no `Mcp-Session-Id`, `_meta` protocol version, `Mcp-Method` / `Mcp-Name` headers, `server/discover` | same | works; replies carry `resultType: "complete"` and no session header; output is masked |
| Same quickstart, stdio and HTTP, on an older stack | fastmcp 2.14.7, mcp 1.30.0 | works (the 2026-07-28-specific test is skipped there because that SDK does not serve it) |
| `@guard` under a `task=True` tool (Tasks extension, `fastmcp-tasks` 4.1.3) | in-memory backend, one process | result is masked, direct and via the task |

Run them: `pytest tests/test_mcp_compat.py tests/test_mcp_sdk_server_compat.py` (the Tasks test needs `pip install fastmcp-tasks`).

## Spec point by point

| 2026-07-28 change | Effect on Sangop | Status |
|---|---|---|
| No protocol sessions, no `Mcp-Session-Id`; state across calls via server-minted handles passed as tool arguments | `@guard` is session-agnostic. **Token reversal is not**: see the next section | tested (no session code in `src/`; stateless HTTP works) |
| No `initialize` handshake; version and capabilities in `_meta` per request; `server/discover` | SDK-level; `@guard` only sees the function call | tested on fastmcp 4.1.3 / mcp 2.3.0 |
| `subscriptions/listen`, `ping` and `logging/setLevel` removed | not used by Sangop | checked in source |
| Tasks moved to an extension (`tasks/get`, `tasks/update`, no `tasks/list`) | the guarded function runs inside the task, so its result is already masked | tested in memory backend only; **not tested** with a Redis backend or separate worker processes (a worker process must call `sangop.configure(...)` itself, and its token vault is its own) |
| Multi round-trip requests (`InputRequiredResult`, `inputRequests`) | Sangop does not look inside these interim results; any personal data placed in a prompt to the user is not masked by `@guard` | **not tested** |
| `resultType` on all results | SDK-level | observed (`complete`) |
| SSE resumability removed | not used | n/a |
| Resource-not-found `-32002` became `-32602`; new codes in `-32020..-32099` | no error code is hard-coded in Sangop | tested (source search) |
| Roots, Sampling, Logging deprecated | not used by Sangop | tested (source search) |
| Caching fields on list results, authorization changes | Sangop adds no auth layer and does not change list results | not applicable |

## The real limits in stateless / multi-instance deployments

1. **Tokens are reversible only inside the process that made them.** The vault is process memory. If a request is served by instance A and a later one by instance B, B cannot turn A's token back into the real value. In that case the token passes through **unchanged** (fail-safe: nothing is leaked, but a trusted tool that expects the real value gets the token). Even with the same session key two instances do not share a mapping. Use one process (or sticky routing) for tools that use `detokenize_params`; for everything that only masks (`pii_mode="redact"`, or tokens the model never needs reversed) any number of instances is fine. Pinned by tests so this text cannot drift. A shared vault, server-minted handles or a keyed deterministic scheme are separate design decisions that we have **not** made or built.
2. **Audit ledger and several processes.** The first version of the ledger could break its hash chain when several processes (for example `uvicorn --workers 4`) wrote to one file; this was found by `tests/test_mcp_compat.py` and fixed in 0.1.3 by taking SQLite's write lock before reading the previous hash. After the fix four processes appending 600 events verify cleanly. Several processes writing to one file still serialise on that lock; for very high write rates use one ledger file per process.
3. **Sangop opens no network connection.** The loopback HTTP server in these tests is FastMCP's, not Sangop's.

## Not covered

`MCPServer` over streamable HTTP, `MCPServer` middleware, and the 2.x extensions system (`mcp.server.extension`) were not run. Other SDKs (TypeScript, Go, C#), MCP gateways and proxies, authorization flows, Redis-backed Tasks workers, real clients such as Claude Desktop or Cursor (we have not run Sangop inside them), and load or latency under HTTP.
