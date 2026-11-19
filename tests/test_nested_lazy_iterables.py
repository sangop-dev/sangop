"""Internal review (26 Oct 2026), F1 (CRITICAL): a lazy iterable NESTED inside a tool result (a generator, map, zip, iter, chain or
filter object inside a dict or list) was returned untouched, and the MCP framework's serializer then consumed it and
sent the raw values to the client. Only a top-level iterator was scrubbed (H3).

Written before the fix (failing first). Synthetic values only."""
import asyncio
import itertools
import json

import pydantic_core
import pytest
from conftest import PAN, PHONE

import sangop
from sangop import tokenizer
from sangop.tokenizer import Vault, scrub_obj

MAX_LAZY_ITEMS = getattr(tokenizer, "MAX_LAZY_ITEMS", 10_000)      # the limit the fix promises


def _payloads():
    return {
        "generator_in_dict": lambda: {"rows": (x for x in [PAN])},
        "map_in_list": lambda: [map(str, [PAN])],
        "zip_in_dict": lambda: {"z": zip([PAN], [PHONE])},
        "iter_in_dict": lambda: {"it": iter([PAN])},
        "chain_in_dict": lambda: {"c": itertools.chain([PAN], [PHONE])},
        "filter_in_dict": lambda: {"f": filter(None, [PAN])},
        "deeply_nested": lambda: {"a": [{"b": (row for row in [{"pan": PAN, "phone": PHONE}])}]},
        "dict_value_iterator": lambda: {"v": iter({"k": PAN}.values())},
    }


PAYLOADS = _payloads()


def _json(obj) -> str:
    return pydantic_core.to_json(obj).decode()


@pytest.mark.parametrize("name", sorted(PAYLOADS))
@pytest.mark.parametrize("mode", ["tokenize", "redact"])
def test_nested_lazy_iterables_are_scrubbed(name, mode):
    out, counts = scrub_obj(PAYLOADS[name](), Vault(), mode)
    text = _json(out)
    assert PAN not in text, (name, text)
    assert PHONE not in text, (name, text)
    assert counts["PAN"] >= 1, (name, counts)


def test_items_keep_their_order_and_shape():
    out, _ = scrub_obj({"z": zip(["a", PAN], ["b", "c"])}, Vault(), "tokenize")
    assert isinstance(out["z"], list) and len(out["z"]) == 2
    assert out["z"][0] == ("a", "b")
    assert out["z"][1][0].startswith("[PII_PAN_") and out["z"][1][1] == "c"


def test_clean_nested_iterators_still_serialise_the_same():
    out, counts = scrub_obj({"n": (i for i in range(3)), "m": map(str.upper, ["x", "y"])}, Vault(), "tokenize")
    assert json.loads(_json(out)) == {"n": [0, 1, 2], "m": ["X", "Y"]}
    assert not counts


def test_shadow_mode_counts_and_keeps_the_values():
    """Shadow only observes. A nested iterator it had to read is handed back as a list of the ORIGINAL values
    (an exhausted iterator would silently lose the data)."""
    out, counts = scrub_obj({"rows": (x for x in [PAN, "ok"])}, Vault(), "shadow")
    assert counts["PAN"] == 1
    assert json.loads(_json(out)) == {"rows": [PAN, "ok"]}


def test_shadow_mode_without_lazy_iterables_still_returns_the_same_object():
    obj = {"pan": PAN, "rows": [PAN]}
    out, counts = scrub_obj(obj, Vault(), "shadow")
    assert out is obj and counts["PAN"] == 2


def test_limit_exact_is_scrubbed():
    out, counts = scrub_obj({"rows": (PAN for _ in range(MAX_LAZY_ITEMS))}, Vault(), "tokenize")
    assert len(out["rows"]) == MAX_LAZY_ITEMS and PAN not in _json(out)
    assert counts["PAN"] == MAX_LAZY_ITEMS


def test_over_the_limit_fails_closed_with_an_event():
    events: list = []
    out, _ = scrub_obj({"rows": (PAN for _ in range(MAX_LAZY_ITEMS + 5))}, Vault(), "tokenize", _events=events)
    text = _json(out)
    assert PAN not in text
    assert isinstance(out["rows"], str) and out["rows"].startswith("[SANGOP_BLOCKED")
    assert events and events[0]["reason"] == "too_many_items" and events[0]["limit"] == MAX_LAZY_ITEMS


def test_nested_async_iterator_fails_closed_with_an_event():
    async def agen():
        yield PAN
    events: list = []
    out, _ = scrub_obj({"rows": agen()}, Vault(), "tokenize", _events=events)
    assert isinstance(out["rows"], str) and out["rows"].startswith("[SANGOP_BLOCKED")
    assert events and events[0]["reason"] == "async_iterable"
    assert PAN not in _json(out)


def test_a_failing_nested_iterator_fails_closed_with_an_event():
    def bad():
        yield PAN
        raise RuntimeError(f"db error near {PAN}")
    events: list = []
    out, _ = scrub_obj({"rows": bad()}, Vault(), "tokenize", _events=events)
    assert isinstance(out["rows"], str) and out["rows"].startswith("[SANGOP_BLOCKED")
    assert events and events[0]["reason"] == "error" and events[0]["error_type"] == "RuntimeError"
    assert PAN not in _json(out) and PAN not in json.dumps(events)


# ---- through @guard: result and ledger ----------------------------------------------------------------------------

def _events(name):
    return [r for r in sangop.get_ledger().tail(200) if r["event"] == name]


def test_guard_scrubs_nested_generators():
    @sangop.guard(purpose="t")
    def tool():
        return {"rows": ({"pan": PAN, "phone": PHONE} for _ in range(3)), "m": map(str, [PAN])}
    text = _json(tool())
    assert PAN not in text and PHONE not in text
    call = _events("tool_call")[0]["record"]                  # tail() is newest first
    assert call["pii_found"]["PAN"] == 4 and call["pii_found"]["PHONE_IN"] == 3
    assert call.get("lazy_iterables_read") == 2


def test_guard_logs_blocked_nested_iterables():
    async def agen():
        yield PAN

    @sangop.guard(purpose="t")
    def tool():
        return {"a": agen(), "b": (PAN for _ in range(MAX_LAZY_ITEMS + 1))}
    out = tool()
    assert PAN not in _json({"a": out["a"], "b": out["b"]})
    ev = [e["record"] for e in _events("nested_iterable_blocked")]
    assert {e["reason"] for e in ev} == {"async_iterable", "too_many_items"}
    assert all(e["tool"] == "tool" and PAN not in json.dumps(e) for e in ev)
    call = _events("tool_call")[0]["record"]
    assert call["nested_iterables_blocked"] == 2


def test_top_level_generator_behaviour_is_unchanged():
    """H3: a tool that returns an iterator still gets a lazy wrapper, item by item."""
    @sangop.guard(purpose="t")
    def tool():
        return iter([{"pan": PAN}, {"rows": (x for x in [PAN])}])
    res = tool()
    assert not isinstance(res, (list, dict))
    items = list(res)
    assert len(items) == 2 and PAN not in _json(items)


# ---- official MCP Python SDK server, in memory (raw PII must not reach the client) --------------------------------

def test_official_mcpserver_in_memory_end_to_end():
    pytest.importorskip("mcp.server.mcpserver")
    from mcp.client import Client
    from mcp.server.mcpserver import MCPServer

    srv = MCPServer("f1")

    @srv.tool()
    @sangop.guard(purpose="lookup")
    def rows() -> dict:
        """Rows with a nested generator."""
        return {"rows": ({"pan": PAN, "phone": PHONE} for _ in range(2)), "ids": map(str, [PAN])}

    async def go():
        async with Client(srv) as c:
            r = await c.call_tool("rows", {})
            parts = [getattr(x, "text", "") or "" for x in r.content]
            return "".join(parts) + json.dumps(getattr(r, "structured_content", None) or {}), r.is_error
    text, is_error = asyncio.run(go())
    assert not is_error, text
    assert PAN not in text and PHONE not in text
    assert "[PII_PAN_" in text


def test_object_with_dict_and_iter_but_no_len_comes_back_as_a_list():
    """Behaviour change from F1 (CHANGELOG, 26 Oct 2026): an object that has attributes (__dict__) and __iter__ but no
    __len__ is treated as a lazy iterable, so the caller gets a scrubbed list instead of the object."""
    class Obj:
        def __init__(self):
            self.name = "x"

        def __iter__(self):
            return iter([PAN, "ok"])

    out, counts = scrub_obj({"o": Obj()}, Vault(), "redact")
    assert isinstance(out["o"], list) and PAN not in out["o"] and "ok" in out["o"]
    assert counts["PAN"] == 1
