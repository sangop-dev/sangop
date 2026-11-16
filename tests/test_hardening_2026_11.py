"""Pre-launch hardening (internal review 26 Oct and 5 Nov 2026: F3, F6, F7, F8, N2-enum, N2-pyd, Log-To-Leak).

Written test-first, synthetic values only. No detector or detection pattern is changed by these fixes (D-034).
"""
import asyncio
import enum
import json

import pytest
from conftest import EMAIL, PAN, PHONE

import sangop
from sangop import SangopBlocked


def _events(name=None):
    """Ledger records of one event type, oldest first (``tail`` returns the newest first)."""
    rows = sangop.get_ledger().tail(200)
    return [r["record"] for r in reversed(rows) if name is None or r["event"] == name]


# ---- F3: a SQL argument that gets real values back must be checked again ------------------------------------------

def test_f3_detokenized_sql_is_checked_again_and_blocked():
    """A revealed value can turn a checked query into one the guard would block (here: a second statement)."""
    tok = sangop.get_vault().token_for("SECRET_JWT", "x'; DROP TABLE users; --")
    called = []

    @sangop.guard(purpose="t", sql_param="query", detokenize_params=("query",), detokenize_kinds="*")
    def run(query: str) -> str:
        called.append(query)
        return "ran"

    with pytest.raises(SangopBlocked):
        run(f"SELECT name FROM people WHERE note = '{tok}' LIMIT 5")
    assert called == [], "the tool must never receive SQL that the guard did not check"
    blocked = [r for r in _events("tool_call") if r.get("outcome") == "blocked"]
    assert blocked and "DROP TABLE users" not in json.dumps(blocked)


def test_f3_ordinary_detokenized_sql_still_runs_with_the_real_value():
    tok = sangop.get_vault().token_for("EMAIL", EMAIL)
    got = []

    @sangop.guard(purpose="t", sql_param="query", detokenize_params=("query",), detokenize_kinds=("EMAIL",))
    def run(query: str) -> str:
        got.append(query)
        return "ok"

    assert run(f"SELECT id FROM people WHERE email = '{tok}' LIMIT 5") == "ok"
    assert EMAIL in got[0] and tok not in got[0]


# ---- F6: sql_param typo and non-str values --------------------------------------------------------------------

def test_f6_sql_param_typo_is_a_value_error_when_the_guard_is_made():
    with pytest.raises(ValueError, match="sql_param"):
        @sangop.guard(purpose="t", sql_param="qury")
        def run(query: str) -> str:
            return "x"


def test_f6_sql_param_through_kwargs_is_still_checked():
    @sangop.guard(purpose="t", sql_param="query")
    def run(**kw) -> str:
        return "ran"

    with pytest.raises(SangopBlocked):
        run(query="DROP TABLE users")
    assert run(query="SELECT id FROM t LIMIT 5") == "ran"


@pytest.mark.parametrize("value", [b"DROP TABLE users", bytearray(b"DROP TABLE users"), memoryview(b"DROP TABLE x"),
                                   ["DROP TABLE users"], {"q": "DROP TABLE users"}, 42])
def test_f6_non_str_sql_value_is_blocked(value):
    called = []

    @sangop.guard(purpose="t", sql_param="query")
    def run(query=None) -> str:
        called.append(query)
        return "ran"

    with pytest.raises(SangopBlocked, match="not a string"):
        run(query=value)
    assert called == []


# ---- R-1 (independent check of 11 Nov): None means "no SQL", as before F6 --------------------------------------

def test_r1_omitted_optional_sql_argument_runs():
    @sangop.guard("t", sql_param="where")
    def q(table, where: str | None = None):
        return f"rows of {table}"

    assert q("users") == "rows of users"
    rec = _events("tool_call")[-1]
    assert rec["outcome"] == "ok" and rec["sql"] == {"present": False, "note": "no SQL given (None)"}


def test_r1_explicit_none_runs():
    @sangop.guard("t", sql_param="where")
    def q(table, where=None):
        return "ok"

    assert q("users", None) == "ok" and q("users", where=None) == "ok"


def test_r1_kwargs_path_none_runs_and_bytes_block():
    @sangop.guard("t", sql_param="where")
    def q(**kw):
        return "ok"

    assert q() == "ok" and q(where=None) == "ok"
    with pytest.raises(SangopBlocked, match="not a string"):
        q(where=b"DROP TABLE users")


def test_r1_a_real_query_is_still_checked():
    @sangop.guard("t", sql_param="where")
    def q(table, where=None):
        return "ok"

    with pytest.raises(SangopBlocked):
        q("users", "1=1; DROP TABLE users")


def test_r1_none_after_detokenize_does_not_crash(monkeypatch):
    """F3 path: if detokenizing turned the SQL argument into None, the same rule applies (no SQL, no crash)."""
    import sys
    g = sys.modules["sangop.guard"]          # the module (the package exports the function under the same name)
    real = g.detokenize_obj
    monkeypatch.setattr(g, "detokenize_obj", lambda obj, *a, **k: None if isinstance(obj, str) else real(obj, *a, **k))
    tok = sangop.get_vault().token_for("EMAIL", EMAIL)

    @sangop.guard("t", sql_param="query", detokenize_params=("query",), detokenize_kinds=("EMAIL",))
    def run(query=None):
        return f"got {query!r}"

    assert run(f"SELECT id FROM t WHERE e = '{tok}' LIMIT 5") == "got None"


def test_f6_non_str_in_shadow_mode_is_logged_not_blocked():
    @sangop.guard(purpose="t", sql_param="query", sql_mode="shadow")
    def run(query) -> str:
        return "ran"

    assert run(b"DROP TABLE users") == "ran"
    rec = _events("tool_call")[-1]
    assert rec["sql"]["allowed"] is False and rec["sql"]["mode"] == "shadow"


# ---- F7: BaseException subclasses -------------------------------------------------------------------------------

class Halt(BaseException):
    pass


@pytest.mark.parametrize("exc_type", [Halt, KeyboardInterrupt, SystemExit])
def test_f7_base_exception_keeps_its_type_and_loses_the_pii(exc_type):
    @sangop.guard(purpose="t")
    def tool() -> str:
        raise exc_type(f"stopped while reading PAN {PAN} phone {PHONE}")

    with pytest.raises(exc_type) as info:
        tool()
    text = str(info.value) + repr(info.value.args)
    assert PAN not in text and PHONE not in text and "[PII_PAN_" in text
    assert info.value.__cause__ is None and info.value.__context__ is None
    assert _events("tool_call")[-1]["outcome"] == "error"


def test_f7_async_tool_and_cancelled_error():
    @sangop.guard(purpose="t")
    async def tool() -> str:
        raise asyncio.CancelledError(f"cancelled at PAN {PAN}")

    with pytest.raises(asyncio.CancelledError) as info:
        asyncio.run(tool())
    assert PAN not in str(info.value)


def test_f7_generator_tool_base_exception_and_normal_close():
    @sangop.guard(purpose="t")
    def gen():
        yield "first"
        raise Halt(f"PAN {PAN}")

    it = gen()
    assert next(it) == "first"
    with pytest.raises(Halt) as info:
        next(it)
    assert PAN not in str(info.value)

    @sangop.guard(purpose="t")
    def gen2():
        yield "a"
        yield "b"

    g = gen2()
    assert next(g) == "a"
    g.close()                                    # GeneratorExit must still work as a normal close


def test_f7_shadow_mode_reraises_the_original():
    @sangop.guard(purpose="t", pii_mode="shadow")
    def tool() -> str:
        raise Halt(f"PAN {PAN}")

    with pytest.raises(Halt) as info:
        tool()
    assert PAN in str(info.value)


def test_f7_exception_attributes_are_scrubbed_too():
    class HaltWith(BaseException):
        def __init__(self, detail):
            super().__init__("halted")
            self.detail = detail

        def __str__(self):
            return f"halted: {self.detail}"

    @sangop.guard(purpose="t")
    def tool() -> str:
        raise HaltWith(f"PAN {PAN}")

    with pytest.raises(HaltWith) as info:
        tool()
    assert PAN not in str(info.value) and PAN not in info.value.detail


def test_f7_an_attribute_that_cannot_be_set_is_dropped_not_kept_raw():
    """bandit B110 (16 Nov 2026): a read-only attribute used to keep its unscrubbed value in __dict__."""
    class HaltRO(BaseException):
        @property
        def detail(self):                       # no setter: setattr(exc, "detail", ...) raises
            return "fixed"

    @sangop.guard(purpose="t")
    def tool() -> str:
        e = HaltRO("halted")
        e.__dict__["detail"] = f"PAN {PAN}"
        raise e

    with pytest.raises(HaltRO) as info:
        tool()
    assert "detail" not in info.value.__dict__
    assert PAN not in repr(vars(info.value))


# ---- F8: memoryview -----------------------------------------------------------------------------------------------

def test_f8_memoryview_is_handled_like_bytes():
    @sangop.guard(purpose="t")
    def tool():
        return {"blob": memoryview(f"PAN {PAN}".encode())}

    out = tool()["blob"]
    assert isinstance(out, (bytes, bytearray)) and PAN.encode() not in out and b"[PII_PAN_" in out


def test_f8_clean_memoryview_is_not_turned_into_a_list_of_numbers():
    @sangop.guard(purpose="t")
    def tool():
        return memoryview(b"hello")

    out = tool()
    assert not isinstance(out, list) and bytes(out) == b"hello"


# ---- N2-enum: scrubbing must never change a shared object --------------------------------------------------------

class Color(enum.Enum):
    A = f"customer PAN {PAN}"
    B = "plain"


def test_n2_enum_member_is_not_changed_for_the_whole_process():
    @sangop.guard(purpose="t")
    def tool():
        return {"c": Color.A, "d": Color.B}

    out = tool()
    assert PAN not in json.dumps(out, default=str) and "[PII_PAN_" in str(out["c"])
    assert Color.A.value == f"customer PAN {PAN}"          # unchanged everywhere else
    assert out["d"] is Color.B


class Singleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.note = f"PAN {PAN}"
        return cls._instance

    def __copy__(self):
        return self


def test_n2_object_whose_copy_is_itself_is_not_changed():
    obj = Singleton()

    @sangop.guard(purpose="t")
    def tool():
        return obj

    out = tool()
    assert PAN not in repr(out) + json.dumps(out, default=str)
    assert Singleton().note == f"PAN {PAN}"


# ---- N2-pyd: a pydantic model is also checked in its JSON form --------------------------------------------------

def test_n2_pydantic_model_serializer_with_private_attr():
    pydantic = pytest.importorskip("pydantic")

    class Customer(pydantic.BaseModel):
        name: str
        _pan: str = pydantic.PrivateAttr(default="")

        @pydantic.model_serializer
        def ser(self):
            return {"name": self.name, "pan": self._pan}

    c = Customer(name="Asha")
    c._pan = PAN

    @sangop.guard(purpose="t")
    def tool():
        return c

    out = tool()
    dumped = out.model_dump(mode="json") if hasattr(out, "model_dump") else out
    assert PAN not in json.dumps(dumped, default=str)
    assert c._pan == PAN                                    # the caller's object is unchanged


def test_n2_clean_pydantic_model_stays_a_model():
    pydantic = pytest.importorskip("pydantic")

    class Item(pydantic.BaseModel):
        name: str

    @sangop.guard(purpose="t")
    def tool():
        return Item(name="pen")

    out = tool()
    assert isinstance(out, Item) and out.name == "pen"


# ---- Log-To-Leak: a second tool gets tokens, and every call is logged ---------------------------------------------

def test_log_to_leak_second_tool_gets_tokens_only():
    @sangop.guard(purpose="lookup")
    def get_customer() -> dict:
        return {"pan": PAN, "phone": PHONE, "email": EMAIL}

    seen = {}

    @sangop.guard(purpose="logging")
    def write_log(text: str) -> str:
        seen["log"] = text
        return "logged"

    @sangop.guard(purpose="mail", detokenize_params=("body",), detokenize_kinds=("EMAIL",))
    def send_mail(body: str) -> str:
        seen["mail"] = body
        return "sent"

    data = get_customer()
    write_log(json.dumps(data))                             # what an injected instruction would ask the model to do
    send_mail(json.dumps(data))
    assert PAN not in seen["log"] and PHONE not in seen["log"] and EMAIL not in seen["log"]
    assert EMAIL in seen["mail"] and PAN not in seen["mail"] and PHONE not in seen["mail"]
    tools = [r.get("tool") for r in _events("tool_call")]
    assert {"get_customer", "write_log", "send_mail"} <= set(tools)
    det = _events("detokenize")
    assert det and det[-1]["revealed"] == {"EMAIL": 1}
