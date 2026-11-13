"""Policy-pack loader: strict and fail-closed. Uses a toy pack built in a temp dir (synthetic)."""
import copy
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

import sangop  # noqa: E402
from sangop.policy import PolicyError, load_pack  # noqa: E402

DISC = "Engineering aid, not legal advice. Does not guarantee compliance."

RETENTION = {"schema_version": 1, "disclaimer": DISC, "pack": "toy", "version": "0.0", "reference": "toy reference",
             "statutory_minimum_days": 365, "audit_log_retention_days": 400}
PURPOSE = {"schema_version": 1, "disclaimer": DISC, "default": "deny", "illustrative": True,
           "purposes": {"billing": {"description": "invoices", "allowed_kinds": ["PAN", "GSTIN"]},
                        "debug": {"description": "no PII", "allowed_kinds": []}}}
SAFEGUARDS = {"schema_version": 1, "disclaimer": DISC, "safeguards": [
    {"id": "a", "reference": "r", "requirement": "x", "sangop_features": ["tokenizer"], "status": "partial", "limits": "l"},
    {"id": "b", "reference": "r", "requirement": "x", "sangop_features": [], "status": "not_provided", "limits": "l"}]}


def write_pack(tmp_path, retention=None, purpose=None, safeguards=None, name="pack"):
    d = tmp_path / name
    d.mkdir()
    for fname, data in (("retention.yaml", retention or RETENTION), ("purpose.yaml", purpose or PURPOSE),
                        ("safeguards.yaml", safeguards or SAFEGUARDS)):
        (d / fname).write_text(yaml.safe_dump(data), encoding="utf-8")
    return d


def mutated(base, fn):
    c = copy.deepcopy(base)
    fn(c)
    return c


def test_valid_pack_loads_and_answers(tmp_path):
    pack = load_pack(write_pack(tmp_path))
    assert pack.name == "toy" and pack.retention.audit_log_retention_days == 400
    assert pack.purpose.allowed_kinds("billing") == frozenset({"PAN", "GSTIN"})
    assert pack.purpose.disallowed("billing", {"PAN", "AADHAAR"}) == frozenset({"AADHAAR"})
    assert pack.safeguard("b").status == "not_provided"
    assert sangop.load_pack is load_pack


def test_unknown_purpose_is_default_deny(tmp_path):
    pack = load_pack(write_pack(tmp_path))
    assert pack.purpose.allowed_kinds("marketing") == frozenset()
    assert pack.purpose.disallowed("marketing", {"EMAIL"}) == frozenset({"EMAIL"})
    assert pack.purpose.allowed_kinds("debug") == frozenset()


def test_retention_boundary(tmp_path):
    pack = load_pack(write_pack(tmp_path))
    assert not pack.retention.may_erase(399.9) and pack.retention.may_erase(400)


@pytest.mark.parametrize("fname", ["retention.yaml", "purpose.yaml", "safeguards.yaml"])
def test_missing_file_fails_closed(tmp_path, fname):
    d = write_pack(tmp_path)
    (d / fname).unlink()
    with pytest.raises(PolicyError, match="missing policy file"):
        load_pack(d)


def test_missing_directory(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        load_pack(tmp_path / "nope")


@pytest.mark.parametrize("kw,fn,msg", [
    ("retention", lambda c: c.update(audit_log_retention_days=364), "below the legal floor"),
    ("retention", lambda c: c.update(statutory_minimum_days=30, audit_log_retention_days=30), "below 365"),
    ("retention", lambda c: c.update(audit_log_retention_days=True), "integer"),
    ("retention", lambda c: c.update(audit_log_retention_days="400"), "integer"),
    ("retention", lambda c: c.update(audit_log_retension_days=500), "unknown key"),
    ("retention", lambda c: c.pop("audit_log_retention_days"), "missing key"),
    ("retention", lambda c: c.update(schema_version=2), "schema_version"),
    ("retention", lambda c: c.update(disclaimer="all good"), "not legal advice"),
    ("retention", lambda c: c.pop("disclaimer"), "missing key"),
    ("purpose", lambda c: c.update(default="allow"), "default must be 'deny'"),
    ("purpose", lambda c: c.update(illustrative=False), "illustrative"),
    ("purpose", lambda c: c["purposes"]["billing"].update(allowed_kinds=["PAN", "SSN"]), "unknown PII kind"),
    ("purpose", lambda c: c["purposes"]["billing"].update(allowed_kinds="PAN"), "list of strings"),
    ("purpose", lambda c: c["purposes"]["billing"].update(allow_kinds=["PAN"]), "unknown key"),
    ("purpose", lambda c: c.update(purposes={}), "non-empty mapping"),
    ("safeguards", lambda c: c["safeguards"][0].update(status="great"), "status"),
    ("safeguards", lambda c: c["safeguards"][1].update(id="a"), "duplicate id"),
    ("safeguards", lambda c: c["safeguards"][0].update(sangop_features=[]), "needs at least one"),
    ("safeguards", lambda c: c["safeguards"][0].pop("limits"), "missing key"),
    ("safeguards", lambda c: c.update(safeguards=[]), "non-empty list"),
])
def test_invalid_values_are_rejected(tmp_path, kw, fn, msg):
    base = {"retention": RETENTION, "purpose": PURPOSE, "safeguards": SAFEGUARDS}
    args = {kw: mutated(base[kw], fn)}
    with pytest.raises(PolicyError, match=msg):
        load_pack(write_pack(tmp_path, **args))


@pytest.mark.parametrize("claim", ["We are DPDP Compliant", "100% secure", "guaranteed compliance", "Approved by the Board"])
def test_forbidden_claims_rejected_anywhere(tmp_path, claim):
    p = mutated(PURPOSE, lambda c: c["purposes"]["billing"].update(description=claim))
    with pytest.raises(PolicyError, match="forbidden claim"):
        load_pack(write_pack(tmp_path, purpose=p))
    s = mutated(SAFEGUARDS, lambda c: c["safeguards"][0].update(limits=claim))
    with pytest.raises(PolicyError, match="forbidden claim"):
        load_pack(write_pack(tmp_path, safeguards=s, name="p2"))


def test_broken_yaml_and_wrong_top_level(tmp_path):
    d = write_pack(tmp_path)
    (d / "retention.yaml").write_text("a: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_pack(d)
    (d / "retention.yaml").write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="mapping"):
        load_pack(d)


def test_yaml_cannot_execute_code(tmp_path):
    marker = tmp_path / "pwned"
    d = write_pack(tmp_path)
    evil = f"!!python/object/apply:pathlib.Path.touch [!!python/object/apply:pathlib.Path [{marker.as_posix()!r}]]\n"
    (d / "purpose.yaml").write_text(evil, encoding="utf-8")
    with pytest.raises(PolicyError):
        load_pack(d)
    assert not marker.exists()


def test_error_never_leaves_a_half_loaded_pack(tmp_path):
    bad = mutated(SAFEGUARDS, lambda c: c["safeguards"][1].update(status="nope"))
    with pytest.raises(PolicyError):
        load_pack(write_pack(tmp_path, safeguards=bad))


SHIPPED = Path(__file__).resolve().parent.parent / "policies" / "dpdp"


@pytest.mark.skipif(not SHIPPED.is_dir(), reason="DPDP pack is a Pro asset kept out of the public repo")
def test_shipped_dpdp_pack_loads_and_is_honest():
    pack = load_pack(SHIPPED)
    assert pack.retention.audit_log_retention_days >= 365
    ids = {s.id for s in pack.safeguards}
    assert {f"rule-6-1-{c}" for c in "abcdefg"} <= ids
    assert pack.safeguard("rule-6-1-d").status == "not_provided"
    assert pack.safeguard("rule-6-1-f").status == "not_provided"
    assert all(s.status != "provided" for s in pack.safeguards), "no safeguard may be claimed as fully provided"
    assert pack.purpose.allowed_kinds("developer_debugging") == frozenset()
    assert pack.purpose.allowed_kinds("not-a-purpose") == frozenset()


# ---- the open example pack that ships inside the package (D-032) ----------------------------------

def test_shipped_example_pack_loads_and_is_clearly_an_example():
    pack = load_pack(sangop.example_pack_path())
    assert pack.name == "example"
    assert "example only" in pack.disclaimer.lower() and "not legal advice" in pack.disclaimer.lower()
    assert pack.retention.audit_log_retention_days >= 365
    assert set(pack.purpose.purposes) == {"customer_support", "developer_debugging"}
    assert pack.purpose.allowed_kinds("customer_support") == frozenset({"EMAIL", "PHONE_IN"})
    assert pack.purpose.allowed_kinds("anything_else") == frozenset()          # default deny
    assert len(pack.safeguards) == 3
    assert pack.safeguard("example-breach-notice").status == "not_provided"    # says plainly what it does NOT do


def test_example_pack_files_are_marked_example_and_make_no_compliance_claims():
    for f in sangop.example_pack_path().glob("*.yaml"):
        text = f.read_text(encoding="utf-8")
        assert "EXAMPLE ONLY" in text, f.name
        low = text.lower()
        for bad in sangop.policy.FORBIDDEN_CLAIMS:
            assert bad not in low, (f.name, bad)


def test_example_pack_is_inside_the_wheel_layout():
    """It lives under src/sangop so hatch's wheel (packages=['src/sangop']) includes it."""
    assert sangop.example_pack_path().parent.name == "sangop"
