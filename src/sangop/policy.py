"""Policy packs: small, strict, fail-closed YAML files that describe what a deployment allows.

A pack is a directory with three files:

    retention.yaml   how long audit logs must be kept (floor from DPDP Rules 2025, rules 6(1)(e) and 8(3))
    purpose.yaml     purpose -> PII kinds that purpose may see (default: deny)
    safeguards.yaml  which DPDP safeguard each Sangop feature helps with, and where it does NOT

Design rules
* Fail closed: any problem (missing file, unknown key, wrong type, unknown PII kind, retention below
  the legal floor, missing disclaimer, forbidden marketing claim) raises ``PolicyError``. A broken
  pack never silently turns into "allow everything".
* Only ``yaml.safe_load`` is used; nothing is executed.
* No network, no telemetry.

Engineering aid only. Not legal advice. Not a compliance guarantee. The shipped example values
are illustrative: your lawyer decides your real purposes and retention.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Tuple, Union

from .detectors import known_kinds


class PolicyError(ValueError):
    """The policy pack is invalid. Never continue as if it were valid."""


# Phrases a pack may not contain: they would be false claims (see README, Known limits).
FORBIDDEN_CLAIMS = (  # prepublish-allow
    "dpdp compliant", "fully compliant",  # prepublish-allow
    "100% secure", "100% safe",  # prepublish-allow
    "guaranteed compliance", "certified",  # prepublish-allow
    "consent manager", "approved by",  # prepublish-allow
)
STATUSES = ("provided", "partial", "not_provided")
SCHEMA_VERSION = 1
LEGAL_MIN_LOG_DAYS = 365  # DPDP Rules 2025, rule 6(1)(e) and rule 8(3): at least one year


def _yaml():
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only without PyYAML
        raise PolicyError("PyYAML is required to load policy packs: pip install 'sangop[policy]'") from exc
    return yaml


def _read(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise PolicyError(f"missing policy file: {path.name}")
    try:
        data = _yaml().safe_load(path.read_text(encoding="utf-8"))
    except PolicyError:
        raise
    except Exception as exc:
        raise PolicyError(f"{path.name}: not valid YAML ({type(exc).__name__})") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{path.name}: top level must be a mapping")
    return data


def _only_keys(d: Mapping[str, Any], required: Tuple[str, ...], optional: Tuple[str, ...], where: str) -> None:
    missing = [k for k in required if k not in d]
    if missing:
        raise PolicyError(f"{where}: missing key(s) {missing}")
    unknown = [k for k in d if k not in required and k not in optional]
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {unknown} (typo? unknown keys are rejected)")


def _str(v: Any, where: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise PolicyError(f"{where}: must be a non-empty string")
    return v


def _scan_claims(obj: Any, where: str) -> None:
    if isinstance(obj, str):
        low = obj.lower()
        for bad in FORBIDDEN_CLAIMS:
            if bad in low:
                raise PolicyError(f"{where}: contains forbidden claim wording {bad!r}")
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            _scan_claims(k, where)
            _scan_claims(v, where)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _scan_claims(v, where)


def _check_common(d: Mapping[str, Any], fname: str) -> None:
    if d.get("schema_version") != SCHEMA_VERSION:
        raise PolicyError(f"{fname}: schema_version must be {SCHEMA_VERSION}")
    disc = _str(d.get("disclaimer"), f"{fname}: disclaimer")
    if "not legal advice" not in disc.lower():
        raise PolicyError(f"{fname}: disclaimer must say 'not legal advice'")
    _scan_claims(d, fname)


@dataclass(frozen=True)
class RetentionPolicy:
    audit_log_retention_days: int
    reference: str

    def may_erase(self, age_days: float) -> bool:
        """True only when an audit-log entry is old enough to be erased under this policy.

        (Another law may still require longer retention: that is outside this check.)"""
        return age_days >= self.audit_log_retention_days


@dataclass(frozen=True)
class PurposePolicy:
    purposes: Mapping[str, FrozenSet[str]]

    def allowed_kinds(self, purpose: str) -> FrozenSet[str]:
        """PII kinds this purpose may see. Unknown purpose -> empty set (default deny)."""
        return self.purposes.get(purpose, frozenset())

    def disallowed(self, purpose: str, kinds) -> FrozenSet[str]:
        """Subset of ``kinds`` that ``purpose`` is NOT allowed to see."""
        return frozenset(kinds) - self.allowed_kinds(purpose)


@dataclass(frozen=True)
class Safeguard:
    id: str
    reference: str
    requirement: str
    sangop_features: Tuple[str, ...]
    status: str
    limits: str


@dataclass(frozen=True)
class PolicyPack:
    name: str
    version: str
    disclaimer: str
    retention: RetentionPolicy
    purpose: PurposePolicy
    safeguards: Tuple[Safeguard, ...]

    def safeguard(self, sid: str) -> Safeguard:
        for s in self.safeguards:
            if s.id == sid:
                return s
        raise KeyError(sid)


def _load_retention(path: Path) -> Tuple[RetentionPolicy, Dict[str, Any]]:
    d = _read(path)
    _only_keys(d, ("schema_version", "disclaimer", "pack", "version", "reference", "statutory_minimum_days",
                   "audit_log_retention_days"), ("notes",), path.name)
    _check_common(d, path.name)
    floor, days = d["statutory_minimum_days"], d["audit_log_retention_days"]
    for k, v in (("statutory_minimum_days", floor), ("audit_log_retention_days", days)):
        if isinstance(v, bool) or not isinstance(v, int):
            raise PolicyError(f"{path.name}: {k} must be an integer number of days")
    if floor < LEGAL_MIN_LOG_DAYS:
        raise PolicyError(f"{path.name}: statutory_minimum_days below {LEGAL_MIN_LOG_DAYS}")
    if days < floor:
        raise PolicyError(f"{path.name}: audit_log_retention_days ({days}) is below the legal floor ({floor})")
    return RetentionPolicy(days, _str(d["reference"], f"{path.name}: reference")), d


def _load_purpose(path: Path) -> PurposePolicy:
    d = _read(path)
    _only_keys(d, ("schema_version", "disclaimer", "default", "illustrative", "purposes"), ("notes",), path.name)
    _check_common(d, path.name)
    if d["default"] != "deny":
        raise PolicyError(f"{path.name}: default must be 'deny' (anything else is not supported)")
    if d["illustrative"] is not True:
        raise PolicyError(f"{path.name}: illustrative must be true: purposes must come from your own notice")
    raw = d["purposes"]
    if not isinstance(raw, dict) or not raw:
        raise PolicyError(f"{path.name}: purposes must be a non-empty mapping")
    out: Dict[str, FrozenSet[str]] = {}
    for name, spec in raw.items():
        where = f"{path.name}: purposes.{name}"
        if not isinstance(name, str) or not name.strip():
            raise PolicyError(f"{path.name}: purpose names must be non-empty strings")
        if not isinstance(spec, dict):
            raise PolicyError(f"{where}: must be a mapping")
        _only_keys(spec, ("description", "allowed_kinds"), (), where)
        _str(spec["description"], f"{where}.description")
        kinds = spec["allowed_kinds"]
        if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
            raise PolicyError(f"{where}.allowed_kinds: must be a list of strings")
        known = known_kinds()
        bad = sorted(k for k in kinds if k not in known)
        if bad:
            raise PolicyError(f"{where}.allowed_kinds: unknown PII kind(s) {bad}")
        out[name] = frozenset(kinds)
    return PurposePolicy(out)


def _load_safeguards(path: Path) -> Tuple[Safeguard, ...]:
    d = _read(path)
    _only_keys(d, ("schema_version", "disclaimer", "safeguards"), ("notes",), path.name)
    _check_common(d, path.name)
    raw = d["safeguards"]
    if not isinstance(raw, list) or not raw:
        raise PolicyError(f"{path.name}: safeguards must be a non-empty list")
    seen, out = set(), []
    for i, item in enumerate(raw):
        where = f"{path.name}: safeguards[{i}]"
        if not isinstance(item, dict):
            raise PolicyError(f"{where}: must be a mapping")
        _only_keys(item, ("id", "reference", "requirement", "sangop_features", "status", "limits"), (), where)
        sid = _str(item["id"], f"{where}.id")
        if sid in seen:
            raise PolicyError(f"{where}: duplicate id {sid!r}")
        seen.add(sid)
        if item["status"] not in STATUSES:
            raise PolicyError(f"{where}.status: must be one of {STATUSES}")
        feats = item["sangop_features"]
        if not isinstance(feats, list) or not all(isinstance(f, str) and f.strip() for f in feats):
            raise PolicyError(f"{where}.sangop_features: must be a list of strings")
        if item["status"] != "not_provided" and not feats:
            raise PolicyError(f"{where}: status {item['status']!r} needs at least one sangop_features entry")
        out.append(Safeguard(sid, _str(item["reference"], f"{where}.reference"),
                             _str(item["requirement"], f"{where}.requirement"), tuple(feats), item["status"],
                             _str(item["limits"], f"{where}.limits")))
    return tuple(out)


def example_pack_path() -> Path:
    """Directory of the small EXAMPLE pack that ships with Sangop (one retention value, two purposes,
    three safeguard entries; all marked as examples and not legal advice).

    It exists so developers can try ``load_pack`` immediately. It is not the full DPDP pack."""
    return Path(__file__).resolve().parent / "example_policy"


def load_pack(directory: Union[str, Path]) -> PolicyPack:
    """Load and validate a policy pack. Raises ``PolicyError`` on any problem (fail closed)."""
    base = Path(directory)
    if not base.is_dir():
        raise PolicyError(f"policy pack directory not found: {base}")
    retention, rd = _load_retention(base / "retention.yaml")
    purpose = _load_purpose(base / "purpose.yaml")
    safeguards = _load_safeguards(base / "safeguards.yaml")
    return PolicyPack(name=_str(rd["pack"], "retention.yaml: pack"), version=_str(str(rd["version"]), "retention.yaml: version"),
                      disclaimer=rd["disclaimer"], retention=retention, purpose=purpose, safeguards=safeguards)
