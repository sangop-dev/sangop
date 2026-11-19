"""Rules plugins: how an installed package adds or replaces detection rules.

The open core ships a basic rule set (``sangop.detectors.BASIC_DETECTORS``). A separately installed package can
provide another rule set through the entry-point group ``sangop.plugins``::

    # pyproject.toml of the plugin package
    [project.entry-points."sangop.plugins"]
    myrules = "my_package.plugin:register"

``register(api)`` receives a :class:`PluginAPI`. Plugins are loaded on first use (the first ``find_all``,
``configure``, ``guard`` or ``selftest``), not at import time.

Fail-closed rules:

* No plugin installed: the basic rule set is used, and ``selftest()`` reports ``"rules": "basic"``.
* A plugin is installed but fails to load or register: every later call that needs the rules raises
  ``RuntimeError``. Sangop never falls back silently to weaker rules than the ones installed.
* A ``configure(...)`` keyword that no installed plugin accepts raises ``TypeError``.

There is deliberately no environment variable or setting that switches installed plugins off. Any installed package
can register a plugin, so install only plugins you trust (the same as for any Python package).
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import detectors as _det

ENTRY_POINT_GROUP = "sangop.plugins"

_STATE: Dict[str, Any] = {"loaded": False, "loading": False, "error": None, "plugins": []}
# Re-entrant: the thread that is loading may call back into Sangop (e.g. a plugin that runs find_all while it
# registers) without deadlocking, while every OTHER thread waits until loading has finished. Without the lock a second
# thread could run with the basic rules while the first was still loading the installed ones (review, 5 Nov 2026).
_LOCK = threading.RLock()
_CONFIGURE_HOOKS: List[Tuple[frozenset, Callable[[dict, Callable[[str, dict], None]], None]]] = []
_KINDS_FILTERS: List[Callable[[Optional[tuple]], Optional[tuple]]] = []
_RECORD_HOOKS: List[Callable[[dict], None]] = []


class PluginAPI:
    """What a plugin's ``register(api)`` may do. Everything here is optional."""

    def __init__(self, plugin_name: str) -> None:
        self.plugin_name = plugin_name

    def set_detectors(self, source: _det.DetectorSource, *, name: str, version: str = "",
                      digit_run=None) -> None:
        """Replace the active rule set. ``source`` is a tuple of ``Detector`` or a zero-argument callable that
        returns the current tuple (so a plugin can switch its own options). ``digit_run`` is the cheap pre-check
        pattern for detectors with ``needs_digit=True`` (default: the basic ``[0-9]{4}``). At most one plugin may
        replace the rule set."""
        if _det._RULES["name"] != "basic":
            raise RuntimeError(f"plugin {self.plugin_name!r} tried to replace the rule set "
                               f"{_det._RULES['name']!r}; at most one rules plugin can replace the rule set")
        if not name or name == "basic":
            raise ValueError("a plugin rule set needs its own name")
        _det._install(source, name, version, digit_run if digit_run is not None else _det._BASIC_DIGIT_RUN)

    def add_configure_hook(self, keys: Iterable[str], hook: Callable[[dict, Callable[[str, dict], None]], None]) -> None:
        """``hook(options, log)`` runs on every ``configure()`` call with the subset of ``keys`` that the caller
        passed (an empty dict when none were passed, so the plugin can apply its defaults)."""
        _CONFIGURE_HOOKS.append((frozenset(keys), hook))

    def add_kinds_filter(self, fn: Callable[[Optional[tuple]], Optional[tuple]]) -> None:
        """``fn(kinds)`` -> kinds, applied to every guarded call's ``kinds`` filter (None = all kinds)."""
        _KINDS_FILTERS.append(fn)

    def add_call_record_hook(self, fn: Callable[[dict], None]) -> None:
        """``fn(record)`` may add fields to every ``tool_call`` ledger record (never raw values)."""
        _RECORD_HOOKS.append(fn)

    def log(self, event: str, data: dict) -> None:
        from .guard import _log
        _log(event, data)


def _reset() -> None:
    _det._install_basic()
    _CONFIGURE_HOOKS.clear()
    _KINDS_FILTERS.clear()
    _RECORD_HOOKS.clear()
    _STATE["plugins"] = []


def _discover() -> Sequence[Tuple[str, Any]]:
    from importlib.metadata import entry_points
    eps = entry_points(group=ENTRY_POINT_GROUP)
    return sorted(((ep.name, ep) for ep in eps), key=lambda x: x[0])


def _load(found: Sequence[Tuple[str, Any]]) -> None:
    _reset()
    _STATE.update(loading=True, error=None)
    try:
        for name, ep in found:
            try:
                register = ep.load() if hasattr(ep, "load") else ep
                register(PluginAPI(name))
                _STATE["plugins"].append(name)
            except Exception as exc:  # noqa: BLE001 - any failure must stop the rules, not weaken them
                _reset()
                _STATE["error"] = f"Sangop rules plugin {name!r} failed to load ({type(exc).__name__}: {exc})"
                raise RuntimeError(_STATE["error"] + "; refusing to run with weaker rules than the ones installed") from exc
        _STATE["loaded"] = True
    finally:
        _STATE["loading"] = False


def ensure_loaded() -> None:
    if _STATE["loaded"]:                       # fast path once loaded (no lock needed: only ever goes False -> True)
        return
    with _LOCK:
        if _STATE["loaded"] or _STATE["loading"]:      # "loading" here can only be this same thread (re-entry)
            return
        if _STATE["error"]:
            raise RuntimeError(_STATE["error"] + "; refusing to run with weaker rules than the ones installed")
        _load(_discover())


def _load_for_tests(found: Optional[Sequence[Tuple[str, Any]]]) -> None:
    """Tests only: load exactly ``found`` (pairs of name and ``register`` callable), or rediscover the installed
    plugins when ``found`` is None. Not a setting: there is no way to switch installed plugins off in production."""
    with _LOCK:
        _STATE.update(loaded=False, error=None)
        if found is None:
            try:
                ensure_loaded()
            except RuntimeError:
                pass
            return
        try:
            _load(found)
        except RuntimeError:
            pass


def loaded_plugins() -> List[str]:
    ensure_loaded()
    return list(_STATE["plugins"])


# ---- used by sangop.guard ----

def accepted_configure_keys() -> frozenset:
    ensure_loaded()
    keys: frozenset = frozenset()
    for k, _ in _CONFIGURE_HOOKS:
        keys |= k
    return keys


def run_configure_hooks(options: dict, log: Callable[[str, dict], None]) -> None:
    for keys, hook in _CONFIGURE_HOOKS:
        hook({k: v for k, v in options.items() if k in keys}, log)


def filter_kinds(kinds: Optional[tuple]) -> Optional[tuple]:
    for fn in _KINDS_FILTERS:
        kinds = fn(kinds)
    return kinds


def apply_record_hooks(record: dict) -> None:
    for fn in _RECORD_HOOKS:
        fn(record)
