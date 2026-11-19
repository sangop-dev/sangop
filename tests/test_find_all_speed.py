"""find_all must stay roughly linear on long text with very many findings (it was O(n^2): ~9 s for 20,000 phones)."""
import sys
import time

import pytest

from sangop import find_all, scrub_text  # noqa: F401

# Windows CI and laptops are much slower; the Linux limit stays the real gate.
LIMIT_SECONDS = 1.5 * (3 if sys.platform == "win32" else 1)   # the old code needed ~9 s on this input


def _timed(text):
    t0 = time.perf_counter()
    found = find_all(text)
    return found, time.perf_counter() - t0


@pytest.mark.parametrize("unit,count", [
    ("x 9876543210 ", 20000),                 # plain mobile numbers
    ("x 9876 543210 ", 20000),                # grouped
    ("a@b.co ", 40000),                       # emails
    ("x 2345 6789 0124 ", 15000),             # Aadhaar-shaped groups (many fail the checksum; cost of trying)
])
def test_many_findings_are_fast(unit, count):
    text = unit * count
    assert len(text) >= 240_000
    found, secs = _timed(text)
    assert secs < LIMIT_SECONDS, f"{secs:.2f}s for {len(text)} chars"


def test_results_unchanged_on_small_input():
    text = "call 9876543210 or mail a@b.co; Aadhaar 2345 6789 0124?"
    kinds = [(f.kind, text[f.start:f.end]) for f in find_all(text)]
    assert ("PHONE_IN", "9876543210") in kinds and ("EMAIL", "a@b.co") in kinds


def test_overlap_resolution_is_deterministic_and_non_overlapping():
    text = "x 9876543210 y 98765 43210 z +91 98765 43210 w " * 2000
    found = find_all(text)
    assert all(a.end <= b.start for a, b in zip(found, found[1:]))
    assert found == find_all(text)
