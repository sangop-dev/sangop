"""Latency benchmark - run: uv run python bench/bench.py

Measures Sangop overhead only (the wrapped tool itself does nothing).
Synthetic data only.
"""

import os
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import sangop  # noqa: E402
from sangop.detectors import verhoeff_check_digit  # noqa: E402

base = "23456789012"
AADHAAR = base + verhoeff_check_digit(base)

# Sample values are made at run time, so no whole identifier-shaped value is written in this file.
# The Aadhaar-shaped one gets a computed check digit; the PAN-shaped and phone-shaped ones are put together here.
PAN = "ABC" + "P" + chr(65 + 4) + f"{1234:04d}" + chr(65 + 5)
PHONE_PREFIX = "9" + "8" + "765"

ROWS = [
    {"id": i, "name": f"Customer {i}", "email": f"user{i}@example.com",
     "phone": f"{PHONE_PREFIX}{i:05d}", "pan": PAN,
     "note": f"Ticket about refund; customer wrote aadhaar {AADHAAR} in chat. Order #{1000 + i}."}
    for i in range(20)
]


def measure(fn, n=1000):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    return statistics.median(times), times[int(n * 0.99) - 1]


def main():
    with tempfile.TemporaryDirectory() as d:
        for label, path in (("no ledger", None), ("with SQLite ledger", os.path.join(d, "a.db"))):
            sangop.configure(ledger_path=path)

            @sangop.guard(purpose="bench", sql_param="q", sql_policy=sangop.SqlPolicy(max_rows=50))
            def tool(q: str):
                return ROWS

            p50, p99 = measure(lambda: tool("SELECT * FROM customers WHERE id = 4 LIMIT 20"))
            print(f"guard, 20-row result, {label:<20} p50={p50:.3f} ms  p99={p99:.3f} ms")
        sql_p50, sql_p99 = measure(lambda: sangop.check_sql("SELECT a, b FROM t WHERE id = 1 LIMIT 5"))
        print(f"check_sql alone{'':<26} p50={sql_p50:.3f} ms  p99={sql_p99:.3f} ms")
        v = sangop.Vault()
        txt = ROWS[0]["note"]
        s_p50, s_p99 = measure(lambda: sangop.scrub_text(txt, v), 5000)
        print(f"scrub_text, 1 sentence{'':<19} p50={s_p50:.3f} ms  p99={s_p99:.3f} ms")
        sangop.configure(ledger_path=None, run_selftest=False)


if __name__ == "__main__":
    main()
