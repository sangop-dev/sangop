"""Write guarded calls to a keyed audit ledger, then verify its hash chain. Invented values only.
Run: python examples/ledger_verify.py   (in real use keep the key in SANGOP_LEDGER_KEY, outside the ledger)"""
import os, secrets, tempfile

import sangop

key = secrets.token_urlsafe(32).encode()          # demo key; `sangop keygen` prints one for real use
sangop.configure(ledger_path=os.path.join(tempfile.mkdtemp(), "audit.db"), ledger_key=key)

@sangop.guard(purpose="notes")
def read_note(note_id: int) -> str:
    return f"note {note_id}: customer with Aadhaar 999941057058 called about a refund"   # UIDAI's published test UID

print(read_note(1))
report = sangop.get_ledger().verify_report()
print("ledger OK:", report["ok"], "|", report["mode"], "|", report["rows"], "rows |", report["message"])
