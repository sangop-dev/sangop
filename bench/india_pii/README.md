# India-PII benchmark: format, method and fingerprints

This folder holds the **scorer** and the **sha256 fingerprints** of our India-PII benchmark sets. The sets themselves
are kept private: their values are synthetic but checksum-valid, so a generated Aadhaar or card number could belong
to a real person by chance, and we do not publish such lists. You can measure any detector, Sangop or another tool,
on **your own** data in the same format with `score.py`.

## File format (JSONL, one example per line)

```json
{"id": "ex-00001", "lang": "en", "style": "prose",
 "text": "Customer KYC: Aadhaar <12 digits> and PAN <10 characters> were verified on 15-10-2025.",
 "spans":  [{"start": 22, "end": 36, "kind": "AADHAAR"}, {"start": 45, "end": 55, "kind": "PAN"}],
 "decoys": [{"start": 73, "end": 83, "like": "DATE"}]}
```

- `id`: unique string. `text`: the example. `lang` and `style`: free labels (`score.py --style X` scores one slice).
- `spans`: the **gold** values, character offsets into `text` (end exclusive) and a kind from
  `AADHAAR PAN GSTIN PHONE_IN EMAIL CARD IFSC UPI SECRET` (sets may also contain kinds no detector here finds, such as
  names or addresses; they count as misses).
- `decoys`: look-alikes that are **not** personal data (dates, amounts, order numbers ...); `like` names what they
  resemble. A prediction that overlaps a decoy is reported in a separate table.

A predictions file for another tool: `{"id": "...", "spans": [{"start": 0, "end": 12, "kind": "AADHAAR"}]}` per line.

```bash
python bench/india_pii/score.py --detector sangop --data my_gold.jsonl
python bench/india_pii/score.py --pred my_tool_predictions.jsonl --data my_gold.jsonl --json out.json
```

## How we measure

- **Strict matching:** a prediction is correct only if the kind **and** the exact start and end match a gold span.
  A wrong kind on a gold span costs one false positive and one false negative. A **lenient** view (same kind,
  overlap of at least half the shorter span) and a **protection view** (was the gold value covered by any mask at
  all) are shown as extra tables, never instead of the strict numbers.
- **Micro-average** over all gold spans of a set.
- **Holdout rule:** a holdout set is only *scored* until its misses are looked at; after that it becomes a
  development set, and the next detector change needs a new holdout. The README says which sets are development sets.
- Every number in the README is produced by running `score.py`, never estimated.

## Fingerprints of the private sets (sha256)

These prove that the sets behind the published numbers have not been changed later. Each `.sha256` file in this
folder holds one line:

| Set | sha256 |
|---|---|
| main dataset (`dataset_v0_1.jsonl`, 2,400 examples) | `c12a2ff41a9c12861e3ea14bc70b57cfed9497d4f8365e2025241e217a44ba54` |
| holdout 1 (`holdout_v0_1.jsonl`) | `577f00811c00d2ddc671dd480e9a3baa5a5fd9f597f7d9bf24b911b99e536bb1` |
| holdout 2 (`holdout2_v0_1.jsonl`) | `61e5a629ddc0375d3f66c2ec782aeebbf8fbb401a7b0b92c09a0f0e66734bd82` |
| holdout 3 (`holdout3_v0_1.jsonl`) | `d84c3c3aed100d0104eb81d4fc2f162108680dd98648f7f7cafa1a5b55d12791` |
| holdout 4 (`holdout4_v0_1.jsonl`) | `d5556eb9e13e7797d5c73d12893ae793f4debd249ab7233cf4b9bd2bcb45fc0a` |
| holdout 5 (`holdout5_v0_1.jsonl`) | `f6a9278e684bab92fcfcce54876028be92418d67c75a33b1d156c892b0b76a5b` |
| holdout 6 (`holdout6_v0_1.jsonl`) | `15f332cbd7bde358489a999119b8ee1f0b10bb6f86252f66c5002d6713407631` |
| holdout 7 (`holdout7_v0_1.jsonl`) | `5f2a21bf1833e577db48a5d581fc52322c9e8b9b150613c147ca4bc747a0b1c0` |

## Results

Both tables (Sangop open core, Sangop Pro) are in the main README under "Accuracy". The benchmark is authored by
this project and its generator knows the checksum rules, so treat it as a regression and comparison aid, not a
promise about your data.

Measured on a synthetic dataset authored by this project; real-world results will differ.
