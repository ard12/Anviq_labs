# Q2 semantic cache -- threshold evaluation

Embedder: `all-MiniLM-L6-v2` (dim=384). 70 labelled pairs (20 same / 50 different) from `data/pairs.jsonl`.

## Precision / recall / false-hit rate by threshold

| tau_hit | precision (no guards) | recall (no guards) | false-hit rate (no guards) | precision (guards) | recall (guards) | false-hit rate (guards) |
|---|---|---|---|---|---|---|
| 0.70 | 0.36 | 1.00 | 0.70 | 0.61 | 0.85 | 0.22 |
| 0.72 | 0.38 | 1.00 | 0.66 | 0.61 | 0.85 | 0.22 |
| 0.74 | 0.41 | 1.00 | 0.58 | 0.68 | 0.85 | 0.16 |
| 0.76 | 0.43 | 1.00 | 0.52 | 0.74 | 0.85 | 0.12 |
| 0.78 | 0.44 | 1.00 | 0.50 | 0.77 | 0.85 | 0.10 |
| 0.80 | 0.45 | 1.00 | 0.48 | 0.81 | 0.85 | 0.08 |
| 0.82 | 0.48 | 1.00 | 0.44 | 0.81 | 0.85 | 0.08 |
| 0.84 | 0.46 | 0.95 | 0.44 | 0.80 | 0.80 | 0.08 |
| 0.86 | 0.45 | 0.90 | 0.44 | 0.79 | 0.75 | 0.08 |
| 0.88 | 0.44 | 0.80 | 0.40 | 0.81 | 0.65 | 0.06 |
| 0.90 | 0.37 | 0.55 | 0.38 | 0.75 | 0.45 | 0.06 |
| 0.92 | 0.25 | 0.25 | 0.30 | 0.75 | 0.15 | 0.02 |
| 0.94 | 0.19 | 0.15 | 0.26 | 0.50 | 0.05 | 0.02 |
| 0.96 | 0.00 | 0.00 | 0.20 | n/a | 0.00 | 0.00 |
| 0.98 | 0.00 | 0.00 | 0.10 | n/a | 0.00 | 0.00 |

Candidate operating point: tau_hit = 0.92 (precision=0.75, recall=0.15, false-hit rate=0.02 over negative pairs, target <= 5%). This candidate does not enable serving automatically: the library defaults to shadow mode; serving requires an explicit opt-in after representative traffic validation.

### Mean similarity score by category

| category | n | same? | mean score |
|---|---|---|---|
| entity_swap | 12 | False | 0.651 |
| negation | 10 | False | 0.966 |
| number_change | 12 | False | 0.896 |
| paraphrase | 20 | True | 0.902 |
| scope_change | 10 | False | 0.793 |
| unrelated | 6 | False | 0.081 |

Regenerate with `python tasks.py eval-q2` (from the repo root) or `python eval.py` (from this directory).
