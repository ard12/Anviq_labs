"""Semantic-cache threshold evaluation.

Runs the labelled pairs in `data/pairs.jsonl` through an embedder and the deterministic guards,
and reports precision / recall / false-hit rate at each candidate `tau_hit`, with and without
guards. This is the evidence behind the threshold recorded in `DECISIONS.md`, and the numbers
this script prints are what `EVAL_RESULTS.md` freezes for the interview.

Usage:
    python eval.py                       # from this directory
    python tasks.py eval-q2              # from the repo root (tasks.py already wires this up)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from semantic_cache import guards
from semantic_cache.embedders import Embedder, HashingEmbedder

ROOT = Path(__file__).resolve().parent
PAIRS_PATH = ROOT / "data" / "pairs.jsonl"
RESULTS_PATH = ROOT / "EVAL_RESULTS.md"

THRESHOLDS = [round(0.70 + 0.02 * i, 2) for i in range(15)]  # 0.70 .. 0.98 step 0.02
FALSE_HIT_TARGET = 0.05  # operating point must keep the WITH-GUARDS false-hit rate <= this


@dataclass(frozen=True, slots=True)
class Pair:
    a: str
    b: str
    same: bool
    category: str


def load_pairs(path: Path) -> list[Pair]:
    pairs = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            pairs.append(Pair(a=row["a"], b=row["b"], same=bool(row["same"]), category=row["category"]))
    return pairs


def build_embedder() -> tuple[Embedder, bool]:
    """Prefer a real sentence embedder ([local-embed] extra) when it's installed; fall back to
    the dependency-free HashingEmbedder otherwise. Returns (embedder, is_meaningful)."""
    try:
        from semantic_cache.embedders import LocalEmbedder

        return LocalEmbedder(), True
    except ImportError:
        return HashingEmbedder(dim=256), False


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    def false_hit_rate(self) -> float | None:
        """FP / (all actual-different pairs) -- the fraction of genuinely different questions
        that this operating point would have served a cached (wrong) answer to. This is the
        number the risk-bounding story is about, not accuracy."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else None


def evaluate(pairs: list[Pair], scores: list[float], threshold: float, *, use_guards: bool) -> Counts:
    counts = Counts()
    for pair, score in zip(pairs, scores, strict=True):
        predicted_same = score >= threshold
        if predicted_same and use_guards and guards.first_failure(pair.a, pair.b) is not None:
            predicted_same = False
        if predicted_same and pair.same:
            counts.tp += 1
        elif predicted_same and not pair.same:
            counts.fp += 1
        elif not predicted_same and pair.same:
            counts.fn += 1
        else:
            counts.tn += 1
    return counts


def fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def main() -> int:
    embedder, meaningful = build_embedder()
    if not meaningful:
        print(
            "WARNING: the [local-embed] extra (sentence-transformers) is not installed. Falling "
            "back to HashingEmbedder -- a bag-of-words hash, NOT a semantic embedder. The numbers "
            "below only prove the pipeline runs end to end; they do not reflect real embedding "
            "quality. Install with: pip install semantic_cache[local-embed]",
            file=sys.stderr,
        )

    pairs = load_pairs(PAIRS_PATH)
    n_pos = sum(1 for p in pairs if p.same)
    n_neg = len(pairs) - n_pos
    print(f"Loaded {len(pairs)} pairs ({n_pos} same, {n_neg} different) from {PAIRS_PATH.name}")
    print(f"Embedder: {embedder.model_id} (dim={embedder.dim}, meaningful={meaningful})")

    a_vectors = embedder.embed([p.a for p in pairs])
    b_vectors = embedder.embed([p.b for p in pairs])
    scores = [float(a_vectors[i] @ b_vectors[i]) for i in range(len(pairs))]

    rows = []
    for tau in THRESHOLDS:
        no_guard = evaluate(pairs, scores, tau, use_guards=False)
        with_guard = evaluate(pairs, scores, tau, use_guards=True)
        rows.append((tau, no_guard, with_guard))

    header = (
        "| tau_hit | precision (no guards) | recall (no guards) | false-hit rate (no guards) "
        "| precision (guards) | recall (guards) | false-hit rate (guards) |"
    )
    sep = "|---|---|---|---|---|---|---|"
    table_lines = [header, sep]
    for tau, ng, wg in rows:
        table_lines.append(
            f"| {tau:.2f} | {fmt(ng.precision())} | {fmt(ng.recall())} | {fmt(ng.false_hit_rate())} "
            f"| {fmt(wg.precision())} | {fmt(wg.recall())} | {fmt(wg.false_hit_rate())} |"
        )

    # Chosen operating point: the lowest tau (best recall) whose WITH-GUARDS false-hit rate is at
    # or below FALSE_HIT_TARGET. Guards, not the raw threshold alone, are what the risk-bounding
    # story leans on for precision -- see README.md "Risk-bounding story".
    chosen_tau: float | None = None
    chosen_counts: Counts | None = None
    for tau, _, wg in rows:
        fhr = wg.false_hit_rate()
        if fhr is not None and fhr <= FALSE_HIT_TARGET:
            chosen_tau, chosen_counts = tau, wg
            break

    if chosen_tau is None:
        chosen_tau, chosen_counts = rows[-1][0], rows[-1][2]
        note = (
            f"No threshold in the sweep reached a with-guards false-hit rate <= {FALSE_HIT_TARGET:.0%}; "
            f"falling back to the most conservative threshold tested (tau_hit = {chosen_tau:.2f}, "
            f"false-hit rate = {fmt(chosen_counts.false_hit_rate())}). With a non-meaningful embedder "
            "this is expected -- re-run with `[local-embed]` installed before trusting this number."
        )
    else:
        note = (
            f"Candidate operating point: tau_hit = {chosen_tau:.2f} "
            f"(precision={fmt(chosen_counts.precision())}, recall={fmt(chosen_counts.recall())}, "
            f"false-hit rate={fmt(chosen_counts.false_hit_rate())} over negative pairs, "
            f"target <= {FALSE_HIT_TARGET:.0%}). This candidate does not enable serving automatically: "
            "the library defaults to shadow mode; serving requires an explicit opt-in after representative "
            "traffic validation."
        )

    print()
    print(note)

    by_category: dict[str, list[float]] = {}
    same_by_category: dict[str, bool] = {}
    for pair, score in zip(pairs, scores, strict=True):
        by_category.setdefault(pair.category, []).append(score)
        same_by_category[pair.category] = pair.same
    category_lines = [
        "### Mean similarity score by category",
        "",
        "| category | n | same? | mean score |",
        "|---|---|---|---|",
    ]
    for category in sorted(by_category):
        cat_scores = by_category[category]
        category_lines.append(
            f"| {category} | {len(cat_scores)} | {same_by_category[category]} "
            f"| {sum(cat_scores) / len(cat_scores):.3f} |"
        )

    meaningful_warning = (
        ""
        if meaningful
        else (
            "\n> **These numbers are not meaningful.** They were produced with `HashingEmbedder`, "
            "a dependency-free bag-of-words hash used so this script (and `python tasks.py "
            "eval-q2`) runs with no network and no model download. Install the `[local-embed]` "
            "extra (`pip install semantic_cache[local-embed]`) and re-run for numbers that reflect "
            "real embedding quality.\n"
        )
    )

    report = "\n".join(
        [
            "# Q2 semantic cache -- threshold evaluation",
            "",
            f"Embedder: `{embedder.model_id}` (dim={embedder.dim}). {len(pairs)} labelled pairs "
            f"({n_pos} same / {n_neg} different) from `data/pairs.jsonl`.",
            meaningful_warning,
            "## Precision / recall / false-hit rate by threshold",
            "",
            *table_lines,
            "",
            note,
            "",
            *category_lines,
            "",
            "Regenerate with `python tasks.py eval-q2` (from the repo root) or `python eval.py` "
            "(from this directory).",
            "",
        ]
    )
    RESULTS_PATH.write_text(report, encoding="utf-8")
    print(f"\nWrote {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
