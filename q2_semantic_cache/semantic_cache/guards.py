"""Deterministic guards.

Embeddings capture topical similarity well and small-but-decisive factual differences badly:
"top 5 startups" and "top 10 startups" sit a fraction of a cosine point apart, but they are
different questions with different correct answers. Guards are cheap, regex-based, and run
*after* the embedding score clears a threshold and *before* a hit is served -- they exist
specifically to catch the differences embeddings are known to blur. Every guard returns a
reason string on rejection so a :class:`~semantic_cache.types.Miss` (or a guard-rejection metric)
can say *why*, not just "no".

Each guard takes the candidate query and the stored (matched) query and returns ``None`` if the
pair passes, or a short human-readable reason if it doesn't. Guards are symmetric and
order-independent by construction.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

_NUMBER_RE = re.compile(r"\d[\d,]*\.?\d*")
_NEGATION_RE = re.compile(
    r"\b(not|never|no|none|nobody|nothing|neither|nor|without|except|cannot)\b|n't\b",
    re.IGNORECASE,
)
# Heuristic proper-noun matcher: a capitalized word not in the first position of the text (to
# avoid flagging every sentence-initial capital as an "entity"), and not a common capitalized
# pronoun/sentence-starter. Good enough to catch Austria/Australia, Python/Java; it is not a real
# NER model and is not trying to be -- see DECISIONS.md.
_WORD_RE = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?")
_PRONOUN_STOPWORDS = {"i", "i'm", "i've", "i'll", "i'd"}
_DIRECTION_WORDS = {
    "more",
    "less",
    "before",
    "after",
    "max",
    "maximum",
    "min",
    "minimum",
    "buy",
    "sell",
    "increase",
    "decrease",
    "greater",
    "smaller",
    "higher",
    "lower",
    "earliest",
    "latest",
    "oldest",
    "newest",
    "first",
    "last",
    "above",
    "below",
    "over",
    "under",
    "win",
    "lose",
    "gain",
}

GuardFn = Callable[[str, str], "str | None"]


def _numbers(text: str) -> set[str]:
    return {tok.replace(",", "") for tok in _NUMBER_RE.findall(text)}


def guard_numbers(a: str, b: str) -> str | None:
    """Numbers, dates, and quantities must match as sets. "top 5" != "top 10"; "2023" != "2024"."""
    na, nb = _numbers(a), _numbers(b)
    if na != nb:
        return f"number mismatch: {sorted(na)} vs {sorted(nb)}"
    return None


def _has_negation(text: str) -> bool:
    return _NEGATION_RE.search(text) is not None


def guard_negation(a: str, b: str) -> str | None:
    """Negation parity: one side saying "not"/"never"/"n't"/... and the other not is a different
    question, even when every other word matches. "Is X safe" != "is X not safe"."""
    if _has_negation(a) != _has_negation(b):
        return "negation present on only one side"
    return None


def _proper_nouns(text: str) -> set[str]:
    words = _WORD_RE.findall(text)
    out: set[str] = set()
    for i, word in enumerate(words):
        if i == 0:
            continue  # skip sentence-initial capitalization
        if word.lower().endswith("'s"):
            word = word[:-2]  # "Austria's" -> "Austria", so possessives don't create a false mismatch
        lower = word.lower()
        if lower in _PRONOUN_STOPWORDS:
            continue
        if word[0].isupper():
            out.add(word)
    return out


def guard_entities(a: str, b: str) -> str | None:
    """Capitalized-entity token sets must match. Austria != Australia; Python != Java."""
    ea, eb = _proper_nouns(a), _proper_nouns(b)
    if ea != eb:
        return f"entity mismatch: {sorted(ea)} vs {sorted(eb)}"
    return None


def _direction_words(text: str) -> set[str]:
    tokens = {w.lower() for w in _WORD_RE.findall(text)}
    return tokens & _DIRECTION_WORDS


def guard_direction(a: str, b: str) -> str | None:
    """Comparison/direction words must match as sets. "more" != "less"; "before" != "after"."""
    da, db = _direction_words(a), _direction_words(b)
    if da != db:
        return f"direction mismatch: {sorted(da)} vs {sorted(db)}"
    return None


@dataclass(frozen=True, slots=True)
class GuardResult:
    name: str
    passed: bool
    reason: str | None


# Registration order is also the order guards run in `first_failure` -- cheapest/most-decisive
# checks first is a nice property but not load-bearing; every guard always runs in `run_guards`.
GUARDS: list[tuple[str, GuardFn]] = [
    ("numbers", guard_numbers),
    ("negation", guard_negation),
    ("entities", guard_entities),
    ("direction", guard_direction),
]


def run_guards(a: str, b: str) -> list[GuardResult]:
    """Run every guard and return a result for each, pass or fail. Used by eval.py to report
    per-guard rejection rates."""
    return [GuardResult(name, (reason := fn(a, b)) is None, reason) for name, fn in GUARDS]


def first_failure(a: str, b: str) -> tuple[str, str] | None:
    """Return ``(guard_name, reason)`` for the first guard that rejects the pair, or ``None`` if
    all guards pass. Used on the cache's hot path, where we only need to know whether to reject
    and why -- not every guard's verdict."""
    for name, fn in GUARDS:
        reason = fn(a, b)
        if reason is not None:
            return name, reason
    return None
