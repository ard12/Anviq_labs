"""Compares a tool's description text between two recordings.

Layered, cheapest/most-certain check first (see module docstring in `patterns.py` for why the
first layer is regex, not a model):

1. normalize (whitespace/case/punctuation) -> identical means cosmetic-only, no finding.
2. rule layer -> SECURITY on patterns newly introduced in `after` (prompt injection, exfil,
   secrets/paths, cross-tool references, hidden text).
3. semantic change score (token Jaccard by default, or a pluggable `Embedder`) -> WARN
   `DESC_SEMANTIC_CHANGE` above the threshold, INFO `DESC_REWORDED` below it. A negation flip or
   a changed number/unit always forces WARN, regardless of the score. The reassuring INFO verdict
   is suppressed once layer 2 has flagged the same text (see `diff_description`).
4. an optional `Judge` for the grey band -- never invoked by `harness check` in CI by default,
   since an LLM call is neither deterministic nor network-free.
"""

from __future__ import annotations

import math
import re
import string
from collections.abc import Sequence
from typing import Protocol

from harness.diff.patterns import new_matches
from harness.diff.types import Finding

_WS_RE = re.compile(r"\s+")
_PUNCT_TABLE = str.maketrans("", "", string.punctuation)

_CATEGORY_RULE_IDS = {
    "instruction": "DESC_INJECTION_INSTRUCTION",
    "exfil": "DESC_EXFIL_PATTERN",
    "sensitive": "DESC_SENSITIVE_PATTERN",
    "hidden_text": "DESC_HIDDEN_TEXT",
}

NEGATION_WORDS = frozenset({"not", "no", "never", "cannot", "cant", "without", "except", "only"})
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?\s*[a-zA-Z%]*")

DEFAULT_SEMANTIC_THRESHOLD = 0.5
# A score within this margin of the threshold is "grey band" territory for the optional Judge.
GREY_BAND = 0.1


def normalize(text: str) -> str:
    """Whitespace/case/punctuation normalization. Two descriptions that normalize equal are
    treated as a purely cosmetic diff (e.g. added a trailing period, re-cased a word)."""
    t = text.strip().lower().translate(_PUNCT_TABLE)
    return _WS_RE.sub(" ", t).strip()


def _tokens(text: str) -> set[str]:
    return set(normalize(text).split())


def jaccard_similarity(before: str, after: str) -> float:
    a, b = _tokens(before), _tokens(after)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class Embedder(Protocol):
    """Minimal embedding protocol. Deliberately not imported from q2_semantic_cache -- that is a
    different, parallel work package; this is its own small contract, `[embed]` extra only."""

    def embed(self, text: str) -> Sequence[float]: ...


class Judge(Protocol):
    """Optional LLM judge for descriptions that land in the semantic grey band. Not called by
    `harness check` in CI by default -- see DECISIONS.md ("LLM judge off by default in CI")."""

    def judge(self, tool: str, before: str, after: str) -> Finding | None: ...


def _negation_flipped(before: str, after: str) -> bool:
    return (_tokens(before) & NEGATION_WORDS) != (_tokens(after) & NEGATION_WORDS)


def _numbers_changed(before: str, after: str) -> bool:
    return set(_NUMBER_RE.findall(normalize(before))) != set(_NUMBER_RE.findall(normalize(after)))


def diff_description(
    tool: str,
    before: str,
    after: str,
    *,
    other_tool_names: frozenset[str] = frozenset(),
    embedder: Embedder | None = None,
    judge: Judge | None = None,
    semantic_threshold: float = DEFAULT_SEMANTIC_THRESHOLD,
) -> list[Finding]:
    before = before or ""
    after = after or ""
    if normalize(before) == normalize(after):
        return []

    findings: list[Finding] = []

    for match in new_matches(before, after, other_tool_names=other_tool_names):
        if match.category.startswith("cross_tool:"):
            rule_id = "DESC_CROSS_TOOL_REFERENCE"
            other = match.category.split(":", 1)[1]
            message = (
                f"description now mentions another tool ({other!r}) it did not mention before "
                "-- possible cross-tool shadowing"
            )
        else:
            rule_id = _CATEGORY_RULE_IDS[match.category]
            kind = match.category.replace("_", " ")
            message = f"description gained new {kind} content not present before: {match.snippet!r}"
        findings.append(
            Finding(
                severity="SECURITY",
                rule_id=rule_id,
                tool=tool,
                path="/description",
                message=message,
                before=before,
                after=after,
            )
        )

    # Did layer 2 already flag this text? A rug-pull usually appends a sentence, which leaves
    # similarity high -- so the score alone would report "meaning looks the same" directly beneath
    # an exfiltration finding about the same string. That reads as the tool contradicting itself,
    # and buries the finding that matters. A corroborating WARN is still worth printing; a
    # reassuring INFO is not, because similarity here only says "few tokens changed".
    flagged_by_rules = bool(findings)

    if embedder is not None:
        score = _cosine(embedder.embed(before), embedder.embed(after))
        method = "embedding cosine similarity"
    else:
        score = jaccard_similarity(before, after)
        method = "token Jaccard similarity"

    forced = _negation_flipped(before, after) or _numbers_changed(before, after)
    if forced or score < semantic_threshold:
        why = []
        if _negation_flipped(before, after):
            why.append("a negation word was added or removed")
        if _numbers_changed(before, after):
            why.append("a number or unit changed")
        if not why:
            why.append(f"{method}={score:.2f} is below the {semantic_threshold} threshold")
        findings.append(
            Finding(
                severity="WARN",
                rule_id="DESC_SEMANTIC_CHANGE",
                tool=tool,
                path="/description",
                message=f"description meaning likely changed ({'; '.join(why)})",
                before=before,
                after=after,
            )
        )
    elif not flagged_by_rules:
        findings.append(
            Finding(
                severity="INFO",
                rule_id="DESC_REWORDED",
                tool=tool,
                path="/description",
                message=f"description text changed but meaning looks the same ({method}={score:.2f})",
                before=before,
                after=after,
            )
        )

    if judge is not None and abs(score - semantic_threshold) <= GREY_BAND:
        judged = judge.judge(tool, before, after)
        if judged is not None:
            findings.append(judged)

    return findings


__all__ = ["DEFAULT_SEMANTIC_THRESHOLD", "Embedder", "Judge", "diff_description", "jaccard_similarity", "normalize"]
