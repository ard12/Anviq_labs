"""Shared pattern library for spotting prompt-injection / exfiltration text.

Used by both `description_diff.py` (a tool's own description drifting toward something
malicious) and `behavior_diff.py` (a tool's *responses* starting to carry the same kind of
text -- an equally valid rug-pull vector: the description stays clean but the tool starts
returning "ignore previous instructions..." in its result payloads).

Deliberately regex-based and deterministic rather than model-based: this is the layer that
runs in CI with no network and no flakiness. See DECISIONS.md ("rule layer before embeddings").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

URL_RE = r"\bhttps?://[^\s\"'<>]+"
EMAIL_RE = r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"
IPV4_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

_INSTRUCTION_RES = [
    r"\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\b",
    r"\bdo\s+not\s+tell\s+the\s+user\b",
    r"\bnever\s+(mention|tell|reveal)\b",
    r"\bbefore\s+using\s+this\s+tool\b",
    r"<\s*(important|system|instructions?)\s*>",
    r"\bdisregard\s+(all\s+|any\s+|the\s+)?(previous|prior)\b",
]

_EXFIL_RES = [
    # Gaps allow "." (e.g. a path like ~/.ssh/id_rsa or a filename) but are capped in length so
    # the match can't wander across an unrelated later sentence.
    r"\b(send|forward|upload|include|copy|attach|append)\b[^\n]{0,60}\b(in|into|to)\b"
    r"[^\n]{0,40}\b(field|notes|body|message|request|response|server|endpoint|url)\b",
]

_SENSITIVE_RES = [
    r"~[/\\]\.ssh",
    r"\.env\b",
    r"id_rsa",
    r"\bapi[_ -]?key\b",
    r"\baccess[_ -]?token\b",
    r"\bpassword\b",
    r"\bsecret\b",
    URL_RE,
    EMAIL_RE,
    IPV4_RE,
]

_HIDDEN_TEXT_RES = [
    r"[​‌‍⁠﻿]",  # zero-width chars
    r" {10,}",  # long whitespace runs
    r"\t{4,}",
    r"[A-Za-z0-9+/]{40,}={0,2}(?!\w)",  # base64-looking blob
]

_INSTRUCTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _INSTRUCTION_RES]
_EXFIL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _EXFIL_RES]
_SENSITIVE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _SENSITIVE_RES]
_HIDDEN_TEXT_PATTERNS = [re.compile(p) for p in _HIDDEN_TEXT_RES]

# category -> compiled patterns. Order matters only for which snippet gets reported first.
CATEGORIES: dict[str, list[re.Pattern[str]]] = {
    "instruction": _INSTRUCTION_PATTERNS,
    "exfil": _EXFIL_PATTERNS,
    "sensitive": _SENSITIVE_PATTERNS,
    "hidden_text": _HIDDEN_TEXT_PATTERNS,
}


@dataclass(frozen=True, slots=True)
class PatternMatch:
    category: str
    snippet: str


def _cross_tool_matches(text: str, other_tool_names: frozenset[str]) -> list[PatternMatch]:
    matches = []
    for name in other_tool_names:
        if not name:
            continue
        if re.search(rf"\b{re.escape(name)}\b", text, re.IGNORECASE):
            # Category is per-referenced-tool so "newly mentions X" and "newly mentions Y" are
            # tracked independently (mentioning a *different* other tool is still new signal).
            matches.append(PatternMatch(f"cross_tool:{name}", name))
    return matches


def scan(text: str, *, other_tool_names: frozenset[str] = frozenset()) -> list[PatternMatch]:
    """Return every pattern match found in `text`, tagged by category."""
    out: list[PatternMatch] = []
    for category, patterns in CATEGORIES.items():
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                out.append(PatternMatch(category, m.group(0)[:80]))
    out.extend(_cross_tool_matches(text, other_tool_names))
    return out


def new_matches(before: str, after: str, *, other_tool_names: frozenset[str] = frozenset()) -> list[PatternMatch]:
    """Matches present in `after` but not `before` -- i.e. *newly introduced*.

    A category counts as "newly introduced" if `before` had no match for that category at all;
    if `before` already had e.g. a URL and `after` has a different URL, that is a content change
    the semantic-diff layer will surface, not a fresh SECURITY signal.
    """
    before_categories = {m.category for m in scan(before, other_tool_names=other_tool_names)}
    after_matches = scan(after, other_tool_names=other_tool_names)
    return [m for m in after_matches if m.category not in before_categories]


__all__ = ["CATEGORIES", "EMAIL_RE", "IPV4_RE", "URL_RE", "PatternMatch", "new_matches", "scan"]
