"""Cacheability policy: decide *before* touching the embedder or the index whether a query is even
a candidate for caching.

This runs first in :meth:`~semantic_cache.cache.SemanticCache.lookup` because it is the cheapest
possible rejection (regex over the raw string, no embedding, no index search) and because some of
these refusals are about correctness, not just cost: a "current price" or "my order status" query
must never be served from cache regardless of how similar it looks to something cached, so it
can't be left to the similarity threshold to catch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from semantic_cache.types import CacheContext

_TIME_SENSITIVE_RE = re.compile(
    r"\b(today|tonight|now|right now|currently|current|latest|breaking|live)\b"
    r"|\bthis (week|month|year)\b"
    r"|\bcurrent price\b",
    re.IGNORECASE,
)
_PERSONAL_RE = re.compile(
    r"\b(my|mine|me|myself)\b|\bi'?m\b|\bi'?ve\b|\bi'?ll\b|\bi'?d\b|\bi\b",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    cacheable: bool
    reason: str | None = None


def is_cacheable(
    query: str,
    ctx: CacheContext,  # reserved for future per-tenant policy overrides; see README
    *,
    has_tools: bool = False,
    temperature: float = 0.0,
    temperature_threshold: float = 0.3,
) -> PolicyDecision:
    """Decide whether ``query`` is even eligible for the cache, independent of what is stored.

    ``ctx`` is accepted (and part of the required signature) but unused today -- it is the hook
    for a future per-tenant override, e.g. a tenant that wants caching disabled outright, or a
    tenant in a regulated domain that wants a stricter temperature threshold. See
    ``q2_semantic_cache/README.md`` "Known limitations".

    ``has_tools``/``temperature``/``temperature_threshold`` are request-time facts that
    ``CacheContext.params_hash`` has already collapsed into an opaque partition key -- they are
    passed separately here because the *policy* needs the real values, not just a hash bucket, to
    decide whether the request qualifies at all.
    """
    if has_tools:
        return PolicyDecision(False, "request has tool calls")
    if temperature > temperature_threshold:
        return PolicyDecision(False, f"temperature {temperature} exceeds threshold {temperature_threshold}")
    if _TIME_SENSITIVE_RE.search(query):
        return PolicyDecision(False, "time-sensitive query")
    if _PERSONAL_RE.search(query):
        return PolicyDecision(False, "personal query")
    if _EMAIL_RE.search(query):
        return PolicyDecision(False, "query contains an email address")
    if _PHONE_RE.search(query):
        return PolicyDecision(False, "query contains a phone number")
    return PolicyDecision(True, None)
