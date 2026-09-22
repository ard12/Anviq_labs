"""Shared value types for the semantic cache.

These are plain, frozen dataclasses on purpose: they cross module boundaries (policy, guards,
index, cache, client) and every one of those modules should be able to reason about them without
worrying that someone mutated a field underneath them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CacheContext:
    """Identifies the request scope a cache entry is valid for.

    Four fields, all strings so they hash and compare cheaply and so a caller can pass in
    whatever hash function it already uses for its own logging:

    - ``tenant``: who is asking. Never match across tenants -- that is a data leak, not a cache
      miss.
    - ``model``: which LLM served (or would serve) the response. "gpt-4o" and "gpt-4o-mini"
      write different answers to the same question.
    - ``system_prompt_hash``: hash of the system prompt in force. Two different system prompts
      are two different "programs" even if the user message is identical.
    - ``params_hash``: hash of the remaining call parameters that affect the response
      (temperature, tool definitions, response_format, etc). Bucket temperature before hashing
      if you want "temperature=0.10" and "temperature=0.11" to share a partition; this type does
      not do that bucketing for you.

    A fifth component -- the embedding model's ``model_id`` -- is folded into the partition key
    by :class:`~semantic_cache.cache.SemanticCache`, not stored here, because it is a property of
    the cache's configuration rather than of the request. See ``cache.py:partition_key_for``.
    """

    tenant: str
    model: str
    system_prompt_hash: str
    params_hash: str


@dataclass(frozen=True, slots=True)
class Hit:
    """A cache lookup that will be served to the caller."""

    response: Any
    score: float
    matched_query: str
    reason: str
    entry_id: str = ""


@dataclass(frozen=True, slots=True)
class Miss:
    """A cache lookup that will *not* be served. ``reason`` is always populated so callers and
    tests can assert *why*, not just that it missed."""

    reason: str
    best_score: float | None = None
