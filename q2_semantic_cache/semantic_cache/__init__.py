"""Semantic cache in front of an LLM API.

Public surface re-exported here so callers do `from semantic_cache import SemanticCache`
instead of reaching into submodules.
"""

from __future__ import annotations

from semantic_cache.cache import SemanticCache
from semantic_cache.client import CachedLLM, CachedResponse
from semantic_cache.embedders import Embedder, HashingEmbedder
from semantic_cache.types import CacheContext, Hit, Miss

__all__ = [
    "CacheContext",
    "CachedLLM",
    "CachedResponse",
    "Embedder",
    "HashingEmbedder",
    "Hit",
    "Miss",
    "SemanticCache",
]
