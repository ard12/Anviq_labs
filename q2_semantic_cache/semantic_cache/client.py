"""``CachedLLM``: a drop-in wrapper around an LLM call that adds cache lookup/storage and
single-flight deduplication of concurrent identical misses.

Single-flight matters because a cache miss is exactly the moment a query is *not yet* cached --
which means the first few seconds after a new/rare question shows up are also the moment a burst
of near-simultaneous callers (a spike of users asking the same trending question, or a retry
storm) will all miss together and, without this, all pay for their own upstream call.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from semantic_cache import policy
from semantic_cache.cache import SemanticCache, normalize_query
from semantic_cache.types import CacheContext, Hit


@dataclass(frozen=True, slots=True)
class CachedResponse:
    """What ``CachedLLM.call`` returns: the response plus enough cache metadata to log or assert
    on, modeled loosely on an HTTP cache's ``X-Cache`` response header."""

    response: Any
    status: str  # "HIT-EXACT" | "HIT-SEMANTIC" | "MISS"
    score: float | None
    reason: str | None
    entry_id: str | None

    @property
    def x_cache_header(self) -> str:
        if self.score is None:
            return f"X-Cache: {self.status}"
        return f"X-Cache: {self.status}; score={self.score:.2f}"


@dataclass
class _InFlight:
    """Shared slot for one in-progress upstream call. The leader (first caller to see a miss for
    this key) populates ``response``/``error`` and sets ``done``; every follower just waits on
    ``done`` and reads the same slot."""

    done: threading.Event = field(default_factory=threading.Event)
    response: Any = None
    error: BaseException | None = None


class CachedLLM:
    """Wraps a synchronous ``llm_call(query, ctx) -> response`` with cache lookup, storage on
    miss, and single-flight coalescing.

    **Single-flight is threading-based, not asyncio-based.** ``llm_call`` is a plain synchronous
    callable -- the shape most LLM client SDKs already have -- so a ``threading.Lock``-guarded
    registry of ``threading.Event``s is the natural fit: the GIL makes registry insert/delete
    atomic without extra bookkeeping, and a thread blocked on ``Event.wait()`` costs a stack, not
    an event-loop task. An asyncio version would use the same *algorithm* with ``asyncio.Lock``/
    ``asyncio.Event`` instead, but it would force every caller onto an event loop and onto an
    async ``llm_call``. If the deployment is already asyncio-native end to end, port this class
    1:1 to the asyncio primitives; the coalescing logic below doesn't change.
    """

    def __init__(self, llm_call: Callable[[str, CacheContext], Any], cache: SemanticCache) -> None:
        self.llm_call = llm_call
        self.cache = cache
        self._lock = threading.Lock()
        self._inflight: dict[tuple[Any, str], _InFlight] = {}

    def call(
        self,
        query: str,
        ctx: CacheContext,
        *,
        has_tools: bool = False,
        temperature: float = 0.0,
    ) -> CachedResponse:
        result = self.cache.lookup(query, ctx, has_tools=has_tools, temperature=temperature)
        if isinstance(result, Hit):
            status = "HIT-EXACT" if result.reason == "exact" else "HIT-SEMANTIC"
            return CachedResponse(
                response=result.response,
                status=status,
                score=result.score,
                reason=result.reason,
                entry_id=result.entry_id,
            )

        # Requests with side effects or fresh/random results must execute independently.
        if not policy.is_cacheable(query, ctx, has_tools=has_tools, temperature=temperature).cacheable:
            return CachedResponse(
                response=self.llm_call(query, ctx),
                status="MISS",
                score=result.best_score,
                reason=result.reason,
                entry_id=None,
            )

        # Miss: coalesce concurrent identical misses in the same partition into one upstream call.
        # Keyed on (partition, normalized query) -- the same scope the cache itself matches within.
        key = (self.cache.partition_key_for(ctx), normalize_query(query))
        with self._lock:
            inflight = self._inflight.get(key)
            leader = inflight is None
            if leader:
                inflight = self._inflight[key] = _InFlight()

        if leader:
            try:
                response = self.llm_call(query, ctx)
                inflight.response = response
                self.cache.store(
                    query,
                    response,
                    ctx,
                    has_tools=has_tools,
                    temperature=temperature,
                )
                return CachedResponse(
                    response=response,
                    status="MISS",
                    score=result.best_score,
                    reason=result.reason,
                    entry_id=None,
                )
            except BaseException as exc:
                # Store failures must propagate to followers too; otherwise the leader raises while
                # waiters incorrectly return an unpersisted response as though the flight succeeded.
                inflight.error = exc
                raise
            finally:
                with self._lock:
                    del self._inflight[key]
                inflight.done.set()

        inflight.done.wait()
        if inflight.error is not None:
            raise inflight.error
        return CachedResponse(
            response=inflight.response,
            status="MISS",
            score=result.best_score,
            reason=result.reason,
            entry_id=None,
        )
