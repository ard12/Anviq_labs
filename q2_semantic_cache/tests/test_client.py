from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from fakes import FakeEmbedder

from semantic_cache.cache import SemanticCache
from semantic_cache.client import CachedLLM
from semantic_cache.types import CacheContext

CTX = CacheContext(tenant="acme", model="gpt-4o", system_prompt_hash="sp1", params_hash="p1")


def test_single_flight_deduplicates_concurrent_identical_misses() -> None:
    query = "what is the capital of France"
    cache = SemanticCache(FakeEmbedder({query: [1.0, 0.0]}, dim=2), mode="serve")

    call_count = 0
    count_lock = threading.Lock()

    def llm_call(q: str, ctx: CacheContext) -> str:
        nonlocal call_count
        with count_lock:
            call_count += 1
        time.sleep(0.05)  # widen the window so concurrent callers actually overlap
        return "Paris"

    client = CachedLLM(llm_call, cache)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: client.call(query, CTX), range(10)))

    assert call_count == 1
    assert all(r.response == "Paris" for r in results)
    assert all(r.status == "MISS" for r in results)

    # the leader stored it, so a follow-up call is now a cache hit with no upstream call
    followup = client.call(query, CTX)
    assert followup.status in {"HIT-EXACT", "HIT-SEMANTIC"}
    assert call_count == 1


def test_cache_hit_never_calls_upstream() -> None:
    query = "what is the capital of France"
    cache = SemanticCache(FakeEmbedder({query: [1.0, 0.0]}, dim=2), mode="serve")
    cache.store(query, "Paris", CTX)

    def llm_call(q: str, ctx: CacheContext) -> str:
        raise AssertionError("upstream should not be called on a cache hit")

    client = CachedLLM(llm_call, cache)
    result = client.call(query, CTX)

    assert result.status == "HIT-EXACT"
    assert result.response == "Paris"


def test_x_cache_header_format() -> None:
    query = "what is the capital of France"
    cache = SemanticCache(FakeEmbedder({query: [1.0, 0.0]}, dim=2), mode="serve")
    cache.store(query, "Paris", CTX)
    client = CachedLLM(lambda q, ctx: "unused", cache)

    result = client.call(query, CTX)

    assert result.x_cache_header == "X-Cache: HIT-EXACT; score=1.00"


def test_upstream_exception_propagates_to_all_waiters() -> None:
    query = "what is the capital of France"
    cache = SemanticCache(FakeEmbedder({query: [1.0, 0.0]}, dim=2), mode="serve")

    def failing_llm_call(q: str, ctx: CacheContext) -> str:
        time.sleep(0.02)
        raise RuntimeError("upstream down")

    client = CachedLLM(failing_llm_call, cache)

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(client.call, query, CTX) for _ in range(5)]
        results = [f.exception() for f in futures]

    assert all(isinstance(exc, RuntimeError) for exc in results)
    # a failed upstream call must not poison the cache
    assert cache.metrics.hits_exact == 0


def test_policy_refused_request_is_not_stored_by_cached_llm() -> None:
    query = "explain vector databases"
    cache = SemanticCache(FakeEmbedder({query: [1.0, 0.0]}, dim=2), mode="serve")
    client = CachedLLM(lambda q, ctx: "private", cache)

    result = client.call(query, CTX, has_tools=True)

    assert result.status == "MISS"
    assert result.reason == "request has tool calls"
    assert not cache._partitions
    assert not cache.metrics.store_rejections  # refused requests never attempt storage


def test_concurrent_tool_requests_execute_independently():
    cache = SemanticCache(FakeEmbedder({}, dim=2))
    barrier = threading.Barrier(2)

    def upstream(query, ctx):
        barrier.wait(timeout=2)
        return object()

    client = CachedLLM(upstream, cache)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(client.call, "perform operation", CTX, has_tools=True) for _ in range(2)]
        results = [future.result(timeout=3) for future in futures]
    assert results[0].response is not results[1].response
    assert not cache.shadow_log
    assert not cache._partitions
