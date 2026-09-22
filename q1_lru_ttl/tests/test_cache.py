"""Core LRU + TTL behavior. Parametrized over both implementations (the hand-rolled
DLL and the OrderedDict shortcut) so they're held to the identical contract."""

from __future__ import annotations

import pytest

from lru_ttl.cache import MISS, LRUTTLCache
from lru_ttl.ordered_dict_impl import OrderedDictLRUTTLCache

IMPLS = [LRUTTLCache, OrderedDictLRUTTLCache]


@pytest.fixture(params=IMPLS, ids=["dll", "ordereddict"])
def cache_cls(request):
    return request.param


# -- construction / validation --------------------------------------------------


def test_capacity_below_one_raises(cache_cls):
    for bad in (0, -1, -100, 1.5, float("nan"), True):
        with pytest.raises(ValueError):
            cache_cls(bad)


def test_default_ttl_non_positive_or_non_finite_raises(cache_cls):
    for bad in (0, -1, -0.5, float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            cache_cls(capacity=2, default_ttl=bad)


def test_per_key_ttl_non_positive_or_non_finite_raises(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    for bad in (0, -1, -0.5, float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            cache.put("k", "v", ttl=bad)


def test_none_default_ttl_means_never_expires(cache_cls):
    cache = cache_cls(capacity=1)  # default_ttl=None, real clock
    cache.put("k", "v")
    assert cache.get("k") == "v"


# -- basic get/put/delete ---------------------------------------------------------


def test_put_then_get_hits(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("a", 1)
    assert cache.get("a") == 1
    assert cache.stats.hits == 1
    assert cache.stats.misses == 0


def test_get_missing_key_is_miss_sentinel_by_default(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    assert cache.get("nope") is MISS
    assert cache.stats.misses == 1


def test_get_missing_key_returns_custom_default(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    assert cache.get("nope", "fallback") == "fallback"


def test_caching_none_value_is_distinguishable_from_miss(cache_cls, clock):
    """The whole reason `get` defaults to a MISS sentinel instead of `None`:
    a cached `None` must not look like an absent key."""
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("k", None)
    assert cache.get("k") is None  # hit, value happens to be None
    assert cache.get("k") is not MISS
    assert cache.get("missing") is MISS  # miss, distinct object
    assert "k" in cache


def test_delete_existing_returns_true_and_removes(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("a", 1)
    assert cache.delete("a") is True
    assert "a" not in cache
    assert len(cache) == 0


def test_delete_missing_returns_false(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    assert cache.delete("nope") is False


def test_len_tracks_stored_entries(cache_cls, clock):
    cache = cache_cls(capacity=3, clock=clock)
    assert len(cache) == 0
    cache.put("a", 1)
    cache.put("b", 2)
    assert len(cache) == 2
    cache.put("a", 99)  # update, not a new entry
    assert len(cache) == 2


# -- LRU order and eviction --------------------------------------------------------


def test_eviction_order_is_least_recently_used(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)  # capacity exceeded, "a" is LRU -> evicted
    assert "a" not in cache
    assert cache.get("b") == 2
    assert cache.get("c") == 3
    assert cache.stats.evictions == 1


def test_capacity_one_evicts_previous_key_immediately(cache_cls, clock):
    cache = cache_cls(capacity=1, clock=clock)
    cache.put("a", 1)
    cache.put("b", 2)
    assert "a" not in cache
    assert cache.get("b") == 2
    assert len(cache) == 1


def test_get_refreshes_recency(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("a", 1)
    cache.put("b", 2)
    cache.get("a")  # "a" becomes MRU, "b" becomes LRU
    cache.put("c", 3)  # "b" should be evicted, not "a"
    assert "b" not in cache
    assert cache.get("a") == 1
    assert cache.get("c") == 3


def test_update_refreshes_recency(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("a", 100)  # update moves "a" to MRU, "b" becomes LRU
    cache.put("c", 3)  # "b" should be evicted
    assert "b" not in cache
    assert cache.get("a") == 100
    assert cache.get("c") == 3


def test_contains_does_not_refresh_recency(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("a", 1)
    cache.put("b", 2)
    assert "a" in cache  # peek only, must NOT promote "a"
    cache.put("c", 3)  # "a" is still LRU -> should be evicted, not "b"
    assert "a" not in cache
    assert cache.get("b") == 2
    assert cache.get("c") == 3


def test_stats_count_evictions_and_hits_and_misses(cache_cls, clock):
    cache = cache_cls(capacity=1, clock=clock)
    cache.put("a", 1)
    cache.get("a")  # hit
    cache.get("z")  # miss
    cache.put("b", 2)  # evicts "a"
    assert cache.stats.hits == 1
    assert cache.stats.misses == 1
    assert cache.stats.evictions == 1
