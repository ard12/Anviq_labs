"""TTL / expiry semantics. Uses the FakeClock fixture exclusively -- no
`time.sleep` anywhere, so boundary conditions are exact and the suite is fast."""

from __future__ import annotations

import pytest

from lru_ttl.cache import MISS, LRUTTLCache
from lru_ttl.ordered_dict_impl import OrderedDictLRUTTLCache

IMPLS = [LRUTTLCache, OrderedDictLRUTTLCache]


@pytest.fixture(params=IMPLS, ids=["dll", "ordereddict"])
def cache_cls(request):
    return request.param


def test_hit_just_before_ttl_boundary(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("k", "v", ttl=10)
    clock.advance(9.999999)
    assert cache.get("k") == "v"


def test_miss_exactly_at_ttl_boundary(cache_cls, clock):
    """`expires_at = clock() + ttl`; expired when `clock() >= expires_at`. At
    t=10 exactly (ttl=10, put at t=0) the entry is expired -- the boundary itself
    counts as expired, not "expires on the next tick after"."""
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("k", "v", ttl=10)
    clock.advance(10.0)
    assert cache.get("k") is MISS


def test_miss_after_ttl_boundary(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("k", "v", ttl=10)
    clock.advance(10.5)
    assert cache.get("k") is MISS


def test_per_key_ttl_overrides_default_ttl(cache_cls, clock):
    cache = cache_cls(capacity=2, default_ttl=100, clock=clock)
    cache.put("short", "v", ttl=5)
    cache.put("long", "v")  # uses default_ttl=100
    clock.advance(5)
    assert cache.get("short") is MISS
    assert cache.get("long") == "v"


def test_ttl_none_on_put_never_expires_even_with_default_ttl(cache_cls, clock):
    cache = cache_cls(capacity=2, default_ttl=5, clock=clock)
    cache.put("forever", "v", ttl=None)
    clock.advance(10_000)
    assert cache.get("forever") == "v"


def test_no_ttl_at_all_never_expires(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)  # default_ttl=None
    cache.put("k", "v")
    clock.advance(10_000)
    assert cache.get("k") == "v"


def test_expired_entry_is_removed_on_get_lazy_expiry(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("k", "v", ttl=1)
    clock.advance(1)
    assert len(cache) == 1  # still physically present, not yet touched
    assert cache.get("k") is MISS  # lazy expiry happens here
    assert len(cache) == 0  # now actually gone
    assert cache.stats.expirations == 1


def test_put_on_existing_key_resets_ttl(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("k", "v1", ttl=5)
    clock.advance(4)
    cache.put("k", "v2", ttl=5)  # resets the clock on the TTL
    clock.advance(4)  # total elapsed since first put: 8s, but only 4s since 2nd put
    assert cache.get("k") == "v2"
    clock.advance(1.0)  # now 5s since the reset -> expired
    assert cache.get("k") is MISS


def test_put_on_existing_key_uses_new_ttl_not_old(cache_cls, clock):
    cache = cache_cls(capacity=2, default_ttl=100, clock=clock)
    cache.put("k", "v1")  # ttl=100
    cache.put("k", "v2", ttl=1)  # shrink the ttl on update
    clock.advance(1)
    assert cache.get("k") is MISS


def test_expired_tail_reclaimed_before_evicting_live_entry(cache_cls, clock):
    """Capacity 2. "a" gets a short ttl and becomes LRU; "b" stays live. When a
    third key is inserted, the LRU-tail ("a") is expired -- it should be reclaimed
    (counted as an expiration) and "b" (the live entry) must survive."""
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("a", 1, ttl=1)
    cache.put("b", 2)  # no ttl, never expires; "a" is now LRU
    clock.advance(1)  # "a" is now expired, but still physically stored
    cache.put("c", 3)  # triggers eviction path; tail ("a") is expired
    assert "a" not in cache
    assert cache.get("b") == 2  # survived
    assert cache.get("c") == 3
    assert cache.stats.expirations == 1
    assert cache.stats.evictions == 0


def test_expired_tail_reclaim_still_evicts_if_capacity_needs_more_room(cache_cls, clock):
    """Same setup, but after reclaiming the expired tail there still isn't room
    (capacity 1): the reclaim itself frees the slot, so no *additional* live
    eviction is needed -- this pins down that the reclaim counts as freeing space,
    not as a separate step before a real eviction."""
    cache = cache_cls(capacity=1, clock=clock)
    cache.put("a", 1, ttl=1)
    clock.advance(1)
    cache.put("b", 2)
    assert "a" not in cache
    assert cache.get("b") == 2
    assert cache.stats.expirations == 1
    assert cache.stats.evictions == 0


def test_contains_respects_expiry(cache_cls, clock):
    cache = cache_cls(capacity=2, clock=clock)
    cache.put("k", "v", ttl=1)
    assert "k" in cache
    clock.advance(1)
    assert "k" not in cache
