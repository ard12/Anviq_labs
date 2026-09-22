"""Property test: random sequences of put/get/delete/contains/advance, replayed
identically against the O(1) cache and a trivially-correct O(n) reference model
(reference_model.ReferenceLRUTTLCache). If they ever disagree, the O(1) cache has
a bug. This is deliberately the strongest correctness evidence in this submission
-- it isn't limited to whatever edge cases a human thought to write by hand.

Both implementations of the O(1) cache (DLL and OrderedDict) are checked.
"""

from __future__ import annotations

from conftest import FakeClock
from hypothesis import given, settings
from hypothesis import strategies as st
from reference_model import MISS as REF_MISS
from reference_model import ReferenceLRUTTLCache

from lru_ttl.cache import MISS, LRUTTLCache
from lru_ttl.ordered_dict_impl import OrderedDictLRUTTLCache

KEYS = st.integers(min_value=0, max_value=5)
VALUES = st.integers(min_value=-1000, max_value=1000) | st.none()
TTLS = st.one_of(st.none(), st.floats(min_value=0.1, max_value=5.0, allow_nan=False))

# 'put' carries its own ttl choice; 'omit' means "call put() without a ttl arg at
# all" (i.e. use the cache's default_ttl), which is distinct from ttl=None.
put_op = st.tuples(st.just("put"), KEYS, VALUES, TTLS, st.booleans())
get_op = st.tuples(st.just("get"), KEYS)
delete_op = st.tuples(st.just("delete"), KEYS)
contains_op = st.tuples(st.just("contains"), KEYS)
advance_op = st.tuples(st.just("advance"), st.floats(min_value=0.0, max_value=6.0, allow_nan=False))

operations = st.lists(
    st.one_of(put_op, get_op, delete_op, contains_op, advance_op),
    min_size=1,
    max_size=60,
)


def _apply(cache, ref, op) -> None:
    kind = op[0]
    if kind == "put":
        _, key, value, ttl, omit = op
        if omit:
            cache.put(key, value)
            ref.put(key, value)
        else:
            cache.put(key, value, ttl=ttl)
            ref.put(key, value, ttl=ttl)
    elif kind == "get":
        _, key = op
        got = cache.get(key)
        want = ref.get(key)
        got_is_miss = got is MISS
        want_is_miss = want is REF_MISS
        assert got_is_miss == want_is_miss, (kind, key, got, want)
        if not got_is_miss:
            assert got == want, (kind, key, got, want)
    elif kind == "delete":
        _, key = op
        assert cache.delete(key) == ref.delete(key), (kind, key)
    elif kind == "contains":
        _, key = op
        assert (key in cache) == (key in ref), (kind, key)
    elif kind == "advance":
        _, dt = op
        # FakeClock is shared between cache and ref (same clock callable), so
        # advancing it once affects both -- no separate advance calls needed.
        pass
    assert len(cache) == len(ref), (kind, op, len(cache), len(ref))


@settings(max_examples=200)
@given(capacity=st.integers(min_value=1, max_value=5), default_ttl=TTLS, ops=operations)
def test_matches_reference_model_dll(capacity, default_ttl, ops):
    clock = FakeClock()
    cache = LRUTTLCache(capacity=capacity, default_ttl=default_ttl, clock=clock)
    ref = ReferenceLRUTTLCache(capacity=capacity, default_ttl=default_ttl, clock=clock)
    for op in ops:
        if op[0] == "advance":
            clock.advance(op[1])
        _apply(cache, ref, op)


@settings(max_examples=200)
@given(capacity=st.integers(min_value=1, max_value=5), default_ttl=TTLS, ops=operations)
def test_matches_reference_model_ordereddict(capacity, default_ttl, ops):
    clock = FakeClock()
    cache = OrderedDictLRUTTLCache(capacity=capacity, default_ttl=default_ttl, clock=clock)
    ref = ReferenceLRUTTLCache(capacity=capacity, default_ttl=default_ttl, clock=clock)
    for op in ops:
        if op[0] == "advance":
            clock.advance(op[1])
        _apply(cache, ref, op)
