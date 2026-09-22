"""O(1) LRU cache with per-key TTL.

Data structure: a `dict[key -> _Node]` for O(1) lookup, plus a hand-written doubly
linked list (DLL) with sentinel head/tail nodes for O(1) recency reordering and
eviction. Most-recently-used (MRU) sits right after `_head`; least-recently-used
(LRU) sits right before `_tail`.

Why a DLL instead of `collections.OrderedDict` (see `ordered_dict_impl.py` for that
version): `OrderedDict.move_to_end` / `popitem` are already O(1) and implemented in
C, so in real production code the shortcut wins. This hand-rolled version exists to
show the mechanism it's built on -- the same mechanism `OrderedDict` uses internally
-- and because it makes stats (evictions vs. expirations) and the "check the tail
before evicting" trick easier to narrate node-by-node in an interview.

Why sentinels: without a dummy `_head`/`_tail`, every insert/remove needs an
`if node is self._real_head` / `if node is self._real_tail` branch to handle the
list-boundary case. Sentinels make the list always non-empty, so `_link`/`_unlink`
have no special cases -- every real node always has a real `.prev` and `.next`.

Expiry semantics:
  - `expires_at = clock() + ttl`. A key is expired once `clock() >= expires_at`
    (the boundary itself counts as expired -- see tests/test_ttl.py).
  - Expiry is lazy: nothing scans for expired keys proactively. `get` checks the
    single node it looked up; `put`'s eviction path checks only the LRU-tail node
    (both O(1)). See the module docstring in `README.md` for why this trades
    "some expired memory lingers until touched or evicted" for average-O(1) ops.
  - `put` on an existing key updates the value, resets the TTL from `clock()` now,
    and moves the key to MRU (it's a fresh write, so it's used-then-recent).
  - Only `time.monotonic` (or another monotonic clock) is supported as the default.
    Wall-clock time (`time.time`) can jump backwards (NTP sync, manual clock change,
    leap seconds) which would let an entry un-expire or expire early. `clock` is
    injectable for tests (see `tests/conftest.py::FakeClock`) but should always be a
    monotonic source in production.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast


class _MissType:
    """Sentinel type for `get`'s default return value.

    A plain `None` default (like `dict.get`) can't tell "key absent/expired" apart
    from "key present and its cached value is `None`". `MISS` is a distinct object
    that can never equal a real cached value, so `cache.get(key) is MISS` is an
    unambiguous miss check even when `None` (or any other falsy value) is a value
    you legitimately cache. Callers who don't care about that distinction can still
    pass their own `default=` (e.g. `cache.get(key, default=None)` behaves like
    `dict.get`).
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "MISS"


MISS = _MissType()


class _UseDefaultType:
    """Sentinel for `put`'s `ttl` parameter.

    `ttl=None` is a meaningful value (never expire), so it can't also mean "I didn't
    pass a ttl, use the cache's default_ttl". A second, distinct sentinel is needed.
    """

    __slots__ = ()


_USE_DEFAULT = _UseDefaultType()


@dataclass
class CacheStats:
    """Running counters. Mutated in place by the cache; read-only by convention."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0


def _validate_capacity(capacity: int) -> None:
    if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
        raise ValueError(f"capacity must be an integer >= 1, got {capacity}")


def _validate_ttl(ttl: float | None, *, label: str = "ttl") -> None:
    if ttl is not None and (not math.isfinite(ttl) or ttl <= 0):
        raise ValueError(f"{label} must be finite and > 0 or None (never expire), got {ttl}")


class _Node[K, V]:
    """One cache entry, and simultaneously one DLL link. `prev`/`next` are never
    `None` for a node that's currently in the list (sentinels included) -- only a
    freshly-created or just-unlinked node has them unset."""

    __slots__ = ("key", "value", "expires_at", "prev", "next")

    def __init__(self, key: K, value: V, expires_at: float | None) -> None:
        self.key = key
        self.value = value
        self.expires_at = expires_at
        self.prev: _Node[K, V] | None = None
        self.next: _Node[K, V] | None = None


class LRUTTLCache[K, V]:
    """Fixed-capacity cache. `get`/`put`/`delete` are O(1) on average."""

    def __init__(
        self,
        capacity: int,
        default_ttl: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        _validate_capacity(capacity)
        _validate_ttl(default_ttl, label="default_ttl")
        self._capacity = capacity
        self._default_ttl = default_ttl
        self._clock = clock
        self._index: dict[K, _Node[K, V]] = {}
        # Sentinels carry no real key/value; `cast` silences the type checker for
        # the otherwise-unreachable K/V=None case. They are never looked up by key
        # and never exposed to callers.
        self._head: _Node[K, V] = _Node(cast(K, None), cast(V, None), None)
        self._tail: _Node[K, V] = _Node(cast(K, None), cast(V, None), None)
        self._head.next = self._tail
        self._tail.prev = self._head
        self.stats = CacheStats()

    # -- doubly linked list helpers (no special-casing thanks to the sentinels) --

    def _unlink(self, node: _Node[K, V]) -> None:
        prev, nxt = node.prev, node.next
        assert prev is not None and nxt is not None
        prev.next = nxt
        nxt.prev = prev
        node.prev = node.next = None

    def _push_front(self, node: _Node[K, V]) -> None:
        """Insert `node` as the new MRU (right after `_head`)."""
        first = self._head.next
        assert first is not None
        node.prev = self._head
        node.next = first
        self._head.next = node
        first.prev = node

    def _move_to_front(self, node: _Node[K, V]) -> None:
        self._unlink(node)
        self._push_front(node)

    # -- expiry --

    def _is_expired(self, node: _Node[K, V]) -> bool:
        return node.expires_at is not None and self._clock() >= node.expires_at

    def _remove_node(self, node: _Node[K, V]) -> None:
        del self._index[node.key]
        self._unlink(node)

    # -- public API --

    def get(self, key: K, default: V | _MissType = MISS) -> V | _MissType:
        """Return the cached value, refreshing recency, or `default` on a miss.

        A miss is either "key never stored", "key was evicted/deleted", or "key's
        TTL has elapsed" (lazy expiry: an expired key found here is removed now).
        """
        node = self._index.get(key)
        if node is None:
            self.stats.misses += 1
            return default
        if self._is_expired(node):
            self._remove_node(node)
            self.stats.misses += 1
            self.stats.expirations += 1
            return default
        self._move_to_front(node)
        self.stats.hits += 1
        return node.value

    def put(self, key: K, value: V, ttl: float | None | _UseDefaultType = _USE_DEFAULT) -> None:
        """Insert or update `key`. Always resets the TTL and moves to MRU.

        `ttl` omitted -> use `default_ttl`. `ttl=None` -> this key never expires,
        regardless of `default_ttl`. `ttl=<seconds>` -> per-key override.
        """
        effective_ttl = self._default_ttl if isinstance(ttl, _UseDefaultType) else ttl
        _validate_ttl(effective_ttl)
        expires_at = None if effective_ttl is None else self._clock() + effective_ttl

        node = self._index.get(key)
        if node is not None:
            node.value = value
            node.expires_at = expires_at
            self._move_to_front(node)
            return

        if len(self._index) >= self._capacity:
            self._evict_one()

        node = _Node(key, value, expires_at)
        self._index[key] = node
        self._push_front(node)

    def _evict_one(self) -> None:
        """Free one slot by dropping the LRU-tail node.

        Improvement over naive "always evict": the tail is exactly the node we're
        about to look at anyway, so checking whether *it* has already expired is
        free (O(1), no extra structure). If it has, this is a reclaimed expiration,
        not a real eviction of live data -- the stats distinguish the two.

        This does *not* find the "best" (most expired, or any other expired) entry
        to reclaim if it isn't the tail -- an expired key in the middle of the list
        sits there, unreclaimed, until it's touched by `get`/`__contains__` or
        happens to age into the tail position. Finding expired entries anywhere in
        O(1) would need a second index (a min-heap on `expires_at`, or a timing
        wheel) kept in sync with every put/delete -- more moving parts, and out of
        scope here. See README.md "Lazy vs active expiry".
        """
        victim = self._tail.prev
        assert victim is not None and victim is not self._head
        expired = self._is_expired(victim)
        self._remove_node(victim)
        if expired:
            self.stats.expirations += 1
        else:
            self.stats.evictions += 1

    def delete(self, key: K) -> bool:
        """Remove `key` if present (expired or not). Returns whether it was there."""
        node = self._index.pop(key, None)
        if node is None:
            return False
        self._unlink(node)
        return True

    def __len__(self) -> int:
        """Count of stored entries, including any not-yet-lazily-reclaimed expired
        ones. `len(cache)` is therefore an upper bound on the number of keys that
        would currently hit, not an exact count -- see README.md."""
        return len(self._index)

    def __contains__(self, key: K) -> bool:
        """Membership check that respects expiry but does **not** touch recency or
        stats -- it's a peek, not a `get`. An expired key is left in place (not
        removed) so this stays a read-only operation."""
        node = self._index.get(key)
        return node is not None and not self._is_expired(node)
