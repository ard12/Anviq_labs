"""The production shortcut: same public behavior as `LRUTTLCache`, built on
`collections.OrderedDict` instead of a hand-rolled doubly linked list.

`OrderedDict.move_to_end` and `popitem` are O(1) and implemented in C, so this is
what I would actually ship. `cache.py`'s DLL exists to demonstrate the mechanism
`OrderedDict` is built on for this interview -- see its module docstring.

Run through the identical test suite as `LRUTTLCache` via parametrization in
`tests/test_cache.py`, so "the shortcut" is held to the exact same contract.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable

from lru_ttl.cache import (
    _USE_DEFAULT,
    MISS,
    CacheStats,
    _MissType,
    _UseDefaultType,
    _validate_capacity,
    _validate_ttl,
)


class OrderedDictLRUTTLCache[K, V]:
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
        # value -> (value, expires_at); OrderedDict order *is* the recency order,
        # LRU at the front (index 0), MRU at the back.
        self._data: OrderedDict[K, tuple[V, float | None]] = OrderedDict()
        self.stats = CacheStats()

    def _expired(self, expires_at: float | None) -> bool:
        return expires_at is not None and self._clock() >= expires_at

    def get(self, key: K, default: V | _MissType = MISS) -> V | _MissType:
        if key not in self._data:
            self.stats.misses += 1
            return default
        value, expires_at = self._data[key]
        if self._expired(expires_at):
            del self._data[key]
            self.stats.misses += 1
            self.stats.expirations += 1
            return default
        self._data.move_to_end(key)
        self.stats.hits += 1
        return value

    def put(self, key: K, value: V, ttl: float | None | _UseDefaultType = _USE_DEFAULT) -> None:
        effective_ttl = self._default_ttl if isinstance(ttl, _UseDefaultType) else ttl
        _validate_ttl(effective_ttl)
        expires_at = None if effective_ttl is None else self._clock() + effective_ttl
        if key in self._data:
            self._data[key] = (value, expires_at)
            self._data.move_to_end(key)
            return
        if len(self._data) >= self._capacity:
            _, (_, victim_expires) = self._data.popitem(last=False)
            if self._expired(victim_expires):
                self.stats.expirations += 1
            else:
                self.stats.evictions += 1
        self._data[key] = (value, expires_at)

    def delete(self, key: K) -> bool:
        return self._data.pop(key, None) is not None

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, key: K) -> bool:
        entry = self._data.get(key)
        return entry is not None and not self._expired(entry[1])
