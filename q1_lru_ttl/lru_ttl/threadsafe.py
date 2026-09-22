"""Thread-safe wrapper around `LRUTTLCache`.

One `threading.Lock` guards every public method -- including `get`. `get` looks
read-only from the outside, but it isn't: it moves the accessed node to MRU (two
pointer updates on the shared DLL) and, on an expired hit, unlinks the node and
mutates `stats`. Two threads calling `get` concurrently without a lock could race
on those pointer writes and corrupt the list (e.g. a node's `.next` pointing
somewhere its `.prev` disagrees with), even though neither thread wrote "the data".
So the lock has to cover reads, not just writes.

This is a single global lock: every operation on the whole cache serializes behind
it, so under heavy concurrent access (many threads, one large cache) this becomes
the bottleneck -- correct, but not scalable. The next step for that case is lock
striping / sharding: partition the key space across N independent `LRUTTLCache`
instances (e.g. `shard = hash(key) % N`), each with its own lock, so unrelated keys
don't contend. The trade-off is that capacity and "least recently used" become
per-shard rather than global -- see DECISIONS.md.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from lru_ttl.cache import _USE_DEFAULT, MISS, CacheStats, LRUTTLCache, _MissType, _UseDefaultType


class ThreadSafeLRUTTLCache[K, V]:
    """Same contract as `LRUTTLCache`, safe for concurrent use from multiple
    threads. Not lock-free and not sharded -- see module docstring."""

    def __init__(
        self,
        capacity: int,
        default_ttl: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._cache: LRUTTLCache[K, V] = LRUTTLCache(capacity, default_ttl, clock)
        self._lock = threading.Lock()

    def get(self, key: K, default: V | _MissType = MISS) -> V | _MissType:
        with self._lock:
            return self._cache.get(key, default)

    def put(self, key: K, value: V, ttl: float | None | _UseDefaultType = _USE_DEFAULT) -> None:
        with self._lock:
            self._cache.put(key, value, ttl)

    def delete(self, key: K) -> bool:
        with self._lock:
            return self._cache.delete(key)

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def __contains__(self, key: K) -> bool:
        with self._lock:
            return key in self._cache

    @property
    def stats(self) -> CacheStats:
        """Returns a point-in-time snapshot (a copy), not a live view, so reading
        it can't race with a concurrent mutation of the underlying counters."""
        with self._lock:
            inner = self._cache.stats
            return CacheStats(inner.hits, inner.misses, inner.evictions, inner.expirations)
