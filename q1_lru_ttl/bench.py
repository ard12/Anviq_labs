"""Micro-benchmark: ops/sec for get and put at capacity 1,000 and 1,000,000.

Not a test (no assertions, not collected by pytest -- it doesn't match test_*.py).
It exists to make the O(1) claim visually obvious: per-op time should stay flat as
capacity grows 1000x, because both `dict` lookup and the DLL pointer updates are
O(1) regardless of how many *other* entries exist.

Run:
    python bench.py
"""

from __future__ import annotations

import random
import time

from lru_ttl.cache import LRUTTLCache
from lru_ttl.ordered_dict_impl import OrderedDictLRUTTLCache

N_OPS = 200_000


def bench_put(cache_cls, capacity: int) -> float:
    cache = cache_cls(capacity=capacity)
    keys = [f"k{i}" for i in range(N_OPS)]
    start = time.perf_counter()
    for k in keys:
        cache.put(k, k)
    elapsed = time.perf_counter() - start
    return N_OPS / elapsed


def bench_get(cache_cls, capacity: int) -> float:
    cache = cache_cls(capacity=capacity)
    # Pre-fill to capacity so gets are a mix of hits and (for get_random) misses.
    for i in range(capacity):
        cache.put(f"k{i}", i)
    keys = [f"k{random.randrange(capacity)}" for _ in range(N_OPS)]
    start = time.perf_counter()
    for k in keys:
        cache.get(k)
    elapsed = time.perf_counter() - start
    return N_OPS / elapsed


def main() -> None:
    print(f"{N_OPS:,} ops per measurement\n")
    header = f"{'impl':<12} {'capacity':>10} {'put ops/sec':>16} {'get ops/sec':>16}"
    print(header)
    print("-" * len(header))
    for cache_cls, label in [(LRUTTLCache, "dll"), (OrderedDictLRUTTLCache, "ordereddict")]:
        for capacity in (1_000, 1_000_000):
            put_rate = bench_put(cache_cls, capacity)
            get_rate = bench_get(cache_cls, capacity)
            print(f"{label:<12} {capacity:>10,} {put_rate:>16,.0f} {get_rate:>16,.0f}")


if __name__ == "__main__":
    main()
