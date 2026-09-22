"""Thread-safety smoke test: many threads hammering get/put/delete concurrently.
This isn't a proof of correctness (that's what the single lock + code review is
for) -- it's a smoke test that the lock actually serializes access: no exceptions,
and the invariant `len(cache) <= capacity` always holds even under contention."""

from __future__ import annotations

import random
import threading

from lru_ttl.threadsafe import ThreadSafeLRUTTLCache

CAPACITY = 16
NUM_THREADS = 8
OPS_PER_THREAD = 500
KEY_SPACE = [f"key-{i}" for i in range(32)]


def test_concurrent_get_put_delete_no_exceptions_and_capacity_holds():
    cache: ThreadSafeLRUTTLCache[str, int] = ThreadSafeLRUTTLCache(capacity=CAPACITY, default_ttl=0.05)
    errors: list[BaseException] = []
    len_violations: list[int] = []

    def worker(seed: int) -> None:
        rng = random.Random(seed)
        try:
            for _ in range(OPS_PER_THREAD):
                key = rng.choice(KEY_SPACE)
                op = rng.random()
                if op < 0.5:
                    cache.get(key)
                elif op < 0.9:
                    cache.put(key, rng.randint(0, 1000))
                else:
                    cache.delete(key)
                observed = len(cache)
                if observed > CAPACITY:
                    len_violations.append(observed)
        except BaseException as exc:  # noqa: BLE001 - smoke test: capture *any* failure
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(NUM_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"worker thread(s) raised: {errors}"
    assert not len_violations, f"len(cache) exceeded capacity {CAPACITY}: saw {len_violations}"
    assert len(cache) <= CAPACITY


def test_concurrent_puts_of_same_key_leave_cache_in_consistent_state():
    """Every thread repeatedly writes the *same* key. Regardless of interleaving,
    the cache must end up with exactly one entry and a coherent (not corrupted)
    internal list -- read it back and delete it to prove the structure isn't
    broken."""
    cache: ThreadSafeLRUTTLCache[str, int] = ThreadSafeLRUTTLCache(capacity=4)

    def worker(n: int) -> None:
        for i in range(200):
            cache.put("shared", n * 1000 + i)
            cache.get("shared")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(NUM_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert len(cache) == 1
    assert "shared" in cache
    assert cache.delete("shared") is True
    assert len(cache) == 0


def test_stats_snapshot_is_internally_consistent_type():
    cache: ThreadSafeLRUTTLCache[str, int] = ThreadSafeLRUTTLCache(capacity=2)
    cache.put("a", 1)
    cache.get("a")
    cache.get("missing")
    snap = cache.stats
    assert snap.hits == 1
    assert snap.misses == 1
