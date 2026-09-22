# Q1: O(1) LRU cache with per-key TTL

Package: `lru_ttl`. Decision log: [`DECISIONS.md`](DECISIONS.md).

## Problem

An in-memory cache with a fixed capacity. `get(key)` and `put(key, value)` must run in O(1). When full, `put` evicts the Least Recently Used entry. On top of plain LRU, every entry also has a TTL, and once it elapses a `get` on that key is a miss even though the key is technically still sitting in memory.

## Approach

There are two implementations of the same contract, built for two different purposes.

`lru_ttl/cache.py` holds `LRUTTLCache`: a `dict[key -> Node]` for O(1) lookup, plus a hand-written doubly linked list with sentinel `head`/`tail` nodes for O(1) recency reordering. Most-recently-used sits right after `head`, least-recently-used right before `tail`. This is the one written to show the mechanism.

`lru_ttl/ordered_dict_impl.py` holds `OrderedDictLRUTTLCache`, the same contract built on `collections.OrderedDict` (`move_to_end` plus `popitem(last=False)`), which is O(1) and implemented in C. This is the one I would actually ship. See [DECISIONS.md Q1-001](DECISIONS.md).

Both run through the same parametrized test suite (`tests/test_cache.py`, `tests/test_ttl.py`), so neither gets special treatment.

### Expiry model

`expires_at = clock() + ttl` is computed once, at `put` time. A key is expired once `clock() >= expires_at`, so the boundary itself counts as expired ([Q1-005](DECISIONS.md)).

Expiry is lazy. Nothing scans the cache looking for stale entries. `get` checks the single node it looked up, and `put`'s eviction path checks the LRU-tail node it was about to evict anyway. Both are O(1) checks layered onto work the cache was already doing. The section on lazy versus active expiry below covers what a more aggressive scheme would cost.

### Thread safety

`lru_ttl/threadsafe.py` wraps `LRUTTLCache` with a single `threading.Lock`, held by every public method including `get`. `get` mutates recency, so it isn't actually a read ([Q1-009](DECISIONS.md)).

## Complexity and trade-offs

| Operation | Time | Notes |
|---|---|---|
| `get(key)` | O(1) | dict lookup, plus 4 pointer writes on a hit to move to MRU |
| `put(key, value)` | O(1) | dict lookup/insert, up to 4 pointer writes; eviction is O(1) because it always removes exactly the tail node |
| `delete(key)` | O(1) | dict delete plus unlink |
| `__len__` | O(1) | `len(dict)` |
| `__contains__(key)` | O(1) | dict lookup only, no list mutation |

These are O(1) on average. The linked-list work is worst-case O(1), but Python's hash tables give average and amortized O(1) lookup and insertion rather than a strict worst-case bound. Nothing sweeps the cache in the hot path.

### Lazy vs active expiry

This cache only notices an entry has expired when something touches it: a `get` on that exact key, or an eviction that lands on it because it is the current LRU tail. An expired key that is never read again and never ages into the tail position sits in memory, counted in `__len__`, until the cache is full enough to evict past it.

That is the price of staying O(1). Finding *any* expired entry anywhere needs a second structure kept in sync with every write: a min-heap keyed on `expires_at`, which costs O(log n) maintenance per write, or a timing wheel bucketing entries by expiry time and sweeping as the clock advances.

Redis answers this with a sampled active-expiry cycle. A background job picks a small random sample of keys that have a TTL, expires the ones that are due, and if more than 25% of the sample turned out to be expired it immediately samples again, on the theory that there is probably more where that came from. It is neither exhaustive nor O(1). It is a probabilistic background cost paid off the hot path, trading "expired memory can linger a little" for "the hot path never carries this cost". That is the natural next step here.

### Memory overhead per entry

Each stored key costs one `_Node` object (`key`, `value`, `expires_at`, `prev`, `next`, declared through `__slots__` so there is no per-instance `__dict__`), one entry in the `_index` dict holding the key and a pointer to the node, and whatever the key and value objects cost themselves.

For rough sizing on 64-bit CPython 3.12 and 3.14: a `__slots__` object with 5 attributes runs about 100 to 120 bytes, and a dict entry adds roughly 50 to 100 bytes amortized once you count the slack the hash table keeps to stay O(1) on growth. Call it 150 to 250 bytes of fixed overhead per entry, on top of the key and value themselves, which carry their own PyObject overhead (a bare `int` is 28 bytes, a short `str` 49 or more).

`OrderedDictLRUTTLCache` is more compact, since it has no hand-rolled node object and stores ordering inside a compact internal hash table, but how much more compact depends on the `OrderedDict` implementation version. The `cache.py` numbers above are the ones to use for back-of-envelope sizing.

### Why the DLL uses sentinels

A `head`/`tail` pair that is always present, even in an empty list, means every insert and unlink is the same four pointer writes whether or not the node sits at an end. No `if node is head` special cases anywhere. Longer version in [Q1-002](DECISIONS.md).

### What changes for a distributed cache

None of this is built, and it is out of scope for one in-memory cache, but it is the honest answer to what is missing before this runs across machines. Everything above assumes one process, one address space, one clock.

Where a key lives becomes a question: consistent hashing across nodes, which also changes what "evict the LRU" means, since there is no global recency order any more, only per-node order, unless you pay for a shared one.

Whose clock counts as `now` becomes another. `clock()` here is a single monotonic source. Across machines you either accept a skew tolerance between loosely synchronized clocks, or stop trusting wall and monotonic time for expiry and move to logical timestamps or lease-based expiry coordinated through the store. Part of why Redis enforces TTL inside the single Redis process rather than in its clients.

Then replication and failover: is a miss on the node that owns a key authoritative, or does a write have to reach a quorum before it counts? And invalidation: a `delete` or an expiry on one node has to become visible to the others, or you accept staleness and say so.

## How to run

From this directory:
```bash
pip install -e .[dev]
pytest -q             # 63 tests: LRU/TTL behaviour across both impls, property test, thread-safety smoke test
python bench.py       # ops/sec at capacity 1k and 1M (not a test, no assertions)
```
From the repo root, `python tasks.py test` runs this suite along with all the others.

Nothing here needs network access or a model download.

## Known limitations and what I would do next

Expired entries can linger in memory until something touches them or eviction passes over them. The fix is a background sweep doing Redis-style random sampling of keys with a TTL, which bounds the memory held by never-read-again expired keys without putting the cost in the hot path.

`ThreadSafeLRUTTLCache` uses one global lock, so it serializes the whole cache under concurrent access. Correct, but it does not scale. Sharding into N independent `LRUTTLCache` instances by `hash(key) % N`, each with its own lock, is the next step; it is written up in [Q1-009](DECISIONS.md) and in the module docstring.

Eviction is bounded by entry count, not by bytes. A workload caching blobs of wildly different sizes cannot bound its memory this way. The brief specifies a fixed capacity in entries, so that is what this implements.

There is no persistence or warm restart. Everything is lost when the process dies, by design: this is a cache, not a store.

One benchmark result is worth reading carefully. Operation count stays flat, but wall-clock time does not: `get` throughput roughly halves at 1M entries compared to 1k. That is CPU cache locality, not a hidden non-O(1) cost. At a million entries the dict and the linked-list nodes no longer fit in L2/L3, so each pointer chase is more likely to reach main memory.
