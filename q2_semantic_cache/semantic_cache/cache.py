"""The semantic cache itself.

``SemanticCache.lookup`` is the whole risk-bounding story in one call stack, in order, cheapest
and safest check first:

1. **Policy** (``policy.is_cacheable``) -- refuse time-sensitive/personal/PII/tool-using/
   high-temperature queries outright. No embedding, no index touched.
2. **Partition scope** -- everything below only ever looks inside the partition for this exact
   ``(tenant, model, system_prompt_hash, params_hash, embedder.model_id)``. A match in another
   partition is not just "wrong", it can be a cross-tenant data leak, so this isn't a similarity
   check, it's a dict lookup that makes cross-partition matches structurally impossible.
3. **Exact match** -- hash the original query unchanged. Case, whitespace, and Unicode
   compatibility characters can change code, identifiers, units, or mathematics. Reworded
   queries go through the guarded semantic path.
4. **Embed + search** the partition's vector index, take the best-scoring live (non-expired)
   candidate.
5. **Threshold**: below ``tau_verify`` -> miss. ``tau_verify..tau_hit`` -> grey zone, ask the
   ``Verifier``. Above ``tau_hit`` -> would serve, pending guards.
6. **Guards** (``guards.py``) -- deterministic checks for the failure modes embeddings are known
   to miss: numbers/dates, negation, entities, direction. Run on any candidate that cleared
   ``tau_verify``, whether or not the verifier is also consulted. A guard failure is always a
   miss, never overridable by score.
7. **Mode**: in ``"shadow"`` mode, everything above still runs and is logged (so you can measure
   what the cache *would* do against real traffic), but the caller always gets a ``Miss``. That
   is how you roll this out without betting production correctness on day-one thresholds.
"""

from __future__ import annotations

import hashlib
import itertools
import math
import threading
import time
from collections import Counter, OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from semantic_cache import guards, policy
from semantic_cache.embedders import Embedder
from semantic_cache.index import NumpyIndex, VectorIndex
from semantic_cache.types import CacheContext, Hit, Miss
from semantic_cache.verifier import NoopVerifier, Verifier

PartitionKey = tuple[str, str, str, str, str]


def normalize_query(query: str) -> str:
    """Preserve the original text for exact matching and single-flight identity.

    Kept as a compatibility helper; lossy normalization must not bypass semantic guards.
    """
    return query


def _validate_ttl(ttl: float | None) -> None:
    if ttl is not None and (not math.isfinite(ttl) or ttl <= 0):
        raise ValueError("ttl must be finite and > 0, or None")


def exact_hash(query: str) -> str:
    return hashlib.sha256(normalize_query(query).encode("utf-8")).hexdigest()


class _Unset:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - repr only, for debugging
        return "<use cache default_ttl>"


_UNSET = _Unset()


@dataclass(slots=True)
class _Entry:
    id: str
    query: str
    normalized_hash: str
    response: Any
    ctx: CacheContext
    created_at: float
    expires_at: float | None
    good_feedback: int = 0
    bad_feedback: int = 0


@dataclass(slots=True)
class ShadowLogEntry:
    """One row of what shadow mode *would* have done, for offline review before flipping
    ``mode`` to ``"serve"``."""

    at: float
    query: str
    ctx: CacheContext
    would_be: Hit | Miss


@dataclass
class Metrics:
    """Counters for observability. ``misses``/``guard_rejections`` are ``Counter`` instead of
    fixed fields so a new miss/guard reason never requires touching this class."""

    hits_exact: int = 0
    hits_semantic: int = 0
    misses: Counter[str] = field(default_factory=Counter)
    guard_rejections: Counter[str] = field(default_factory=Counter)
    verifier_calls: int = 0
    capacity_evictions: int = 0
    ttl_expirations: int = 0
    bad_feedback_evictions: int = 0
    store_rejections: Counter[str] = field(default_factory=Counter)
    shadow_would_hit: int = 0
    shadow_would_miss: int = 0


class _Partition:
    """Everything scoped to one ``PartitionKey``: its own vector index, its own LRU order, its
    own exact-match map, its own lock. Partitions never share state, which is exactly the point:
    isolation is the mechanism, not a side effect.
    """

    __slots__ = ("entries", "exact_index", "index", "key", "lock", "order")

    def __init__(self, key: PartitionKey, dim: int, index_factory: Callable[[int], VectorIndex]) -> None:
        self.key = key
        self.entries: dict[str, _Entry] = {}
        self.order: OrderedDict[str, None] = OrderedDict()  # recency order; MRU at the end
        self.exact_index: dict[str, str] = {}  # normalized-query hash -> entry_id
        self.index: VectorIndex = index_factory(dim)
        self.lock = threading.RLock()

    def touch(self, entry_id: str) -> None:
        self.order.move_to_end(entry_id, last=True)


class SemanticCache:
    def __init__(
        self,
        embedder: Embedder,
        *,
        index_factory: Callable[[int], VectorIndex] = NumpyIndex,
        verifier: Verifier | None = None,
        tau_hit: float = 0.92,
        tau_verify: float = 0.80,
        top_k: int = 5,
        capacity_per_partition: int = 10_000,
        default_ttl: float | None = 3600.0,
        mode: Literal["serve", "shadow"] = "shadow",
        shadow_log_capacity: int = 1000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0.0 <= tau_verify <= tau_hit <= 1.0 + 1e-9:
            raise ValueError("require 0 <= tau_verify <= tau_hit <= 1")
        if capacity_per_partition < 1:
            raise ValueError("capacity_per_partition must be >= 1")
        if top_k < 1:
            raise ValueError("top_k must be >= 1")
        if mode not in {"serve", "shadow"}:
            raise ValueError("mode must be 'serve' or 'shadow'")
        if shadow_log_capacity < 1:
            raise ValueError("shadow_log_capacity must be >= 1")
        _validate_ttl(default_ttl)
        self.embedder = embedder
        self._index_factory = index_factory
        self.verifier: Verifier = verifier or NoopVerifier()
        self.tau_hit = tau_hit
        self.tau_verify = tau_verify
        self.top_k = top_k
        self.capacity_per_partition = capacity_per_partition
        self.default_ttl = default_ttl
        self.mode: Literal["serve", "shadow"] = mode
        self._clock = clock
        self._partitions: dict[PartitionKey, _Partition] = {}
        self._entry_partition: dict[str, PartitionKey] = {}
        self._partitions_lock = threading.RLock()  # guards partition creation only
        self._next_id = itertools.count(1)
        self.metrics = Metrics()
        self.shadow_log: deque[ShadowLogEntry] = deque(maxlen=shadow_log_capacity)

    # -- partitioning -----------------------------------------------------------------

    def partition_key_for(self, ctx: CacheContext) -> PartitionKey:
        """The embedder's ``model_id`` is folded in here (not stored on ``CacheContext``) because
        it is a property of *this cache's* configuration, not of the request: vectors from
        different embedding models live in incomparable spaces and must never share an index."""
        return (ctx.tenant, ctx.model, ctx.system_prompt_hash, ctx.params_hash, self.embedder.model_id)

    def _get_or_create_partition(self, key: PartitionKey) -> _Partition:
        partition = self._partitions.get(key)
        if partition is not None:
            return partition
        with self._partitions_lock:
            partition = self._partitions.get(key)
            if partition is None:
                partition = _Partition(key, self.embedder.dim, self._index_factory)
                self._partitions[key] = partition
            return partition

    # -- lookup -------------------------------------------------------------------------

    def lookup(
        self,
        query: str,
        ctx: CacheContext,
        *,
        has_tools: bool = False,
        temperature: float = 0.0,
    ) -> Hit | Miss:
        decision = policy.is_cacheable(query, ctx, has_tools=has_tools, temperature=temperature)
        if not decision.cacheable:
            self.metrics.misses[decision.reason or "not_cacheable"] += 1
            return Miss(reason=decision.reason or "not_cacheable")
        result = self._lookup_internal(query, ctx, has_tools=has_tools, temperature=temperature)
        if self.mode == "shadow":
            self.shadow_log.append(ShadowLogEntry(at=self._clock(), query=query, ctx=ctx, would_be=result))
            if isinstance(result, Hit):
                self.metrics.shadow_would_hit += 1
                return Miss(reason="shadow_mode", best_score=result.score)
            self.metrics.shadow_would_miss += 1
            return result
        return result

    def _lookup_internal(
        self,
        query: str,
        ctx: CacheContext,
        *,
        has_tools: bool,
        temperature: float,
    ) -> Hit | Miss:
        decision = policy.is_cacheable(query, ctx, has_tools=has_tools, temperature=temperature)
        if not decision.cacheable:
            self.metrics.misses[decision.reason or "not_cacheable"] += 1
            return Miss(reason=decision.reason or "not_cacheable")

        key = self.partition_key_for(ctx)
        partition = self._partitions.get(key)
        if partition is None or not partition.entries:
            self.metrics.misses["empty_partition"] += 1
            return Miss(reason="empty_partition")

        with partition.lock:
            exact_id = partition.exact_index.get(exact_hash(query))
            if exact_id is not None:
                entry = partition.entries.get(exact_id)
                if entry is not None and not self._is_expired(entry):
                    partition.touch(exact_id)
                    self.metrics.hits_exact += 1
                    return Hit(
                        response=entry.response, score=1.0, matched_query=entry.query, reason="exact", entry_id=entry.id
                    )
                if entry is not None:
                    self._purge_expired(partition, exact_id)

            if not partition.entries:
                self.metrics.misses["empty_partition"] += 1
                return Miss(reason="empty_partition")

            vector = self.embedder.embed([query])[0]
            candidates = partition.index.search(vector, self.top_k)
            best: tuple[str, float] | None = None
            for cand_id, score in candidates:
                entry = partition.entries.get(cand_id)
                if entry is None:
                    continue
                if self._is_expired(entry):
                    self._purge_expired(partition, cand_id)
                    continue
                best = (cand_id, score)
                break  # candidates are sorted descending; first live one is the best

            if best is None:
                self.metrics.misses["no_live_candidates"] += 1
                return Miss(reason="no_live_candidates")

            cand_id, score = best
            entry = partition.entries[cand_id]

            if score < self.tau_verify:
                self.metrics.misses["below_threshold"] += 1
                return Miss(reason="below_threshold", best_score=score)

            failure = guards.first_failure(query, entry.query)
            if failure is not None:
                guard_name, guard_reason = failure
                self.metrics.guard_rejections[guard_name] += 1
                self.metrics.misses[f"guard:{guard_name}"] += 1
                return Miss(reason=f"guard:{guard_name}: {guard_reason}", best_score=score)

            if score >= self.tau_hit:
                partition.touch(cand_id)
                self.metrics.hits_semantic += 1
                return Hit(
                    response=entry.response,
                    score=score,
                    matched_query=entry.query,
                    reason="semantic",
                    entry_id=entry.id,
                )

            # grey zone: tau_verify <= score < tau_hit, guards already passed
            self.metrics.verifier_calls += 1
            if self.verifier.same_intent(query, entry.query):
                partition.touch(cand_id)
                self.metrics.hits_semantic += 1
                return Hit(
                    response=entry.response,
                    score=score,
                    matched_query=entry.query,
                    reason="semantic+verified",
                    entry_id=entry.id,
                )
            self.metrics.misses["verifier_rejected"] += 1
            return Miss(reason="verifier_rejected", best_score=score)

    # -- store / invalidate / feedback ---------------------------------------------------

    def store(
        self,
        query: str,
        response: Any,
        ctx: CacheContext,
        ttl: float | None | _Unset = _UNSET,
        *,
        has_tools: bool = False,
        temperature: float = 0.0,
    ) -> str | None:
        """Store ``response`` under ``query`` in ``ctx``'s partition.

        The same cacheability policy used by lookup is enforced here so personal, PII,
        time-sensitive, tool-using, and high-temperature requests are not retained even when a
        caller invokes store directly.

        ``ttl`` follows the Q1 convention: omit it to use ``self.default_ttl``; pass an explicit
        ``float`` for a per-entry override; pass ``None`` explicitly for "never expires". If a
        normalized-equal query is already cached in this partition, this **upserts** that entry
        (refreshes response/TTL/recency, re-embeds) instead of storing a duplicate vector --
        otherwise repeated storage of the same question would silently grow the index without
        ever being hit via the (cheaper) exact-match path.
        """
        decision = policy.is_cacheable(query, ctx, has_tools=has_tools, temperature=temperature)
        if not decision.cacheable:
            self.metrics.store_rejections[decision.reason or "not_cacheable"] += 1
            return None

        resolved_ttl = self.default_ttl if isinstance(ttl, _Unset) else ttl
        _validate_ttl(resolved_ttl)
        now = self._clock()
        expires_at = None if resolved_ttl is None else now + resolved_ttl

        key = self.partition_key_for(ctx)
        partition = self._get_or_create_partition(key)
        vector = self.embedder.embed([query])[0]
        qhash = exact_hash(query)

        with partition.lock:
            existing_id = partition.exact_index.get(qhash)
            if existing_id is not None and existing_id in partition.entries:
                partition.index.add(existing_id, vector)  # validate before changing the cached answer
                entry = partition.entries[existing_id]
                entry.query = query
                entry.response = response
                entry.created_at = now
                entry.expires_at = expires_at
                partition.touch(existing_id)
                return existing_id

            entry_id = f"{key[0]}:{next(self._next_id)}"
            partition.index.add(entry_id, vector)  # failure must not install an exact-only entry or evict one
            if len(partition.entries) >= self.capacity_per_partition:
                self._evict_lru(partition)

            partition.entries[entry_id] = _Entry(
                id=entry_id,
                query=query,
                normalized_hash=qhash,
                response=response,
                ctx=ctx,
                created_at=now,
                expires_at=expires_at,
            )
            partition.exact_index[qhash] = entry_id
            partition.order[entry_id] = None
            self._entry_partition[entry_id] = key
            return entry_id

    def invalidate(self, entry_id: str) -> bool:
        key = self._entry_partition.get(entry_id)
        if key is None:
            return False
        partition = self._partitions[key]
        with partition.lock:
            return self._remove_entry(partition, entry_id) is not None

    def feedback(self, entry_id: str, good: bool) -> None:
        """Record user/downstream feedback on a served entry. Bad feedback evicts the entry
        immediately -- a single confirmed-wrong answer is enough to pull it, rather than waiting
        on TTL or an audit sample to catch up."""
        key = self._entry_partition.get(entry_id)
        if key is None:
            return
        partition = self._partitions[key]
        with partition.lock:
            entry = partition.entries.get(entry_id)
            if entry is None:
                return
            if good:
                entry.good_feedback += 1
                return
            entry.bad_feedback += 1
            self._remove_entry(partition, entry_id)
            self.metrics.bad_feedback_evictions += 1

    # -- internals ------------------------------------------------------------------------

    def _is_expired(self, entry: _Entry) -> bool:
        return entry.expires_at is not None and self._clock() >= entry.expires_at

    def _remove_entry(self, partition: _Partition, entry_id: str) -> _Entry | None:
        entry = partition.entries.pop(entry_id, None)
        partition.order.pop(entry_id, None)
        if entry is not None and partition.exact_index.get(entry.normalized_hash) == entry_id:
            del partition.exact_index[entry.normalized_hash]
        partition.index.remove(entry_id)
        self._entry_partition.pop(entry_id, None)
        return entry

    def _purge_expired(self, partition: _Partition, entry_id: str) -> None:
        if self._remove_entry(partition, entry_id) is not None:
            self.metrics.ttl_expirations += 1

    def _evict_lru(self, partition: _Partition) -> None:
        if not partition.order:
            return
        lru_id = next(iter(partition.order))
        if self._remove_entry(partition, lru_id) is not None:
            self.metrics.capacity_evictions += 1
