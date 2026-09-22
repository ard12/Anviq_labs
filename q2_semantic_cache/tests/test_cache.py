from __future__ import annotations

import numpy as np
import pytest
from fakes import FakeClock, FakeEmbedder, unit_vector

from semantic_cache.cache import SemanticCache
from semantic_cache.types import CacheContext, Hit, Miss

CTX = CacheContext(tenant="acme", model="gpt-4o", system_prompt_hash="sp1", params_hash="p1")


class _AlwaysSameIntent:
    def same_intent(self, a: str, b: str) -> bool:
        return True


def make_cache(vectors: dict[str, list[float]], **kwargs) -> SemanticCache:
    kwargs.setdefault("mode", "serve")
    return SemanticCache(FakeEmbedder(vectors, dim=2), **kwargs)


def test_exact_hit() -> None:
    stored = "what is the capital of France?"
    cache = make_cache({stored: [1.0, 0.0]})
    cache.store(stored, "Paris", CTX)

    result = cache.lookup(stored, CTX)

    assert isinstance(result, Hit)
    assert result.reason == "exact"
    assert result.response == "Paris"
    assert result.score == 1.0
    assert cache.metrics.hits_exact == 1


def test_exact_normalization_preserves_semantically_meaningful_punctuation() -> None:
    stored, query = "What is 1.5 + 2?", "What is 15 + 2?"
    cache = make_cache({stored: [1.0, 0.0], query: unit_vector(0.2)})
    cache.store(stored, "3.5", CTX)

    result = cache.lookup(query, CTX)

    assert isinstance(result, Miss)
    assert result.reason == "below_threshold"


def test_semantic_hit_above_threshold() -> None:
    stored, query = "what is the capital of France", "capital of France, what is it"
    cache = make_cache({stored: [1.0, 0.0], query: unit_vector(0.95)})
    cache.store(stored, "Paris", CTX)

    result = cache.lookup(query, CTX)

    assert isinstance(result, Hit)
    assert result.reason == "semantic"
    assert result.score == pytest.approx(0.95)
    assert result.matched_query == stored
    assert cache.metrics.hits_semantic == 1


def test_miss_below_threshold() -> None:
    stored, query = "what is the capital of France", "what's the best way to bake sourdough bread"
    cache = make_cache({stored: [1.0, 0.0], query: unit_vector(0.2)})
    cache.store(stored, "Paris", CTX)

    result = cache.lookup(query, CTX)

    assert isinstance(result, Miss)
    assert result.reason == "below_threshold"
    assert result.best_score == pytest.approx(0.2)


def test_grey_zone_rejected_by_default_noop_verifier() -> None:
    stored, query = "what is the capital of France", "what's France's capital, exactly"
    cache = make_cache({stored: [1.0, 0.0], query: unit_vector(0.85)})  # between tau_verify/tau_hit
    cache.store(stored, "Paris", CTX)

    result = cache.lookup(query, CTX)

    assert isinstance(result, Miss)
    assert result.reason == "verifier_rejected"
    assert cache.metrics.verifier_calls == 1


def test_grey_zone_confirmed_by_permissive_verifier() -> None:
    stored, query = "what is the capital of France", "what's France's capital, exactly"
    cache = make_cache({stored: [1.0, 0.0], query: unit_vector(0.85)}, verifier=_AlwaysSameIntent())
    cache.store(stored, "Paris", CTX)

    result = cache.lookup(query, CTX)

    assert isinstance(result, Hit)
    assert result.reason == "semantic+verified"
    assert cache.metrics.verifier_calls == 1
    assert cache.metrics.hits_semantic == 1


def test_partition_isolation_by_tenant() -> None:
    stored = "what is the capital of France"
    cache = make_cache({stored: [1.0, 0.0]})
    cache.store(stored, "Paris", CTX)
    other_tenant = CacheContext(
        tenant="other-tenant", model=CTX.model, system_prompt_hash=CTX.system_prompt_hash, params_hash=CTX.params_hash
    )

    result = cache.lookup(stored, other_tenant)

    assert isinstance(result, Miss)
    assert result.reason == "empty_partition"


def test_partition_isolation_by_model() -> None:
    stored = "what is the capital of France"
    cache = make_cache({stored: [1.0, 0.0]})
    cache.store(stored, "Paris", CTX)
    other_model = CacheContext(
        tenant=CTX.tenant, model="gpt-3.5-turbo", system_prompt_hash=CTX.system_prompt_hash, params_hash=CTX.params_hash
    )

    result = cache.lookup(stored, other_model)

    assert isinstance(result, Miss)
    assert result.reason == "empty_partition"


def test_guard_rejects_hard_negative_even_above_tau_hit() -> None:
    """The embedder here scores the pair at 0.97 -- well above tau_hit -- simulating exactly the
    failure mode guards exist for: an embedding model that is fooled by shared vocabulary."""
    stored, query = "top 5 startups in fintech", "top 10 startups in fintech"
    cache = make_cache({stored: [1.0, 0.0], query: unit_vector(0.97)})
    cache.store(stored, "Stripe, Plaid, ...", CTX)

    result = cache.lookup(query, CTX)

    assert isinstance(result, Miss)
    assert result.reason.startswith("guard:numbers")
    assert cache.metrics.guard_rejections["numbers"] == 1


def test_policy_runs_before_semantic_match() -> None:
    """Even with a near-perfect embedding score, a personal query is refused before the index is
    ever consulted."""
    stored, query = "what is the capital of France", "what is my favorite color"
    cache = make_cache({stored: [1.0, 0.0], query: unit_vector(0.99)})
    cache.store(stored, "Paris", CTX)

    result = cache.lookup(query, CTX)

    assert isinstance(result, Miss)
    assert result.reason == "personal query"


def test_ttl_expiry() -> None:
    stored = "what is the capital of France"
    clock = FakeClock()
    cache = make_cache({stored: [1.0, 0.0]}, default_ttl=100.0, clock=clock)
    cache.store(stored, "Paris", CTX)

    clock.advance(99.0)
    assert isinstance(cache.lookup(stored, CTX), Hit)

    clock.advance(1.0)  # now == expires_at: boundary counts as expired
    result = cache.lookup(stored, CTX)
    assert isinstance(result, Miss)
    assert cache.metrics.ttl_expirations == 1


def test_ttl_none_never_expires() -> None:
    stored = "what is the capital of France"
    clock = FakeClock()
    cache = make_cache({stored: [1.0, 0.0]}, default_ttl=None, clock=clock)
    cache.store(stored, "Paris", CTX)

    clock.advance(10_000_000.0)

    assert isinstance(cache.lookup(stored, CTX), Hit)


def test_capacity_eviction_evicts_lru() -> None:
    q1, q2, q3 = "query one", "query two", "query three"
    vectors = {q1: [1.0, 0.0], q2: [0.0, 1.0], q3: [-1.0, 0.0]}
    cache = make_cache(vectors, capacity_per_partition=2)

    cache.store(q1, "r1", CTX)
    cache.store(q2, "r2", CTX)
    cache.store(q3, "r3", CTX)  # partition full at q1,q2 -> evicts q1 (least recently used)

    assert isinstance(cache.lookup(q1, CTX), Miss)
    assert isinstance(cache.lookup(q2, CTX), Hit)
    assert isinstance(cache.lookup(q3, CTX), Hit)
    assert cache.metrics.capacity_evictions == 1


def test_feedback_good_keeps_entry() -> None:
    stored = "what is the capital of France"
    cache = make_cache({stored: [1.0, 0.0]})
    cache.store(stored, "Paris", CTX)
    hit = cache.lookup(stored, CTX)
    assert isinstance(hit, Hit)

    cache.feedback(hit.entry_id, good=True)

    assert isinstance(cache.lookup(stored, CTX), Hit)
    assert cache.metrics.bad_feedback_evictions == 0


def test_feedback_bad_evicts_entry() -> None:
    stored = "what is the capital of France"
    cache = make_cache({stored: [1.0, 0.0]})
    cache.store(stored, "Paris", CTX)
    hit = cache.lookup(stored, CTX)
    assert isinstance(hit, Hit)

    cache.feedback(hit.entry_id, good=False)

    result = cache.lookup(stored, CTX)
    assert isinstance(result, Miss)
    assert cache.metrics.bad_feedback_evictions == 1


def test_shadow_mode_never_serves_but_tracks_would_be_hits() -> None:
    stored = "what is the capital of France"
    cache = make_cache({stored: [1.0, 0.0]}, mode="shadow")
    cache.store(stored, "Paris", CTX)

    result = cache.lookup(stored, CTX)

    assert isinstance(result, Miss)
    assert result.reason == "shadow_mode"
    assert cache.metrics.hits_exact == 1  # the internal decision is still tracked
    assert cache.metrics.shadow_would_hit == 1
    assert len(cache.shadow_log) == 1
    assert isinstance(cache.shadow_log[0].would_be, Hit)


def test_shadow_mode_is_the_safe_default() -> None:
    stored = "what is the capital of France"
    cache = SemanticCache(FakeEmbedder({stored: [1.0, 0.0]}, dim=2))
    cache.store(stored, "Paris", CTX)

    result = cache.lookup(stored, CTX)

    assert isinstance(result, Miss)
    assert result.reason == "shadow_mode"


def test_store_rejects_personal_queries_without_retaining_them() -> None:
    query = "what is my account balance"
    cache = make_cache({query: [1.0, 0.0]})

    entry_id = cache.store(query, "private", CTX)

    assert entry_id is None
    assert not cache._partitions
    assert cache.metrics.store_rejections["personal query"] == 1


def test_invalidate_removes_entry() -> None:
    stored = "what is the capital of France"
    cache = make_cache({stored: [1.0, 0.0]})
    entry_id = cache.store(stored, "Paris", CTX)

    assert cache.invalidate(entry_id) is True
    assert isinstance(cache.lookup(stored, CTX), Miss)
    assert cache.invalidate(entry_id) is False  # already gone


def test_store_upserts_same_normalized_query() -> None:
    stored = "what is the capital of France?"
    cache = make_cache({stored: [1.0, 0.0]})

    id1 = cache.store(stored, "Paris (old)", CTX)
    id2 = cache.store(stored, "Paris (new)", CTX)

    assert id1 == id2
    result = cache.lookup(stored, CTX)
    assert isinstance(result, Hit)
    assert result.response == "Paris (new)"


def test_invalid_thresholds_raise() -> None:
    with pytest.raises(ValueError):
        make_cache({}, tau_hit=0.5, tau_verify=0.8)  # tau_verify > tau_hit


@pytest.mark.parametrize(
    "stored,query",
    [
        ("simplify x²", "simplify x2"),
        ("explain variable Foo", "explain variable foo"),
        ('count spaces in "a  b"', 'count spaces in "a b"'),
    ],
)
def test_exact_path_does_not_collapse_meaningful_text(stored, query):
    cache = make_cache({stored: [1.0, 0.0], query: unit_vector(0.2)})
    cache.store(stored, "stored answer", CTX)
    assert isinstance(cache.lookup(query, CTX), Miss)
    cache.store(query, "different answer", CTX)
    assert cache.lookup(stored, CTX).response == "stored answer"


def test_shadow_does_not_retain_policy_refused_queries():
    cache = make_cache({}, mode="shadow")
    assert cache.lookup("what is my account balance", CTX).reason == "personal query"
    assert not cache.shadow_log
    assert not cache._partitions


def test_shadow_log_is_bounded():
    cache = make_cache({}, mode="shadow", shadow_log_capacity=2)
    for query in ("first", "second", "third"):
        cache.lookup(query, CTX)
    assert [entry.query for entry in cache.shadow_log] == ["second", "third"]


@pytest.mark.parametrize("ttl", [0, -1, float("nan"), float("inf"), float("-inf")])
def test_invalid_ttl_rejected_before_storage(ttl):
    with pytest.raises(ValueError):
        make_cache({}, default_ttl=ttl)
    cache = make_cache({})
    with pytest.raises(ValueError):
        cache.store("query", "answer", CTX, ttl=ttl)
    assert not cache._partitions


def test_typo_in_mode_cannot_silently_enable_serving():
    with pytest.raises(ValueError):
        make_cache({}, mode="shadwo")


def test_bad_embedding_does_not_corrupt_or_evict_existing_entry():
    query = "valid query"
    cache = make_cache({query: [1.0, 0.0]}, capacity_per_partition=1)
    cache.store(query, "original", CTX)
    cache.embedder.embed = lambda texts: np.array([[float("nan"), 0.0]])
    for attempted_query in (query, "new query"):
        with pytest.raises(ValueError):
            cache.store(attempted_query, "bad answer", CTX)
        assert cache.lookup(query, CTX).response == "original"
    assert len(cache._partitions[cache.partition_key_for(CTX)].entries) == 1
