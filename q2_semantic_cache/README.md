# Q2: semantic cache in front of an LLM API

## Problem

Exact-match caching of LLM calls has a low hit rate because people rephrase. "What's the capital of France?" and "capital of france" are the same question and two separate cache misses. Matching on meaning raises the hit rate, but it introduces a failure mode that exact-match caching structurally cannot have: serving a confidently wrong answer to a question that only looks like the cached one. "Top 5 startups in fintech" and "top 10 startups in fintech" are nearly identical strings and different questions with different correct answers.

So the hard part is not detecting lookalikes. Embed, take a cosine, done. The hard part is bounding how often a lookalike gets served as a match.

## Approach

`SemanticCache.lookup(query, ctx)` runs a fixed pipeline, cheapest and safest check first:

```
policy.is_cacheable()  --refuse-->  Miss("time-sensitive query" | "personal query" | "request has tool calls" | ...)
        |
        v (partition = tenant + model + system_prompt_hash + params_hash + embedder.model_id)
original-text exact-match hash  --hit-->  Hit(reason="exact", score=1.0)
        |
        v
embed(query) + search partition's index, take best live candidate
        |
        v
score < tau_verify (0.80)  -->  Miss("below_threshold")
        |
        v
guards.first_failure(query, matched)  --fail-->  Miss("guard:<name>: <reason>")
        |
        v
score >= tau_hit (0.92)  -->  Hit(reason="semantic")
        |
        v (tau_verify <= score < tau_hit: the grey zone)
verifier.same_intent(query, matched)  --false-->  Miss("verifier_rejected")
        |
        v (true)
Hit(reason="semantic+verified")
```

Two properties hold throughout. Every step that can say no runs before every step that costs more, and every step that says yes is followed by at least one check allowed to overrule it.

Nothing above the pipeline can skip a stage. `mode="shadow"` runs the whole decision and then overrides the final answer to `Miss`, rather than being a second code path that could quietly drift away from `"serve"` mode. Shadow is the constructor default. Serving cached answers is an explicit opt-in, after validation against your own traffic.

Every `Embedder` in `embedders.py` returns L2-normalized vectors, so cosine similarity is a plain dot product. `NumpyIndex` in `index.py` is brute force and exact rather than approximate, over one dense matrix per partition. The trade-offs section explains why that is the right choice at this scale and what to replace it with beyond it.

Partitioning is worth calling out, because it does the work people usually expect a policy check to do. `tenant`, `model`, `system_prompt_hash` and `params_hash` from `CacheContext`, plus the embedding model's `model_id`, select a partition through `SemanticCache.partition_key_for`. Each partition owns its index, its LRU order and its exact-match map. A lookup has no code path that can see another partition's vectors, because there is no shared structure to search across by accident.

## Bounding the risk of a wrong hit

**1. Scope.** Every lookup is confined to one partition. This is a dict lookup on an exact tuple, not a similarity check that could be fooled. Two different system prompts are two different programs reading the same user text, so serving one prompt's answer under another is not a near miss, it is silently wrong. Because `tenant` is in the key, cross-tenant leakage is impossible by construction rather than forbidden by policy.

**2. A precision-first threshold, taken from evidence.** `eval.py` sweeps `tau_hit` from 0.70 to 0.98 against 70 hand-labelled pairs in `data/pairs.jsonl`, weighted towards hard negatives, and reports the lowest threshold whose false-hit rate stays at or under 5% with guards on. Measured with MiniLM, 0.92 gives a 2% false-hit rate over the negative pairs, against 30% with guards off. Precision is 0.75 and recall 0.15, so one in four served hits in that eval is wrong. That is not good enough to serve by default, which is why the cache ships in shadow mode. `EVAL_RESULTS.md` has the full table; `DECISIONS.md` records the known misses (scope changes carrying no digit, negation or entity, such as marathon against half marathon) and the small-sample caveat.

**3. A cost model behind the threshold.** What the threshold really encodes is `P(correct)·saving > P(wrong)·cost_wrong`. A wrong cached answer to "is this drug interaction dangerous" costs far more than a wrong answer about otters, so `cost_wrong` is not one number across domains. This implementation does not try to compute it per domain, since that is a product decision rather than a library default. What it gives you is the knob: raise `tau_hit` and `tau_verify`, switch to shadow, or route certain `CacheContext` partitions to no caching at all. `policy.is_cacheable` already refuses the clearest high-risk shapes, personal data and PII, whatever the threshold says.

**4. Deterministic guards for what embeddings are known to miss.** `guards.py` compares numbers and dates as sets ("top 5" against "top 10", "2023" against "2024"), negation parity ("is X safe" against "is X not safe"), capitalized-entity sets (Austria against Australia, Python against Java), and comparison or direction words (buy against sell, before against after). They run on every candidate that clears `tau_verify`, including candidates scoring above `tau_hit`, because a high cosine score is exactly what these categories produce: shared vocabulary, one decisive word different. `tests/test_cache.py::test_guard_rejects_hard_negative_even_above_tau_hit` pins this with a pair scoring 0.97.

**5. A verifier, used narrowly.** Scores between `tau_verify` and `tau_hit` go to a `Verifier`. The default is `NoopVerifier`, which always says no; `DECISIONS.md` covers why refusing is the safe default. A real verifier, a cross-encoder or `LLMJudgeVerifier`, only ever runs inside that band, so its cost never lands on the common hit or the below-threshold miss.

**6. Freshness, and categories that are never cached.** TTL is per entry with lazy expiry, and `None` means never expires. It bounds how stale a served answer can be. Before any similarity work, `policy.is_cacheable` refuses time-sensitive queries ("today", "latest", "current price") and personal ones ("my", "I"). A perfect semantic match to a stale or non-shareable answer is still wrong, which makes this a category refusal rather than a threshold problem.

**7. Shadow mode, feedback eviction, monitoring.** Shadow mode runs the full decision and logs what would have been served without touching a real response, which is the rollout path for a new deployment or a newly lowered threshold. `feedback(entry_id, good=False)` evicts on a single confirmed-wrong report instead of waiting for the TTL. The layer above this in production samples served hits for review and tracks the measured false-hit rate against the eval-set one; when those diverge, either the eval set or the threshold needs work. That loop is not built here. The shadow log keeps at most 1,000 eligible observations by default, and policy-refused queries never enter it.

**8. Poisoning.** Storage is per partition, so a poisoned entry in one tenant's cache cannot surface in another's. `store()` applies the same cacheability policy as `lookup()`, so personal, PII-bearing, time-sensitive, tool-using and high-temperature requests are never retained. There is no output-quality check on otherwise cacheable responses before storage; that gap is in the limitations below.

## Complexity and trade-offs

| Operation | Complexity | Notes |
|---|---|---|
| `lookup` exact-match path | O(L) hashing plus O(1) average lookup | `L` is query length; original text is preserved |
| `lookup` semantic path | O(n·d) per partition | `n` = live entries in the partition, `d` = embedding dim; brute-force matmul |
| `store` | O(n·d) | re-embeds (O(d) per call here, less if the embedder batches) plus one index insert; O(n) when it triggers an LRU eviction |
| `invalidate` / `feedback(good=False)` | O(1) amortized dict ops plus O(n) index removal | `NumpyIndex.remove` rebuilds the matrix without the removed row |
| TTL expiry | O(1) per checked entry, lazy | checked only when an entry is looked up or is a top-k candidate; a dead entry nobody queries again is never proactively swept |

`NumpyIndex` does exact cosine similarity by brute force. It is deliberately not an approximate nearest neighbour index: no graph, no tree, no recall-for-speed trade, no "probe more nodes" knob. That holds up to roughly 100k entries per partition, where a 100k by 384 float64 matmul takes a handful of milliseconds. Past that, or if you expect one partition to grow that large, put an HNSW-backed index behind the same `VectorIndex` protocol of `add`, `search` and `remove`: FAISS, pgvector's `hnsw` index type, or Qdrant. Nothing above `index.py` changes, because `SemanticCache` takes an `index_factory: Callable[[int], VectorIndex]`.

Single-flight in `client.py` is built on threads rather than asyncio. `llm_call` is a plain synchronous callable, which is the shape most LLM SDKs already expose, so a registry of `threading.Event`s behind a `threading.Lock` is the natural fit, and the GIL makes the bookkeeping atomic without further coordination. An asyncio version runs the identical algorithm with `asyncio.Lock` and `asyncio.Event`, at the price of forcing every caller onto an event loop. `DECISIONS.md` has the full argument.

## How to run

From this directory:
```bash
pip install -e ".[dev]"       # numpy + pytest + hypothesis
pytest -q                     # 75 tests, no network, no model download
python eval.py                # threshold sweep -> prints table, writes EVAL_RESULTS.md
ruff check .                  # from the repo root: `ruff check q2_semantic_cache`
```
From the repo root:
```bash
python tasks.py test          # runs this suite along with every other package's
python tasks.py eval-q2       # same as `python eval.py` above, run from the repo root
```

Optional extras, none of them needed for the tests:
```bash
pip install -e ".[local-embed]"   # sentence-transformers all-MiniLM-L6-v2, for real eval numbers
pip install -e ".[api-embed]"     # OpenAIEmbedder (needs OPENAI_API_KEY)
pip install -e ".[llm-judge]"     # LLMJudgeVerifier.using_openai (needs OPENAI_API_KEY)
```

### Minimal usage sketch

```python
from semantic_cache import CacheContext, CachedLLM, HashingEmbedder, SemanticCache

cache = SemanticCache(HashingEmbedder(dim=256), mode="serve")  # opt in only after shadow validation
client = CachedLLM(llm_call=my_llm_call, cache=cache)

ctx = CacheContext(tenant="acme", model="gpt-4o", system_prompt_hash="sp1", params_hash="p1")
result = client.call("What is the capital of France?", ctx)
print(result.x_cache_header)   # "X-Cache: HIT-SEMANTIC; score=0.93" (or MISS on the first call)
```

## Known limitations and what I would do next

`EVAL_RESULTS.md` came from the real `all-MiniLM-L6-v2` embedder, via `pip install -e ".[local-embed]"` and then `python tasks.py eval-q2`. Without that extra, `eval.py` falls back to `HashingEmbedder` and says loudly that the numbers mean nothing, so regenerate the file with the extra installed. The eval set is 70 pairs I wrote by hand, which makes the numbers directional rather than precise. `DECISIONS.md` lists the known misses under "Threshold choice + eval evidence": scope changes with no digit, negation or entity to catch, and the entity guard rejecting some true paraphrases.

There is no per-domain `cost_wrong`. The threshold is one global number. A deployment putting both "fun facts" and "medical dosage" traffic through the same cache should route the second to a much higher threshold, to shadow mode, or past the cache entirely, keyed off something in `CacheContext` such as a domain tag (today that is folded opaquely into `system_prompt_hash`). The `ctx` parameter in `policy.py` exists for this and is not used yet.

There is no output-quality gate before `store()`. Cacheability is enforced on both lookup and storage, but for an eligible query the response is stored as given, which in `CachedLLM` means the wrapped `llm_call` response verbatim. An output check belongs to the caller and is not implemented here.

Expiry is lazy, with no background sweep. An entry only gets purged when it is looked up, is the best semantic candidate, or is evicted for capacity. One that expires and is never queried again sits in memory until capacity eviction reaches it. A sweep thread would bound memory more tightly.

Nothing samples served hits for audit. Point 7 above calls for tracking a measured false-hit rate separately from the eval set. `feedback()` is the hook for signal flowing back in, but the sampling itself is an operational process built on `metrics` and `shadow_log`, not a library feature.

Everything is in-process. Partitions, LRU order and single-flight coalescing live in one process's memory, so a multi-process or multi-host deployment gets independent caches with no shared state and no cross-process coalescing. Correct, but with a lower effective hit rate. Fixing it properly means a shared vector store and a distributed lock, which is its own project.

`NumpyIndex.remove` is O(n). Fine at the stated 100k per partition, but it would need attention, or the HNSW swap above, if invalidation and bad-feedback eviction became frequent on much larger partitions.
