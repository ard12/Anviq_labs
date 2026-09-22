# Anviq Labs: product engineering problem statements

Four problems. Each one leans on the one before it.

| # | Problem | Where | Builds on |
|---|---------|-------|-----------|
| 1 | O(1) LRU cache with per-key TTL | [`q1_lru_ttl/`](q1_lru_ttl/) | |
| 2 | Semantic cache in front of an LLM API | [`q2_semantic_cache/`](q2_semantic_cache/) | Q1 (TTL/eviction) |
| 3 | Tool-use harness: record, diff, CI gate for tool "rug-pulls" | [`q3_tool_harness/`](q3_tool_harness/) | shared [`schema/`](schema/) |
| 4 | Trust and observability layer for agents calling third-party tools | [`q4_trust_layer/`](q4_trust_layer/) | Q3 (differ, recording format) |

If you read one thing, read [`q4_trust_layer/DESIGN.md`](q4_trust_layer/DESIGN.md). It carries the most reasoning, and the first three problems feed into it.

Every folder has a `DECISIONS.md` saying what I picked, what I turned down, and why: [Q1](q1_lru_ttl/DECISIONS.md), [Q2](q2_semantic_cache/DECISIONS.md), [Q3](q3_tool_harness/DECISIONS.md), [Q4](q4_trust_layer/DECISIONS.md). The decisions that cut across all four are in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Shared contract

[`schema/`](schema/) holds the recording format (`recording.schema.json`), the reference canonicalization and hashing (`canonical.py`, RFC 8785 JCS + SHA-256), and `golden_vectors.json`. Every Python and Go component has to reproduce those vectors byte for byte. That is what keeps the Go proxy in Q4 and the Python differ in Q3 agreeing about whether a tool definition changed.

## Run

```bash
python tasks.py test       # all test suites
python tasks.py demo-q3    # drift gate: benign change passes, rug-pull fails
python tasks.py eval-q2    # semantic-cache precision/recall at each threshold
python tasks.py demo-q4    # proxy catches a tool changing its contract mid-session
python tasks.py bench      # proxy overhead, p50/p99
```

Python 3.12 or newer, and Go 1.23+ for Q4's proxy (see the `go` directive in `q4_trust_layer/proxy/go.mod`). The tests and `demo-q4` need `pip install jsonschema pytest numpy hypothesis`.

## What each part contains

Q1 is a dict plus a hand-written doubly linked list, with expiry done lazily on read. It is property-tested against a deliberately naive reference model, which is the part I'd point at if you want evidence it's correct rather than just passing (63 tests).

Q2 partitions the cache by tenant, model and system prompt, then puts deterministic guards in front of the similarity score. Embeddings are bad at this on their own: the negation pairs in my eval set ("is X safe" against "is X not safe" and similar) average 0.97 cosine similarity, which is well above any threshold worth using. The threshold comes from the eval in [`q2_semantic_cache/EVAL_RESULTS.md`](q2_semantic_cache/EVAL_RESULTS.md), and the library defaults to shadow mode, so nothing is served from cache until someone looks at those numbers on real traffic (75 tests).

Q3 records a session to a hash-chained log and diffs two recordings across three layers: schema, description text and observed behaviour. It exits non-zero in CI, with an accept file for changes you meant to make (143 tests).

Q4 is the design document, a Go sidecar proxy whose overhead is measured rather than estimated, and a Python control plane that reuses Q3's differ (90 tests). `demo.py` runs the whole thing: a tool rewrites its own description mid-session, gets blocked, then quarantined across every other session.

The shared schema and hashing have their own 34 tests, cross-checked against an independent JCS implementation.
