# Decision log

One entry per non-obvious choice. Format: **Decision** / Alternatives / Why / Revisit when.
Entries are grouped by problem. If you can't defend an entry out loud, rewrite or delete it.

---

## Cross-cutting

### D-001 Hybrid languages: Python everywhere, Go only for the Q4 hot path
- **Alternatives:** all Python; all Go; TypeScript (native MCP SDK).
- **Why:** Python gives the fastest iteration and the best LLM/embedding ecosystem for Q1–Q3. The only place where language performance changes the answer is the Q4 per-call interceptor, which has a latency budget and must handle thousands of concurrent sessions. Go's goroutines and low GC pauses fit that. The two halves meet at one language-neutral contract (D-002), so the split is a boundary, not a mess.
- **Revisit when:** the Go proxy isn't green by Sun 12:00. Then fall back to a Python asyncio proxy and keep Go as the stated v2.

### D-002 One recording format (JSONL + JSON Schema) shared by Q3 and Q4
- **Alternatives:** protobuf; OpenTelemetry spans; per-component ad-hoc JSON.
- **Why:** JSONL can be appended, streamed and grepped, and needs no codegen. A recording from the Q3 harness and an audit log from the Q4 proxy are the same thing, so replay and diff tooling work on both. OTel is where this goes in production (export adapter), but its span model is a poor fit for "the definition in force at call time".
- **Revisit when:** event volume makes JSON parsing the bottleneck. Then use protobuf on the wire, with JSONL still available as the export format.

### D-003 Canonical hash = RFC 8785 (JCS) + SHA-256, with minimal normalization
- **Alternatives:** `json.dumps(sort_keys=True)`; hash the raw bytes; a semantic normalization (resolve `$ref`, normalize descriptions) before hashing.
- **Why:** Python and Go must agree byte-for-byte, or the proxy flags drift that isn't there (or misses drift that is). `sort_keys` differs from JCS on number formatting (`1.0` vs `1`, `1e-06` vs `0.000001`) and on non-BMP key ordering. The normalization before hashing is kept deliberately tiny (drop `$comment`, sort and dedupe `required`), so the hot path does not need a JSON-Schema engine. "Is this change meaningful?" is answered by the differ, off the hot path. The description is inside the hash on purpose.
- **Evidence:** `schema/golden_vectors.json`, checked by `schema/test_canonical.py` and cross-checked against the independent `jcs` PyPI library (0 mismatches). The Go proxy must pass the same vectors.

### D-004 Hash-chained events (`prev_hash`/`event_hash`)
- **Alternatives:** no integrity; sign every event; external append-only store only.
- **Why:** Q4 has to answer "can we trust what just happened". A per-session hash chain makes deletion or edits detectable for the cost of one SHA-256 per event, and needs no key management in v1. Signing the chain head is the v2 step.

### D-005 `tasks.py` instead of a Makefile
- **Why:** development happens on Windows, where there is no `make`. One Python entry point runs the same commands locally and in CI.

---

## Q1 LRU + TTL
_(merged from `q1_lru_ttl/DECISIONS.md` at validation: DLL vs OrderedDict, lazy vs active expiry, clock injection, locking.)_

## Q2 Semantic cache
_(merged from `q2_semantic_cache/DECISIONS.md` at validation: partition key, threshold choice + eval evidence, guards, index choice, single-flight.)_

## Q3 Tool harness
_(merged from `q3_tool_harness/DECISIONS.md` at validation: severity model, rename heuristic, description-risk rules, accept-file workflow, SARIF.)_

## Q4 Trust layer
_(merged from `q4_trust_layer/DECISIONS.md` at validation: sidecar vs gateway, policy matrix, latency budget, sharding, fail-open/closed, v1 cuts.)_
