# Q4 decisions (trust layer: `DESIGN.md`, `proxy/`)

Format: **Decision** / Alternatives / Why / Revisit when. Prefix `Q4-proxy`. If you cannot defend an entry out
loud, rewrite or delete it. Numbers quoted here are from `DESIGN.md` §6 (measured, not estimated).

---

### Q4-proxy-01 Per-host sidecar, not a central gateway
- **Decision:** the data plane is a sidecar proxy next to each agent host. The same binary can run as a per-cluster
  gateway for hosts that cannot run a sidecar.
- **Alternatives:** a single central gateway; an SDK/library inside each agent; a service mesh filter.
- **Why:** the budget is single-digit milliseconds, and a central choke point is both the latency floor (extra network
  hop, queueing behind all traffic) and the failure domain for every session. A sidecar's bug or overload hits one
  host. Its costs (config pushed to many nodes; needs network policy so agents cannot bypass it) are small because
  the only shared config is the small quarantine list. An in-agent SDK is not enforceable against a compromised or
  negligent agent; a mesh filter would tie us to one mesh and make hashing/schema logic awkward.
- **Revisit when:** policy needs to change faster than a poll can propagate, or fleet size makes per-host operation
  costly (then a regional gateway tier, still stateless apart from session state).

### Q4-proxy-02 Suspend the tool for the session on mismatch; do not abort the session
- **Decision:** on a `def_hash` mismatch the (session, tool) is suspended immediately and locally; calls get
  `TOOL_CONTRACT_CHANGED`. The control plane then escalates: resume, warn, stay suspended, or quarantine across sessions.
  If a later list restores the exact previously pinned, valid definition, the temporary per-session suspension is
  cleared; a fleet-wide quarantine still takes precedence.
- **Alternatives:** abort the session; warn and proceed; block until the control plane answers, for every tool.
- **Why:** most real changes are negligent and cosmetic or additive, so aborting destroys accumulated agent work for
  little safety gain. "Warn and proceed" is unsafe because the model is exactly what a rug-pull targets: a warning the
  model reads is not a control. Suspension is one flag under a lock (no network), and returns a structured error the
  agent can act on (re-plan or ask the user). Returning to the exact pinned hash restores the already-approved
  contract, so keeping that version blocked would turn a transient bad deployment into a permanent session denial.
- **Revisit when:** false-suspension rate is high (tune the policy table, not the mechanism), or a policy needs
  "abort the session on SECURITY" (add as a table option).

### Q4-proxy-03 Fail closed for side-effecting tools, fail open with audit for read-only, when control is unreachable
- **Decision:** while a tool is suspended with no verdict, and the control plane could not be reached, read-only tools
  (`readOnlyHint: true` on the new definition) are allowed against the new schema with a `policy_decision(warn)`;
  everything else stays blocked. Unannotated tools count as side-effecting. A failed report is retried on the next list.
- **Alternatives:** fail closed for everything; fail open for everything; per-tool operator flag only.
- **Why:** the costs are asymmetric. A stalled read-only tool loses a capability; an unvetted write/destructive tool can
  lose data. Defaulting unknown to the stricter class keeps the failure mode safe for tools that forgot annotations.
  Annotations are attacker-controlled (a rug-pull can flip `readOnlyHint`), which is why the *pinned* definition's
  annotation change is a SECURITY finding in the differ, and why fail-open only applies to the new definition when
  the control plane cannot say otherwise; operator config overriding the class is in the control contract.
- **Revisit when:** a read-only tool is found to be an exfiltration path (its results feed other tools): then
  fail-open should depend on data sensitivity, not just read/write.

### Q4-proxy-04 Hash-only hot path; the full semantic diff runs in the control plane
- **Decision:** the proxy computes `def_hash` only on `tools/list` and compares strings. It never resolves `$ref`s,
  judges descriptions, or runs the differ. Only on a mismatch does it call `control/`.
- **Alternatives:** run the differ in the proxy; validate the definition against rules in-line; hash on every call.
- **Why:** the hash normalization is deliberately tiny (`schema/canonical.py`) so the proxy needs no schema engine
  beyond argument validation. A per-call cost of one sha256 of a definition would be ~10 µs per tool for no
  information gain; the diff needs the Python differ and is rare. Keeps the proxy small enough to explain and the
  latency budget dominated by JSON handling, not policy.
- **Revisit when:** control-plane round trips become a scaling issue (then embed a verdict cache in the proxy keyed by
  `(old_hash, new_hash)`).

### Q4-proxy-05 Sharded session map, per-session mutex, no global lock
- **Decision:** `Store` = `[64]{mu, map}`; a session's pins and hash chain sit behind its own mutex; quarantine is an
  atomic pointer to an immutable map; schema cache is a `sync.Map` with one mutex only around compilation.
- **Alternatives:** one `sync.RWMutex` around a map; `sync.Map` for sessions; a goroutine-per-session actor.
- **Why:** with 64 shards, two sessions collide only at the map-lookup step (~24 ns); a single lock would serialize
  every request's lookup and, under a slow writer, every hot-path call. Explicit shards are easy to explain and to
  race-test. An actor per session costs a goroutine and channel hop per call with no benefit, since one session's
  calls are rarely concurrent. A fixed 64 is a guess at "enough for tens of cores".
- **Revisit when:** profiling shows shard contention (unlikely at these numbers) or the shared event channel becomes
  the bottleneck (then one channel/writer per shard).

### Q4-proxy-06 Quarantine by polling every 1 s; staleness window accepted
- **Decision:** each proxy polls `GET /quarantine` every 1 s and swaps in an immutable snapshot; a failed poll keeps
  the last good snapshot.
- **Alternatives:** push/pubsub; check the control plane on each call; longer poll.
- **Why:** polling needs no broker, no connection state, and no hop on the call path. The list is tiny. The window
  (up to ~1 s + the control hop) is acceptable because the observing session is already suspended locally at once;
  other sessions were equally exposed in the seconds before detection anyway. Keeping the last good snapshot is safer
  than blanking the list on a hiccup.
- **Revisit when:** the exposure window matters (e.g. exfiltration of large data per second): move to push (NATS/SSE)
  with the poll as a safety net.

### Q4-proxy-07 Bounded event channel, non-blocking send, count drops and flag the session
- **Decision:** events go to a bounded channel (default 4,096) drained by one writer goroutine. A full channel drops
  the event, increments a counter and sets the session's `AuditIncomplete` flag; the call path never blocks.
- **Alternatives:** block until space; unbounded queue; synchronous file write per event; write to the log before
  answering the call.
- **Why:** the log is evidence, not a gate. Blocking would let a slow disk stall agent calls (breaks the latency
  ceiling); an unbounded queue trades that for memory exhaustion. Dropping visibly (counter + flag) keeps the failure
  loud. The trade-off is stated in `DESIGN.md` §10: availability of calls over completeness of audit. Consequence
  worth knowing: `seq` and the hash are assigned *before* enqueue, so a dropped event leaves a visible gap (a missing
  `seq`, a `prev_hash` that matches nothing) in the file, which `harness` reports as an integrity problem rather than
  silently accepting an incomplete log. Known weakness: the `AuditIncomplete` flag is in-memory only (not written
  into the log or exported).
- **Revisit when:** drops are seen in practice: size the channel from measured burst, or write-ahead to a local
  spool before acknowledging.

### Q4-proxy-08 Go port of canonical hashing on `gowebpki/jcs`; parity verified against golden vectors
- **Decision:** `internal/canonical` ports `normalize_tool`, `tool_hash`, `event_hash` from `schema/canonical.py`. It
  marshals with `encoding/json` and canonicalizes with `github.com/gowebpki/jcs` (an RFC 8785 implementation) rather
  than hand-writing JCS.
- **Alternatives:** hand-port `_encode_number`/`_encode_string`/key sorting; a different JCS library; shell out to
  Python.
- **Why:** UTF-16 key ordering and ECMAScript number formatting are where cross-language hashes silently diverge, so
  reuse a maintained implementation and *test the contract*. `normalize_tool` is ported by hand (it is ~30 lines and
  is ours, not RFC 8785): drop `$comment`, sort+dedupe `required` by UTF-16 code units, include
  `outputSchema`/`annotations` when present.
- **How parity was verified:** `internal/canonical` tests load `../../schema/golden_vectors.json` and check every
  `json` entry (canonical string **and** hash: UTF-16 key order, escapes, numbers incl. `-0`, `1e+21`, `1e-7`) and every
  `tools` entry (normalized canonical string **and** hash), plus the reorder/`$comment`/duplicate-`required`
  equivalence and the rug-pull difference. Also: an end-to-end test re-hashes events read back from disk (numbers are
  then `float64`, as a Python reader sees them) and validates them against `recording.schema.json`.
- **Known gaps vs the Python reference:** Python raises on integers beyond 2^53 and on lone surrogates; the Go port
  does not check (JSON decoded from an upstream is `float64` throughout, so large integers would round rather
  than raise). Not covered by golden vectors; low risk for tool schemas. NaN/Inf cannot occur in decoded JSON.
- **Revisit when:** the golden vectors grow (they are the contract), or a definition with huge integers appears.

### Q4-proxy-09 `control/` integration is an injectable stub for now
- **Decision:** `internal/control.Client` speaks the HTTP contract in `DESIGN.md` §0 (`POST /changes`,
  `GET /quarantine`) against a configurable `control_base_url`. `control/` does not exist yet in this repo. Empty
  URL = every call fails fast, which the proxy already handles as "control plane unreachable" (suspend forever for
  side-effecting tools; fail-open for read-only). Tests point it at an `httptest.Server` that plays each verdict.
- **Alternatives:** an interface with a fake; embed a Go differ; block the proxy work until Python exists.
- **Why:** the contract lives in one document that a separate agent implements against, and the proxy's behaviour
  under every verdict and failure is already tested. A struct with an injectable base URL is the smallest thing that
  can be pointed at the real service with no code change. The proxy also sends `session_id`, `old_hash`, `new_hash`
  so `control/` can cross-check `def_hash` computed in two languages.
- **Revisit when:** `control/` lands: run an integration test with the real service, and add auth on this hop.

### Q4-proxy-10 Background re-list instead of `list_changed` notifications
- **Decision:** after a `tools/call`, if more than `relist_interval_ms` (default 30 s) has passed since the session last
  listed that server, the proxy re-lists in a goroutine and checks the hashes. `notifications/tools/list_changed` is
  not handled.
- **Alternatives:** rely on the agent's own re-list; handle SSE notifications; re-list on every call.
- **Why:** without it, a server that silently swaps a definition is invisible until the agent happens to re-list,
  which defeats "mid-session". A notification needs SSE (out of v1 scope). Re-listing on every call is a network hop
  on the hot path. A timer-triggered background re-list is off the call path and bounds exposure to the interval.
- **Revisit when:** exposure of 30 s is too long for a class of tools (per-server interval), or SSE lands.

### Q4-proxy-11 Pins are per session, taken from first sight; no baseline lookup at first sight
- **Decision:** a session pins the first valid, non-quarantined definition it sees. There is no comparison to an approved baseline in the registry at pin time. Every list is inspected before it is returned: changed, quarantined, unhashable, and schema-invalid definitions are replaced by structured JSON-RPC errors rather than exposed to the agent.
- **Alternatives:** require an approved baseline for every tool before it can be called.
- **Why:** it keeps v1 small and the proxy stateless w.r.t. the registry, and the pre-prod Q3 gate is the control
  for "first sight is already malicious". The cost is real (a new session before quarantine propagation can pin the bad definition); it is listed in `DESIGN.md` §9 as the first thing to add (still off the call path,
  at `tools/list`).
- **Revisit when:** control/ has a registry with approved pointers (right after v1).

### Q4-proxy-12 Upstream connection pool sized for the load, not Go defaults
- **Decision:** `MaxIdleConnsPerHost = 1024` (default 2), same for the load generator's client.
- **Why:** found while measuring: with the default, hundreds of concurrent sessions to one tool server reconnect on most
  calls, and the measured overhead was dominated by TCP handshakes, not proxy logic. This is a good example of why
  the numbers in §6 are measured.
- **Revisit when:** upstreams use HTTP/2 (one connection multiplexes) or number in the thousands (cap total idle).

### Q4-proxy-13 Scope cuts and honest gaps (so nobody discovers them in the interview)
- **Decision:** v1 does not: evict sessions or close per-session log files before shutdown; write `session_end`; redact args/results;
  ship logs off-box; escalate argument-validation failures to the
  control plane; detect removed tools; implement a shadow mode; expose metrics beyond `Writer.Drops()`. All listed in
  `DESIGN.md` §9-§10.
- **Why:** each is real work that adds no proof of the trust design; the design, the mismatch->verdict loop, the
  latency measurements and the audit chain are what v1 demonstrates. Naming them keeps them from being mistaken for
  features.
- **Code size note:** the non-test Go code is about 1,250 non-comment lines including `cmd/loadgen` (193) and
  `cmd/proxyd` (61), above the 400-600 guideline. Most of the excess is the async verdict/retry/fail-open handling and
  the load generator, which the deliverable asked for; there are no stubs in it.
- **Revisit when:** moving from interview artifact to production: session eviction and redaction come first.

---

# Control plane and demo (`control/`, `demo.py`, `demo_support/`), prefix `Q4-control`

### Q4-control-01 Standard-library HTTP server, no web framework
- **Decision:** `control/http_api.py` is `http.server.ThreadingHTTPServer` plus a small handler; the logic lives in
  `service.py` with no HTTP in it. No third-party dependency beyond the local `harness`.
- **Alternatives:** FastAPI/Flask; `aiohttp`; embedding the differ in the Go proxy.
- **Why:** three routes and JSON bodies do not need a framework; fewer dependencies means the demo runs from a clean
  checkout, and every line can be explained. Separating `service.py` from the transport lets most tests call the
  service directly, with a few real-socket tests for the wire behaviour. A thread per request is enough because the
  differ is short and rare (only on a definition change), and the proxy's `/changes` traffic is one call per change.
- **Revisit when:** verdict latency under load matters (then a worker pool / ASGI server, or run several instances
  behind the proxy's `control_base_url`).

### Q4-control-02 The policy is a validated JSON file; the risk-class override lives in the same file
- **Decision:** `control/default_policy.json` is the DESIGN §0.1 matrix (rows `NONE, INFO, WARN, BREAKING, SECURITY`,
  columns `read_only, side_effecting, destructive`, values `resume|warn|suspend|quarantine`) plus a `risk_overrides`
  list of `{server, tool, risk_class}`. `--policy FILE` replaces it. Loading rejects a missing row/cell, an unknown
  verdict, an unknown row or column, or a bad override, so a typo fails at startup rather than during an incident.
  Risk class comes from `readOnlyHint is True` -> `read_only`, else `destructiveHint is True` -> `destructive`, else
  `side_effecting`; an override beats the annotation. "NONE" and "INFO" are separate rows (same default values) so an
  operator can treat cosmetic and no-op changes differently.
- **Alternatives:** YAML (extra dependency); the table in code; overrides in a second file; deriving risk class from
  the *old* definition.
- **Why:** JSON needs no dependency and DESIGN allows it. `is True` (not truthiness) because annotations are
  untrusted input: the string `"true"` must not make a tool read-only. Risk class is taken from the **new**
  definition (DESIGN §0.1 step 3), because it is what the agent would now call. The known weakness is that annotations
  are attacker-controlled, which is why flipping `readOnlyHint` true -> false is itself a SECURITY finding in the
  differ, and why operators can pin a class per tool. A malformed policy is never "best effort": a wrong table is a
  security bug.
- **Revisit when:** policy needs per-server or per-tenant tables, or hot reload (today: restart to change).

### Q4-control-03 The "verdict cache" caches the diff, keyed by `(old_hash, new_hash)`, with single flight and an LRU bound
- **Decision:** the cache maps `(old_hash, new_hash)` (the hashes *control recomputed*, see -04) to the differ's result
  (sorted findings + highest severity). The policy lookup, risk class, quarantine and approval checks run on every
  request. Values are `Future`s: the first request for a key runs the differ, concurrent requests for the same key wait
  for that one result (single flight), later ones reuse it. Failures are not cached. The cache is an LRU of 4,096
  entries. `GET /stats` exposes `cache_hits` / `cache_misses`; responses carry `cache_hit`.
- **Alternatives:** cache the final verdict; a plain dict with a lock and no single flight; unbounded; TTL.
- **Why:** caching the *diff* is what saves work (1,000 sessions, one rug-pull, one diff), and it keeps the verdict
  correct when the same pair appears under another server name or after the operator approved a hash or edited the
  policy: the cheap parts are recomputed per request. Single flight matters precisely in the case the cache exists for:
  N sessions report the same change at the same instant, and a check-then-compute dict would run the differ N times.
  The differ is a pure function of the two definitions, so no TTL is needed. The bound stops slow memory growth from
  flapping tools (each entry holds the findings, including the description text).
- **Revisit when:** the entry count or memory needs tuning, or the differ gets a non-deterministic layer (embedding /
  LLM judge): then the key must include the model/version.

### Q4-control-04 Hash parity check: trust our own hash, report a disagreement loudly, never silently
- **Decision:** on every `/changes`, control recomputes `harness._canonical.tool_hash` for `old_def` and `new_def` and
  compares with the proxy's `old_hash`/`new_hash`. On disagreement: `log.error("HASH MISMATCH ...")` with both
  values, a `hash_mismatches` counter in `/stats`, a `hash_mismatch: [{field, proxy, control}]` field in the response,
  and the `reason` is prefixed `HASH_MISMATCH (...)` (so it reaches the session's audit log via `policy_decision`). The
  request is still classified from the definitions, and the cache and approvals use control's own hash.
- **Alternatives:** refuse the request (400); fail closed (force `suspend`); ignore.
- **Why:** DESIGN §0.1 says "log loudly and trust its own value". A refusal would make the proxy treat control as
  unreachable, and a hash disagreement says nothing about whether the definition is malicious; the diff of the two
  definitions is still valid. But it is a contract bug, so it must be visible in four places (log, counter, response,
  audit trail). In the real demo the counter stays 0 (Go and Python agree on the raw upstream objects, including
  the extra `title` field and integer constraints); a test forces a mismatch.
- **Revisit when:** a mismatch is ever seen in practice: then stop and fix the Go port or the golden vectors, and
  consider making it a hard failure in staging.

### Q4-control-05 Quarantine is driven by the verdict, per request; approval wins even against a diff already running
- **Decision:** `(server, tool)` is added to the quarantine set whenever the *verdict* is `quarantine` (with the
  default table that is exactly "highest severity is SECURITY"), before the response is returned (so the next poll sees
  it). This is done per request, not in the cached part. Approval is re-checked under the lock immediately before
  adding, so an operator approval that lands while the differ is running is not undone by a late quarantine.
- **Alternatives:** hard-code "SECURITY -> quarantine" outside the table; quarantine inside the cached computation.
- **Why:** the table is the single source of truth, so an operator who changes SECURITY x read_only to `suspend` gets
  exactly that. Doing it per request is what makes a cache hit from a second server name quarantine that server too.
  The re-check closes a small race found while writing the cache (approve between diff and add), covered by a test.
- **Revisit when:** quarantine needs a reason/expiry/owner (today: only server+tool, cleared only by approval).

### Q4-control-06 `POST /baselines/approve`: DESIGN §0.3 shape, minimal validation, unconditional clear
- **Decision:** request `{server, tool, def_hash, approved_by?, reason?}`, response `{server, tool, approved_hash,
  cleared_quarantine}` (`true` only if the pair was quarantined). `def_hash` must match `sha256:` + 64 hex digits.
  `approved_by`/`reason` are optional strings (the proxy is not a caller; DESIGN shows them but does not require them).
  The pointer is per `(server, tool)`, one hash; approval clears the quarantine whatever hash triggered it; a later
  `/changes` whose recomputed `new_hash` equals the approved hash returns `resume` with reason `matches approved
  baseline`, ahead of any findings. Every approval is logged at WARNING with who/why.
- **Alternatives:** require that the approved hash equals the hash that caused the quarantine; require `approved_by`;
  keep a list of approved hashes per tool; authenticate.
- **Why:** it follows the contract literally (effects a, b, c) with the least machinery. Not tying approval to "the
  quarantining hash" keeps the operator able to approve a *different* known-good hash (e.g. the vendor's fixed
  release), at the cost that approving the wrong (but well-formed) hash clears the quarantine while the bad definition
  is still what the vendor serves; the next session to report the bad definition quarantines it again. `approved_by`
  is self-asserted: there is no auth in v1 (DESIGN §0), so it is an audit note, not an identity.
- **Revisit when:** auth exists (then `approved_by` comes from the credential, and approvals could need two-person
  rules for destructive tools) or the approved-baseline registry is persisted.

### Q4-control-07 Additions beyond §0 and the error contract
- **Decision:** `/changes` responses carry extra fields the proxy ignores: `severity` (`NONE|INFO|WARN|BREAKING|
  SECURITY`, or null for an approved-baseline hit), `risk_class`, `cache_hit`, and `hash_mismatch` when relevant.
  Extra routes: `GET /healthz`, `GET /stats`. Bad input is `400 {"error"}` (missing fields, invalid JSON, a definition
  with no `name`), unknown route `404`, wrong method `405`, an unexpected exception `500`. Only a valid request gets `200`.
- **Alternatives:** exactly the §0 fields only; put the counters in logs.
- **Why:** unknown JSON fields are ignored by the proxy's decoder, so this is backward compatible, and the demo, tests
  and operators need to see severity/cache behaviour without parsing text. Non-200 on a bad request is deliberate:
  DESIGN §0 says the proxy treats any non-200 as "control unreachable" and applies its fail-open/closed rule, which is
  the safe reading of "the control plane could not classify this".
- **Revisit when:** the contract is versioned (then the extras become documented fields).

### Q4-control-08 In-memory state, thread-per-request server: what a restart does
- **Decision:** verdict cache, quarantine set and approved baselines live in process memory behind one lock (held only
  briefly; never while the differ runs). A restart loses all of it. One request per connection (the
  `BaseHTTPRequestHandler` default, HTTP/1.0 semantics), listen backlog raised to 128.
- **Alternatives:** persist quarantine and approvals to a file/SQLite/Redis; keep-alive connections; a process pool.
- **Why:** DESIGN allows in-memory for v1. **The consequence is worth saying plainly:** a control-plane restart empties
  `GET /quarantine`, the proxies replace their snapshot wholesale on the next successful poll (DESIGN §0.2), and a
  quarantined tool becomes callable again until some session reports the change again. Sessions already suspended stay
  suspended, but *new* sessions can pin the poisoned definition (§9) after the emptied quarantine snapshot reaches the proxy. Persisting the quarantine
  set and approval pointers (a JSON file would do) is the first thing to add; it was not built.
- **Revisit when:** before any use beyond the demo. Then also: several control instances need a shared store (the
  cache can stay per instance; quarantine and approvals cannot).

### Q4-control-09 Differ scope: one tool pair, rule and judge layers only
- **Decision:** `control/differ.py` calls `schema_diff.diff_tool` and `description_diff.diff_description` for the one
  tool, like `harness/diff/differ.py` does per tool. `other_tool_names` is empty, and no `Embedder` or `Judge` is used.
- **Alternatives:** call `diff_recordings` with two one-tool in-memory recordings; keep a per-server list of sibling tool
  names learned from earlier reports and pass it in; wire an embedder.
- **Why:** the direct calls are what `diff_recordings` does internally, without inventing recordings. A change report
  contains one tool, so **`DESC_CROSS_TOOL_REFERENCE` (cross-tool shadowing, DESIGN §2) cannot fire in the control
  plane**: this is a real gap versus DESIGN §2's "via control at change time", and it is stated in the README.
  Learning sibling names from history would make verdicts depend on which reports arrived earlier (no longer a pure
  function of `(old, new)`, which breaks the cache key). The embedder/judge are off for the same determinism reason
  as in Q3 (no network, no model, reproducible).
- **Revisit when:** the proxy reports the full tool list of the server with a change (then pass the sibling names).

### Q4-control-10 `harness` is used as a local package; hashes come from its vendored `_canonical`
- **Decision:** `control` imports `harness.diff` and `harness._canonical.tool_hash`. `pyproject.toml` declares
  `harness>=0.1.0` (not on PyPI: `pip install -e ../../q3_tool_harness` first). Tests use a `conftest.py` sys.path
  shim like Q3's; the demo starts the control plane with `PYTHONPATH` set to `control/` and `q3_tool_harness/`.
- **Alternatives:** copy the differ into `control/` (the design forbids it); a relative `file:` dependency (not valid
  in PEP 508); import the reference `schema/canonical.py` directly.
- **Why:** one differ, no forks. Using `harness._canonical` (a private module) means control's hash is exactly what
  the differ and recordings use; Q3's tests keep that copy equal to `schema/canonical.py` and the golden vectors. It
  is a private-module import across packages, accepted because the alternative is a second copy.
- **Revisit when:** `harness` publishes a public `tool_hash`, or is released to an index.

### Q4-control-11 The demo runs four real processes and asserts every expected outcome
- **Decision:** `demo.py` builds the Go proxy to a scratch binary and starts the mock tool server, the control plane
  and the proxy as child processes on free ports (bind to port 0, read the number, close, pass it on: a tiny race that
  is acceptable on localhost). The scripted agents use plain HTTP against the proxy only. Waiting for asynchronous
  effects is done by polling with a 10 s bound and a 0.2-0.25 s interval, never by a blind sleep. Each expected outcome
  goes through `Checker.expect`, which prints `[ok]`/`[FAIL]`; any failure or exception gives exit code 1 (130 on
  Ctrl-C). The children are started in their own process group on Windows so Ctrl-C reaches only the demo; `finally`
  stops them (the proxy first gets a Ctrl-Break/SIGINT so it drains its audit queue, then `terminate`, then `kill`),
  and the last act checks each process exited and each port refuses connections. `relist_interval_ms` is `-1`
  (background re-list off) so the scripted lists are the only trigger and the run is deterministic;
  `quarantine_poll_interval_ms` stays at the real default of 1000.
- **Alternatives:** an in-process control plane (thread) and in-process mock; shelling out to `go run`; fixed `sleep`s;
  hard-coded ports; a scripted transcript without assertions.
- **Why:** the value of the demo is that it is the first real integration of proxy and control (the proxy had only
  been tested against mocks). Real processes prove the wire contract; asserted outcomes make it a test rather than a
  slide. Polling with a bound is what DESIGN §0.4 asks for and also reports the real propagation time (about 0.6-0.7 s
  here). A pre-built binary avoids `go run`'s extra process layer, whose child could outlive a `terminate` of the
  parent on Windows.
- **Revisit when:** it needs CI on a machine without Go (then skip with a clear message) or must run in parallel.

### Q4-control-12 Demo cast and mock server details chosen to test the contract, not just to look good
- **Decision:** three sessions. `sess-alice` and `sess-bob` list before the flip (both report the same change, so the
  control plane's cache visibly hits once); `sess-carol` lists only after quarantine and proves the poisoned definition
  itself is withheld from a new session. The mock also serves `list_files`, which must
  keep working (quarantine is per tool). Tool definitions carry an extra `title` field and `list_files` has integer
  `minimum`/`maximum`, so the Go <-> Python hash check covers raw objects with non-contract fields and JSON numbers. The
  poisoned wording and `notes` parameter are copied from `q3_tool_harness/fixtures/make_fixtures.py`. The mock never
  reads real files. The demo also proves that no call reached the poisoned `read_file` on the vendor side (the mock
  records calls), and runs a tamper test on a copy of a log.
- **Alternatives:** one session only; hash parity only via unit tests; importing the Q3 fixture module.
- **Why:** one session cannot show cache hits, cross-session quarantine, or pre-exposure filtering. Copying constants
  (rather than importing `make_fixtures.py`, which edits `sys.path` and imports the recorder) keeps the demo
  independent of Q3 fixture refactors; the price is that it can drift.
- **Revisit when:** Q3's fixtures become a package with a stable API.

### Q4-control-13 Audit logs are loaded non-strictly; "no `session_end`" is expected
- **Decision:** the demo stops the proxy gracefully, then loads each `<session_id>.jsonl` with `harness.recording.load`
  (non-strict: problems are returned in `integrity_problems`, not raised) and requires the list to be empty. The check
  that `session_end` is absent is explicit.
- **Alternatives:** `strict=True`; verifying while the proxy is still running.
- **Why:** `verify()` checks schema, `seq` continuity, `prev_hash` and `event_hash` per event and does not require a
  terminal event, so an open log passes the same checks a closed one does; non-strict keeps the report readable when
  something is wrong. Stopping the proxy first makes the read race-free (all queued events flushed).
- **Revisit when:** the proxy writes `session_end` (then require it for closed sessions).
