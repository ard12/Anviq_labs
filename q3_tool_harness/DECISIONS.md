# Q3 decisions

Format: Decision / Alternatives / Why / Revisit when.

## Severity model and default fail-on
- **Decision:** four severities. `SECURITY` (someone may be attacked), `BREAKING` (existing callers will fail), `WARN` (meaning or limits probably changed), `INFO` (safe or additive). `harness check` fails on `SECURITY,BREAKING` by default; `--fail-on` overrides it.
- **Alternatives:** a numeric risk score with a threshold; fail on everything but INFO; per-rule severity config files.
- **Why:** the four levels come from the shared schema (`$defs/finding`). Two levels block because they map to the two things a rug-pull does: break callers or attack the model. WARN is noisy by nature (heuristics), so blocking on it by default would train people to disable the gate. A discrete label is easy to explain in a PR comment; a score is not.
- **Revisit when:** teams want WARN to block on specific tools (add per-tool policy) or the WARN false-positive rate has been measured on real traffic.

## Rename heuristic and its false-positive risk
- **Decision:** within one object's `properties`, pair each removed name with each added name. A pair is a candidate only if the types match (hard gate). Confidence = `0.6 * name_similarity + 0.4 * description_similarity` (difflib ratios; name only if neither has a description). Candidates need name similarity >= 0.3 or description similarity >= 0.5, and confidence >= 0.5. Matching is one-to-one, greedy by descending confidence. The confidence is printed in the finding message. Unmatched removals and additions fall back to `PARAM_REMOVED` / `PARAM_ADDED_*`.
- **Alternatives:** never detect renames (report remove + add); embedding similarity; Hungarian assignment instead of greedy.
- **Why:** a rename and a remove+add are both BREAKING, so a wrong guess never changes the gate verdict, only the explanation. The type hard gate is what keeps unrelated params apart: `priority: number` vs `recipient: string` can never pair. Same-type unrelated pairs (`priority` vs `timeout_ms`, similarity 0.33) stay below 0.5. Greedy is optimal enough for the handful of params a tool has and is easy to explain.
- **Risk:** two genuinely different params with similar names and same type (`start_date` removed, `end_date` added) can be reported as a rename. Cost: a misleading message, not a wrong verdict.
- **Revisit when:** tools have many parameters per object, or the misleading-message rate matters.

## Rule layer before embeddings
- **Decision:** description analysis is regexes first (`diff/patterns.py`), then token Jaccard. An `Embedder` protocol is supported but optional (`[embed]` extra, nothing imports a model at module level). The SECURITY verdict never depends on the embedder.
- **Alternatives:** embedding-only similarity; an LLM classifier.
- **Why:** CI must be deterministic, offline and fast. Embeddings are good at "did the meaning drift" but bad at "does this sentence tell the model to exfiltrate a key": a malicious sentence can be short and leave cosine similarity high. Regexes on *newly introduced* patterns are explainable line by line.
- **Deliberate simplifications:** "newly introduced" is per category (or per referenced tool name for cross-tool references): if the baseline already had a URL, a different new URL is not flagged as new SECURITY signal. A bare `always` is not a pattern (it appears in most benign descriptions); the brief's other injection phrases are covered. The exfil regex allows dots in the gap (paths like `~/.ssh/id_rsa`) but caps gap length, so it can match across a sentence boundary.
- **Revisit when:** false negatives are found (attackers will paraphrase); add patterns or an offline classifier.

## LLM judge off by default in CI
- **Decision:** a `Judge` protocol exists and is called only for descriptions in a grey band (score within 0.1 of the threshold), and only if the caller passes one. `harness check` never does.
- **Alternatives:** always call an LLM; no hook at all.
- **Why:** an LLM call is non-deterministic, needs network and secrets, costs money, and could itself be prompt-injected by the description it is judging. A flaky security gate gets ignored. The hook is there so an interactive or nightly run can add a second opinion.
- **Revisit when:** there is a local, pinned, deterministic judge.

## Accept-file design
- **Decision:** `harness accept` writes `{"accepted": [{tool, rule_id, path, after_hash, reason, expires}]}`. A finding is accepted only if tool, rule_id, path and the hash of its `after` value all match and the entry has not expired. Accepted findings are still printed (tagged) but do not block. Only findings whose severity is in `--fail-on` are affected. `accept` writes every current finding; the reviewer prunes the file and fills in `reason`/`expires`.
- **Alternatives:** an allowlist of rule_ids; a git-ignored baseline that is simply replaced; inline suppression comments.
- **Why:** it works like snapshot approval. Keying on the `after` hash means an approved change is approved exactly once: if the tool changes again, the entry stops matching and the gate fails again. Expiry stops permanent exceptions. The hash reuses `canonical.sha256_hex` from the shared contract.
- **Limitation:** for description findings `after` is the whole new description, so any later wording edit invalidates the acceptance (intended, but noisy).
- **Revisit when:** approvals need an owner/audit trail (add `approved_by`, require non-empty `reason`).

## Exit-code contract
- **Decision:** `check` returns 0 pass, 1 policy failure, 2 usage or integrity error (bad flags, unreadable file, invalid JSON/schema, broken hash chain, seq gap, bad accept file). argparse already exits 2 on bad usage. `diff` always exits 0 for a successful run and prints integrity problems as a warning at the top; `replay`/`record-demo` use 0/1/2 similarly.
- **Alternatives:** one non-zero code for everything.
- **Why:** CI has to distinguish "the tool changed, look at it" (1) from "the evidence is untrustworthy or the check could not run" (2). A tampered recording must never silently pass, and must never look like an ordinary policy failure.
- **Limitation:** `diff` on a file that cannot be read at all raises rather than returning 0; "always 0" refers to findings, not I/O errors.

## SARIF
- **Decision:** SARIF 2.1.0 with one `rule` per rule_id, `level` = error for SECURITY/BREAKING, warning for WARN, note for INFO. The location is the current recording file (line 1) plus a logical location `tool + JSON pointer`.
- **Alternatives:** custom JSON only; precise line numbers per finding.
- **Why:** SARIF is what GitHub code scanning ingests, so findings show up in PRs without extra tooling. Precise lines would require tracking which recording line produced each finding; the logical location carries the useful information. The test validates structure by hand (no network for the official schema).
- **Revisit when:** findings need to be anchored to a source file of tool definitions.

## Redaction
- **Decision:** `Recorder` applies `redact()` to args and results before writing; default replaces the value of any dict key matching `password|token|secret|api[_-]?key|authorization` (case-insensitive, recursive) with `***REDACTED***`. The live call still gets the real values. Callers can pass their own redactor.
- **Alternatives:** value-pattern scanning (regexes for key formats); redact only at load time; no redaction.
- **Why:** secrets must not reach disk at all, so it happens before the write. Key-name matching is predictable and cheap; it cannot catch a secret sitting in a free-text value.
- **Limitation:** definitions are not redacted (they should not contain secrets); event `meta` is not redacted. A redacted value changes what replay returns.
- **Revisit when:** recordings hold free-text user data (add a value scanner / allowlist).

## Behavior diff thresholds
- **Decision:** the shape is the set of JSON types per key path over all successful responses (array elements share one `[]` path). Any difference in the set at a path is `RESPONSE_SHAPE_CHANGED` (WARN). `ERROR_RATE_CHANGED` needs at least 3 calls on both sides and an absolute change of at least 0.2. `RESPONSE_INJECTION_PATTERN` uses the same pattern library as descriptions, on text newly present in responses versus the baseline.
- **Alternatives:** statistical tests; value-level diffs; alert on every difference.
- **Why:** responses legitimately differ in values, so only structure is compared. With one or two calls an error rate is meaningless (1 of 1 = 100%), so a minimum sample avoids noise. WARN, not BREAKING, because a shape change may be a harmless additive field.
- **Limitation:** shape only reflects what the recorded calls happened to return; optional keys that were not exercised look "added" or "removed". The numbers (3, 0.2) are defaults, not tuned on real data.
- **Revisit when:** there is real traffic to tune against.

## Local $ref only
- **Decision:** `$ref` values beginning with `#` are resolved (JSON Pointer, `~0/~1` and percent-decoding, cycle-safe: a cycle resolves to `{}`). Remote refs and unresolvable pointers are left as-is and compared structurally.
- **Alternatives:** fetch remote refs; use a full resolver library.
- **Why:** fetching makes the diff depend on the network and lets a tool author change the meaning of a schema by changing a remote file. MCP tool schemas are self-contained in practice.
- **Revisit when:** real servers ship remote refs; then resolve against a pinned, recorded copy.

## Other decisions
- **Vendored contract files.** `_canonical.py` is a byte-identical copy of `schema/canonical.py`; `harness/_schema/recording.schema.json` is a copy of the schema so the installed package does not depend on repo layout. `tests/golden_vectors.json` is a copy for the golden test. Trade-off: copies can drift; the golden test catches canonical.py drift but nothing compares the schema copy (revisit: a CI diff check).
- **Compare final definitions.** `diff_recordings` compares the *last* definition of each tool in each recording. A mid-session re-listing is recorded and visible in `Recording.tools[key]` (all versions), and is what Q4 acts on live; the offline differ judges the end state.
- **Tool identity is (server, name).** A tool that moves to another server appears as removed + added.
- **`outputSchema` reuses the input-schema engine.** Rule ids such as `PARAM_REMOVED` are therefore also used for output properties; the path (`/outputSchema/...`) says which.
- **Deterministic fixtures.** `Recorder` takes injectable `clock`, `id_gen` and `timer`, so `fixtures/make_fixtures.py` output is byte-identical between runs (a test checks it). Defaults are wall clock, uuid4 and `time.perf_counter`.
- **Flush, not fsync, per event.** A process crash leaves a valid prefix; a power loss might lose the tail. fsync per event would dominate the cost of recording.
- **Types treated as widening.** `integer -> number` and any strict superset of a type union are WARN; everything else that changes the type set is BREAKING. `pattern`/`format` changes are treated as tightening even if the new one is looser, since regex containment is not decidable cheaply. `additionalProperties` only true -> false is flagged.
- **`Finding` is frozen with `to_dict()`** that drops null `before`/`after`, so JSON output validates against the schema's `finding` definition.

### Q3-VAL Differ checks every definition version seen in the current recording, not just the last

- **Decision:** `diff_recordings` diffs the baseline's latest definition against every *distinct* `def_hash` version in the current recording (findings de-duplicated by rule, path and message).
- **Alternatives:** compare only the last definition per tool (the first implementation).
- **Why:** a tool that turns malicious mid-session and reverts before the session ends ("flash rug-pull") has a last definition identical to the baseline, so a last-only diff passes it. `tests/test_differ.py::test_flash_rug_pull_reverted_before_session_end_is_still_flagged` pins this. Cost is one extra diff per distinct version, which is rare, so the fast path for unchanged tools is untouched.
- **Revisit when:** recordings routinely contain many distinct versions per tool (a flapping tool); then cap or summarise versions.

### Q3-VAL-2 The reassuring INFO verdict is suppressed once the rule layer has flagged the text

- **Decision:** when layer 2 (regex rules) produces a SECURITY finding for a description, layer 3 no longer emits
  the INFO `DESC_REWORDED` verdict for that same description. A WARN `DESC_SEMANTIC_CHANGE` is still emitted if it
  fires.
- **Alternatives:** leave both (the layers are independent detectors, so both verdicts are "true"); drop layer 3
  entirely when layer 2 fires; downgrade the wording instead of suppressing.
- **Why:** a rug-pull typically *appends* a sentence, so token similarity stays high. On the `rugpull.jsonl`
  fixture the report printed the exfil finding and then "description text changed but meaning looks the same
  (token Jaccard similarity=0.53)" about the same string. Both statements are individually defensible, but a
  reviewer reads a self-contradiction and the real finding is buried. Similarity above the threshold only means
  "few tokens changed", which is not evidence of safety once a rule has matched; a WARN is corroboration, so it
  stays. Pinned by `tests/test_description_diff.py::test_reworded_info_is_suppressed_once_the_rule_layer_flagged_the_text`.
- **Revisit when:** layer 3 gains a real semantic model. An embedding score that *disagrees* with the rule layer is
  then a signal worth surfacing (probable false positive), rather than noise.
