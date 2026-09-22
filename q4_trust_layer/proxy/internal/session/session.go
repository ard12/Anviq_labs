// Package session holds all per-session state: pinned tool definitions
// (def_hash + compiled schema), suspension, and the hash-chained event
// sequence. A Session belongs to exactly one proxy instance (session
// affinity, see DESIGN.md §7) and is guarded by its own mutex — there is no
// global lock. Store shards sessions N ways so that even within one process,
// unrelated sessions never contend on the same mutex.
package session

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/anviq-candidate/anviq-interview/proxy/internal/canonical"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/eventlog"
)

// Key identifies a (server, tool) pair within a session's pinned-tool map.
func Key(server, tool string) string { return server + "\x00" + tool }

// PinnedTool is the contract a session has approved for a given tool: the
// def_hash it first saw (or was last re-pinned to) and the compiled schema
// for validating arguments against it.
type PinnedTool struct {
	DefHash           string
	Tool              map[string]any
	Schema            *jsonschema.Schema
	SchemaError       string
	InvalidDefinition string // most recent definition could not be hashed
	RiskClass         string // "read_only" | "destructive" | "side_effecting" (default)
	Suspended         bool
	Pending           *PendingChange
}

// PendingChange is the definition observed on a later tools/list that did not
// match DefHash, while the control plane's classification is outstanding.
type PendingChange struct {
	Revision       uint64
	NewHash        string
	NewTool        map[string]any
	NewSchema      *jsonschema.Schema
	SchemaError    string
	RiskClass      string
	Unreachable    bool // the async POST /changes attempt failed or timed out
	VerdictApplied bool
}

// riskClass derives a coarse risk class from MCP tool annotations. Unknown or
// unannotated tools default to the stricter "side_effecting" class: fail-safe
// by default rather than fail-open by default. See DESIGN.md §5.
func riskClass(tool map[string]any) string {
	if ann, ok := tool["annotations"].(map[string]any); ok {
		if ro, ok := ann["readOnlyHint"].(bool); ok && ro {
			return "read_only"
		}
		if d, ok := ann["destructiveHint"].(bool); ok && d {
			return "destructive"
		}
	}
	return "side_effecting"
}

func actionFor(verdict string) string {
	switch verdict {
	case "resume":
		return "allow"
	case "warn":
		return "warn"
	default:
		return "block"
	}
}

// Session is a single agent session's state. All mutation goes through its
// methods, which take the mutex internally; callers never see the lock.
type Session struct {
	ID    string
	Agent string

	mu         sync.Mutex
	started    bool
	pinned     map[string]*PinnedTool
	lastList   map[string]time.Time // server -> last time tools/list was observed or claimed for re-list
	seq        int
	nextChange uint64
	prevHash   any // string, or nil for seq 0

	AuditIncomplete atomic.Bool
}

func newSession(id string) *Session {
	return &Session{ID: id, pinned: make(map[string]*PinnedTool), lastList: make(map[string]time.Time)}
}

// buildEventLocked constructs the next event in this session's hash chain.
// Caller must hold s.mu. Returns nil (and marks AuditIncomplete) only if
// hashing itself fails, which should be unreachable for well-formed events.
func (s *Session) buildEventLocked(typ string, fields map[string]any) map[string]any {
	ev := map[string]any{
		"v":          1,
		"seq":        s.seq,
		"ts":         time.Now().UTC().Format(time.RFC3339),
		"session_id": s.ID,
		"type":       typ,
	}
	for k, v := range fields {
		ev[k] = v
	}
	if s.seq == 0 {
		ev["prev_hash"] = nil
	} else {
		ev["prev_hash"] = s.prevHash
	}
	h, err := canonical.EventHash(ev)
	if err != nil {
		s.AuditIncomplete.Store(true)
		return nil
	}
	ev["event_hash"] = h
	s.prevHash = h
	s.seq++
	return ev
}

func (s *Session) emit(w *eventlog.Writer, ev map[string]any) {
	if ev == nil {
		return
	}
	if !w.Enqueue(s.ID, ev) {
		s.AuditIncomplete.Store(true)
	}
}

// EnsureStarted emits session_start exactly once, on the first request seen
// for this session. Idempotent.
func (s *Session) EnsureStarted(w *eventlog.Writer, agent string) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.Agent = agent
	ev := s.buildEventLocked("session_start", map[string]any{"agent": agent})
	s.emit(w, ev)
	s.mu.Unlock()
}

// EmitEvent appends a generic event (tool_call, tool_response,
// policy_decision, session_end, ...) to this session's hash chain.
func (s *Session) EmitEvent(w *eventlog.Writer, typ string, fields map[string]any) {
	s.mu.Lock()
	ev := s.buildEventLocked(typ, fields)
	s.emit(w, ev)
	s.mu.Unlock()
}

// MarkListed records that a tools/list for server just went through this
// session (the agent's own list counts as a re-check).
func (s *Session) MarkListed(server string) {
	s.mu.Lock()
	s.lastList[server] = time.Now()
	s.mu.Unlock()
}

// ClaimRelist returns true (at most once per interval, per server) if the
// caller should now trigger a background re-list of server on this session's
// behalf. Claiming updates the timestamp, so concurrent calls do not all
// start their own re-list.
func (s *Session) ClaimRelist(server string, interval time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.lastList[server]) < interval {
		return false
	}
	s.lastList[server] = time.Now()
	return true
}

// ListOutcome describes what happened when a definition observed on
// tools/list was checked against this session's pin.
type ListOutcome struct {
	Revision    uint64
	Action      string // "pinned" | "unchanged" | "mismatch" | "pending" | "retry" | "invalid"
	Key         string
	OldHash     string
	NewHash     string
	RiskClass   string // risk class of the newly observed definition
	SchemaError string
	// OldTool/NewTool are only populated on Action == "mismatch": the raw
	// definitions needed for the control plane's POST /changes {old_def, new_def}.
	OldTool map[string]any
	NewTool map[string]any
}

// ObserveDefinition pins a tool on first sight, no-ops if the hash matches,
// or suspends the tool for this session on mismatch (the moment-of-detection
// response from DESIGN.md §5). defHash and schema must already be computed —
// hashing and schema compilation happen outside the session lock.
func (s *Session) ObserveDefinition(w *eventlog.Writer, server string, tool map[string]any, defHash string, schema *jsonschema.Schema, schemaError string) ListOutcome {
	name, _ := tool["name"].(string)
	key := Key(server, name)
	outcome := ListOutcome{Key: key}

	s.mu.Lock()
	defer s.mu.Unlock()
	pt, ok := s.pinned[key]
	var events []map[string]any
	hadInvalidDefinition := ok && pt.InvalidDefinition != ""
	if ok {
		pt.InvalidDefinition = ""
	}
	switch {
	case !ok:
		rc := riskClass(tool)
		s.pinned[key] = &PinnedTool{DefHash: defHash, Tool: tool, Schema: schema, SchemaError: schemaError, RiskClass: rc, Suspended: schemaError != ""}
		events = append(events, s.buildEventLocked("tool_definition", map[string]any{
			"server": server, "tool": tool, "def_hash": defHash,
		}))
		outcome.Action = "pinned"
		if schemaError != "" {
			outcome.Action = "invalid"
			outcome.SchemaError = schemaError
			events = append(events, s.buildEventLocked("policy_decision", map[string]any{
				"server": server, "tool_name": name, "action": "block",
				"reason": "TOOL_SCHEMA_INVALID: " + schemaError,
			}))
		}
		outcome.NewHash = defHash
		outcome.RiskClass = rc
	case pt.DefHash == defHash:
		outcome.Action = "unchanged"
		if schemaError == "" && (hadInvalidDefinition || pt.Pending != nil) {
			// The upstream restored the exact definition that this session had
			// already trusted. Clear the temporary fail-closed state created by a
			// blocked change; no control-plane approval is needed for the unchanged
			// pinned contract. A global quarantine is checked separately and still
			// takes precedence.
			pt.Suspended = false
			pt.Pending = nil
			events = append(events, s.buildEventLocked("policy_decision", map[string]any{
				"server": server, "tool_name": name, "action": "resume",
				"reason": "previously pinned definition restored after blocked change",
			}))
		}
		if pt.Suspended {
			outcome.Action = "pending"
		}
		if pt.SchemaError != "" {
			outcome.Action = "invalid"
			outcome.SchemaError = pt.SchemaError
		}
		outcome.OldHash = defHash
		outcome.NewHash = defHash
	case pt.SchemaError != "" && schemaError == "":
		// An invalid first definition was never exposed as an approved contract.
		// Let the first corrected, compilable definition become the real pin.
		rc := riskClass(tool)
		s.pinned[key] = &PinnedTool{DefHash: defHash, Tool: tool, Schema: schema, RiskClass: rc}
		outcome.Action = "pinned"
		outcome.OldHash = pt.DefHash
		outcome.NewHash = defHash
		outcome.RiskClass = rc
		events = append(events, s.buildEventLocked("tool_definition", map[string]any{
			"server": server, "tool": tool, "def_hash": defHash,
		}))
	case pt.Pending != nil && pt.Pending.NewHash == defHash:
		// Same changed definition seen again (agent re-list or background
		// re-list) while already suspended: already reported, nothing new.
		outcome.Action = "pending"
		outcome.OldHash = pt.DefHash
		outcome.NewHash = defHash
		if pt.Pending.SchemaError != "" {
			outcome.Action = "invalid"
			outcome.SchemaError = pt.Pending.SchemaError
		} else if pt.Pending.Unreachable && !pt.Pending.VerdictApplied {
			// The earlier report never reached the control plane: retry it on
			// this list (the agent's or the background re-list). No new events.
			pt.Pending.Unreachable = false
			outcome.Action = "retry"
			outcome.RiskClass = pt.Pending.RiskClass
			outcome.OldTool = pt.Tool
			outcome.NewTool = tool
		}
		outcome.Revision = pt.Pending.Revision
	default:
		rc := riskClass(tool)
		outcome.Action = "mismatch"
		outcome.OldHash = pt.DefHash
		outcome.NewHash = defHash
		outcome.RiskClass = rc
		outcome.SchemaError = schemaError
		outcome.OldTool = pt.Tool
		outcome.NewTool = tool
		pt.Suspended = true
		s.nextChange++
		outcome.Revision = s.nextChange
		pt.Pending = &PendingChange{Revision: outcome.Revision, NewHash: defHash, NewTool: tool, NewSchema: schema, SchemaError: schemaError, RiskClass: rc}
		events = append(events, s.buildEventLocked("tool_definition", map[string]any{
			"server": server, "tool": tool, "def_hash": defHash,
		}))
		reason := fmt.Sprintf("TOOL_CONTRACT_CHANGED: def_hash %s -> %s; suspended pending control-plane classification", pt.DefHash, defHash)
		if schemaError != "" {
			outcome.Action = "invalid"
			reason = "TOOL_SCHEMA_INVALID: " + schemaError
		}
		events = append(events, s.buildEventLocked("policy_decision", map[string]any{
			"server": server, "tool_name": name, "action": "block",
			"reason": reason,
		}))
	}
	for _, ev := range events {
		s.emit(w, ev)
	}
	return outcome
}

// Verdict is the control plane's classification of a mismatch, per the
// /changes response contract in DESIGN.md's "Interface contract for control/".
type Verdict struct {
	Action string // "resume" | "warn" | "suspend" | "quarantine"
	Reason string
}

// ApplyVerdict updates pinned state once the control plane classifies a
// mismatch (or reports that it could not be reached). Safe to call from a
// background goroutine; if the tool has since moved on (re-pinned by a later
// tools/list) this is a no-op.
func (s *Session) ApplyVerdict(w *eventlog.Writer, server, toolName string, revision uint64, unreachable bool, v Verdict) {
	key := Key(server, toolName)

	s.mu.Lock()
	defer s.mu.Unlock()
	pt, ok := s.pinned[key]
	if !ok || pt.Pending == nil || pt.Pending.Revision != revision || pt.Pending.VerdictApplied {
		return
	}
	if unreachable {
		pt.Pending.Unreachable = true
		return
	}
	pt.Pending.VerdictApplied = true
	var events []map[string]any
	if pt.Pending.SchemaError != "" {
		events = append(events, s.buildEventLocked("policy_decision", map[string]any{
			"server": server, "tool_name": toolName, "action": "block",
			"reason": "TOOL_SCHEMA_INVALID: an invalid schema cannot be resumed",
		}))
		for _, ev := range events {
			s.emit(w, ev)
		}
		return
	}
	switch v.Action {
	case "resume", "warn":
		s.pinned[key] = &PinnedTool{
			DefHash: pt.Pending.NewHash, Tool: pt.Pending.NewTool,
			Schema: pt.Pending.NewSchema, RiskClass: pt.Pending.RiskClass,
		}
		events = append(events, s.buildEventLocked("policy_decision", map[string]any{
			"server": server, "tool_name": toolName, "action": actionFor(v.Action), "reason": v.Reason,
		}))
	case "quarantine":
		events = append(events, s.buildEventLocked("policy_decision", map[string]any{
			"server": server, "tool_name": toolName, "action": "quarantine", "reason": v.Reason,
		}))
		// Stays Suspended here; the poller's GET /quarantine cache is what
		// actually blocks every session (including this one) at the top of
		// PrepareCall, on its next poll tick. See DESIGN.md §7.
	default: // "suspend" (BREAKING): keep suspended for this session.
		events = append(events, s.buildEventLocked("policy_decision", map[string]any{
			"server": server, "tool_name": toolName, "action": "block", "reason": v.Reason,
		}))
	}
	for _, ev := range events {
		s.emit(w, ev)
	}
}

// RejectDefinition invalidates any outstanding approval when an observed tool
// cannot be hashed. Keep an existing trusted pin, but never allow calls under it
// while the upstream is advertising an unverifiable definition.
func (s *Session) RejectDefinition(w *eventlog.Writer, server, name, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := Key(server, name)
	pt := s.pinned[key]
	if pt == nil {
		pt = &PinnedTool{SchemaError: reason}
		s.pinned[key] = pt
	}
	pt.InvalidDefinition = reason
	pt.Suspended = true
	pt.Pending = nil
	s.emit(w, s.buildEventLocked("policy_decision", map[string]any{
		"server": server, "tool_name": name, "action": "block", "reason": "TOOL_SCHEMA_INVALID: " + reason,
	}))
}

// CallDecision is the outcome of checking whether a tools/call may proceed.
type CallDecision struct {
	Allow   bool
	Code    string // machine-readable reason for the JSON-RPC error's data.reason
	Message string
	DefHash string
	Schema  *jsonschema.Schema
}

// PrepareCall is the hot-path check for tools/call: is this (server, tool)
// pinned, and if suspended, does policy allow the call through anyway? See
// DESIGN.md §5 for the fail-closed/fail-open-with-audit rule this implements.
func (s *Session) PrepareCall(server, toolName string) CallDecision {
	key := Key(server, toolName)
	s.mu.Lock()
	defer s.mu.Unlock()

	pt, ok := s.pinned[key]
	if !ok {
		return CallDecision{Code: "TOOL_NOT_PINNED", Message: "call tools/list before tools/call for this tool (v1 requires an explicit pin)"}
	}
	if pt.InvalidDefinition != "" {
		return CallDecision{Code: "TOOL_SCHEMA_INVALID", Message: "tool definition cannot be verified"}
	}
	if pt.SchemaError != "" {
		return CallDecision{Code: "TOOL_SCHEMA_INVALID", Message: "tool is blocked because its input schema is invalid: " + pt.SchemaError}
	}
	if pt.Pending != nil && pt.Pending.SchemaError != "" {
		return CallDecision{Code: "TOOL_SCHEMA_INVALID", Message: "tool is blocked because its changed input schema is invalid: " + pt.Pending.SchemaError}
	}
	if !pt.Suspended {
		return CallDecision{Allow: true, DefHash: pt.DefHash, Schema: pt.Schema}
	}
	if pt.Pending != nil && !pt.Pending.VerdictApplied && pt.Pending.Unreachable && pt.RiskClass == "read_only" && pt.Pending.RiskClass == "read_only" {
		// Fail-open-with-audit: a read-only tool, with no verdict available
		// because the control plane could not be reached, is allowed through
		// against its newly observed (unapproved) schema so the session keeps
		// making progress; the call is still fully logged.
		return CallDecision{
			Allow: true, Code: "WARN_CONTROL_PLANE_UNREACHABLE",
			Message: "read-only tool allowed with audit: control plane unreachable, no verdict yet",
			DefHash: pt.Pending.NewHash, Schema: pt.Pending.NewSchema,
		}
	}
	return CallDecision{Code: "TOOL_CONTRACT_CHANGED", Message: "tool suspended for this session: definition changed and has not been cleared"}
}

// Store is an N-way sharded map of sessions: each shard has its own mutex, so
// unrelated sessions never contend on the same lock and there is no global
// lock across the process. See DESIGN.md §7 ("Scale").
type Store struct {
	shards [64]shard
}

type shard struct {
	mu sync.Mutex
	m  map[string]*Session
}

func NewStore() *Store {
	s := &Store{}
	for i := range s.shards {
		s.shards[i].m = make(map[string]*Session)
	}
	return s
}

func fnv32(s string) uint32 {
	const offset, prime = 2166136261, 16777619
	h := uint32(offset)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return h
}

func (s *Store) shardFor(id string) *shard {
	return &s.shards[fnv32(id)%uint32(len(s.shards))]
}

// Get returns the session for id, creating it if this is the first time it
// has been seen by this proxy instance.
func (s *Store) Get(id string) *Session {
	sh := s.shardFor(id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sess, ok := sh.m[id]
	if !ok {
		sess = newSession(id)
		sh.m[id] = sess
	}
	return sess
}

// Len returns the number of sessions currently held (all shards). For
// metrics/tests only; takes every shard lock briefly.
func (s *Store) Len() int {
	n := 0
	for i := range s.shards {
		s.shards[i].mu.Lock()
		n += len(s.shards[i].m)
		s.shards[i].mu.Unlock()
	}
	return n
}
