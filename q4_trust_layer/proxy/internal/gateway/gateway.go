// Package gateway is the proxy's HTTP handler: the MCP-style JSON-RPC 2.0
// reverse proxy described in q4_trust_layer/DESIGN.md §3-5. One Gateway
// serves every session and every configured upstream tool server; all
// per-request state lives in the session.Store (sharded) and the
// schemacache/quarantine caches (lock-free reads), so ServeHTTP itself holds
// no lock of its own.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/anviq-candidate/anviq-interview/proxy/internal/canonical"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/control"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/eventlog"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/quarantine"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/rpc"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/schemacache"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/session"
)

const (
	// maxRequestBodyBytes bounds both memory use and the amount of JSON the
	// proxy parses for one request. Eight MiB matches the control-plane cap and
	// leaves ample room for tool arguments containing sizeable text payloads.
	maxRequestBodyBytes int64 = 8 * 1024 * 1024
	// maxJSONNumberBytes prevents jsonschema from converting an attacker-sized
	// json.Number to an unbounded big.Rat. This is far above ordinary numeric
	// representations while keeping pathological conversion work bounded.
	maxJSONNumberBytes = 4096
)

var errJSONNumberTooLong = errors.New("JSON number token exceeds limit")

type Gateway struct {
	Servers        map[string]string // server name (from /servers/{name}) -> upstream base URL
	Sessions       *session.Store
	Schemas        *schemacache.Cache
	Events         *eventlog.Writer
	Quarantine     *quarantine.Set
	Control        *control.Client
	Upstream       *http.Client
	ControlTimeout time.Duration
	// RelistInterval > 0 enables background re-listing (see maybeRelist).
	RelistInterval time.Duration
}

func New(servers map[string]string, sessions *session.Store, schemas *schemacache.Cache, events *eventlog.Writer, q *quarantine.Set, ctl *control.Client, controlTimeout time.Duration) *Gateway {
	return &Gateway{
		Servers: servers, Sessions: sessions, Schemas: schemas, Events: events,
		Quarantine: q, Control: ctl, ControlTimeout: controlTimeout,
		Upstream: &http.Client{Timeout: 30 * time.Second, Transport: upstreamTransport()},
	}
}

// upstreamTransport keeps many idle connections per upstream host. Go's
// default is 2, which at hundreds of concurrent sessions per tool server
// forces constant reconnects (new TCP handshake per call) and would blow the
// latency budget. See DECISIONS.md "upstream connection pooling".
func upstreamTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 2048
	t.MaxIdleConnsPerHost = 1024
	return t
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is supported (MCP-style JSON-RPC over HTTP; see DESIGN.md)", http.StatusMethodNotAllowed)
		return
	}
	server := strings.Trim(strings.TrimPrefix(r.URL.Path, "/servers/"), "/")
	upstream, ok := g.Servers[server]
	if !ok {
		http.Error(w, "unknown server: "+server, http.StatusNotFound)
		return
	}
	sessionID := r.Header.Get("X-Session-Id")
	if sessionID == "" {
		http.Error(w, "missing X-Session-Id header", http.StatusBadRequest)
		return
	}
	if !eventlog.ValidSessionID(sessionID) {
		http.Error(w, "invalid X-Session-Id: use 1-128 letters, digits, underscores, or hyphens", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, fmt.Sprintf("request body exceeds %d bytes", maxRequestBodyBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "error reading body", http.StatusBadRequest)
		return
	}
	var req rpc.Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusOK, rpc.ErrorResponse(nil, rpc.CodeBadRequest, "invalid JSON-RPC request", "BAD_REQUEST", nil))
		return
	}

	sess := g.Sessions.Get(sessionID)
	sess.EnsureStarted(g.Events, r.Header.Get("X-Agent-Id"))

	switch req.Method {
	case "tools/list":
		g.handleToolsList(r.Context(), w, server, upstream, sess, req, body)
	case "tools/call":
		g.handleToolsCall(r.Context(), w, server, upstream, sess, req, body)
	default:
		g.forwardPassthrough(r.Context(), w, upstream, body)
	}
}

// postUpstream forwards body byte-for-byte to the upstream tool server.
func (g *Gateway) postUpstream(ctx context.Context, base string, body []byte) ([]byte, int, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := g.Upstream.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return respBody, resp.StatusCode, nil
}

func (g *Gateway) forwardPassthrough(ctx context.Context, w http.ResponseWriter, upstream string, body []byte) {
	respBody, status, err := g.postUpstream(ctx, upstream, body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, rpc.ErrorResponse(nil, rpc.CodeUpstreamError, err.Error(), "UPSTREAM_UNREACHABLE", nil))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// validateJSONNumberLengths tokenizes JSON without constructing a second
// object tree. Decoder.Token understands JSON strings and escapes, avoiding
// the false matches and bypasses of a regex-based number scan. Syntax errors
// are returned to the caller but left to the existing JSON parser to report.
func validateJSONNumberLengths(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if number, ok := tok.(json.Number); ok && len(number.String()) > maxJSONNumberBytes {
			return errJSONNumberTooLong
		}
	}
}

type listBlock struct {
	Code    int
	Reason  string
	Message string
	Tool    string
}

// handleToolsList inspects and pins the upstream answer before exposing it.
// A changed, quarantined, unhashable, or schema-invalid definition is replaced
// with a structured JSON-RPC error so poisoned tool text never reaches the model.
func (g *Gateway) handleToolsList(ctx context.Context, w http.ResponseWriter, server, upstream string, sess *session.Session, req rpc.Request, body []byte) {
	respBody, status, err := g.postUpstream(ctx, upstream, body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, rpc.ErrorResponse(req.ID, rpc.CodeUpstreamError, err.Error(), "UPSTREAM_UNREACHABLE", nil))
		return
	}
	sess.MarkListed(server)
	if block := g.observeListResponse(server, sess, respBody); block != nil {
		writeJSON(w, http.StatusOK, rpc.ErrorResponse(req.ID, block.Code, block.Message, block.Reason, map[string]any{"tool": block.Tool}))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

// observeListResponse pins/checks every tool in a tools/list response body.
func (g *Gateway) observeListResponse(server string, sess *session.Session, respBody []byte) *listBlock {
	var resp rpc.Response
	invalid := &listBlock{Code: rpc.CodeDefinitionInvalid, Reason: "TOOL_SCHEMA_INVALID", Message: "upstream returned an invalid tools/list response"}
	if json.Unmarshal(respBody, &resp) != nil {
		return invalid
	}
	if resp.Error != nil {
		return nil
	}
	var result rpc.ToolsListResult
	if json.Unmarshal(resp.Result, &result) != nil || result.Tools == nil {
		return invalid
	}
	var blocked *listBlock
	seen := make(map[string]bool)
	for _, tool := range result.Tools {
		name, _ := tool["name"].(string)
		if seen[name] {
			sess.RejectDefinition(g.Events, server, name, "duplicate tool name in tools/list")
			blocked = invalid
			continue
		}
		seen[name] = true
		if name != "" && g.Quarantine.Contains(server, name) {
			sess.EmitEvent(g.Events, "policy_decision", map[string]any{
				"server": server, "tool_name": name, "action": "quarantine",
				"reason": "tool is quarantined for all sessions",
			})
			blocked = &listBlock{Code: rpc.CodeToolQuarantined, Reason: "TOOL_QUARANTINED", Message: "tools/list withheld because it contains a quarantined tool", Tool: name}
			continue
		}
		outcome := g.observeTool(server, sess, tool)
		if blocked != nil {
			continue // all tools must still be inspected, even after finding a blocked one
		}
		switch outcome.Action {
		case "invalid":
			blocked = &listBlock{Code: rpc.CodeDefinitionInvalid, Reason: "TOOL_SCHEMA_INVALID", Message: "tools/list withheld because a tool definition is invalid", Tool: name}
		case "mismatch", "pending", "retry":
			blocked = &listBlock{Code: rpc.CodeContractChanged, Reason: "TOOL_CONTRACT_CHANGED", Message: "tools/list withheld because a tool contract changed and has not been cleared", Tool: name}
		}
	}
	return blocked
}

// maybeRelist is called after a tools/call response has been written. If it
// has been longer than RelistInterval since this session last saw a
// tools/list for this server, it re-lists in a background goroutine, so a
// silent contract change is caught even if the agent never re-lists. It adds
// nothing to the call's own latency: the caller already has its response.
func (g *Gateway) maybeRelist(server, upstream string, sess *session.Session) {
	if g.RelistInterval <= 0 || !sess.ClaimRelist(server, g.RelistInterval) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), g.ControlTimeout+5*time.Second)
		defer cancel()
		body := []byte(`{"jsonrpc":"2.0","id":"proxy-relist","method":"tools/list","params":{}}`)
		respBody, _, err := g.postUpstream(ctx, upstream, body)
		if err != nil {
			return
		}
		_ = g.observeListResponse(server, sess, respBody)
	}()
}

func (g *Gateway) observeTool(server string, sess *session.Session, tool map[string]any) session.ListOutcome {
	name, _ := tool["name"].(string)
	if name == "" {
		sess.EmitEvent(g.Events, "policy_decision", map[string]any{
			"server": server, "tool_name": "", "action": "block", "reason": "TOOL_SCHEMA_INVALID: tool name is missing",
		})
		return session.ListOutcome{Action: "invalid", SchemaError: "tool name is missing"}
	}
	defHash, err := canonical.ToolHash(tool)
	if err != nil {
		sess.RejectDefinition(g.Events, server, name, "definition cannot be hashed: "+err.Error())
		return session.ListOutcome{Action: "invalid", SchemaError: err.Error()}
	}
	inputSchema, ok := tool["inputSchema"].(map[string]any)
	var schema *jsonschema.Schema
	var schemaError string
	if !ok {
		sess.RejectDefinition(g.Events, server, name, "inputSchema must be a JSON object")
		return session.ListOutcome{Action: "invalid"}
	} else if compiled, compileErr := g.Schemas.Compiled(defHash, inputSchema); compileErr != nil {
		schemaError = compileErr.Error()
	} else {
		schema = compiled
	}
	outcome := sess.ObserveDefinition(g.Events, server, tool, defHash, schema, schemaError)
	if outcome.Action != "mismatch" && outcome.Action != "retry" {
		return outcome
	}
	go g.reportAndApply(server, name, sess, outcome)
	return outcome
}

// reportAndApply runs on a background goroutine, off every request's
// critical path (see DESIGN.md §4: "POST the change to the control plane
// asynchronously"). It is the only caller of control.Client from this
// package.
func (g *Gateway) reportAndApply(server, tool string, sess *session.Session, outcome session.ListOutcome) {
	ctx, cancel := context.WithTimeout(context.Background(), g.ControlTimeout)
	defer cancel()
	resp, err := g.Control.ReportChange(ctx, control.ChangeRequest{
		Server: server, Tool: tool, SessionID: sess.ID,
		OldHash: outcome.OldHash, NewHash: outcome.NewHash,
		OldDef: outcome.OldTool, NewDef: outcome.NewTool,
	})
	if err != nil {
		sess.ApplyVerdict(g.Events, server, tool, outcome.Revision, true, session.Verdict{})
		return
	}
	sess.ApplyVerdict(g.Events, server, tool, outcome.Revision, false, session.Verdict{Action: resp.Verdict, Reason: resp.Reason})
}

// handleToolsCall is the hot path: quarantine check, suspension check,
// argument validation against the pinned schema, forward, audit. See
// DESIGN.md §6 for the latency budget this is built to.
func (g *Gateway) handleToolsCall(ctx context.Context, w http.ResponseWriter, server, upstream string, sess *session.Session, req rpc.Request, body []byte) {
	var params rpc.ToolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
		writeJSON(w, http.StatusOK, rpc.ErrorResponse(req.ID, rpc.CodeInvalidParams, "invalid tools/call params", "BAD_REQUEST", nil))
		return
	}

	if g.Quarantine.Contains(server, params.Name) {
		sess.EmitEvent(g.Events, "policy_decision", map[string]any{
			"server": server, "tool_name": params.Name, "action": "quarantine",
			"reason": "tool is quarantined for all sessions",
		})
		writeJSON(w, http.StatusOK, rpc.ErrorResponse(req.ID, rpc.CodeToolQuarantined, "tool is quarantined", "TOOL_QUARANTINED", nil))
		return
	}

	decision := sess.PrepareCall(server, params.Name)
	if !decision.Allow {
		code := rpc.CodeContractChanged
		if decision.Code == "TOOL_NOT_PINNED" {
			code = rpc.CodeToolNotPinned
		} else if decision.Code == "TOOL_SCHEMA_INVALID" {
			code = rpc.CodeDefinitionInvalid
		}
		writeJSON(w, http.StatusOK, rpc.ErrorResponse(req.ID, code, decision.Message, decision.Code, nil))
		return
	}

	if decision.Code != "" { // allowed, but only via fail-open: leave an audit trail
		sess.EmitEvent(g.Events, "policy_decision", map[string]any{
			"server": server, "tool_name": params.Name, "action": "warn",
			"reason": decision.Code + ": " + decision.Message,
		})
	}

	if decision.Schema != nil {
		if err := validateJSONNumberLengths(params.Arguments); errors.Is(err, errJSONNumberTooLong) {
			sess.EmitEvent(g.Events, "policy_decision", map[string]any{
				"server": server, "tool_name": params.Name, "action": "block",
				"reason": "ARGS_NUMBER_TOO_LONG: numeric argument exceeds 4096 bytes",
			})
			writeJSON(w, http.StatusOK, rpc.ErrorResponse(req.ID, rpc.CodeInvalidParams, "numeric argument is too long", "ARGS_NUMBER_TOO_LONG", nil))
			return
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(params.Arguments))
		if err != nil {
			sess.EmitEvent(g.Events, "policy_decision", map[string]any{
				"server": server, "tool_name": params.Name, "action": "block",
				"reason": "ARGS_NOT_JSON: " + err.Error(),
			})
			writeJSON(w, http.StatusOK, rpc.ErrorResponse(req.ID, rpc.CodeInvalidParams, "arguments are not valid JSON", "ARGS_NOT_JSON", nil))
			return
		}
		if err := decision.Schema.Validate(inst); err != nil {
			// A validation failure against the pinned schema is itself a drift
			// signal (behaviour disagreeing with the approved contract, even
			// though def_hash hasn't changed) — see DESIGN.md §4. v1 fails
			// closed and audits it; it does not itself call the control plane
			// (no def actually changed to report).
			g.recordCallFailure(sess, server, params, decision.DefHash, "ARGS_SCHEMA_VIOLATION: "+err.Error())
			writeJSON(w, http.StatusOK, rpc.ErrorResponse(req.ID, rpc.CodeInvalidParams, "arguments do not match the pinned schema", "ARGS_SCHEMA_VIOLATION", nil))
			return
		}
	}

	callID := fmt.Sprintf("%s-%d", sess.ID, time.Now().UnixNano())
	var argsAny any
	_ = json.Unmarshal(params.Arguments, &argsAny)
	sess.EmitEvent(g.Events, "tool_call", map[string]any{
		"call_id": callID, "server": server, "tool_name": params.Name,
		"def_hash": decision.DefHash, "args": argsAny,
	})

	start := time.Now()
	respBody, status, err := g.postUpstream(ctx, upstream, body)
	latencyMS := float64(time.Since(start)) / float64(time.Millisecond)

	if err != nil {
		sess.EmitEvent(g.Events, "tool_response", map[string]any{
			"call_id": callID, "ok": false, "latency_ms": latencyMS,
			"error": map[string]any{"message": err.Error()},
		})
		writeJSON(w, http.StatusOK, rpc.ErrorResponse(req.ID, rpc.CodeUpstreamError, err.Error(), "UPSTREAM_UNREACHABLE", nil))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)

	fields := map[string]any{"call_id": callID, "latency_ms": latencyMS}
	var resp rpc.Response
	if json.Unmarshal(respBody, &resp) == nil && resp.Error == nil {
		var resultAny any
		_ = json.Unmarshal(resp.Result, &resultAny)
		fields["ok"] = true
		fields["result"] = resultAny
	} else if resp.Error != nil {
		fields["ok"] = false
		fields["error"] = map[string]any{"code": resp.Error.Code, "message": resp.Error.Message}
	} else {
		fields["ok"] = false
		fields["error"] = map[string]any{"message": "upstream returned a non-JSON-RPC response"}
	}
	sess.EmitEvent(g.Events, "tool_response", fields)
	g.maybeRelist(server, upstream, sess)
}

// recordCallFailure logs a tool_call/tool_response pair for a call that was
// rejected before it ever reached the upstream server (e.g. an argument
// schema violation), so the audit log has a complete record of what the
// agent attempted, not just what succeeded.
func (g *Gateway) recordCallFailure(sess *session.Session, server string, params rpc.ToolsCallParams, defHash, reason string) {
	callID := fmt.Sprintf("%s-%d", sess.ID, time.Now().UnixNano())
	var argsAny any
	_ = json.Unmarshal(params.Arguments, &argsAny)
	sess.EmitEvent(g.Events, "tool_call", map[string]any{
		"call_id": callID, "server": server, "tool_name": params.Name, "def_hash": defHash, "args": argsAny,
	})
	sess.EmitEvent(g.Events, "tool_response", map[string]any{
		"call_id": callID, "ok": false, "latency_ms": 0.0,
		"error": map[string]any{"message": reason},
	})
}
