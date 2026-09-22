// Package rpc has the minimal JSON-RPC 2.0 types the proxy needs for
// MCP-style "tools/list" and "tools/call" over plain HTTP POST. SSE and
// stdio transports are out of scope for v1 (see DESIGN.md §9).
package rpc

import "encoding/json"

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a structured JSON-RPC error. Data always carries "reason", a
// stable machine-readable code the calling agent can branch on (re-plan
// without the tool, ask the user, etc.) without parsing Message. See
// DESIGN.md §5.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Server error codes, in JSON-RPC's reserved -32000..-32099 implementation-
// defined range, plus the standard -32602 for schema-invalid arguments.
const (
	CodeInvalidParams     = -32602
	CodeToolNotPinned     = -32001
	CodeContractChanged   = -32002
	CodeToolQuarantined   = -32003
	CodeUpstreamError     = -32004
	CodeDefinitionInvalid = -32005
	CodeBadRequest        = -32600
)

func ErrorResponse(id json.RawMessage, code int, message, reason string, extra map[string]any) Response {
	data := map[string]any{"reason": reason}
	for k, v := range extra {
		data[k] = v
	}
	return Response{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: message, Data: data}}
}

// ToolsCallParams is the params object of a "tools/call" request. Arguments
// is kept raw so it can be forwarded to the upstream byte-for-byte and
// separately decoded (via jsonschema.UnmarshalJSON, which preserves number
// precision with json.Number) for schema validation.
type ToolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolsListResult is the result object of a "tools/list" response.
type ToolsListResult struct {
	Tools []map[string]any `json:"tools"`
}
