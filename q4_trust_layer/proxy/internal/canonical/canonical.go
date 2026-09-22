// Package canonical is a Go port of schema/canonical.py. It MUST stay behaviourally
// identical to that file (see schema/golden_vectors.json for the cross-language
// parity contract) because the proxy and the Python control/harness code compute
// def_hash and event_hash independently and compare them.
//
// Canonical form = RFC 8785 (JSON Canonicalization Scheme, "JCS"). Rather than
// re-implement JCS's UTF-16 key sorting and ECMAScript number formatting by hand
// (the two easiest places to get a byte-for-byte contract subtly wrong), we lean
// on github.com/gowebpki/jcs, a dedicated RFC 8785 implementation: we marshal the
// Go value to JSON with the stdlib encoder, then hand those bytes to jcs.Transform,
// which re-parses and re-serializes per the RFC. That is the documented allowed
// dependency (see q4_trust_layer/DESIGN.md and DECISIONS.md, "Go port of canonical
// hashing").
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf16"

	"github.com/gowebpki/jcs"
)

// HashPrefix matches canonical.py's HASH_PREFIX.
const HashPrefix = "sha256:"

// CanonicalJSON serializes v per RFC 8785, matching canonical.py's canonical_json.
func CanonicalJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("canonical: value is not JSON-serializable: %w", err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("canonical: JCS transform failed: %w", err)
	}
	return string(out), nil
}

// Sha256Hex matches canonical.py's sha256_hex: HASH_PREFIX + sha256(canonical_json(v)).
func Sha256Hex(v any) (string, error) {
	s, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(s))
	return HashPrefix + hex.EncodeToString(sum[:]), nil
}

// normalizeSchema ports canonical.py's _normalize_schema: drop $comment at every
// level, and sort+dedupe any "required" array of strings by UTF-16 code unit.
func normalizeSchema(node any) any {
	switch n := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(n))
		for k, v := range n {
			if k == "$comment" {
				continue
			}
			out[k] = normalizeSchema(v)
		}
		if req, ok := out["required"]; ok {
			if arr, ok := req.([]any); ok {
				if strs, ok := allStrings(arr); ok {
					out["required"] = sortDedupeUTF16(strs)
				}
			}
		}
		return out
	case []any:
		out := make([]any, len(n))
		for i, v := range n {
			out[i] = normalizeSchema(v)
		}
		return out
	default:
		return node
	}
}

func allStrings(arr []any) ([]string, bool) {
	out := make([]string, len(arr))
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// sortDedupeUTF16 sorts unique strings by UTF-16 code unit, matching Python's
// `sorted(set(req), key=lambda s: s.encode("utf-16-be"))`.
func sortDedupeUTF16(strs []string) []any {
	seen := make(map[string]bool, len(strs))
	uniq := make([]string, 0, len(strs))
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			uniq = append(uniq, s)
		}
	}
	sort.Slice(uniq, func(i, j int) bool { return utf16Less(uniq[i], uniq[j]) })
	out := make([]any, len(uniq))
	for i, s := range uniq {
		out[i] = s
	}
	return out
}

func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// NormalizeTool ports canonical.py's normalize_tool: project a tool definition
// onto the fields that define its contract. description is included on purpose
// (a changed description is exactly what a rug-pull looks like); whether the
// change *matters* is the differ's job, not the hot path's.
func NormalizeTool(tool map[string]any) map[string]any {
	out := map[string]any{
		"name":        tool["name"],
		"description": "",
		"inputSchema": normalizeSchema(tool["inputSchema"]),
	}
	if d, ok := tool["description"]; ok {
		out["description"] = d
	}
	for _, k := range [...]string{"outputSchema", "annotations"} {
		if v, ok := tool[k]; ok {
			out[k] = normalizeSchema(v)
		}
	}
	return out
}

// ToolHash matches canonical.py's tool_hash.
func ToolHash(tool map[string]any) (string, error) {
	return Sha256Hex(NormalizeTool(tool))
}

// EventHash matches canonical.py's event_hash: hash of an event for the
// per-session hash chain, excluding the event's own event_hash field.
func EventHash(event map[string]any) (string, error) {
	filtered := make(map[string]any, len(event))
	for k, v := range event {
		if k == "event_hash" {
			continue
		}
		filtered[k] = v
	}
	return Sha256Hex(filtered)
}
