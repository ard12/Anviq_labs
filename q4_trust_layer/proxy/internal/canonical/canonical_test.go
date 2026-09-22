package canonical

import (
	"encoding/json"
	"os"
	"testing"
)

// goldenPath is ../../schema/golden_vectors.json relative to proxy/ (per
// q4_trust_layer/DESIGN.md and the WP4 brief), i.e. four levels up from this
// package (internal/canonical -> internal -> proxy -> q4_trust_layer -> repo root).
const goldenPath = "../../../../schema/golden_vectors.json"

type goldenFile struct {
	JSON []struct {
		ID        string `json:"id"`
		Input     any    `json:"input"`
		Canonical string `json:"canonical"`
		Hash      string `json:"hash"`
	} `json:"json"`
	Tools []struct {
		ID              string         `json:"id"`
		Input           map[string]any `json:"input"`
		NormalizedCanon string         `json:"normalized_canonical"`
		Hash            string         `json:"hash"`
	} `json:"tools"`
}

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden vectors at %s: %v (run go test from q4_trust_layer/proxy, or check the repo layout)", goldenPath, err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parsing golden vectors: %v", err)
	}
	return g
}

func TestGoldenJSON(t *testing.T) {
	g := loadGolden(t)
	for _, c := range g.JSON {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			got, err := CanonicalJSON(c.Input)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			if got != c.Canonical {
				t.Errorf("canonical mismatch:\n got  %s\n want %s", got, c.Canonical)
			}
			hash, err := Sha256Hex(c.Input)
			if err != nil {
				t.Fatalf("Sha256Hex: %v", err)
			}
			if hash != c.Hash {
				t.Errorf("hash mismatch: got %s want %s", hash, c.Hash)
			}
		})
	}
}

func TestGoldenTools(t *testing.T) {
	g := loadGolden(t)
	for _, c := range g.Tools {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			hash, err := ToolHash(c.Input)
			if err != nil {
				t.Fatalf("ToolHash: %v", err)
			}
			if hash != c.Hash {
				t.Errorf("hash mismatch: got %s want %s", hash, c.Hash)
			}
			norm := NormalizeTool(c.Input)
			gotCanon, err := CanonicalJSON(norm)
			if err != nil {
				t.Fatalf("CanonicalJSON(normalize): %v", err)
			}
			if gotCanon != c.NormalizedCanon {
				t.Errorf("normalized canonical mismatch:\n got  %s\n want %s", gotCanon, c.NormalizedCanon)
			}
		})
	}
}

func TestCosmeticReorderingKeepsHashButRugpullChanges(t *testing.T) {
	g := loadGolden(t)
	byID := map[string]string{}
	for _, c := range g.Tools {
		h, err := ToolHash(c.Input)
		if err != nil {
			t.Fatalf("ToolHash(%s): %v", c.ID, err)
		}
		byID[c.ID] = h
	}
	if byID["read_file_basic"] != byID["read_file_reordered_same_hash"] {
		t.Errorf("reordering + $comment + duplicate required should not change the hash")
	}
	if byID["read_file_basic"] == byID["read_file_rugpull"] {
		t.Errorf("a changed description/schema must change the hash")
	}
}

func TestEventHashIgnoresOwnField(t *testing.T) {
	ev := map[string]any{"v": 1, "seq": 0, "session_id": "s", "type": "session_end", "reason": "completed"}
	h, err := EventHash(ev)
	if err != nil {
		t.Fatalf("EventHash: %v", err)
	}
	ev2 := map[string]any{}
	for k, v := range ev {
		ev2[k] = v
	}
	ev2["event_hash"] = h
	h2, err := EventHash(ev2)
	if err != nil {
		t.Fatalf("EventHash: %v", err)
	}
	if h != h2 {
		t.Errorf("event_hash must ignore its own field: %s != %s", h, h2)
	}
}

func benchTool() map[string]any {
	return map[string]any{
		"name":        "read_file",
		"description": "Read a UTF-8 text file and return its contents.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": map[string]any{"type": "string", "description": "Absolute path."}},
			"required":   []any{"path"},
		},
	}
}

// BenchmarkToolHash: cost of def_hash for one typical tool. Paid only on
// tools/list, never per tools/call.
func BenchmarkToolHash(b *testing.B) {
	tool := benchTool()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ToolHash(tool); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEventHash: cost of one hash-chain link. Paid per emitted event
// (a tools/call emits two: tool_call and tool_response).
func BenchmarkEventHash(b *testing.B) {
	ev := map[string]any{
		"v": 1, "seq": 7, "ts": "2026-09-19T12:00:00Z", "session_id": "s1", "type": "tool_call",
		"prev_hash": "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000",
		"call_id":   "s1-1", "server": "fs", "tool_name": "read_file",
		"def_hash": "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111",
		"args":     map[string]any{"path": "/x"},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EventHash(ev); err != nil {
			b.Fatal(err)
		}
	}
}
