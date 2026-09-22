package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/anviq-candidate/anviq-interview/proxy/internal/canonical"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/eventlog"
)

func TestStaleVerdictCannotApproveNewerChange(t *testing.T) {
	w, err := eventlog.NewWriter(t.TempDir(), 128)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	s := newSession("session")
	tool := map[string]any{"name": "read_file", "inputSchema": map[string]any{}}
	s.ObserveDefinition(w, "fs", tool, "v1", nil, "")
	v2 := s.ObserveDefinition(w, "fs", tool, "v2", nil, "")
	s.ObserveDefinition(w, "fs", tool, "v3", nil, "")
	// Returning to v2 must also invalidate the first v2 report (ABA case).
	current := s.ObserveDefinition(w, "fs", tool, "v2", nil, "")
	s.ApplyVerdict(w, "fs", "read_file", v2.Revision, false, Verdict{Action: "resume"})
	if s.PrepareCall("fs", "read_file").Allow {
		t.Fatal("stale resume approved a newer change")
	}
	s.ApplyVerdict(w, "fs", "read_file", v2.Revision, true, Verdict{})
	if s.pinned[Key("fs", "read_file")].Pending.Unreachable {
		t.Fatal("stale failure changed current state")
	}
	s.ApplyVerdict(w, "fs", "read_file", current.Revision, false, Verdict{Action: "resume"})
	if !s.PrepareCall("fs", "read_file").Allow {
		t.Fatal("current approval did not resume")
	}
}

func TestConcurrentAuditEventsKeepChainOrder(t *testing.T) {
	dir := t.TempDir()
	w, err := eventlog.NewWriter(dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	s := newSession("session")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.EnsureStarted(w, "test")
			for j := 0; j < 100; j++ {
				s.EmitEvent(w, "policy_decision", map[string]any{"server": "fs", "tool_name": "read_file", "action": "allow", "reason": "test"})
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2001 {
		t.Fatalf("want 2001 events, got %d", len(lines))
	}
	var previous any
	for i, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event["seq"] != float64(i) || event["prev_hash"] != previous {
			t.Fatalf("out of order event %d: %s", i, line)
		}
		hash, err := canonical.EventHash(event)
		if err != nil || event["event_hash"] != hash {
			t.Fatalf("invalid hash at %d: %v", i, err)
		}
		previous = hash
	}
}

func BenchmarkStoreGetExisting(b *testing.B) {
	s := NewStore()
	s.Get("bench")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Get("bench")
	}
}

func BenchmarkPrepareCallPinned(b *testing.B) {
	sess := newSession("bench")
	sess.pinned[Key("fs", "read_file")] = &PinnedTool{DefHash: "sha256:x"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if d := sess.PrepareCall("fs", "read_file"); !d.Allow {
			b.Fatal("not allowed")
		}
	}
}

// TestStoreShardsSpreadSessions checks sessions land on many shards (no
// accidental single hot shard) and Get is idempotent.
func TestStoreShardsSpreadSessions(t *testing.T) {
	s := NewStore()
	for i := 0; i < 6400; i++ {
		s.Get(fmt.Sprintf("session-%d", i))
	}
	if s.Len() != 6400 {
		t.Fatalf("want 6400 sessions, got %d", s.Len())
	}
	if s.Get("session-1") != s.Get("session-1") {
		t.Fatal("Get must return the same *Session for the same id")
	}
	max := 0
	for i := range s.shards {
		if n := len(s.shards[i].m); n > max {
			max = n
		}
	}
	if max > 200 { // uniform would be 100
		t.Fatalf("shard skew too high: largest shard holds %d of 6400", max)
	}
}
