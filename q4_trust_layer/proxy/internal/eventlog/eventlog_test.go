package eventlog

import (
	"sync"
	"testing"
)

func TestRejectUnsafeSessionIDs(t *testing.T) {
	w, err := NewWriter(t.TempDir(), 32)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, id := range []string{"", "../escape", `..\escape`, "C:escape", "CON", "nul", "LPT1"} {
		if w.Enqueue(id, map[string]any{}) {
			t.Fatalf("accepted unsafe ID %q", id)
		}
	}
	if !w.Enqueue("safe-session_1", map[string]any{}) {
		t.Fatal("rejected safe ID")
	}
}

func TestConcurrentCloseAndEnqueue(t *testing.T) {
	w, err := NewWriter(t.TempDir(), 4096)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				w.Enqueue("session", map[string]any{"value": j})
			}
		}()
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.Enqueue("session", map[string]any{}) {
		t.Fatal("accepted event after close")
	}
}
