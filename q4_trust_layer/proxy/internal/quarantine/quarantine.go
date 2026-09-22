// Package quarantine holds the small, process-wide set of (server, tool)
// pairs the control plane has quarantined. It is refreshed by polling
// GET /quarantine (v1; see DESIGN.md §7) and swapped in atomically so the
// tools/call hot path never blocks on a lock or a network call to check it.
package quarantine

import (
	"context"
	"sync/atomic"
	"time"
)

// Entry identifies one quarantined (server, tool) pair.
type Entry struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
}

func key(server, tool string) string { return server + "\x00" + tool }

// Set is a lock-free, eventually-consistent snapshot of the quarantine list.
// Reads (Contains) never block; a refresh (Replace) swaps in a whole new
// immutable map rather than mutating one in place.
type Set struct {
	ptr atomic.Pointer[map[string]struct{}]
}

func NewSet() *Set {
	s := &Set{}
	empty := map[string]struct{}{}
	s.ptr.Store(&empty)
	return s
}

// Contains is the hot-path check: one atomic load + one map read, no lock.
func (s *Set) Contains(server, tool string) bool {
	m := s.ptr.Load()
	_, ok := (*m)[key(server, tool)]
	return ok
}

func (s *Set) Replace(entries []Entry) {
	m := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		m[key(e.Server, e.Tool)] = struct{}{}
	}
	s.ptr.Store(&m)
}

// RunPoller fetches immediately, then every interval, until ctx is done.
// A fetch error leaves the current (stale) snapshot in place: staying with
// last-known-good is safer than blanking the quarantine list on a hiccup.
func (s *Set) RunPoller(ctx context.Context, interval time.Duration, fetch func(context.Context) ([]Entry, error)) {
	for {
		if entries, err := fetch(ctx); err == nil {
			s.Replace(entries)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
