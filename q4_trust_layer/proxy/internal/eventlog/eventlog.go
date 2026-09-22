// Package eventlog is the async sink for recording events: a bounded channel
// drained by a single writer goroutine that appends JSONL lines per session,
// in the shared schema/recording.schema.json format. It never blocks the
// caller beyond a single non-blocking channel send. See DESIGN.md §6 and
// DECISIONS.md "bounded event channel + drop policy".
package eventlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

type record struct {
	sessionID string
	event     map[string]any
}

type Writer struct {
	mu       sync.RWMutex
	closed   bool
	closeErr error
	dir      string
	ch       chan record
	done     chan struct{}
	drops    atomic.Uint64
	// files is only ever touched by the single run() goroutine, so it needs
	// no lock of its own.
	files map[string]*os.File
}

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ValidSessionID keeps externally supplied session names within the log directory
// and excludes Windows device names, including when followed by the .jsonl suffix.
func ValidSessionID(id string) bool {
	if !sessionIDPattern.MatchString(id) {
		return false
	}
	u := strings.ToUpper(id)
	if u == "CON" || u == "PRN" || u == "AUX" || u == "NUL" {
		return false
	}
	return !(len(u) == 4 && (strings.HasPrefix(u, "COM") || strings.HasPrefix(u, "LPT")) && u[3] >= '1' && u[3] <= '9')
}

// NewWriter creates the output directory (if needed) and starts the writer
// goroutine. capacity bounds how many events may be queued before Enqueue
// starts dropping (and callers mark their session audit_incomplete).
func NewWriter(dir string, capacity int) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("eventlog: creating %s: %w", dir, err)
	}
	if capacity <= 0 {
		capacity = 4096
	}
	w := &Writer{
		dir:   dir,
		ch:    make(chan record, capacity),
		done:  make(chan struct{}),
		files: make(map[string]*os.File),
	}
	go w.run()
	return w, nil
}

func (w *Writer) run() {
	defer func() {
		for _, f := range w.files {
			if err := f.Close(); err != nil && w.closeErr == nil {
				w.closeErr = err
			}
		}
		close(w.done)
	}()
	for rec := range w.ch {
		f, err := w.fileFor(rec.sessionID)
		if err != nil {
			// Disk-level failure writing the audit log. This is distinct from a
			// dropped-due-to-backpressure event (counted at Enqueue time); we
			// still count it so operators see total write failures.
			w.drops.Add(1)
			continue
		}
		b, err := json.Marshal(rec.event)
		if err != nil {
			w.drops.Add(1)
			continue
		}
		b = append(b, '\n')
		if _, err := f.Write(b); err != nil {
			w.drops.Add(1)
		}
	}
}

func (w *Writer) fileFor(sessionID string) (*os.File, error) {
	if f, ok := w.files[sessionID]; ok {
		return f, nil
	}
	if !ValidSessionID(sessionID) {
		return nil, fmt.Errorf("eventlog: invalid session ID")
	}
	f, err := os.OpenFile(filepath.Join(w.dir, sessionID+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	w.files[sessionID] = f
	return f, nil
}

// Enqueue attempts a non-blocking send of event for sessionID. It returns
// false if the channel is full (the event was dropped): the caller should
// mark the session audit_incomplete. This is the only interaction with the
// writer on the hot path, and it is O(1) and non-blocking.
func (w *Writer) Enqueue(sessionID string, event map[string]any) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed || !ValidSessionID(sessionID) {
		w.drops.Add(1)
		return false
	}
	select {
	case w.ch <- record{sessionID, event}:
		return true
	default:
		w.drops.Add(1)
		return false
	}
}

// Drops returns the total number of events dropped (backpressure or write
// failure) since startup. Exposed for metrics/tests.
func (w *Writer) Drops() uint64 { return w.drops.Load() }

// Close stops accepting new events, drains the channel, and closes all open
// session files. Safe to call repeatedly or concurrently with Enqueue (or to force a
// deterministic flush before reading the JSONL back).
func (w *Writer) Close() error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
	w.mu.Unlock()
	<-w.done
	return w.closeErr
}
