// Command loadgen measures the per-call latency the proxy adds on top of a
// mock upstream tool server with a fixed 20ms response time, at 1, 100 and
// 1000 concurrent sessions. Run: go run ./cmd/loadgen
//
// "direct" calls the mock upstream with no proxy in front of it (the
// baseline). "proxy" pins each session with one tools/list, then repeats
// tools/call through the gateway. The reported "overhead" is proxy-latency
// minus direct-latency at each percentile — this is the number pasted into
// DESIGN.md §6.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/anviq-candidate/anviq-interview/proxy/internal/control"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/eventlog"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/gateway"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/quarantine"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/schemacache"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/session"
)

const upstreamLatency = 20 * time.Millisecond

var toolDef = map[string]any{
	"name":        "read_file",
	"description": "Read a UTF-8 text file and return its contents.",
	"inputSchema": map[string]any{
		"type":       "object",
		"properties": map[string]any{"path": map[string]any{"type": "string"}},
		"required":   []any{"path"},
	},
}

func mockUpstream() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"tools": []any{toolDef}},
			})
		default:
			time.Sleep(upstreamLatency)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"ok": true},
			})
		}
	}))
}

func toolsListBody() []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
}

func toolsCallBody(id int) []byte {
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id + 2, "method": "tools/call",
		"params": map[string]any{"name": "read_file", "arguments": map[string]any{"path": "/tmp/x"}},
	})
	return b
}

func percentile(latencies []time.Duration, p float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), latencies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(p / 100 * float64(len(sorted)-1))
	return sorted[idx]
}

// runLoad fans out `concurrency` goroutines, each making `callsPerSession`
// timed calls via `call`, and returns every individual latency plus the
// total wall-clock time (for throughput).
func runLoad(concurrency, callsPerSession int, think time.Duration, call func(sessionIdx, callIdx int) time.Duration) ([]time.Duration, time.Duration) {
	var wg sync.WaitGroup
	results := make([][]time.Duration, concurrency)
	start := time.Now()
	for s := 0; s < concurrency; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			lat := make([]time.Duration, 0, callsPerSession)
			rng := rand.New(rand.NewSource(int64(s)))
			for c := 0; c < callsPerSession; c++ {
				if think > 0 { // agent-like pacing: 0.5x..1.5x think time, not timed
					time.Sleep(think/2 + time.Duration(rng.Int63n(int64(think))))
				}
				lat = append(lat, call(s, c))
			}
			results[s] = lat
		}(s)
	}
	wg.Wait()
	elapsed := time.Since(start)
	var all []time.Duration
	for _, r := range results {
		all = append(all, r...)
	}
	return all, elapsed
}

func report(w io.Writer, label string, conc int, directLat []time.Duration, directElapsed time.Duration, proxyLat []time.Duration, proxyElapsed time.Duration) {
	dp50, dp95, dp99 := percentile(directLat, 50), percentile(directLat, 95), percentile(directLat, 99)
	pp50, pp95, pp99 := percentile(proxyLat, 50), percentile(proxyLat, 95), percentile(proxyLat, 99)
	fmt.Fprintf(w, "[%s] concurrency=%d (n=%d calls per mode)\n", label, conc, len(directLat))
	fmt.Fprintf(w, "  direct    p50=%-10s p95=%-10s p99=%-10s throughput=%.0f req/s\n",
		dp50, dp95, dp99, float64(len(directLat))/directElapsed.Seconds())
	fmt.Fprintf(w, "  proxy     p50=%-10s p95=%-10s p99=%-10s throughput=%.0f req/s\n",
		pp50, pp95, pp99, float64(len(proxyLat))/proxyElapsed.Seconds())
	fmt.Fprintf(w, "  overhead  p50=%-10s p95=%-10s p99=%-10s  <- added by the proxy\n\n",
		pp50-dp50, pp95-dp95, pp99-dp99)
}

func main() {
	upstream := mockUpstream()
	defer upstream.Close()

	eventDir, err := os.MkdirTemp("", "q4-loadgen-events-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(eventDir)
	events, err := eventlog.NewWriter(eventDir, 1<<20)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer events.Close()

	gw := gateway.New(
		map[string]string{"fs": upstream.URL},
		session.NewStore(), schemacache.New(), events,
		quarantine.NewSet(), control.New("", time.Second), time.Second,
	)
	proxy := httptest.NewServer(gw)
	defer proxy.Close()

	// Same pooling for the load generator's own client, or it (not the
	// proxy) becomes the bottleneck: the default keeps only 2 idle
	// connections per host.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 4096
	tr.MaxIdleConnsPerHost = 2048
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}

	fmt.Printf("q4 trust-layer proxy - load generator\n")
	fmt.Printf("mock upstream fixed latency: %s\n\n", upstreamLatency)

	scenarios := []struct {
		label string
		think time.Duration
	}{
		{"closed-loop, no think time: saturation stress", 0},
		{"paced, ~300ms think time: agent-like", 300 * time.Millisecond},
	}
	for _, sc := range scenarios {
		for _, conc := range []int{1, 100, 1000} {
			callsPerSession := 20
			if conc >= 1000 {
				callsPerSession = 10
			}
			if sc.think > 0 {
				callsPerSession = 8
			}

			directCall := func(s, c int) time.Duration {
				start := time.Now()
				resp, err := client.Post(upstream.URL, "application/json", bytes.NewReader(toolsCallBody(c)))
				if err != nil {
					return time.Since(start)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				return time.Since(start)
			}

			proxyCall := func(s, c int) time.Duration {
				sessionID := fmt.Sprintf("loadgen-%d-%d", conc, s)
				if c == 0 {
					req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/servers/fs", bytes.NewReader(toolsListBody()))
					req.Header.Set("X-Session-Id", sessionID)
					if resp, err := client.Do(req); err == nil {
						_, _ = io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
				}
				req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/servers/fs", bytes.NewReader(toolsCallBody(c)))
				req.Header.Set("X-Session-Id", sessionID)
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					return time.Since(start)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				return time.Since(start)
			}

			// Warm-up (discarded): open the connection pools and pin every
			// session, so the measured runs compare steady state to steady
			// state instead of charging TCP handshakes to whichever mode
			// runs first.
			runLoad(conc, 3, 0, directCall)
			runLoad(conc, 3, 0, proxyCall)

			directLat, directElapsed := runLoad(conc, callsPerSession, sc.think, directCall)
			proxyLat, proxyElapsed := runLoad(conc, callsPerSession, sc.think, proxyCall)

			report(os.Stdout, sc.label, conc, directLat, directElapsed, proxyLat, proxyElapsed)
		}
	}

	fmt.Printf("event writer drops: %d\n", events.Drops())
}
