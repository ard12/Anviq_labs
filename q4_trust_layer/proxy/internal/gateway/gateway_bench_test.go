package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	benchListBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	benchCallBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x"}}}`
)

// cannedRT is an in-process upstream: it answers instantly with no socket, so
// the benchmark measures only the proxy's own work. The same canned body
// serves tools/list (has "tools") and tools/call (extra "ok" key is harmless).
type cannedRT struct{}

func (cannedRT) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Read a UTF-8 text file and return its contents.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}],"ok":true}}`
	return &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r,
	}, nil
}

func newBenchGateway(b *testing.B) *Gateway {
	gw, _ := newTestGateway(b, "http://upstream.invalid", "")
	gw.Upstream = &http.Client{Transport: cannedRT{}}
	return gw
}

func benchPost(gw *Gateway, sid, body string) {
	req := httptest.NewRequest(http.MethodPost, "/servers/fs", strings.NewReader(body))
	req.Header.Set("X-Session-Id", sid)
	gw.ServeHTTP(httptest.NewRecorder(), req)
}

// BenchmarkToolsCall is the proxy's own added CPU cost per tools/call with a
// zero-latency in-process upstream: JSON-RPC parse, quarantine check, session
// lookup, schema validation, event hash-chain + enqueue, response write. The
// httptest.NewRequest/NewRecorder cost is included (a small constant).
func BenchmarkToolsCall(b *testing.B) {
	gw := newBenchGateway(b)
	benchPost(gw, "bench", benchListBody)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchPost(gw, "bench", benchCallBody)
	}
}

// BenchmarkToolsList is the (rare) path that computes def_hash: parse the
// tool list, JCS + sha256 each tool, compare with the pin.
func BenchmarkToolsList(b *testing.B) {
	gw := newBenchGateway(b)
	benchPost(gw, "bench", benchListBody)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchPost(gw, "bench", benchListBody)
	}
}

// BenchmarkToolsCallParallel: one session per goroutine, GOMAXPROCS-way
// concurrency, exercising the sharded session store under contention.
func BenchmarkToolsCallParallel(b *testing.B) {
	gw := newBenchGateway(b)
	var n atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		sid := fmt.Sprintf("bench-%d", n.Add(1))
		benchPost(gw, sid, benchListBody)
		for pb.Next() {
			benchPost(gw, sid, benchCallBody)
		}
	})
}
