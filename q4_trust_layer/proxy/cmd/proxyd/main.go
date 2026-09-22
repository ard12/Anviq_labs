// Command proxyd runs the Q4 trust-layer data-plane proxy described in
// q4_trust_layer/DESIGN.md. Run: go run ./cmd/proxyd -config path/to/config.json
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/anviq-candidate/anviq-interview/proxy/internal/config"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/control"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/eventlog"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/gateway"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/quarantine"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/schemacache"
	"github.com/anviq-candidate/anviq-interview/proxy/internal/session"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to proxy config JSON (see testdata/config.json)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	events, err := eventlog.NewWriter(cfg.EventLogDir, cfg.EventChannelCapacity())
	if err != nil {
		log.Fatal(err)
	}
	defer events.Close()

	q := quarantine.NewSet()
	ctl := control.New(cfg.ControlBaseURL, cfg.ControlTimeout())
	if cfg.ControlBaseURL == "" {
		log.Println("warning: no control_base_url configured; mismatches will suspend forever (no verdict will ever arrive) and the quarantine list will stay empty. See DECISIONS.md.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go q.RunPoller(ctx, cfg.QuarantinePollInterval(), func(ctx context.Context) ([]quarantine.Entry, error) {
		return ctl.Quarantine(ctx)
	})

	gw := gateway.New(cfg.Servers, session.NewStore(), schemacache.New(), events, q, ctl, cfg.ControlTimeout())
	gw.RelistInterval = cfg.RelistInterval()
	srv := &http.Server{Addr: cfg.Listen, Handler: gw}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		cancel()
		_ = srv.Close()
	}()

	log.Printf("q4 trust-layer proxy listening on %s (servers: %v)", cfg.Listen, serverNames(cfg.Servers))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func serverNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
