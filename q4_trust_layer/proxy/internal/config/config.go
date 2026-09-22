// Package config loads the proxy's static configuration: which upstream tool
// servers exist and how to reach the control plane. Kept deliberately tiny
// (one JSON file, no hot-reload) — see DECISIONS.md "config is static in v1".
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	// Listen is the address the proxy's HTTP server binds, e.g. ":8080".
	Listen string `json:"listen"`
	// Servers maps a path segment ("/servers/{server}") to the upstream base URL.
	Servers map[string]string `json:"servers"`
	// ControlBaseURL is the control plane's HTTP base URL (POST /changes,
	// GET /quarantine). Empty means "no control plane configured": the proxy
	// still enforces suspend-on-mismatch locally, it just never gets a verdict,
	// which is equivalent to "control plane permanently unreachable" (see
	// DESIGN.md §5 fail-open/fail-closed).
	ControlBaseURL string `json:"control_base_url"`
	// EventLogDir is where per-session JSONL recordings are written.
	EventLogDir string `json:"event_log_dir"`
	// QuarantinePollInterval defaults to 1s per the brief.
	QuarantinePollIntervalMS int `json:"quarantine_poll_interval_ms"`
	// ControlTimeoutMS bounds the async POST /changes call.
	ControlTimeoutMS int `json:"control_timeout_ms"`
	// RelistIntervalMS: how often the proxy re-lists a server's tools in the
	// background for an active session, to catch a contract change the agent
	// has not re-listed for. 0 = default (30000); negative = disabled.
	RelistIntervalMS int `json:"relist_interval_ms"`
	// EventChannelSize bounds the async event-writer queue (per process, not
	// per session). See DECISIONS.md "bounded event channel + drop policy".
	EventChannelSize int `json:"event_channel_size"`
}

func (c Config) QuarantinePollInterval() time.Duration {
	if c.QuarantinePollIntervalMS <= 0 {
		return time.Second
	}
	return time.Duration(c.QuarantinePollIntervalMS) * time.Millisecond
}

func (c Config) ControlTimeout() time.Duration {
	if c.ControlTimeoutMS <= 0 {
		return 2 * time.Second
	}
	return time.Duration(c.ControlTimeoutMS) * time.Millisecond
}

func (c Config) RelistInterval() time.Duration {
	switch {
	case c.RelistIntervalMS < 0:
		return 0
	case c.RelistIntervalMS == 0:
		return 30 * time.Second
	}
	return time.Duration(c.RelistIntervalMS) * time.Millisecond
}

func (c Config) EventChannelCapacity() int {
	if c.EventChannelSize <= 0 {
		return 4096
	}
	return c.EventChannelSize
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: reading %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.EventLogDir == "" {
		c.EventLogDir = "./events"
	}
	return c, nil
}
