// Package control is the proxy's client for the control plane HTTP API
// described in q4_trust_layer/DESIGN.md ("Interface contract for control/").
// That service does not exist in this repo yet (it is a separate, later work
// package — see q4_trust_layer/DECISIONS.md "what's stubbed about control/
// integration for now"); Client.BaseURL is injectable so pointing the proxy
// at the real thing later is a one-line config change, and an empty BaseURL
// makes every call fail fast in a way callers already treat as "control
// plane unreachable".
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/anviq-candidate/anviq-interview/proxy/internal/quarantine"
)

var ErrNoBaseURL = errors.New("control: no base URL configured")

// ChangeRequest matches control/'s POST /changes request body.
type ChangeRequest struct {
	Server    string         `json:"server"`
	Tool      string         `json:"tool"`
	SessionID string         `json:"session_id"` // informational (forensics); verdicts must not depend on it
	OldHash   string         `json:"old_hash"`   // proxy-computed def_hash; control should recompute and compare (cross-language parity check)
	NewHash   string         `json:"new_hash"`
	OldDef    map[string]any `json:"old_def"`
	NewDef    map[string]any `json:"new_def"`
}

// ChangeResponse matches control/'s POST /changes response body.
type ChangeResponse struct {
	Verdict  string           `json:"verdict"` // "resume" | "warn" | "suspend" | "quarantine"
	Reason   string           `json:"reason"`
	Findings []map[string]any `json:"findings,omitempty"`
}

type quarantineListResponse struct {
	Quarantine []quarantine.Entry `json:"quarantine"`
}

// Client is a thin HTTP client. It is deliberately small enough to fake in
// tests without an interface: gateway code depends on *Client directly and
// tests point BaseURL at an httptest.Server.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: timeout}}
}

// ReportChange posts a detected def_hash mismatch and returns the control
// plane's verdict. Callers invoke this from a background goroutine — it must
// never sit on the tools/list hot path (see DESIGN.md §4).
func (c *Client) ReportChange(ctx context.Context, req ChangeRequest) (ChangeResponse, error) {
	if c.BaseURL == "" {
		return ChangeResponse{}, ErrNoBaseURL
	}
	body, err := json.Marshal(req)
	if err != nil {
		return ChangeResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/changes", bytes.NewReader(body))
	if err != nil {
		return ChangeResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return ChangeResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ChangeResponse{}, fmt.Errorf("control: POST /changes: status %d", resp.StatusCode)
	}
	var out ChangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ChangeResponse{}, err
	}
	return out, nil
}

// Quarantine fetches the current quarantine list, matching GET /quarantine.
func (c *Client) Quarantine(ctx context.Context) ([]quarantine.Entry, error) {
	if c.BaseURL == "" {
		return nil, ErrNoBaseURL
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/quarantine", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control: GET /quarantine: status %d", resp.StatusCode)
	}
	var out quarantineListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Quarantine, nil
}
