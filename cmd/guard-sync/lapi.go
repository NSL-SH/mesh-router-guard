package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// lapi is the CrowdSec local API, as a machine (watcher): reading alerts and allowlists,
// adding and deleting decisions. The bouncer key cannot do any of that.
type lapi struct {
	base     string
	machine  string
	password string
	token    string
	hc       *http.Client
}

type lapiDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

type lapiSource struct {
	Scope string `json:"scope"`
	Value string `json:"value"`
	IP    string `json:"ip,omitempty"`
}

type lapiAlert struct {
	ID        int64          `json:"id"`
	Scenario  string         `json:"scenario"`
	StartAt   string         `json:"start_at"`
	CreatedAt string         `json:"created_at"`
	Simulated bool           `json:"simulated"`
	Source    lapiSource     `json:"source"`
	Decisions []lapiDecision `json:"decisions"`
}

func newLAPI(base, machine, password string) *lapi {
	return &lapi{
		base:     strings.TrimRight(base, "/"),
		machine:  machine,
		password: password,
		hc:       &http.Client{Timeout: 2 * time.Minute},
	}
}

func (l *lapi) login(ctx context.Context) error {
	var out struct {
		Token string `json:"token"`
	}
	body := map[string]any{"machine_id": l.machine, "password": l.password, "scenarios": []string{}}
	if err := l.do(ctx, http.MethodPost, "/v1/watchers/login", nil, body, &out); err != nil {
		return err
	}
	if out.Token == "" {
		return fmt.Errorf("login: no token")
	}
	l.token = out.Token
	return nil
}

func (l *lapi) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := l.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if l.token != "" {
		req.Header.Set("Authorization", "Bearer "+l.token)
	}
	res, err := l.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 256<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, res.StatusCode, strings.TrimSpace(string(data[:min(len(data), 300)])))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// alerts lists alerts; query is the LAPI's own filters (since, scenario, has_active_decision...).
func (l *lapi) alerts(ctx context.Context, query url.Values) ([]lapiAlert, error) {
	var out []lapiAlert
	if query.Get("limit") == "" {
		query.Set("limit", "10000")
	}
	if err := l.do(ctx, http.MethodGet, "/v1/alerts", query, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// allowlisted returns every allowlist entry still in force, as prefixes (an address is
// its /32 or /128).
func (l *lapi) allowlisted(ctx context.Context, now time.Time) ([]netip.Prefix, error) {
	var lists []struct {
		Name  string `json:"name"`
		Items []struct {
			Value      string    `json:"value"`
			Expiration time.Time `json:"expiration"`
		} `json:"items"`
	}
	if err := l.do(ctx, http.MethodGet, "/v1/allowlists", url.Values{"with_content": {"true"}}, nil, &lists); err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, list := range lists {
		for _, item := range list.Items {
			// the zero time (0001-01-01) is "never expires"
			if item.Expiration.Year() > 1 && item.Expiration.Before(now) {
				continue
			}
			if p, ok := parseValue(item.Value); ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// importBatch is how many decisions one import alert carries (cscli decisions import
// uses the same size).
const importBatch = 1000

// addDecisions posts the decisions as import alerts. Alerts that already carry decisions
// skip the LAPI's own allowlist check: plan() has done it.
func (l *lapi) addDecisions(ctx context.Context, decisions []lapiDecision, now time.Time) error {
	for start := 0; start < len(decisions); start += importBatch {
		batch := decisions[start:min(start+importBatch, len(decisions))]
		ts := now.UTC().Format(time.RFC3339)
		alert := map[string]any{
			"scenario": importScenario, "scenario_hash": "", "scenario_version": "",
			"message":      fmt.Sprintf("NSL list import: %d decisions", len(batch)),
			"events_count": 1, "start_at": ts, "stop_at": ts, "capacity": 0, "leakspeed": "0",
			"simulated": false, "remediation": true, "events": []any{},
			"source":    map[string]string{"scope": "nsl", "value": "import"},
			"decisions": batch,
		}
		if err := l.do(ctx, http.MethodPost, "/v1/alerts", nil, []any{alert}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (l *lapi) deleteDecision(ctx context.Context, id int64) error {
	return l.do(ctx, http.MethodDelete, fmt.Sprintf("/v1/decisions/%d", id), nil, nil, nil)
}
