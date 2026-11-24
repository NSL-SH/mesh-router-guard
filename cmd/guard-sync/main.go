// guard-sync: the box's link to the NSL fleet ban list (mesh-router-backend Guard.ts).
//
// Every GUARD_SYNC_MINUTES it
//   - reports what this box's own CrowdSec banned (address, scenario, time) to
//     POST <backend>/router/api/guard/v1/reports, signed with the box credential like route
//     registration (GUARD_REPORT=off: nothing is sent);
//   - fetches GET <backend>/router/api/guard/v1/list (fleet bans + public lists), verifies its
//     Ed25519 signature against the key pinned at first use, and makes CrowdSec's
//     imported decisions match it, leaving out every value an allowlist of this box
//     covers (the local API does not check allowlists for imported decisions).
//
// It talks to CrowdSec as a machine (watcher) over the stack network and never sees
// attacker traffic itself. The enforcement is mesh-router-guard's, unchanged: imported
// decisions reach its nft sets like local ones.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type config struct {
	backend  string
	userID   string
	sig      string
	lapiURL  string
	machine  string
	password string
	stateDir string
	listKey  string
	interval time.Duration
	report   bool
	doImport bool
}

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func loadConfig() (config, error) {
	c := config{
		lapiURL:  env("LAPI_URL", "http://crowdsec:8080/"),
		machine:  env("SYNC_MACHINE", "guard-sync"),
		password: env("SYNC_PASSWORD", ""),
		stateDir: env("GUARD_STATE_DIR", "/var/lib/mesh-router-guard"),
		listKey:  env("GUARD_LIST_KEY", ""),
		report:   env("GUARD_REPORT", "on") != "off",
		doImport: env("GUARD_IMPORT", "on") != "off",
	}
	if f := env("SYNC_PASSWORD_FILE", ""); f != "" && c.password == "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return c, err
		}
		c.password = strings.TrimSpace(string(b))
	}
	if c.password == "" {
		return c, errors.New("SYNC_PASSWORD (or SYNC_PASSWORD_FILE) is required")
	}
	parts := strings.Split(env("PROVIDER_STR", ""), ",")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return c, errors.New("PROVIDER_STR must be <backend>,<userid>,<signature>")
	}
	c.backend = strings.TrimRight(strings.TrimSpace(parts[0]), "/")
	c.userID = strings.TrimSpace(parts[1])
	c.sig = strings.TrimSpace(parts[2])
	minutes, err := strconv.Atoi(env("GUARD_SYNC_MINUTES", "60"))
	if err != nil || minutes < 5 {
		minutes = 60
	}
	c.interval = time.Duration(minutes) * time.Minute
	return c, nil
}

// status is state/sync.json: what the last runs did, read by the template's
// tools/guard.sh (and so mesh-console), and the pinned list key.
type status struct {
	ListKey    string        `json:"listKey,omitempty"`
	LastReport *reportStatus `json:"lastReport,omitempty"`
	LastImport *importStatus `json:"lastImport,omitempty"`
}

type reportStatus struct {
	At    time.Time `json:"at"`
	Sent  int       `json:"sent"`
	Error string    `json:"error,omitempty"`
	// OK is the start of the last window that reached the backend.
	OK time.Time `json:"ok"`
}

type importStatus struct {
	At          time.Time      `json:"at"`
	GeneratedAt string         `json:"generatedAt,omitempty"`
	Entries     map[string]int `json:"entries,omitempty"`
	Added       int            `json:"added"`
	Deleted     int            `json:"deleted"`
	Kept        int            `json:"kept"`
	Allowlisted int            `json:"allowlisted"`
	Error       string         `json:"error,omitempty"`
	OK          time.Time      `json:"ok"`
}

func (c config) statusPath() string { return filepath.Join(c.stateDir, "sync.json") }

func loadStatus(c config) status {
	var st status
	if b, err := os.ReadFile(c.statusPath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func saveStatus(c config, st status) {
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := c.statusPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err == nil {
		_ = os.Rename(tmp, c.statusPath())
	}
}

var hc = &http.Client{Timeout: 2 * time.Minute}

func backendDo(ctx context.Context, method, u string, body any, out any) error {
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
	req.Header.Set("User-Agent", "mesh-router-guard/guard-sync")
	res, err := hc.Do(req)
	if err != nil {
		// the URL carries the box signature: never log it
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return uerr.Err
		}
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusNotFound {
		return errors.New("backend has no guard API (HTTP 404)")
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("backend: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(data[:min(len(data), 200)])))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c config) endpoint(kind string) string {
	// PROVIDER_STR's first field is the backend host; its API lives under /router/api.
	return fmt.Sprintf("%s/router/api/guard/v1/%s/%s/%s", c.backend, kind, url.PathEscape(c.userID), url.PathEscape(c.sig))
}

// reportOnce sends the local bans since the last window that reached the backend (at
// most 24 h back: older ones would not count anyway).
func reportOnce(ctx context.Context, c config, l *lapi, st *status, now time.Time) {
	from := now.Add(-24 * time.Hour)
	if st.LastReport != nil && st.LastReport.OK.After(from) {
		from = st.LastReport.OK.Add(-5 * time.Minute)
	}
	rs := &reportStatus{At: now}
	if st.LastReport != nil {
		rs.OK = st.LastReport.OK
	}
	st.LastReport = rs
	since := now.Sub(from).Round(time.Second)
	alerts, err := l.alerts(ctx, url.Values{"since": {since.String()}, "include_capi": {"false"}})
	if err != nil {
		rs.Error = err.Error()
		log.Printf("report: reading alerts: %v", err)
		return
	}
	reports := reportsFromAlerts(alerts)
	for start := 0; start < len(reports); start += 500 {
		batch := reports[start:min(start+500, len(reports))]
		var res struct {
			Accepted int      `json:"accepted"`
			Counted  int      `json:"counted"`
			Banned   []string `json:"banned"`
		}
		if err := backendDo(ctx, http.MethodPost, c.endpoint("reports"), map[string]any{"alerts": batch}, &res); err != nil {
			rs.Error = err.Error()
			log.Printf("report: %v", err)
			return
		}
		rs.Sent += len(batch)
		if len(res.Banned) > 0 {
			log.Printf("report: fleet ban reached for %s", strings.Join(res.Banned, " "))
		}
	}
	rs.OK = now
	if len(reports) > 0 {
		log.Printf("report: %d banned addresses sent", len(reports))
	}
}

type signedList struct {
	Key     string `json:"key"`
	Sig     string `json:"sig"`
	Payload string `json:"payload"`
}

// verifyList checks the signature, pinning the key the first time (or checking
// GUARD_LIST_KEY when the operator set one).
func verifyList(c config, st *status, sl signedList) error {
	pinned := c.listKey
	if pinned == "" {
		pinned = st.ListKey
	}
	if pinned != "" && sl.Key != pinned {
		return fmt.Errorf("list signed by %s, not the pinned key %s: refusing it (delete listKey from %s to re-pin)", sl.Key, pinned, c.statusPath())
	}
	key, err := base64.StdEncoding.DecodeString(sl.Key)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("list: malformed key")
	}
	sig, err := base64.StdEncoding.DecodeString(sl.Sig)
	if err != nil || !ed25519.Verify(key, []byte(sl.Payload), sig) {
		return errors.New("list: bad signature")
	}
	if pinned == "" {
		st.ListKey = sl.Key
		log.Printf("import: pinned list key %s", sl.Key)
	}
	return nil
}

func importOnce(ctx context.Context, c config, l *lapi, st *status, now time.Time) {
	is := &importStatus{At: now}
	if st.LastImport != nil {
		is.OK = st.LastImport.OK
	}
	st.LastImport = is
	fail := func(format string, args ...any) {
		is.Error = fmt.Sprintf(format, args...)
		log.Printf("import: %s", is.Error)
	}

	var sl signedList
	if err := backendDo(ctx, http.MethodGet, c.endpoint("list"), nil, &sl); err != nil {
		fail("fetching the list: %v", err)
		return
	}
	if err := verifyList(c, st, sl); err != nil {
		fail("%v", err)
		return
	}
	desired, err := desiredFromList([]byte(sl.Payload), now)
	if err != nil {
		fail("%v", err)
		return
	}
	var meta struct {
		GeneratedAt string `json:"generatedAt"`
	}
	_ = json.Unmarshal([]byte(sl.Payload), &meta)
	is.GeneratedAt = meta.GeneratedAt
	is.Entries = map[string]int{}
	for _, w := range desired {
		is.Entries[w.origin]++
	}

	allow, err := l.allowlisted(ctx, now)
	if err != nil {
		fail("reading allowlists: %v", err)
		return
	}
	imported, err := l.alerts(ctx, url.Values{"scenario": {importScenario}, "has_active_decision": {"true"}})
	if err != nil {
		fail("reading imported decisions: %v", err)
		return
	}
	p := plan(desired, existingFromAlerts(imported, now), allow, now)
	is.Kept, is.Allowlisted = p.kept, p.allowlisted

	// Add first: a renewed value is never without a decision.
	if err := l.addDecisions(ctx, p.add, now); err != nil {
		fail("adding decisions: %v", err)
		return
	}
	is.Added = len(p.add)
	for _, id := range p.del {
		if err := l.deleteDecision(ctx, id); err != nil {
			fail("deleting decision %d: %v", id, err)
			return
		}
		is.Deleted++
	}
	is.OK = now
	log.Printf("import: %d entries, %d added, %d deleted, %d kept, %d allowlisted here", len(desired), is.Added, is.Deleted, is.Kept, is.Allowlisted)
}

func runOnce(ctx context.Context, c config) {
	st := loadStatus(c)
	defer func() { saveStatus(c, st) }()
	now := time.Now().UTC()
	l := newLAPI(c.lapiURL, c.machine, c.password)
	if err := l.login(ctx); err != nil {
		log.Printf("local API login: %v", err)
		if c.report {
			st.LastReport = &reportStatus{At: now, Error: "local API: " + err.Error(), OK: okOf(st.LastReport)}
		}
		return
	}
	if c.report {
		reportOnce(ctx, c, l, &st, now)
	}
	if c.doImport {
		importOnce(ctx, c, l, &st, now)
	}
}

func okOf(r *reportStatus) time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.OK
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("[guard-sync] ")
	c, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(c.stateDir, 0o755); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Printf("backend %s, every %s (report %v, import %v)", c.backend, c.interval, c.report, c.doImport)

	// CrowdSec registers this machine at its start: wait for it rather than fail.
	for {
		l := newLAPI(c.lapiURL, c.machine, c.password)
		if err := l.login(ctx); err == nil {
			break
		} else if ctx.Err() != nil {
			return
		} else {
			log.Printf("waiting for the local API: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}

	for {
		runOnce(ctx, c)
		// Jitter, so a fleet restarted at once does not hit the backend at once.
		wait := c.interval + time.Duration(rand.Int64N(int64(c.interval/6)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
