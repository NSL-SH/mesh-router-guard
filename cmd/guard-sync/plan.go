package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// importScenario names the alerts guard-sync's decisions hang off; the decisions
// themselves carry the list's origin (nsl-fleet, nsl-<list>).
const importScenario = "nsl/import"

// maxEntries bounds what one list may push into CrowdSec.
const maxEntries = 200_000

// maxBan bounds an imported decision, whatever the list says (the backend caps at 7 days).
const maxBan = 8 * 24 * time.Hour

var originRe = regexp.MustCompile(`^nsl-[a-z0-9-]{1,40}$`)

// guardList is the backend's GuardList (mesh-router-backend src/services/Guard.ts).
type guardList struct {
	V           int    `json:"v"`
	GeneratedAt string `json:"generatedAt"`
	Sources     []struct {
		Origin   string `json:"origin"`
		Until    string `json:"until"`
		Scenario string `json:"scenario"`
		Entries  []struct {
			Value    string `json:"value"`
			Until    string `json:"until"`
			Scenario string `json:"scenario"`
		} `json:"entries"`
		Values []string `json:"values"`
	} `json:"sources"`
}

type want struct {
	origin   string
	scenario string
	until    time.Time
}

type have struct {
	id     int64
	origin string
	until  time.Time
}

// parseValue reads an address or a range; an address is its full-length prefix.
func parseValue(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// canonical is the value CrowdSec stores: the bare address for a full-length prefix.
func canonical(p netip.Prefix) (value, scope string) {
	if p.IsSingleIP() {
		return p.Addr().String(), "Ip"
	}
	return p.String(), "Range"
}

// desiredFromList turns a verified list into value -> want, the latest `until` winning
// when sources overlap.
func desiredFromList(payload []byte, now time.Time) (map[string]want, error) {
	var list guardList
	if err := json.Unmarshal(payload, &list); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	if list.V != 1 {
		return nil, fmt.Errorf("list: unsupported version %d", list.V)
	}
	out := map[string]want{}
	put := func(origin, value, scenario, until string) {
		if len(out) >= maxEntries {
			return
		}
		p, ok := parseValue(value)
		if !ok {
			return
		}
		t, err := time.Parse(time.RFC3339, until)
		if err != nil || !t.After(now) {
			return
		}
		if t.After(now.Add(maxBan)) {
			t = now.Add(maxBan)
		}
		v, _ := canonical(p)
		if cur, ok := out[v]; ok && !t.After(cur.until) {
			return
		}
		if scenario == "" {
			scenario = origin
		}
		out[v] = want{origin: origin, scenario: scenario, until: t}
	}
	for _, src := range list.Sources {
		if !originRe.MatchString(src.Origin) {
			continue
		}
		for _, e := range src.Entries {
			put(src.Origin, e.Value, firstNonEmpty(e.Scenario, src.Scenario), firstNonEmpty(e.Until, src.Until))
		}
		for _, v := range src.Values {
			put(src.Origin, v, src.Scenario, src.Until)
		}
	}
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// existingFromAlerts collects the decisions guard-sync imported earlier that are still
// in force: value -> decisions.
func existingFromAlerts(alerts []lapiAlert, now time.Time) map[string][]have {
	out := map[string][]have{}
	for _, a := range alerts {
		if a.Scenario != importScenario {
			continue
		}
		for _, d := range a.Decisions {
			if !strings.HasPrefix(d.Origin, "nsl-") {
				continue
			}
			left, err := time.ParseDuration(d.Duration)
			if err != nil || left <= 0 {
				continue
			}
			out[d.Value] = append(out[d.Value], have{id: d.ID, origin: d.Origin, until: now.Add(left)})
		}
	}
	return out
}

func allowlistedValue(p netip.Prefix, allow []netip.Prefix) bool {
	for _, a := range allow {
		if a.Overlaps(p) {
			return true
		}
	}
	return false
}

// An imported decision is renewed when it nears its end and the list still wants it
// longer, or when the list now wants it much longer (a fleet ban that escalated). Public
// lists come with ~49 h; a value is re-added about every 46 h, not every hour.
const (
	renewWithin = 3 * time.Hour
	renewGap    = 24 * time.Hour
)

type planResult struct {
	add         []lapiDecision
	del         []int64
	kept        int
	allowlisted int
}

// plan is what to change in CrowdSec so its imported decisions match the list: values
// the box allowlists (SSO logins, the owner's list) are never imported, and decisions
// for values the list no longer holds are deleted.
func plan(desired map[string]want, existing map[string][]have, allow []netip.Prefix, now time.Time) planResult {
	var r planResult
	values := make([]string, 0, len(desired))
	for v := range desired {
		values = append(values, v)
	}
	sort.Strings(values)

	for _, v := range values {
		w := desired[v]
		p, _ := parseValue(v)
		cur := existing[v]
		if allowlistedValue(p, allow) {
			r.allowlisted++
			for _, h := range cur {
				r.del = append(r.del, h.id)
			}
			continue
		}
		best := -1
		for i, h := range cur {
			if best < 0 || h.until.After(cur[best].until) {
				best = i
			}
		}
		renew := best < 0 ||
			(cur[best].until.Sub(now) < renewWithin && w.until.After(cur[best].until.Add(time.Hour))) ||
			w.until.After(cur[best].until.Add(renewGap))
		for i, h := range cur {
			if renew || i != best {
				r.del = append(r.del, h.id)
			}
		}
		if !renew {
			r.kept++
			continue
		}
		value, scope := canonical(p)
		r.add = append(r.add, lapiDecision{
			Origin:   w.origin,
			Type:     "ban",
			Scope:    scope,
			Value:    value,
			Duration: w.until.Sub(now).Round(time.Second).String(),
			Scenario: w.scenario,
		})
	}
	for v, hs := range existing {
		if _, ok := desired[v]; ok {
			continue
		}
		for _, h := range hs {
			r.del = append(r.del, h.id)
		}
	}
	sort.Slice(r.del, func(i, j int) bool { return r.del[i] < r.del[j] })
	return r
}

// reportAlert is one entry of POST /guard/v1/reports.
type reportAlert struct {
	IP       string `json:"ip"`
	Scenario string `json:"scenario"`
	At       string `json:"at"`
}

// reportsFromAlerts keeps what this box's own detection banned: Hub scenarios on a
// single address, with a decision CrowdSec made itself (origin crowdsec). Imported,
// manual and allowlisted sources never get there. One entry per address, the latest.
func reportsFromAlerts(alerts []lapiAlert) []reportAlert {
	latest := map[string]reportAlert{}
	for _, a := range alerts {
		if a.Simulated || !strings.HasPrefix(a.Scenario, "crowdsecurity/") || a.Source.Scope != "Ip" {
			continue
		}
		local := false
		for _, d := range a.Decisions {
			if d.Origin == "crowdsec" {
				local = true
				break
			}
		}
		p, ok := parseValue(a.Source.Value)
		if !local || !ok || !p.IsSingleIP() {
			continue
		}
		ip := p.Addr().String()
		at := firstNonEmpty(a.StartAt, a.CreatedAt)
		if cur, ok := latest[ip]; ok && cur.At >= at {
			continue
		}
		latest[ip] = reportAlert{IP: ip, Scenario: a.Scenario, At: at}
	}
	out := make([]reportAlert, 0, len(latest))
	for _, r := range latest {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
