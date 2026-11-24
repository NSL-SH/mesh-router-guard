package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func iso(t time.Time) string { return t.Format(time.RFC3339) }

func TestDesiredFromList(t *testing.T) {
	payload := `{"v":1,"generatedAt":"x","sources":[
	  {"origin":"nsl-fleet","entries":[{"value":"8.8.8.8","until":"` + iso(t0.Add(24*time.Hour)) + `","scenario":"crowdsecurity/ssh-bf"}]},
	  {"origin":"nsl-blocklist-de","until":"` + iso(t0.Add(49*time.Hour)) + `","scenario":"blocklist-de","values":["8.8.8.8","9.9.9.9","2a01:4f8::1","garbage"]},
	  {"origin":"nsl-spamhaus-drop","until":"` + iso(t0.Add(49*time.Hour)) + `","scenario":"spamhaus-drop","values":["1.10.16.7/20","2a14:c380:12::/48"]},
	  {"origin":"nsl-old","until":"` + iso(t0.Add(-time.Hour)) + `","values":["7.7.7.7"]},
	  {"origin":"crowdsec","until":"` + iso(t0.Add(time.Hour)) + `","values":["6.6.6.6"]},
	  {"origin":"nsl-far","until":"` + iso(t0.Add(30*24*time.Hour)) + `","values":["5.5.5.5"]}
	]}`
	got, err := desiredFromList([]byte(payload), t0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]want{
		// blocklist.de holds it longer than the fleet ban: the latest until wins
		"8.8.8.8":           {"nsl-blocklist-de", "blocklist-de", t0.Add(49 * time.Hour)},
		"9.9.9.9":           {"nsl-blocklist-de", "blocklist-de", t0.Add(49 * time.Hour)},
		"2a01:4f8::1":       {"nsl-blocklist-de", "blocklist-de", t0.Add(49 * time.Hour)},
		"1.10.16.0/20":      {"nsl-spamhaus-drop", "spamhaus-drop", t0.Add(49 * time.Hour)},
		"2a14:c380:12::/48": {"nsl-spamhaus-drop", "spamhaus-drop", t0.Add(49 * time.Hour)},
		// capped at maxBan; expired and non-nsl origins dropped
		"5.5.5.5": {"nsl-far", "nsl-far", t0.Add(maxBan)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
	if _, err := desiredFromList([]byte(`{"v":2}`), t0); err == nil {
		t.Fatal("version 2 accepted")
	}
}

func TestPlan(t *testing.T) {
	desired := map[string]want{
		"1.1.1.1":       {"nsl-blocklist-de", "blocklist-de", t0.Add(49 * time.Hour)},   // new
		"2.2.2.2":       {"nsl-blocklist-de", "blocklist-de", t0.Add(49 * time.Hour)},   // has 40 h left: kept
		"3.3.3.3":       {"nsl-blocklist-de", "blocklist-de", t0.Add(49 * time.Hour)},   // 2 h left: renewed
		"4.4.4.4":       {"nsl-fleet", "crowdsecurity/ssh-bf", t0.Add(96 * time.Hour)},  // escalated: renewed
		"5.5.5.5":       {"nsl-blocklist-de", "blocklist-de", t0.Add(49 * time.Hour)},   // SSO-allowlisted here
		"198.51.0.0/16": {"nsl-spamhaus-drop", "spamhaus-drop", t0.Add(49 * time.Hour)}, // holds an allowlisted address
		"2a01:4f8::5":   {"nsl-blocklist-de", "blocklist-de", t0.Add(49 * time.Hour)},   // in an allowlisted /64
	}
	existing := map[string][]have{
		"2.2.2.2": {{id: 20, origin: "nsl-blocklist-de", until: t0.Add(40 * time.Hour)}, {id: 21, origin: "nsl-blocklist-de", until: t0.Add(10 * time.Hour)}},
		"3.3.3.3": {{id: 30, origin: "nsl-blocklist-de", until: t0.Add(2 * time.Hour)}},
		"4.4.4.4": {{id: 40, origin: "nsl-fleet", until: t0.Add(20 * time.Hour)}},
		"5.5.5.5": {{id: 50, origin: "nsl-blocklist-de", until: t0.Add(20 * time.Hour)}},
		"6.6.6.6": {{id: 60, origin: "nsl-blocklist-de", until: t0.Add(20 * time.Hour)}}, // delisted
	}
	allow := []netip.Prefix{
		netip.MustParsePrefix("5.5.5.5/32"),
		netip.MustParsePrefix("198.51.7.9/32"),
		netip.MustParsePrefix("2a01:4f8::/64"),
	}
	got := plan(desired, existing, allow, t0)

	var added []string
	for _, d := range got.add {
		added = append(added, d.Value+" "+d.Scope+" "+d.Duration)
	}
	wantAdded := []string{"1.1.1.1 Ip 49h0m0s", "3.3.3.3 Ip 49h0m0s", "4.4.4.4 Ip 96h0m0s"}
	if !reflect.DeepEqual(added, wantAdded) {
		t.Errorf("added %v, want %v", added, wantAdded)
	}
	if wantDel := []int64{21, 30, 40, 50, 60}; !reflect.DeepEqual(got.del, wantDel) {
		t.Errorf("deleted %v, want %v", got.del, wantDel)
	}
	if got.kept != 1 || got.allowlisted != 3 {
		t.Errorf("kept %d allowlisted %d, want 1 and 3", got.kept, got.allowlisted)
	}
}

func TestReportsFromAlerts(t *testing.T) {
	local := []lapiDecision{{Origin: "crowdsec", Value: "x"}}
	alerts := []lapiAlert{
		{Scenario: "crowdsecurity/ssh-bf", StartAt: "2030-01-01T00:00:00Z", Source: lapiSource{Scope: "Ip", Value: "8.8.8.8"}, Decisions: local},
		{Scenario: "crowdsecurity/http-probing", StartAt: "2030-01-01T01:00:00Z", Source: lapiSource{Scope: "Ip", Value: "8.8.8.8"}, Decisions: local},
		{Scenario: "crowdsecurity/ssh-bf", Source: lapiSource{Scope: "Ip", Value: "9.9.9.9"}, Decisions: []lapiDecision{{Origin: "cscli"}}},
		{Scenario: "nsl/import", Source: lapiSource{Scope: "nsl", Value: "import"}, Decisions: []lapiDecision{{Origin: "crowdsec"}}},
		{Scenario: "my/custom", Source: lapiSource{Scope: "Ip", Value: "7.7.7.7"}, Decisions: local},
		{Scenario: "crowdsecurity/ssh-bf", Simulated: true, Source: lapiSource{Scope: "Ip", Value: "6.6.6.6"}, Decisions: local},
		{Scenario: "crowdsecurity/ssh-bf", Source: lapiSource{Scope: "Range", Value: "5.5.5.0/24"}, Decisions: local},
	}
	got := reportsFromAlerts(alerts)
	want := []reportAlert{{IP: "8.8.8.8", Scenario: "crowdsecurity/http-probing", At: "2030-01-01T01:00:00Z"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestVerifyListPins(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	payload := `{"v":1,"sources":[]}`
	sl := signedList{
		Key:     base64.StdEncoding.EncodeToString(pub),
		Sig:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload))),
		Payload: payload,
	}
	c := config{stateDir: t.TempDir()}
	var st status
	if err := verifyList(c, &st, sl); err != nil || st.ListKey != sl.Key {
		t.Fatalf("first list: %v, pinned %q", err, st.ListKey)
	}
	tampered := sl
	tampered.Payload = `{"v":1,"sources":[{"origin":"nsl-x"}]}`
	if err := verifyList(c, &st, tampered); err == nil {
		t.Fatal("tampered payload accepted")
	}
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	other := signedList{
		Key:     base64.StdEncoding.EncodeToString(pub2),
		Sig:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv2, []byte(payload))),
		Payload: payload,
	}
	if err := verifyList(c, &st, other); err == nil {
		t.Fatal("a list under another key accepted once one is pinned")
	}
}
