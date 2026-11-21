package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPsiphonRegionsNoticeCache pins the region-refresh path: Psiphon's
// AvailableEgressRegions notice lands in psiphon-regions.json, normalised and
// sorted, and an unchanged repeat keeps the old timestamp.
func TestPsiphonRegionsNoticeCache(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())

	p := &Psiphon{}
	p.handleNotice(`{"noticeType":"AvailableEgressRegions","data":{"regions":["us"," JP ","DE","us","x","JP"]}}`)
	got := loadPsiphonRegions()
	want := []string{"DE", "JP", "US"}
	if len(got) != len(want) {
		t.Fatalf("regions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("regions = %v, want %v", got, want)
		}
	}

	fi1, err := os.Stat(psiphonRegionsPath())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	p.handleNotice(`{"noticeType":"AvailableEgressRegions","data":{"regions":["JP","US","DE"]}}`)
	fi2, err := os.Stat(psiphonRegionsPath())
	if err != nil {
		t.Fatal(err)
	}
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Errorf("unchanged list rewrote the cache (mtime moved)")
	}

	p.handleNotice(`{"noticeType":"AvailableEgressRegions","data":{"regions":["JP","US","DE","FR"]}}`)
	if got := loadPsiphonRegions(); len(got) != 4 || got[1] != "FR" {
		t.Errorf("changed list not persisted: %v", got)
	}
}

// TestGuardPsiphonRegion pins the connect-time fallback: a saved region the
// live list no longer offers is dropped (with a notice), while an empty cache
// never overrides the user's pick.
func TestGuardPsiphonRegion(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())

	var msgs []string
	old := connectStage
	connectStage = func(s string) { msgs = append(msgs, s) }
	defer func() { connectStage = old }()

	if got := guardPsiphonRegion("订阅+Psiphon", ""); got != "" {
		t.Errorf("empty region = %q", got)
	}
	if got := guardPsiphonRegion("订阅+Psiphon", "JP"); got != "JP" {
		t.Errorf("no cache must keep the pick, got %q", got)
	}
	savePsiphonRegions([]string{"US", "DE"})
	if got := guardPsiphonRegion("订阅+Psiphon", "de"); got != "DE" {
		t.Errorf("offered region = %q, want DE", got)
	}
	if got := guardPsiphonRegion("订阅+Psiphon", "JP"); got != "" {
		t.Errorf("unavailable region = %q, want auto", got)
	}
	if len(msgs) != 1 || !strings.Contains(msgs[0], "JP") {
		t.Errorf("expected one fallback notice mentioning JP, got %v", msgs)
	}
}

// TestPsiphonRegionsDataStore pins the datastore fallback: the region list is
// rebuilt from the plaintext "region":"XX" server entries Psiphon writes to its
// bolt datastore, since AvailableEgressRegions arrives empty before the server
// list finishes downloading.
func TestPsiphonRegionsDataStore(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())

	dataDir := t.TempDir()
	storeDir := filepath.Join(dataDir, "ca.psiphon.PsiphonTunnel.tunnel-core", "datastore")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A bolt file is a binary page store with JSON values embedded; the scan
	// only cares about the plaintext region fields, so fake the surrounding
	// bytes with NULs.
	blob := append([]byte{0, 0, 0, 0}, []byte(`{"region":"US","x":1} {"region":"de"} {"region": "JP"} {"region":"US"} {"region":"toolong"} {"region":"1"} {"region":""}`)...)
	if err := os.WriteFile(filepath.Join(storeDir, "psiphon.boltdb"), blob, 0o644); err != nil {
		t.Fatal(err)
	}

	refreshPsiphonRegionsFromDataStore(dataDir)
	got := loadPsiphonRegions()
	want := []string{"DE", "JP", "US"}
	if len(got) != len(want) {
		t.Fatalf("regions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("regions = %v, want %v", got, want)
		}
	}

	// A missing datastore must not wipe an existing cache.
	refreshPsiphonRegionsFromDataStore(filepath.Join(dataDir, "absent"))
	if again := loadPsiphonRegions(); len(again) != len(want) {
		t.Errorf("missing datastore clobbered cache: %v", again)
	}
}

// TestSubscriptionPsiphonNoDialerProxy pins the 1.1.17 root-cause fix: the
// Psiphon exit is a LOOPBACK SOCKS listener and must be dialed directly. A
// dialer-proxy on it reaches 127.0.0.1 through the remote node's own loopback
// and never connects — the exact subscription+Psiphon failure users reported.
// Psiphon's underlay hop is the dedicated SUB-BASE SOCKS inbound instead.
func TestSubscriptionPsiphonNoDialerProxy(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	opts := options{
		mixedPort:        7890,
		apiPort:          9090,
		connMode:         "subscription",
		psiphonMode:      true,
		psiphonSocksPort: 43721,
		customProxies: []ProxySpec{
			{Name: "remote-node", Type: "ss", Fields: map[string]any{
				"server": "203.0.113.7", "port": 8388, "cipher": "aes-128-gcm", "password": "pw",
			}},
		},
		activeProxy: "remote-node",
	}
	b, err := renderSubscriptionConfig(opts)
	if err != nil {
		t.Fatalf("renderSubscriptionConfig: %v", err)
	}
	cfg := string(b)

	start := strings.Index(cfg, `name: "Psiphon"`)
	if start < 0 {
		t.Fatalf("no Psiphon outbound in config:\n%s", cfg)
	}
	end := strings.Index(cfg[start:], "\n\n")
	block := cfg[start:]
	if end >= 0 {
		block = cfg[start : start+end]
	}
	if strings.Contains(block, "dialer-proxy") {
		t.Errorf("Psiphon loopback entry must not carry dialer-proxy:\n%s", block)
	}
	for _, want := range []string{
		"socks-port: 7891",                  // dedicated underlay inbound
		"IN-TYPE,SOCKS,SUB-BASE",            // Psiphon's dials ride the base node
		"PROCESS-NAME,psiphon.exe,SUB-BASE", // loop guard
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q\n%s", want, cfg)
		}
	}
}