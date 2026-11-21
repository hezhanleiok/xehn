package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSettingsRoundTrip pins the two properties the settings page depends on:
// a written file is read back byte-for-byte equivalent, and a value that came
// from the UI survives a save/load cycle.
func TestSettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", dir)

	in := defaultSettings()
	in.Theme = themeDark
	in.Lang = langEN
	in.MixedPort = 1080
	in.IPFamily = famV6
	in.Pin = "2606:4700::1"
	in.ProxyMode = modeBlacklist
	in.CaptureMode = captureTun
	in.AllowLan = true

	if err := saveSettings(in); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}
	p := filepath.Join(dir, settingsName)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("settings file not written: %v", err)
	}

	// A BOM would make encoding/json reject the file and silently reset every
	// preference to its default, so the bytes are checked directly.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF {
		t.Fatal("settings.json written with a UTF-8 BOM")
	}

	out := loadSettings()
	if out.Theme != themeDark || out.Lang != langEN {
		t.Errorf("theme/lang = %q/%q, want dark/en", out.Theme, out.Lang)
	}
	if out.MixedPort != 1080 {
		t.Errorf("mixed port = %d, want 1080", out.MixedPort)
	}
	if out.IPFamily != famV6 {
		t.Errorf("family = %q, want v6", out.IPFamily)
	}
	// Internalized knobs: whatever the file said, the shipped defaults win.
	if out.MTU != 0 {
		t.Errorf("mtu = %d, want 0 (internalized)", out.MTU)
	}
	if out.Pin != in.Pin {
		t.Errorf("pin = %q, want %q", out.Pin, in.Pin)
	}
	if out.DNSCustom != "" || out.DNSOff {
		t.Errorf("dns = %q/off=%t, want internalized empty/on", out.DNSCustom, out.DNSOff)
	}
	if out.ProxyMode != modeBlacklist {
		t.Errorf("proxy mode = %q, want %q", out.ProxyMode, modeBlacklist)
	}
	if !out.DNSLeak {
		t.Error("dns leak = false, want the internalized always-on true")
	}
	if out.CaptureMode != captureTun {
		t.Errorf("capture = %q, want tun", out.CaptureMode)
	}
	if !out.AllowLan {
		t.Error("allow lan = false, want true")
	}
	if out.AutoStart {
		t.Error("autostart = true, want false")
	}
}

// TestSettingsNormalize covers the guards: nothing a hand-edited file can hold
// may reach the renderer as an unusable value.
func TestSettingsNormalize(t *testing.T) {
	s := clientSettings{
		MixedPort:  0,
		APIPort:    0,
		MTU:        -5,
		TimeoutSec: 900,
		Theme:      "neon",
		Lang:       "fr",
		ProxyMode:  "sometimes",
	}
	s.normalize()
	if s.MixedPort <= 0 || s.APIPort <= 0 {
		t.Errorf("ports not defaulted: %d/%d", s.MixedPort, s.APIPort)
	}
	if s.APIPort == s.MixedPort {
		t.Error("api port left equal to the mixed port")
	}
	if s.MTU != 0 {
		t.Errorf("mtu = %d, want 0 (automatic)", s.MTU)
	}
	if s.TimeoutSec != 2 {
		t.Errorf("timeout = %d, want the default", s.TimeoutSec)
	}
	if s.Theme != themeLight || s.Lang != langZH || s.ProxyMode != modeCustom {
		t.Errorf("theme/lang/mode = %q/%q/%q, want light/zh/custom", s.Theme, s.Lang, s.ProxyMode)
	}
	if s.CaptureMode != captureProxy || s.IPFamily != famV4 {
		t.Errorf("capture/family = %q/%q, want proxy/v4", s.CaptureMode, s.IPFamily)
	}
}

// TestSettingsInternalized pins the knobs the settings page no longer exposes:
// a hand-edited file may carry any of them, but load/save must force the shipped
// defaults so the UI never shows a state it cannot explain or change back.
func TestSettingsInternalized(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", dir)
	raw := `{
		"api_port": 12345,
		"mtu": 1400,
		"timeout_sec": 30,
		"rescan": true,
		"auto_repair": false,
		"dns_custom": "9.9.9.9",
		"dns_off": true,
		"dns_leak": false
	}`
	if err := os.WriteFile(filepath.Join(dir, settingsName), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s := loadSettings()
	if s.APIPort == 12345 {
		t.Errorf("api port = %d, want the internalized default", s.APIPort)
	}
	if s.MTU != 0 || s.TimeoutSec != 2 {
		t.Errorf("mtu/timeout = %d/%d, want 0/2", s.MTU, s.TimeoutSec)
	}
	if s.Rescan || !s.AutoRepair {
		t.Errorf("rescan/autoRepair = %t/%t, want false/true", s.Rescan, s.AutoRepair)
	}
	if s.DNSCustom != "" || s.DNSOff || !s.DNSLeak {
		t.Errorf("dns = %q/off=%t/leak=%t, want empty/false/true", s.DNSCustom, s.DNSOff, s.DNSLeak)
	}
	// The forced values must also survive the write path, not just the read.
	if err := saveSettings(s); err != nil {
		t.Fatal(err)
	}
	out := loadSettings()
	if out.DNSCustom != "" || out.DNSOff || !out.DNSLeak || out.MTU != 0 {
		t.Errorf("save/load drifted: %+v", out)
	}
}

// TestSettingsFamilyGates pins the IPv6 capability matrix: stacked exits are
// v4-only, nested WARP protocols cannot carry v6, but subscription mode is not
// gated on the WARP proto at all (the imported node decides).
func TestSettingsFamilyGates(t *testing.T) {
	cases := []struct {
		name string
		s    clientSettings
		want string
	}{
		{"psiphon locks v4", clientSettings{Proto: protoWG, IPFamily: famBoth, Psiphon: true}, famV4},
		{"openvpn locks v4", clientSettings{Proto: protoWG, IPFamily: famV6, OpenVPN: true}, famV4},
		{"nested proto locks v4", clientSettings{Proto: protoWWarp, IPFamily: famBoth}, famV4},
		{"capable proto keeps v6", clientSettings{Proto: protoWG, IPFamily: famV6}, famV6},
		{"subscription ignores warp proto", clientSettings{ConnMode: "subscription", Proto: protoWWarp, IPFamily: famBoth}, famBoth},
		{"subscription exit still locks", clientSettings{ConnMode: "subscription", Proto: protoWG, IPFamily: famV6, Psiphon: true}, famV4},
	}
	for _, tc := range cases {
		s := tc.s
		s.normalize()
		if s.IPFamily != tc.want {
			t.Errorf("%s: family = %q, want %q", tc.name, s.IPFamily, tc.want)
		}
	}
}

// TestSettingsLegacyMigration checks the one-time upgrade path: an old file
// with the independent tun/system_proxy/ipv6 switches becomes a capture mode
// and an address family, and the legacy keys are not written again.
func TestSettingsLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", dir)
	legacy := `{"tun": true, "system_proxy": true, "ipv6": true, "proto": "awg"}`
	if err := os.WriteFile(filepath.Join(dir, settingsName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s := loadSettings()
	if s.CaptureMode != captureTun {
		t.Errorf("capture = %q, want tun", s.CaptureMode)
	}
	if s.IPFamily != famV6 {
		t.Errorf("family = %q, want v6", s.IPFamily)
	}
	if err := saveSettings(s); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, settingsName))
	if err != nil {
		t.Fatal(err)
	}
	var written map[string]json.RawMessage
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tun", "system_proxy", "ipv6"} {
		if _, ok := written[key]; ok {
			t.Errorf("legacy key %s still written", key)
		}
	}
}

// TestSettingsRoutingMigration maps the pre-preset routing choice onto the new
// dropdown: the old "rule" mode with the region split on was exactly today's
// bypass preset, while "rule" alone becomes custom.
func TestSettingsRoutingMigration(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{`{"proxy_mode": "rule", "geo_split": true}`, modeBypass},
		{`{"proxy_mode": "rule"}`, modeCustom},
		{`{"proxy_mode": "global"}`, modeGlobal},
	} {
		dir := t.TempDir()
		t.Setenv("WARP_CLIENT_HOME", dir)
		if err := os.WriteFile(filepath.Join(dir, settingsName), []byte(tc.raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := loadSettings().ProxyMode; got != tc.want {
			t.Errorf("%s: mode = %q, want %q", tc.raw, got, tc.want)
		}
	}
}
