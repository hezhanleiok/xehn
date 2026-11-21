package main

import (
	"context"
	"strings"
	"testing"
)

// A subscription front + VPN Gate exit is repaired by the guard's OpenVPN
// branch (st.OpenVPNMode is checked before the subscription path in repairOnce).
// That branch used to run the WARP endpoint scan with proto "订阅", which
// parseProto rejects outright — the repair died instantly, giveUp flipped
// Connected off, and the home page showed "disconnected" with nothing in the
// GUI log. These lock down the fix: the session must rebuild through the
// subscription pipeline, and the user's pinned relay must survive the rebuild.

// writeSubRepairSettings isolates appDir() into a temp home and persists the
// settings a repair reads back. saveSettings is the canonical writer, so the
// test exercises the same normalize() the real file goes through.
func writeSubRepairSettings(t *testing.T, s clientSettings) {
	t.Helper()
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	if err := saveSettings(s); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}
}

// The delegation itself, proven without a core or a network: with no imported
// proxies runConnectSubscription returns "订阅模式没有可用节点" before it ever
// touches coreDir/EnsureBinary, so a SubMode repair that reaches that message
// took the subscription pipeline. The old WARP-scan path could only produce
// "invalid -proto" here.
func TestRepairOpenVPNSubscriptionUsesSubscriptionPipeline(t *testing.T) {
	s := defaultSettings()
	s.ConnMode = "subscription"
	s.OpenVPNRegion = "JP"
	s.OpenVPNNode = "jp-58.189.75.234-1779"
	// Deliberately empty: the early return is what keeps this hermetic.
	s.CustomProxies = nil
	writeSubRepairSettings(t, s)

	st := clientState{
		Proto:         "订阅",
		Connected:     true,
		SubMode:       true,
		OpenVPNMode:   true,
		OpenVPNRegion: "JP",
		MixedPort:     7890,
		APIPort:       9090,
		Family:        famV4,
	}
	var logs []string
	// Cancelled as a backstop: the empty-proxy check still runs first, so the
	// asserted message is unchanged, but no later stage can reach the network.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, ok := repairOpenVPNOnce(ctx, st, func(m string) { logs = append(logs, m) })
	if ok {
		t.Fatal("repair reported success with no proxies; expected a clean failure")
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "订阅模式没有可用节点") {
		t.Fatalf("repair did not take the subscription pipeline; logs:\n%s", joined)
	}
	if strings.Contains(joined, "invalid -proto") {
		t.Fatalf("repair fell back to the WARP scan (the original crash); logs:\n%s", joined)
	}
}

// The data the subscription pipeline needs must all survive optionsFromState:
// the mode switch, the imported front node, and — the part the relay picker
// actually orders by — the pinned relay from settings.json.
func TestOptionsFromStateSubscriptionOpenVPNKeepsPinAndProxies(t *testing.T) {
	s := defaultSettings()
	s.ConnMode = "subscription"
	s.OpenVPNRegion = "JP"
	s.OpenVPNNode = "jp-58.189.75.234-1779"
	s.CustomProxies = []ProxySpec{{
		Name:   "front-node",
		Type:   "vless",
		Fields: map[string]any{"server": "example.com", "port": 443},
	}}
	s.ActiveProxy = "front-node"
	writeSubRepairSettings(t, s)

	st := clientState{
		Proto:         "订阅",
		Connected:     true,
		SubMode:       true,
		OpenVPNMode:   true,
		OpenVPNRegion: "JP",
		MixedPort:     7890,
		APIPort:       9090,
		// A v6 family must be forced back to v4: the relay is IPv4-only.
		Family: famV6,
	}
	o := optionsFromState(st)

	if o.connMode != "subscription" {
		t.Errorf("connMode = %q, want subscription", o.connMode)
	}
	if !o.openvpnMode {
		t.Error("openvpnMode was dropped by the repair")
	}
	if o.openvpnNodePin != "jp-58.189.75.234-1779" {
		t.Errorf("openvpnNodePin = %q, want the pinned relay; the repair would rotate off the user's choice", o.openvpnNodePin)
	}
	if len(o.customProxies) != 1 || o.activeProxy != "front-node" {
		t.Errorf("front node lost: proxies=%d active=%q", len(o.customProxies), o.activeProxy)
	}
	if o.family != famV4 || o.ipv6 {
		t.Errorf("family = %q ipv6=%v, want v4-only for an IPv4 relay", o.family, o.ipv6)
	}
	// The root cause, stated as a fact: the WARP scan cannot parse this proto,
	// which is exactly why the repair must not go through it.
	if _, err := parseProto(o.proto); err == nil {
		t.Error("parseProto accepted \"订阅\"; the WARP-scan crash premise no longer holds")
	}
}