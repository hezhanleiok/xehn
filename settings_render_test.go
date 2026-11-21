package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderRoutingPresets pins the five presets' rule sets: global ignores the
// domain lists, direct turns mihomo off the proxy, blacklist falls back to
// DIRECT, and custom keeps the two lists in the documented order (proxy rules
// first, so a domain in both lists takes the tunnel).
func TestRenderRoutingPresets(t *testing.T) {
	base := options{
		mixedPort:    7890,
		apiPort:      9090,
		mtu:          1280,
		dns:          "223.5.5.5, 1.1.1.1",
		domainDirect: []string{"intra.example"},
		domainProxy:  []string{"example.com"},
	}
	ce := cachedEndpoint{Endpoint: "162.159.192.1:2408"}
	run := protoRun{kind: kindWG, name: protoWG}

	cases := []struct {
		name    string
		mode    string
		want    []string
		notWant []string
	}{
		{
			name: "global",
			mode: modeGlobal,
			// Global ignores the user's domain lists, but the LAN still stays
			// local and QUIC is dropped: a UDP flow cannot be matched by domain
			// and would slip past the system proxy entirely.
			want: []string{
				"mode: rule",
				"  - MATCH,WARP",
				"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
				"AND,(AND,(DST-PORT,443),(NETWORK,UDP)),REJECT",
			},
			notWant: []string{"GEOSITE", "DOMAIN-SUFFIX,example.com"},
		},
		{
			name:    "direct",
			mode:    modeDirect,
			want:    []string{"mode: direct", "  - MATCH,DIRECT"},
			notWant: []string{"  - MATCH,WARP", "DOMAIN-SUFFIX"},
		},
		{
			name: "blacklist",
			mode: modeBlacklist,
			want: []string{
				"DOMAIN-SUFFIX,example.com,WARP",
				"  - MATCH,DIRECT",
			},
			notWant: []string{"DOMAIN-SUFFIX,intra.example,DIRECT", "  - MATCH,WARP"},
		},
		{
			name: "custom",
			mode: modeCustom,
			want: []string{
				"DOMAIN-SUFFIX,example.com,WARP",
				"DOMAIN-SUFFIX,intra.example,DIRECT",
				"  - MATCH,WARP",
			},
		},
		{
			name: "bypass",
			mode: modeBypass,
			want: []string{
				"DOMAIN-SUFFIX,example.com,WARP",
				"DOMAIN-SUFFIX,intra.example,DIRECT",
				"  - MATCH,WARP",
			},
		},
	}

	for _, tc := range cases {
		opts := base
		opts.proxyMode = tc.mode
		b, err := renderClientConfig(opts, ce, run)
		if err != nil {
			t.Fatalf("%s: renderClientConfig: %v", tc.name, err)
		}
		cfg := string(b)
		for _, w := range tc.want {
			if !strings.Contains(cfg, w) {
				t.Errorf("%s: config missing %q\n%s", tc.name, w, cfg)
			}
		}
		for _, w := range tc.notWant {
			if strings.Contains(cfg, w) {
				t.Errorf("%s: config unexpectedly contains %q\n%s", tc.name, w, cfg)
			}
		}
		if err := os.WriteFile("routing-"+tc.name+"-test.yaml", b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRenderDNSLeak checks the leak-protection block: respect-rules plus a
// proxy-server resolver, the resolvers' own addresses pinned to the tunnel, and
// the TUN hijack. Each has to disappear when the switch is off or the proxy is
// bypassed, or the config would promise protection it does not provide.
func TestRenderDNSLeak(t *testing.T) {
	ce := cachedEndpoint{Endpoint: "162.159.192.1:2408"}
	run := protoRun{kind: kindWG, name: protoWG}
	base := options{
		mixedPort: 7890,
		apiPort:   9090,
		dns:       "223.5.5.5, 1.1.1.1",
		dnsLeak:   true,
		proxyMode: modeCustom,
	}

	cases := []struct {
		name    string
		mutate  func(*options)
		want    []string
		notWant []string
	}{
		{
			name:   "protected",
			mutate: func(o *options) {},
			want: []string{
				"respect-rules: true",
				"proxy-server-nameserver:",
				"IP-CIDR,223.5.5.5/32,WARP",
				"IP-CIDR,1.1.1.1/32,WARP",
			},
		},
		{
			name:    "switch off",
			mutate:  func(o *options) { o.dnsLeak = false },
			notWant: []string{"respect-rules", "proxy-server-nameserver", "IP-CIDR,223.5.5.5/32"},
		},
		{
			name:    "no dns handed out",
			mutate:  func(o *options) { o.noDNS = true },
			notWant: []string{"dns:\n", "respect-rules"},
		},
		{
			name:    "direct mode",
			mutate:  func(o *options) { o.proxyMode = modeDirect },
			notWant: []string{"respect-rules", "dns-hijack"},
		},
		{
			name:   "tun hijack",
			mutate: func(o *options) { o.tunMode = true },
			want:   []string{"dns-hijack:\n    - any:53"},
		},
		{
			name: "lan resolver stays direct",
			mutate: func(o *options) {
				o.dns = "192.168.1.1, 1.1.1.1"
			},
			want: []string{"IP-CIDR,192.168.1.1/32,DIRECT", "IP-CIDR,1.1.1.1/32,WARP"},
		},
	}

	for _, tc := range cases {
		opts := base
		tc.mutate(&opts)
		b, err := renderClientConfig(opts, ce, run)
		if err != nil {
			t.Fatalf("%s: renderClientConfig: %v", tc.name, err)
		}
		cfg := string(b)
		for _, w := range tc.want {
			if !strings.Contains(cfg, w) {
				t.Errorf("%s: config missing %q\n%s", tc.name, w, cfg)
			}
		}
		for _, w := range tc.notWant {
			if strings.Contains(cfg, w) {
				t.Errorf("%s: config unexpectedly contains %q\n%s", tc.name, w, cfg)
			}
		}
	}
}

// TestRenderCaptureAndFamily pins the config-level effect of the settings page:
// LAN access widens the listener, TUN adds its block, and the address family
// decides both the core's IPv6 switch and the outbound's addresses/routes.
func TestRenderCaptureAndFamily(t *testing.T) {
	// The build ships no device identity (every install registers its own), so
	// the test supplies a fixture and asserts against the literal. Asserting
	// against the global was the bug: once it is empty, "ipv6: "+global becomes
	// "ipv6: " and matches the header's own "ipv6: false".
	prevKey, prevV6 := warpPrivateKey, warpAddressV6
	warpPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	warpAddressV6 = "2001:db8::1"
	defer func() { warpPrivateKey, warpAddressV6 = prevKey, prevV6 }()
	const testV6 = "2001:db8::1"

	ce := cachedEndpoint{Endpoint: "162.159.192.1:2408"}
	run := protoRun{kind: kindWG, name: protoWG}
	base := options{mixedPort: 7890, apiPort: 9090, mtu: 1280, dns: "223.5.5.5"}

	cases := []struct {
		name    string
		mutate  func(*options)
		want    []string
		notWant []string
	}{
		{
			name:   "lan on",
			mutate: func(o *options) { o.allowLan = true },
			want:   []string{`allow-lan: true`, `bind-address: "*"`},
		},
		{
			name:   "lan off",
			mutate: func(o *options) { o.allowLan = false },
			want:   []string{"allow-lan: false", "bind-address: 127.0.0.1"},
		},
		{
			name:   "tun",
			mutate: func(o *options) { o.tunMode = true },
			want:   []string{"tun:\n  enable: true", "listen: 127.0.0.1:1053"},
		},
		{
			name:    "v4 only",
			mutate:  func(o *options) { o.family = famV4 },
			want:    []string{"ipv6: false", "ip: " + warpAddress, "allowed-ips: ['0.0.0.0/0']"},
			notWant: []string{"ipv6: " + testV6, "::/0"},
		},
		{
			name:   "v6 only",
			mutate: func(o *options) { o.family = famV6 },
			want: []string{
				"ipv6: true",
				"ipv6: " + testV6,
				"allowed-ips: ['::/0']",
			},
			notWant: []string{"ip: " + warpAddress, "0.0.0.0/0"},
		},
		{
			name:   "dual stack",
			mutate: func(o *options) { o.family = famBoth },
			want: []string{
				"ipv6: true",
				"ip: " + warpAddress,
				"ipv6: " + testV6,
				"allowed-ips: ['0.0.0.0/0', '::/0']",
			},
		},
	}

	for _, tc := range cases {
		opts := base
		tc.mutate(&opts)
		b, err := renderClientConfig(opts, ce, run)
		if err != nil {
			t.Fatalf("%s: renderClientConfig: %v", tc.name, err)
		}
		cfg := string(b)
		for _, w := range tc.want {
			if !strings.Contains(cfg, w) {
				t.Errorf("%s: config missing %q\n%s", tc.name, w, cfg)
			}
		}
		for _, w := range tc.notWant {
			if strings.Contains(cfg, w) {
				t.Errorf("%s: config unexpectedly contains %q\n%s", tc.name, w, cfg)
			}
		}
	}
}

// TestRenderBypassSplitsDNS pins the fix for "bypass mainland is still slow":
// the preset routed CN traffic direct but resolved every domain through the
// tunnel, so each page paid a WARP round trip before the direct connection even
// started. CN lookups must go to a domestic resolver, directly, and GEOIP must
// not trigger a resolve of its own.
func TestRenderBypassSplitsDNS(t *testing.T) {
	home := t.TempDir()
	t.Setenv("WARP_CLIENT_HOME", home)
	coreDirPath := filepath.Join(home, "core")
	if err := os.MkdirAll(coreDirPath, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"geosite.dat", "geoip.metadb"} {
		if err := os.WriteFile(filepath.Join(coreDirPath, n), make([]byte, 600*1024), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	render := func(dns string) string {
		opts := options{
			mixedPort: 7890,
			apiPort:   9090,
			mtu:       1280,
			dns:       dns,
			dnsLeak:   true,
			proxyMode: modeBypass,
		}
		b, err := renderClientConfig(opts,
			cachedEndpoint{Endpoint: "162.159.192.1:2408"},
			protoRun{kind: kindWG, name: protoWG})
		if err != nil {
			t.Fatalf("renderClientConfig: %v", err)
		}
		return string(b)
	}

	cfg := render("223.5.5.5, 1.1.1.1")
	for _, want := range []string{
		"GEOSITE,cn,DIRECT",
		"GEOIP,CN,DIRECT,no-resolve",         // never resolve just to test GeoIP
		"IP-CIDR,223.5.5.5/32,DIRECT",        // domestic resolver stays off the tunnel
		"IP-CIDR,1.1.1.1/32,WARP",            // foreign resolver still follows it
		`"geosite:cn": 223.5.5.5`,            // CN domains resolved domestically
		`"geosite:geolocation-!cn": 1.1.1.1`, // foreign domains resolved abroad
		// The whitelist v2rayN ships, ported: QUIC dropped everywhere but CN,
		// Google always proxied, the CN DNS endpoints reached directly.
		"AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT",
		"GEOSITE,google,WARP",
		"DOMAIN-SUFFIX,alidns.com,DIRECT",
		// LAN stays local — without this a router page or a NAS is routed
		// through the exit and simply does not answer.
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("bypass config missing %q\n%s", want, cfg)
		}
	}

	// Foreign-only resolvers: the CN half of the split has nothing to use, so
	// only the foreign half is emitted — silently inventing a domestic resolver
	// would override the user's choice.
	foreign := render("1.1.1.1, 8.8.8.8")
	if !strings.Contains(foreign, `"geosite:geolocation-!cn": 1.1.1.1`) {
		t.Errorf("foreign policy missing\n%s", foreign)
	}
	if strings.Contains(foreign, `"geosite:cn"`) {
		t.Errorf("CN policy emitted without a domestic resolver\n%s", foreign)
	}

	// Without the databases the preset must stay inert rather than emit rules
	// mihomo cannot load.
	if err := os.Remove(filepath.Join(coreDirPath, "geosite.dat")); err != nil {
		t.Fatal(err)
	}
	if noGeo := render("223.5.5.5, 1.1.1.1"); strings.Contains(noGeo, "GEOSITE,cn,DIRECT") {
		t.Errorf("geo rules emitted without geodata\n%s", noGeo)
	}
}

// TestRenderSubscriptionTunDNS pins the mode-B defect fix: the subscription
// renderer must emit the same resolver/TUN blocks as the WARP one. Before,
// sub+TUN produced a config with no tun device (zero capture) and sub mode had
// no dns block at all (leak protection and the bypass DNS split were inert).
func TestRenderSubscriptionTunDNS(t *testing.T) {
	base := options{
		mixedPort: 7890,
		apiPort:   9090,
		proxyMode: modeCustom,
		dnsLeak:   true,
		connMode:  "subscription",
		customProxies: []ProxySpec{
			{Name: "node-a", Type: "ss", Fields: map[string]any{
				"server": "1.2.3.4", "port": 8388, "cipher": "aes-128-gcm", "password": "pw",
			}},
		},
		activeProxy: "node-a",
	}

	cases := []struct {
		name    string
		mutate  func(*options)
		want    []string
		notWant []string
	}{
		{
			name:   "tun capture",
			mutate: func(o *options) { o.tunMode = true },
			want: []string{
				"dns:\n  enable: true",
				"respect-rules: true",
				"proxy-server-nameserver:",
				"listen: 127.0.0.1:1053",
				"tun:\n  enable: true",
				"auto-route: true",
				"dns-hijack:\n    - any:53",
			},
		},
		{
			name:    "system proxy capture",
			mutate:  func(o *options) {},
			want:    []string{"dns:\n  enable: true", "respect-rules: true", "nameserver:"},
			notWant: []string{"tun:\n", "dns-hijack", "listen: 127.0.0.1:1053"},
		},
		{
			name: "direct mode drops hardening",
			mutate: func(o *options) {
				o.tunMode = true
				o.proxyMode = modeDirect
			},
			want:    []string{"tun:\n  enable: true", "dns:\n  enable: true"},
			notWant: []string{"respect-rules", "dns-hijack"},
		},
	}

	for _, tc := range cases {
		opts := base
		tc.mutate(&opts)
		b, err := renderSubscriptionConfig(opts)
		if err != nil {
			t.Fatalf("%s: renderSubscriptionConfig: %v", tc.name, err)
		}
		cfg := string(b)
		for _, w := range tc.want {
			if !strings.Contains(cfg, w) {
				t.Errorf("%s: config missing %q\n%s", tc.name, w, cfg)
			}
		}
		for _, w := range tc.notWant {
			if strings.Contains(cfg, w) {
				t.Errorf("%s: config unexpectedly contains %q\n%s", tc.name, w, cfg)
			}
		}
	}
}
