package main

import (
	"strings"
	"testing"
)

// TestDefaultResolversPreferOverseas pins the DNS-leak fix: mihomo asks the
// first reachable resolver, so a domestic one at the head means every lookup
// leaves through the local ISP even while traffic is tunnelled. The user's leak
// test showed exactly that — exit in US/SG, resolvers reported as China Telecom.
func TestDefaultResolversPreferOverseas(t *testing.T) {
	list := confDNSList(options{})
	if len(list) == 0 {
		t.Fatal("no default resolvers configured")
	}
	first := list[0]
	if isDomesticResolver(first) {
		t.Fatalf("first resolver is domestic (%s); lookups would bypass the tunnel", first)
	}
	// No domestic resolver may appear at all: mihomo queries every entry in
	// parallel and takes the fastest answer, so merely demoting one still lets
	// it win on RTT and hand the query to the local ISP resolver.
	for _, s := range list {
		if isDomesticResolver(s) {
			t.Fatalf("domestic resolver %s still configured; parallel querying lets it win", s)
		}
	}
}

// TestDNSResolversPinnedToEgress is the other half: respect-rules only routes
// the DNS *connection* by rules, so every configured resolver address needs its
// own IP-CIDR pointing at the exit group.
func TestDNSResolversPinnedToEgress(t *testing.T) {
	o := options{proxyMode: modeCustom, dnsLeak: true}
	rules := routeRules(o, "PSIPHON")
	for _, s := range confDNSList(o) {
		want := "IP-CIDR," + s + "/32,PSIPHON"
		var found bool
		for _, r := range rules {
			if r == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("resolver %s has no rule pinning it to the tunnel; got %v", s, rules)
		}
	}
}

// TestSubscriptionCarrierDNSStaysInTunnel covers subscription mode, which builds
// its config through a different renderer. It used to hard-code domestic
// resolvers with no respect-rules and no IP-CIDR at all — a real leak.
func TestSubscriptionCarrierDNSStaysInTunnel(t *testing.T) {
	cfg := string(subscriptionCarrierConfig(
		[]ProxySpec{{Name: "node-a"}}, "node-a", 7890, 9090))
	if !strings.Contains(cfg, "respect-rules: true") {
		t.Error("subscription config lacks respect-rules; resolver queries bypass the rule set")
	}
	// Anchor on the leading newline + indent: "proxy-server-nameserver:" also
	// ends with "nameserver:", so a bare substring check would false-positive.
	if strings.Contains(cfg, "\n  nameserver:\n    - 119.29.29.29") ||
		strings.Contains(cfg, "\n  nameserver:\n    - 223.5.5.5") {
		t.Error("subscription config still uses a domestic resolver as the primary nameserver")
	}
	for _, want := range []string{
		"IP-CIDR,1.1.1.1/32,node-a",
		"IP-CIDR,8.8.8.8/32,node-a",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("subscription config missing %q", want)
		}
	}
}
