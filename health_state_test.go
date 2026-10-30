package main

import "testing"

// A health repair rebuilds the session from state.json alone. Everything the
// user asked for — the routing preset, the resolvers, DNS leak protection, the
// custom domain lists — has to survive that round trip, or a repair silently
// turns 绕过大陆 into "proxy everything" and stops tunnelling the resolver.
func TestOptionsFromStateKeepsRoutingAndDNS(t *testing.T) {
	st := clientState{
		Proto:        protoAWG,
		Connected:    true,
		MixedPort:    7890,
		APIPort:      9090,
		ProxyMode:    modeBypass,
		DNS:          "223.5.5.5, 1.1.1.1",
		DNSLeak:      true,
		DomainDirect: "intra.example.com, nas.example.com",
		DomainProxy:  "example.com",
	}
	o := optionsFromState(st)

	if o.proxyMode != modeBypass {
		t.Errorf("proxyMode = %q, want %q", o.proxyMode, modeBypass)
	}
	if o.dns != "223.5.5.5, 1.1.1.1" {
		t.Errorf("dns = %q", o.dns)
	}
	if !o.dnsLeak {
		t.Error("dnsLeak was dropped by the repair")
	}
	if len(o.domainDirect) != 2 || o.domainDirect[0] != "intra.example.com" {
		t.Errorf("domainDirect = %v", o.domainDirect)
	}
	if len(o.domainProxy) != 1 || o.domainProxy[0] != "example.com" {
		t.Errorf("domainProxy = %v", o.domainProxy)
	}

	// An old state file has none of these fields: the repair must fall back to
	// the defaults rather than crash or build an empty preset.
	old := optionsFromState(clientState{Proto: protoAWG, Connected: true, MixedPort: 7890})
	if old.proxyMode == modeBypass {
		t.Error("a state without a preset must not invent one")
	}
	if old.dnsLeak {
		t.Error("a state without dns_leak must not claim leak protection")
	}
}
