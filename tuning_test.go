package main

import (
	"os"
	"strings"
	"testing"
)

func TestNormalizeTuning(t *testing.T) {
	if normalizeRank("") != rankPing || normalizeRank("PING") != rankPing || normalizeRank("bogus") != rankPing {
		t.Fatalf("rank default must be ping")
	}
	if normalizeRank("speed") != rankSpeed || normalizeRank(" Speed ") != rankSpeed {
		t.Fatalf("speed not recognised")
	}
	if normalizeStack("") != defaultIPStack || normalizeStack("SYSTEM") != "system" || normalizeStack("nope") != defaultIPStack {
		t.Fatalf("stack normalization wrong")
	}
	if normalizeCC("") != defaultCC || normalizeCC("Cubic") != "cubic" || normalizeCC("nope") != defaultCC {
		t.Fatalf("cc normalization wrong")
	}
}

func TestBetterEndpointSpeedTier(t *testing.T) {
	defer func() { endpointRankMode = rankPing }()
	endpointRankMode = rankSpeed

	// A is far faster but much higher latency: the throughput tier wins.
	fast := cachedEndpoint{Endpoint: "a", Speed: 200, EpPingMS: 300, Loss: 0}
	slow := cachedEndpoint{Endpoint: "b", Speed: 20, EpPingMS: 30, Loss: 0}
	if !betterEndpoint(fast, slow) {
		t.Fatalf("a 10x throughput edge must outrank lower latency")
	}
	if betterEndpoint(slow, fast) {
		t.Fatalf("the slower tier must not win")
	}

	// Within a tier (ratio < 1.5) latency decides again.
	near1 := cachedEndpoint{Endpoint: "a", Speed: 100, EpPingMS: 80}
	near2 := cachedEndpoint{Endpoint: "b", Speed: 95, EpPingMS: 30}
	if betterEndpoint(near1, near2) {
		t.Fatalf("inside one tier the lower-latency endpoint must win")
	}
	if !betterEndpoint(near2, near1) {
		t.Fatalf("lower latency should win inside a tier")
	}

	// A measured endpoint outranks an unmeasured one regardless of latency.
	measured := cachedEndpoint{Endpoint: "a", Speed: 50, EpPingMS: 200}
	unmeasured := cachedEndpoint{Endpoint: "b", Speed: 0, EpPingMS: 10}
	if !betterEndpoint(measured, unmeasured) {
		t.Fatalf("proven throughput must outrank an unmeasured endpoint")
	}

	// Both unmeasured: pure latency, exactly the historical behaviour.
	p1 := cachedEndpoint{Endpoint: "a", EpPingMS: 90}
	p2 := cachedEndpoint{Endpoint: "b", EpPingMS: 20}
	if !betterEndpoint(p2, p1) {
		t.Fatalf("two unmeasured endpoints must fall back to latency")
	}

	// ping mode ignores speed entirely.
	endpointRankMode = rankPing
	if betterEndpoint(fast, slow) {
		t.Fatalf("ping mode must ignore the speed tier")
	}
	if !betterEndpoint(slow, fast) {
		t.Fatalf("ping mode must rank by latency")
	}
}

func TestRenderTuningsGate(t *testing.T) {
	opts := options{mixedPort: 7890, apiPort: 9090, mtu: 1280}
	ce := cachedEndpoint{Endpoint: "162.159.192.1:2408"}
	run := protoRun{kind: kindWG, name: protoWG}

	off, err := renderClientConfig(opts, ce, run)
	if err != nil {
		t.Fatalf("render (gate off): %v", err)
	}
	for _, w := range []string{"tcp-concurrent", "unified-delay", "lazy: true"} {
		if strings.Contains(string(off), w) {
			t.Fatalf("gate off must not render %q\n%s", w, off)
		}
	}

	opts.tuningsOK = true
	on, err := renderClientConfig(opts, ce, run)
	if err != nil {
		t.Fatalf("render (gate on): %v", err)
	}
	for _, w := range []string{"tcp-concurrent: true", "unified-delay: true", "lazy: true", "timeout: 3000"} {
		if !strings.Contains(string(on), w) {
			t.Fatalf("gate on must render %q\n%s", w, on)
		}
	}
}

func TestMihomoPeerTransportOptions(t *testing.T) {
	// A throwaway MASQUE device: pemBody only needs a decodeable PEM block, and
	// the private key is rendered verbatim, so neither has to be a real key.
	prev := masqueAcct
	defer func() { masqueAcct = prev }()
	masqueAcct = &masqueAccount{
		PrivateKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PeerPublicKey: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		IPv4:          "172.16.0.2",
	}
	run := mustParseProto(protoMASQUE)

	render := func(stack, cc string) string {
		o := options{ipStack: stack, congestion: cc}
		p, err := mihomoProxy(o, "MASQUE H3 WARP", "162.159.198.2:443", run, 0, nil)
		if err != nil {
			t.Fatalf("mihomoProxy: %v", err)
		}
		return renderProxiesYAML([][]kv{p})
	}

	// Defaults are unchanged: bbr / gvisor.
	def := render("", "")
	if !strings.Contains(def, "congestion-controller: bbr") || !strings.Contains(def, "mode: gvisor") {
		t.Fatalf("default transport must stay bbr/gvisor\n%s", def)
	}

	// An override flows through to the rendered fields.
	ov := render("system", "cubic")
	if !strings.Contains(ov, "congestion-controller: cubic") || !strings.Contains(ov, "mode: system") {
		t.Fatalf("override transport not rendered\n%s", ov)
	}
}

func TestOverrideTuningFromEnv(t *testing.T) {
	defer func() {
		os.Unsetenv("WARP_ENDPOINT_RANK")
		os.Unsetenv("WARP_IP_STACK")
		os.Unsetenv("WARP_CC")
	}()
	os.Setenv("WARP_ENDPOINT_RANK", "speed")
	os.Setenv("WARP_IP_STACK", "system")
	os.Setenv("WARP_CC", "cubic")
	o := options{endpointRank: rankPing, ipStack: defaultIPStack, congestion: defaultCC}
	overrideTuningFromEnv(&o)
	if o.endpointRank != rankSpeed || o.ipStack != "system" || o.congestion != "cubic" {
		t.Fatalf("env overrides not applied: %+v", o)
	}
}