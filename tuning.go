package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/xhwarp/warp-client/internal/core"
)

// Endpoint ranking modes (S1-1). ping is the historical behaviour and stays the
// default; speed is the opt-in optimization that tiers working endpoints by
// measured steady-state throughput before falling back to latency.
const (
	rankPing  = "ping"
	rankSpeed = "speed"

	// Shipped MASQUE transport defaults. Optionizing them (S1-5) must not change
	// what an untouched install renders.
	defaultIPStack = "gvisor"
	defaultCC      = "bbr"

	// endpointRankProbeCount caps how many top ping-ranked candidates the speed
	// ranking measures, so opting in costs seconds rather than a full speedtest.
	endpointRankProbeCount = 4

	// speedTierRatio is how far apart two measured throughputs must be to count
	// as different tiers. Within a tier, loss and latency decide — a 5% speed
	// edge must not override a much closer node.
	speedTierRatio = 1.5
)

func normalizeRank(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), rankSpeed) {
		return rankSpeed
	}
	return rankPing
}

func normalizeStack(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "gvisor", "system", "mixed":
		return strings.ToLower(strings.TrimSpace(v))
	}
	return defaultIPStack
}

func normalizeCC(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "bbr", "bbr3", "cubic", "reno":
		return strings.ToLower(strings.TrimSpace(v))
	}
	return defaultCC
}

// effectiveStack / effectiveCC resolve what the renderer emits: the normalized
// option value, or the shipped default when unset.
func effectiveStack(o options) string { return normalizeStack(o.ipStack) }
func effectiveCC(o options) string    { return normalizeCC(o.congestion) }

// overrideTuningFromEnv applies the hidden A/B switches (S1-5): an env var wins
// over the persisted choice so a transport or the ranking mode can be flipped
// for one run without editing settings.json. Shared by the GUI's settings.apply
// and the CLI's common-flag pass so both honour it identically.
func overrideTuningFromEnv(o *options) {
	if v := os.Getenv("WARP_ENDPOINT_RANK"); v != "" {
		o.endpointRank = normalizeRank(v)
	}
	if v := os.Getenv("WARP_IP_STACK"); v != "" {
		o.ipStack = normalizeStack(v)
	}
	if v := os.Getenv("WARP_CC"); v != "" {
		o.congestion = normalizeCC(v)
	}
}

// Tuning capability gate (S1-4 / S1-5). The additive globals and a non-default
// stack/cc are only rendered when the running core actually parses them; a core
// that rejects them degrades to the previous config rather than failing the
// connect. Probes are cached per binary file, exactly like the protocol gate,
// and a probe that could not run degrades open (assume supported) so a scanner
// hiccup never disables a working transport.
var (
	tuneMu          sync.Mutex
	tuneKey         coreFileKey
	tuneGlobals     bool
	tuneGlobalsSeen bool
	tuneStackCC     = map[string]bool{}
)

func tuningGlobalsSupported(bin, workDir string) bool {
	if bin == "" {
		return true
	}
	tuneMu.Lock()
	defer tuneMu.Unlock()
	key := coreFileKeyOf(bin)
	if tuneKey != key {
		tuneKey, tuneGlobalsSeen, tuneStackCC = key, false, map[string]bool{}
	}
	if tuneGlobalsSeen {
		return tuneGlobals
	}
	ok, ran, _ := core.TestConfigDetail(bin, workDir, []byte(tuningGlobalsYAML()))
	tuneGlobals = !ran || ok
	tuneGlobalsSeen = true
	return tuneGlobals
}

func stackCCSupported(bin, workDir, stack, cc string) bool {
	if stack == defaultIPStack && cc == defaultCC {
		return true
	}
	if bin == "" {
		return true
	}
	tuneMu.Lock()
	defer tuneMu.Unlock()
	key := coreFileKeyOf(bin)
	if tuneKey != key {
		tuneKey, tuneGlobalsSeen, tuneStackCC = key, false, map[string]bool{}
	}
	combo := stack + "/" + cc
	if v, seen := tuneStackCC[combo]; seen {
		return v
	}
	yaml, err := masqueTuningYAML(stack, cc)
	if err != nil {
		return true
	}
	ok, ran, _ := core.TestConfigDetail(bin, workDir, []byte(yaml))
	supported := !ran || ok
	tuneStackCC[combo] = supported
	return supported
}

// resolveTuning folds the capability gate into the options a connect renders
// with: it enables the additive globals only when the core takes them, and
// falls back to the shipped stack/cc when a chosen override is unsupported.
func resolveTuning(o *options, bin, workDir string) {
	o.tuningsOK = tuningGlobalsSupported(bin, workDir)
	stack, cc := effectiveStack(*o), effectiveCC(*o)
	if stack == defaultIPStack && cc == defaultCC {
		return
	}
	if !stackCCSupported(bin, workDir, stack, cc) {
		stageMsg(fmt.Sprintf("核心不支持 ip-stack=%s / congestion=%s，回退到 %s/%s", stack, cc, defaultIPStack, defaultCC))
		o.ipStack, o.congestion = defaultIPStack, defaultCC
	}
}

// tuningGlobalsYAML is a parseable config carrying the additive globals and a
// url-test group with lazy health-checking — the exact fields the WARP render
// adds when the gate is open.
func tuningGlobalsYAML() string {
	return `tcp-concurrent: true
unified-delay: true
proxies:
  - name: "PROBE"
    type: wireguard
    private-key: ` + probeWGPrivateKey + `
    ip: 172.16.0.2
    peers:
      - server: 162.159.192.1
        port: 2408
        public-key: ` + probeWGPublicKey + `
        allowed-ips: ['0.0.0.0/0']
        persistent-keepalive: 25
    mtu: 1280
    udp: true
proxy-groups:
  - name: G
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    lazy: true
    timeout: 3000
    proxies:
      - PROBE
rules:
  - MATCH,G
`
}

// masqueTuningYAML probes one non-default ip-stack / congestion-controller pair
// on a throwaway masque outbound, the same field shape mihomoPeer renders.
func masqueTuningYAML(stack, cc string) (string, error) {
	privDER, pubDER, err := genECKeyPair()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("proxies:\n  - name: \"PROBE\"\n    type: masque\n    server: 162.159.198.2\n    port: 443\n")
	fmt.Fprintf(&b, "    sni: %s\n    private-key: %s\n    public-key: %s\n",
		masqueSNI, base64.StdEncoding.EncodeToString(privDER), base64.StdEncoding.EncodeToString(pubDER))
	b.WriteString("    ip: 172.16.0.2\n    udp: true\n    remote-dns-resolve: true\n    dns: ['1.1.1.1']\n")
	fmt.Fprintf(&b, "    congestion-controller: %s\n    ip-stack:\n      mode: %s\n", cc, stack)
	b.WriteString("rules:\n  - MATCH,PROBE\n")
	return b.String(), nil
}