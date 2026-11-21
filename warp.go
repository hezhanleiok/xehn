package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
)

// Set once from -interface (main.go) before any tunnel is built. Empty scanInterface
// means the default bind; scanSourceIP is the interface's address, kept for host-ping
// and display only. Global to avoid threading through newTunnel's callers.
var (
	scanInterface string
	scanSourceIP  netip.Addr
)

// Registration (register.go) overwrites these in place, so var not const.
//
// There is deliberately NO built-in device identity. Every install must create
// its own WARP device on first run: a hardcoded private key (and the IPv6 that
// belongs to it) is somebody else's device — Cloudflare routes v6 per device,
// so traffic from a borrowed address is dropped, and a shared key makes every
// user of this build look like one client to the API. validateAccountFor()
// refuses to render anything until registration or an account file filled
// these in.
var (
	warpPrivateKey = ""
	warpPublicKey  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	// warpAddress is WARP's fixed client-side IPv4. It is the same on every
	// device (the tunnel is addressed per key, not per address), so it is safe
	// as a default; the account's own v4 replaces it when present.
	warpAddress = "172.16.0.2"
	// warpAddressV6 is device-specific and comes from the account. Empty means
	// "this account has no IPv6": IPv6 families are refused rather than faked
	// with an address that belongs to another device.
	warpAddressV6 = ""
)

const (
	tunnelMTU = 1280
	keepalive = 25

	mtuMin = 576
	mtuMax = 1500
)

// -jc/-jmin/-jmax/-i1 override these in place (flags.go), so var not const.
var (
	awgJc   = 6
	awgJmin = 10
	awgJmax = 50
	awgI1   = i1Default
)

const (
	i1Keyword = "none"
	i1Default = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"
)

const (
	junkCountLimitMin = 1
	junkCountLimitMax = 128
)

const (
	junkCountMin = 4
	junkCountMax = 6
	junkSizeMin  = 10
	junkSizeMax  = 50
	junkSpanMin  = 20
	junkSpanMax  = 100
)

func genJunkParams() {
	awgJc = randRange(junkCountMin, junkCountMax)
	awgJmin = randRange(junkSizeMin, junkSizeMax)
	awgJmax = awgJmin + randRange(junkSpanMin, junkSpanMax)
}

func randRange(lo, hi int) int {
	return lo + rand.Intn(hi-lo+1)
}

// The extended set (alternate UDP ports Cloudflare also serves, from
// CloudflareWarpSpeedTest) is only swept when no primary port gets through, so
// a restrictive network still has a chance without making every scan pay 50
// extra per-port timeouts. warpPorts holds what phase 1 found open.
var (
	primaryWarpPorts  = []int{2408, 500, 1701, 4500}
	extendedWarpPorts = []int{
		854, 859, 864, 878, 880, 890, 891, 894, 903, 908,
		928, 934, 939, 942, 943, 945, 946, 955, 968, 987,
		988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843,
		2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279,
		5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}
	warpPorts = primaryWarpPorts
)

// -sweep-ports: "open" keeps phase 1 and sweeps the ports it found, "all" skips
// phase 1 and sweeps every port warpscout knows about.
const (
	sweepOpen = "open"
	sweepAll  = "all"
)

var sweepModes = []string{sweepOpen, sweepAll}

func allWarpPorts() []int {
	return append(slices.Clone(primaryWarpPorts), extendedWarpPorts...)
}

func base64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func baseUAPI(awg bool) (string, error) {
	if warpPrivateKey == "" {
		return "", fmt.Errorf("尚未注册 WARP 账号：首次连接会自动注册，若一直失败请检查网络或运行 xehn register")
	}
	privHex, err := base64ToHex(warpPrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if awg {
		fmt.Fprintf(&b, "jc=%d\n", awgJc)
		fmt.Fprintf(&b, "jmin=%d\n", awgJmin)
		fmt.Fprintf(&b, "jmax=%d\n", awgJmax)
		if awgI1 != "" {
			fmt.Fprintf(&b, "i1=%s\n", awgI1)
		}
	}
	return b.String(), nil
}

func peerUAPI(endpoint string) (string, error) {
	pubHex, err := base64ToHex(warpPublicKey)
	if err != nil {
		return "", fmt.Errorf("public key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	return b.String(), nil
}

type protoKind int

const (
	kindWG protoKind = iota
	kindAWG
	kindWWARP
	kindMASQUE
	kindMASQUEH2
	kindMASQUEMASQUE
)

type protoRun struct {
	kind protoKind
	name string
}

const (
	protoWG       = "wg"
	protoAWG      = "awg"
	protoWWarp    = "wwarp"
	protoMASQUE   = "masque"    // MASQUE over HTTP/3 (QUIC) — mihomo's default
	protoMASQUEH2 = "masque-h2" // MASQUE over HTTP/2 (TCP)
	// MASQUE in MASQUE (H3 in H3): one CONNECT-IP tunnel carried inside
	// another. The inner hop dials from inside the outer one, so Cloudflare
	// sees the outer edge and the inner tunnel gets its own exit address —
	// Aether's --mim, expressed here as two masque outbounds chained with
	// mihomo's dialer-proxy.
	protoMASQUEMASQUE = "masque-mm"
)

func (r protoRun) isAWG() bool { return r.kind == kindAWG }

// WARP-in-WARP is not a wire protocol: it is two wg/awg outbounds chained via
// mihomo's dialer-proxy (opts.proto = outer carrier, opts.innerProto = inner,
// opts.through = the outer endpoint). kindWWARP exists only so the UI and the
// connect pipeline can name it as one of the five first-class protocols; the
// engine (scan/nest/render) always sees the outer/inner runs instead.
func (r protoRun) isWWARP() bool { return r.kind == kindWWARP }

// Both MASQUE kinds run the same CONNECT-IP tunnel and differ only in the
// transport underneath it, so everything that branches on "is this MASQUE"
// stays one branch and only the transport asks isH2. masque-mm is MASQUE too:
// each of its two hops is an ordinary CONNECT-IP tunnel, the inner one dialled
// through the outer.
func (r protoRun) isMASQUE() bool {
	return r.kind == kindMASQUE || r.kind == kindMASQUEH2 || r.kind == kindMASQUEMASQUE
}
func (r protoRun) isH2() bool { return r.kind == kindMASQUEH2 }

// isMASQUEMASQUE marks the nested pair. The render and the connect pipeline
// treat it as "masque with an outer masque", never as a separate transport.
func (r protoRun) isMASQUEMASQUE() bool { return r.kind == kindMASQUEMASQUE }

var protoRuns = []protoRun{
	{kindWG, protoWG},
	{kindAWG, protoAWG},
	{kindWWARP, protoWWarp},
	{kindMASQUE, protoMASQUE},
	{kindMASQUEH2, protoMASQUEH2},
	{kindMASQUEMASQUE, protoMASQUEMASQUE},
}

func parseProto(p string) (protoRun, error) {
	for _, r := range protoRuns {
		if r.name == p {
			return r, nil
		}
	}
	return protoRun{}, fmt.Errorf("invalid -proto %q: use wg, awg, wwarp, masque, masque-h2 or masque-mm", p)
}

// protoV6Capable reports whether a protocol can carry IPv6 in the tunnel. The
// two nested protocols cannot: their inner link MTU is 1220 bytes, below the
// 1280-byte minimum an IPv6 packet needs, so v6 would handshake and blackhole.
// protoChained reports whether a protocol is implemented as two nested
// tunnels. Psiphon rides a single underlay, so it cannot be combined with these.
func protoChained(p string) bool {
	return p == protoWWarp || p == protoMASQUEMASQUE
}

func protoV6Capable(p string) bool {
	switch p {
	case protoWG, protoAWG, protoMASQUE, protoMASQUEH2:
		return true
	default:
		return false
	}
}

// protoLabel is the uppercase tag the connect pipeline stamps on every stage
// log line ("[WG] Tunnel handshake succeeded"), keyed by the user-facing
// protocol name (wwarp chains report as WARP-in-WARP, not as their carrier).
// protoLabel is the protocol's name in stage logs and the state file, using the
// same names the UI shows (GOOL for WARP-in-WARP).
func protoLabel(p string) string {
	switch p {
	case protoWWarp:
		return "GOOL"
	case protoMASQUE:
		return "MASQUE H3"
	case protoMASQUEH2:
		return "MASQUE H2"
	case protoMASQUEMASQUE:
		return "MASQUE in MASQUE"
	case protoAWG:
		return "AWG"
	case protoWG:
		return "WireGuard"
	}
	return strings.ToUpper(p)
}
