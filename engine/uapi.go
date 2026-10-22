package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// AWGJunk carries the AmneziaWG obfuscation parameters. Defaults match the
// Windows client (warpscout/warp.go: awgJc/awgJmin/awgJmax/awgI1) so both
// platforms present the same fingerprint.
type AWGJunk struct {
	Jc   int
	Jmin int
	Jmax int
	I1   string
}

// DefaultAWGJunk is the profile the desktop client ships with.
func DefaultAWGJunk() AWGJunk { return AWGJunk{Jc: 4, Jmin: 20, Jmax: 60} }

// RenderDeviceUAPI renders the device half of the WireGuard/AmneziaWG UAPI
// document: the private key, plus the junk parameters when awg is set.
//
// It is the pure, parameterised form of warpscout's baseUAPI/peerUAPI
// (warpscout/warp.go:114 and :133), which read package globals and therefore
// cannot be reused in a library. Keep the two in step: the desktop side is the
// reference for the format, and both feed the same amneziawg-go device.
func RenderDeviceUAPI(privateKeyB64 string, awg bool, junk AWGJunk) (string, error) {
	privHex, err := base64ToHex(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if awg {
		fmt.Fprintf(&b, "jc=%d\n", junk.Jc)
		fmt.Fprintf(&b, "jmin=%d\n", junk.Jmin)
		fmt.Fprintf(&b, "jmax=%d\n", junk.Jmax)
		if junk.I1 != "" {
			fmt.Fprintf(&b, "i1=%s\n", junk.I1)
		}
	}
	return b.String(), nil
}

// RenderPeerUAPI renders the peer half: the Cloudflare edge public key, the
// endpoint to dial and the default routes. keepalive must be > 0 or the peer is
// dropped by Cloudflare's NAT between packets.
func RenderPeerUAPI(peerPublicKeyB64, endpoint string, keepalive int) (string, error) {
	pubHex, err := base64ToHex(peerPublicKeyB64)
	if err != nil {
		return "", fmt.Errorf("public key: %w", err)
	}
	if endpoint == "" {
		return "", fmt.Errorf("endpoint 为空")
	}
	if keepalive <= 0 {
		// Same default the desktop uses; a zero keepalive is a silent,
		// intermittent "it connects and then dies" bug on mobile networks.
		keepalive = 25
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

// base64ToHex converts the base64 keys Cloudflare hands out into the hex form
// the UAPI wants. Copied from warpscout/warp.go:106; both must agree.
func base64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
