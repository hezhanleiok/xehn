package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xhwarp/warp-client/internal/core"
)

// probeOpenVPNProto is the capability name for the native openvpn outbound. It
// is not a protoRun (the base protocol still carries it), so the probe list
// appends it explicitly.
const probeOpenVPNProto = "openvpn"

// probePEMCredentials builds one throwaway self-signed pair. The OpenVPN
// outbound parses ca/cert/key while loading the config (`mihomo -t`), so the
// probe needs real PEM, not placeholders; a one-hour leaf under its own CA is
// enough and costs one ECDSA keygen.
func probePEMCredentials() (caPEM, certPEM, keyPEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "warp-probe"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", "", err
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	key := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return cert, cert, key, nil
}

// Capability probing: the UI must not offer a protocol the running mihomo
// cannot parse. Rather than mapping versions to feature flags by hand (which
// rots the moment the upstream adds or renames a field), each protocol is
// probed by feeding the actual core a minimal, syntactically valid config of
// exactly the shape connect would render and asking `mihomo -t` to validate
// it. Exit 0 = supported; anything else = "please upgrade the core".

// Deterministic throwaway key material: the probe only needs parseable keys,
// never a tunnel that answers. base64(32 zero-ish bytes) is a valid WireGuard
// key format; the WARP public key is public by definition.
const (
	probeWGPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	probeWGPublicKey  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

// probeYAML renders the minimal config one protocol's connect config is shaped
// like. It must track mihomoPeer's field set in wgconf.go: a probe config that
// drifts from the real render would pass while the real connect fails (or
// vice versa).
func probeYAML(proto string) (string, error) {
	wgPeer := func(indent string) string {
		// indent lands the key at the proxy-item field level; the list and its
		// fields step in by 2/4 — anything deeper is a different mapping and
		// mihomo rejects the file as invalid YAML.
		return fmt.Sprintf(`%speers:
%s  - server: 162.159.192.1
%s    port: 2408
%s    public-key: %s
%s    allowed-ips: ['0.0.0.0/0']
%s    persistent-keepalive: 25
`, indent, indent, indent, indent, probeWGPublicKey, indent, indent)
	}
	switch proto {
	case protoWG, protoAWG:
		var b strings.Builder
		b.WriteString("proxies:\n  - name: \"PROBE\"\n    type: wireguard\n")
		b.WriteString("    private-key: " + probeWGPrivateKey + "\n    ip: 172.16.0.2\n")
		b.WriteString(wgPeer("    "))
		b.WriteString("    mtu: 1280\n    udp: true\n    remote-dns-resolve: true\n    dns: ['1.1.1.1']\n")
		if proto == protoAWG {
			b.WriteString(`    amnezia-wg-option:
      jc: 3
      jmin: 10
      jmax: 50
      s1: 0
      s2: 0
      h1: 1
      h2: 2
      h3: 3
      h4: 4
`)
		}
		b.WriteString("rules:\n  - MATCH,PROBE\n")
		return b.String(), nil

	case protoWWarp:
		// dialer-proxy chaining: the outer half carries no DNS, the inner one
		// dials through it — exactly mihomoProxies' chain render.
		var b strings.Builder
		b.WriteString("proxies:\n  - name: \"PROBE OUTER\"\n    type: wireguard\n")
		b.WriteString("    private-key: " + probeWGPrivateKey + "\n    ip: 172.16.0.2\n")
		b.WriteString(wgPeer("    "))
		b.WriteString("    mtu: 1280\n    udp: true\n")
		b.WriteString("  - name: \"PROBE INNER\"\n    type: wireguard\n")
		b.WriteString("    private-key: " + probeWGPrivateKey + "\n    ip: 172.16.0.3\n")
		b.WriteString(wgPeer("    "))
		b.WriteString("    mtu: 1220\n    udp: true\n    remote-dns-resolve: true\n    dns: ['1.1.1.1']\n")
		b.WriteString("    dialer-proxy: \"PROBE OUTER\"\n")
		b.WriteString("rules:\n  - MATCH,PROBE INNER\n")
		return b.String(), nil

	case protoMASQUE, protoMASQUEH2, protoMASQUEMASQUE:
		privDER, pubDER, err := genECKeyPair()
		if err != nil {
			return "", err
		}
		// One masque outbound. The probe only has to be parseable, so the
		// address, the keys and the SNI are throwaway values of the right shape.
		proxy := func(name, ip string, extra ...string) string {
			var b strings.Builder
			fmt.Fprintf(&b, "  - name: %q\n    type: masque\n    server: 162.159.198.2\n    port: 443\n", name)
			if proto == protoMASQUEH2 {
				b.WriteString("    network: h2\n")
			}
			fmt.Fprintf(&b, "    sni: %s\n    private-key: %s\n    public-key: %s\n",
				masqueSNI, base64.StdEncoding.EncodeToString(privDER), base64.StdEncoding.EncodeToString(pubDER))
			fmt.Fprintf(&b, "    ip: %s\n    udp: true\n    remote-dns-resolve: true\n    dns: ['1.1.1.1']\n", ip)
			// Same transport tuning mihomoPeer renders; a core without
			// with_gvisor must fail here rather than at connect time.
			b.WriteString("    congestion-controller: bbr\n    ip-stack:\n      mode: gvisor\n")
			for _, e := range extra {
				b.WriteString(e)
			}
			return b.String()
		}
		var b strings.Builder
		b.WriteString("proxies:\n")
		if proto == protoMASQUEMASQUE {
			// MASQUE in MASQUE: the outer hop carries the inner one, which is
			// exactly the field the render adds; probing it here is what proves
			// this core can take the nested pair at all.
			b.WriteString(proxy("PROBE OUTER", "172.16.0.2"))
			b.WriteString(proxy("PROBE INNER", "172.16.0.2", "    dialer-proxy: \"PROBE OUTER\"\n"))
			b.WriteString("rules:\n  - MATCH,PROBE INNER\n")
			return b.String(), nil
		}
		b.WriteString(proxy("PROBE", "172.16.0.2"))
		b.WriteString("rules:\n  - MATCH,PROBE\n")
		return b.String(), nil

	case probeOpenVPNProto:
		// Exactly the connect render: base outbound, then an openvpn outbound
		// chained onto it with dialer-proxy and the same field set.
		ca, cert, key, err := probePEMCredentials()
		if err != nil {
			return "", err
		}
		var b strings.Builder
		b.WriteString("proxies:\n  - name: \"PROBE BASE\"\n    type: wireguard\n")
		b.WriteString("    private-key: " + probeWGPrivateKey + "\n    ip: 172.16.0.2\n")
		b.WriteString(wgPeer("    "))
		b.WriteString("    mtu: 1280\n    udp: true\n")
		b.WriteString("  - name: \"PROBE OPENVPN\"\n    type: openvpn\n")
		b.WriteString("    server: 127.0.0.1\n    port: 1194\n    proto: tcp\n    dev: tun\n")
		fmt.Fprintf(&b, "    ca: %q\n    cert: %q\n    key: %q\n", ca, cert, key)
		b.WriteString("    udp: true\n    handshake-timeout: 20\n    dialer-proxy: \"PROBE BASE\"\n")
		b.WriteString("rules:\n  - MATCH,PROBE OPENVPN\n")
		return b.String(), nil
	}
	return "", fmt.Errorf("no probe for proto %q", proto)
}

// protoSupportedBy reports whether the core binary accepts this protocol's
// config shape. Unknown probe errors count as unsupported: the caller shows
// "please upgrade the core", which is the honest safe answer.
func protoSupportedBy(bin, workDir, proto string) bool {
	_, supported, _ := probeCoreCapabilities(bin, workDir)
	if os.Getenv("WARP_PROBE_DEBUG") != "" {
		y, yerr := probeYAML(proto)
		terr := error(nil)
		if yerr == nil {
			terr = core.TestConfig(bin, workDir, []byte(y))
		}
		probeDebugf("bin=%q dir=%q proto=%q supported=%v yamlErr=%v direct=%v",
			bin, workDir, proto, supported, yerr, terr)
	}
	return supported[proto]
}

// coreFileKey identifies the exact bytes on disk, not just the path. Caching
// on path alone kept a stale verdict after a core was replaced or quarantined,
// and one transient "probe never ran" could disable every protocol until the
// process restarted.
type coreFileKey struct {
	path string
	size int64
	mod  int64
}

func coreFileKeyOf(bin string) coreFileKey {
	k := coreFileKey{path: bin}
	if fi, err := os.Stat(bin); err == nil {
		k.size = fi.Size()
		k.mod = fi.ModTime().UnixNano()
	}
	return k
}

// coreCapabilities caches one probe round per binary file.
var (
	capMu     sync.Mutex
	capKey    coreFileKey
	capVer    string
	capResult map[string]bool
)

// probeDebugf writes probe diagnostics to stderr when WARP_PROBE_DEBUG is set:
// the gate's answer depends on a child process's exit code, and without the
// binary path and the verdict in the log a failure is indistinguishable from a
// wrong protocol name.
func probeDebugf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[probe] "+format+"\n", args...)
}

// resetCoreCapabilityCache drops the cached probe result so the next
// probeCoreCapabilities re-runs against a (possibly replaced) binary.
func resetCoreCapabilityCache() {
	capMu.Lock()
	capResult = nil
	capKey = coreFileKey{}
	capMu.Unlock()
}

// probeCoreCapabilities probes every protocol against bin and caches the
// outcome. It is safe to call repeatedly; only the first call runs mihomo.
func probeCoreCapabilities(bin, workDir string) (version string, supported map[string]bool, err error) {
	capMu.Lock()
	defer capMu.Unlock()
	key := coreFileKeyOf(bin)
	if capResult != nil && capKey == key {
		return capVer, capResult, nil
	}
	ver, verr := core.BinaryVersion(bin)
	supported = map[string]bool{}
	var firstErr error
	// unknown stays true when a probe never reached the core (or the core could
	// not even report its version). Such a round is handed back to the caller
	// with every protocol enabled, but is NOT cached: otherwise one antivirus
	// hiccup would freeze a wrong verdict for the whole session.
	unknown := false
	if verr != nil {
		unknown = true
		firstErr = verr
	}
	names := make([]string, 0, len(protoRuns)+1)
	for _, r := range protoRuns {
		names = append(names, r.name)
	}
	names = append(names, probeOpenVPNProto)
	for _, name := range names {
		yaml, err := probeYAML(name)
		if err != nil {
			supported[name] = false
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ok, ran, terr := core.TestConfigDetail(bin, workDir, []byte(yaml))
		// A crash is not an answer: the process died before it could parse the
		// config, so it says nothing about whether this protocol works. Retry
		// once (a scanner often injects only on first touch), then assume the
		// protocol is fine and let the connect report the real problem — a probe
		// that disables every protocol leaves the user with a client that
		// refuses to connect for a reason it cannot name.
		var crash *core.CrashError
		if errors.As(terr, &crash) {
			time.Sleep(250 * time.Millisecond)
			ok2, ran2, terr2 := core.TestConfigDetail(bin, workDir, []byte(yaml))
			var crash2 *core.CrashError
			if ran2 && !errors.As(terr2, &crash2) {
				supported[name] = ok2
				if !ok2 && firstErr == nil {
					firstErr = terr2
				}
				continue
			}
			supported[name] = true
			unknown = true
			if firstErr == nil {
				firstErr = fmt.Errorf("%v：%s", crash, crash.Hint())
			}
			continue
		}
		if !ran {
			// The probe could not run at all (temp file unwritable, binary
			// unexecutable, a scanner in the way). Assume the protocol is fine:
			// the connect itself will surface a real parse error, and blocking
			// here would leave the user with an unusable client and a message
			// about the wrong thing.
			supported[name] = true
			unknown = true
			if firstErr == nil {
				firstErr = terr
			}
			continue
		}
		supported[name] = ok
		if !ok && firstErr == nil {
			firstErr = terr
		}
	}
	if verr != nil && firstErr == nil {
		firstErr = verr
	}
	if !unknown {
		capKey, capVer, capResult = key, ver, supported
	}
	return ver, supported, firstErr
}
