package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func renderConf(o options, endpoint string, run protoRun) string {
	if outer == nil {
		return renderIface(o, endpoint, run)
	}
	return renderChainConf(o, endpoint, run)
}

// A .conf cannot express a chain - the client builds it - so a nested run writes
// both interfaces into the one file and leaves the wiring to the reader.
func renderChainConf(o options, endpoint string, run protoRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# WARP-in-WARP chain: two interfaces in one file, split it in two before\n")
	fmt.Fprintf(&b, "# using them. The inner tunnel only reaches the region it was scanned in\n")
	fmt.Fprintf(&b, "# while its packets travel inside the outer one - routing that is the\n")
	fmt.Fprintf(&b, "# client's job, not the config's.\n")
	if o.ipFamily() != famV4 && warpAddressV6 == outerAddress(true) {
		fmt.Fprintf(&b, "#\n# Both interfaces carry the same Address, which handshakes and then passes\n")
		fmt.Fprintf(&b, "# nothing: this account file predates stored IPv6 addresses. Re-register.\n")
	}
	fmt.Fprintf(&b, "\n")

	// The resolvers belong at the far end of the chain, and the outer tunnel's
	// own routes are the client's business either way.
	outerOpts := o
	outerOpts.noDNS = true
	fmt.Fprintf(&b, "# --- outer: %s ---\n", outer.label)
	_ = withOuterKeys(func() error {
		b.WriteString(renderIface(outerOpts, outer.endpoint, outer.run))
		return nil
	})

	innerOpts := o
	innerOpts.mtu = nestedMTU(o.mtu)
	fmt.Fprintf(&b, "\n# --- inner: %s (%s), inside the tunnel above ---\n", endpoint, run.name)
	b.WriteString(withChainAddr(o.ipFamily() == famV6, func() string { return renderIface(innerOpts, endpoint, run) }))
	return b.String()
}

// Two interfaces holding the same Address handshake and then pass nothing at
// all - measured on the hand-built chain. Both halves only collide on an account
// file written before the addresses were stored, where each falls back to the
// same constant; Cloudflare ignores the tunnel-local v4 address, so moving the
// inner one off it is free. There is no such freedom on v6 - it is a real routed
// per-device address - so that stays as it is and the file says so.
const chainInnerAddress = "172.16.0.3"

func withChainAddr(ipv6 bool, fn func() string) string {
	if ipv6 || warpAddress != outerAddress(false) {
		return fn()
	}
	prev := warpAddress
	warpAddress = chainInnerAddress
	defer func() { warpAddress = prev }()
	return fn()
}

func outerAddress(ipv6 bool) string {
	if ipv6 {
		if outerAcct.IPv6 != "" {
			return outerAcct.IPv6
		}
		return warpAddressV6
	}
	if outerAcct.IPv4 != "" {
		return outerAcct.IPv4
	}
	return warpAddress
}

func renderIface(o options, endpoint string, run protoRun) string {
	var b strings.Builder

	fmt.Fprintf(&b, "[Interface]\n")
	switch o.ipFamily() {
	case famV6:
		fmt.Fprintf(&b, "Address = %s/128\n", warpAddressV6)
	case famBoth:
		fmt.Fprintf(&b, "Address = %s/32, %s/128\n", warpAddress, warpAddressV6)
	default:
		fmt.Fprintf(&b, "Address = %s/32\n", warpAddress)
	}
	fmt.Fprintf(&b, "PrivateKey = %s\n", warpPrivateKey)
	if dns := confDNS(o); dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	if o.mtu > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", o.mtu)
	}
	if o.tableOff {
		fmt.Fprintf(&b, "Table = off\n")
	}
	if run.isAWG() {
		fmt.Fprintf(&b, "Jc = %d\n", awgJc)
		fmt.Fprintf(&b, "Jmin = %d\n", awgJmin)
		fmt.Fprintf(&b, "Jmax = %d\n", awgJmax)
		if awgI1 != "" {
			fmt.Fprintf(&b, "I1 = %s\n", awgI1)
		}
	}

	fmt.Fprintf(&b, "\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", warpPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowedIPsList(o.ipFamily()), ", "))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)

	return b.String()
}

// allowedIPsList is the routes a tunnel of this family claims. A family the
// interface carries no address for only blackholes traffic, so the list follows
// Address exactly.
func allowedIPsList(family string) []string {
	switch family {
	case famV6:
		return []string{"::/0"}
	case famBoth:
		return []string{"0.0.0.0/0", "::/0"}
	default:
		return []string{"0.0.0.0/0"}
	}
}

const confStdout = "-"

func writeConf(o options, endpoint string, run protoRun) error {
	conf, err := renderConfFor(o, endpoint, run)
	if err != nil {
		return err
	}
	if o.conf == confStdout {
		_, err := os.Stdout.Write(conf)
		return err
	}
	return os.WriteFile(o.conf, conf, 0600)
}

func renderConfFor(o options, endpoint string, run protoRun) ([]byte, error) {
	if isMihomo(o.confType) {
		return renderMihomoConf(o, endpoint, run)
	}
	if run.isMASQUE() {
		return renderMasqueConf(endpoint, run.isH2())
	}
	return []byte(renderConf(o, endpoint, run)), nil
}

const (
	confTypeNative     = "native"
	confTypeMihomo     = "mihomo"
	confTypeMihomoJSON = "mihomo-json"
)

var confTypes = []string{confTypeNative, confTypeMihomo, confTypeMihomoJSON}

func isMihomo(confType string) bool {
	return confType == confTypeMihomo || confType == confTypeMihomoJSON
}

const (
	// Overseas only. mihomo queries every resolver in parallel and takes the
	// fastest answer, so a domestic entry here wins by RTT alone — and it answers
	// CDN front domains with an edge that 502s (or, for a plain lookup, hands the
	// query to the local ISP resolver, which is the leak the DNS test reports).
	// Both paths must stay outside the country for a tunnelled session to be
	// private, so the domestic pair is gone rather than merely demoted.
	warpDNSv4 = "8.8.8.8, 1.1.1.1, 1.0.0.1"
	warpDNSv6 = "2606:4700:4700::1111, 2606:4700:4700::1001"
)

func confDNS(o options) string {
	if o.noDNS {
		return ""
	}
	if o.dns != "" {
		return o.dns
	}
	switch o.ipFamily() {
	case famV6:
		return warpDNSv6
	case famBoth:
		return warpDNSv4 + ", " + warpDNSv6
	default:
		return warpDNSv4
	}
}

// mihomo takes the resolvers as a list, the .conf as one line.
func confDNSList(o options) []string {
	dns := confDNS(o)
	if dns == "" {
		return nil
	}
	list := strings.Split(dns, ",")
	for i := range list {
		list[i] = strings.TrimSpace(list[i])
	}
	return list
}

// A mihomo proxy is built as data rather than text, because the same fields go
// out as YAML and as JSON; an ordered list keeps the YAML fields in the order
// they are written here, which a map would not.
type kv struct {
	k string
	v any // string, quoted, int, bool, []string, []kv, [][]kv
}

// Proxy names are the only scalars YAML has to quote.
type quoted string

// mihomoAddr carries the tunnel-side address(es). A dual-stack outbound names
// both so mihomo can route each family through the same device.
func mihomoAddr(v4, v6, family string) []kv {
	switch family {
	case famV6:
		return []kv{{"ipv6", v6}}
	case famBoth:
		return []kv{{"ip", v4}, {"ipv6", v6}}
	default:
		return []kv{{"ip", v4}}
	}
}

// mihomo lists proxies by name, so several warpscout configs pasted into one
// file have to differ by protocol. The endpoint address stays out of it: the run
// already picked the single best one, and the name would go stale on the next scan.
func mihomoName(run protoRun) string {
	switch run.kind {
	case kindAWG:
		return "AWG WARP"
	case kindMASQUE:
		return "MASQUE H3 WARP"
	case kindMASQUEH2:
		return "MASQUE H2 WARP"
	}
	return "WG WARP"
}

// mihomo keys proxies by name, so the two halves of a chain have to differ - and
// naming them is the only place the config says it is one ("AWG WARP OUTER" plus
// "WG WARP-in-WARP", against a plain run's bare "WG WARP").
const (
	mihomoOuterSuffix = " OUTER"
	mihomoChainSuffix = "-in-WARP"
)

func renderMihomoConf(o options, endpoint string, run protoRun) ([]byte, error) {
	proxies, err := mihomoProxies(o, endpoint, run)
	if err != nil {
		return nil, err
	}
	if o.confType == confTypeMihomoJSON {
		return mihomoJSON(proxies)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "proxies:\n")
	for _, p := range proxies {
		writeYAML(&b, p, "  ", "- ")
	}
	return []byte(b.String()), nil
}

// renderProxiesYAML renders just the proxies list body (no "proxies:" header),
// so a caller assembling a larger config can splice several outbounds together.
func renderProxiesYAML(proxies [][]kv) string {
	var b strings.Builder
	for _, p := range proxies {
		writeYAML(&b, p, "  ", "- ")
	}
	return b.String()
}

// mihomoSocksProxy builds the Psiphon socks5 outbound node. Psiphon listens on
// 127.0.0.1 at the fixed port xehn picked before starting it (the port is
// fixed, not dynamic, so this config can be rendered before Psiphon is up).
func mihomoSocksProxy(port int) []kv {
	return []kv{
		{k: "name", v: quoted(mihomoPsiphonName)},
		{k: "type", v: "socks5"},
		{k: "server", v: "127.0.0.1"},
		{k: "port", v: port},
	}
}

// mihomoOpenVPNProxy renders one VPN Gate relay as a native openvpn outbound.
// The PEM blocks are `quoted`, which both YAML and JSON turn into a single
// escaped line — a raw multi-line string would fork the YAML document.
// capMTU is the nested budget (outer tunnel MTU minus encapsulation). mihomo
// defaults the openvpn tunnel MTU to 1500, and a VPN Gate profile carries no
// MTU line, so a UDP relay would otherwise write 1500-byte datagrams into a
// 1280-ish base tunnel: every full-size packet fragments, and one lost fragment
// costs the whole packet. TCP relays carry the same packets as a byte stream
// (the base stack segments them), so they keep the default.
func mihomoOpenVPNProxy(p ovpnProfile, capMTU int) []kv {
	p = normalizeOVPNProfile(p)
	if p.Proto == "udp" && capMTU > 0 && (p.MTU <= 0 || p.MTU > capMTU) {
		p.MTU = capMTU
	}
	out := []kv{
		{k: "name", v: quoted(mihomoOpenVPNName)},
		{k: "type", v: "openvpn"},
		{k: "server", v: p.Remote},
		{k: "port", v: p.Port},
		{k: "proto", v: p.Proto},
		{k: "dev", v: p.Dev},
	}
	if p.Cipher != "" {
		out = append(out, kv{k: "cipher", v: p.Cipher})
	}
	if len(p.DataCiphers) > 0 {
		out = append(out, kv{k: "data-ciphers", v: p.DataCiphers})
	}
	if p.Auth != "" {
		out = append(out, kv{k: "auth", v: p.Auth})
	}
	if p.CA != "" {
		out = append(out, kv{k: "ca", v: quoted(p.CA)})
	}
	if p.Cert != "" {
		out = append(out, kv{k: "cert", v: quoted(p.Cert)})
	}
	if p.Key != "" {
		out = append(out, kv{k: "key", v: quoted(p.Key)})
	}
	if p.TLSAuth != "" {
		out = append(out, kv{k: "tls-auth", v: quoted(p.TLSAuth)})
	}
	if p.TLSCrypt != "" {
		out = append(out, kv{k: "tls-crypt", v: quoted(p.TLSCrypt)})
	}
	if p.TLSCryptV2 != "" {
		out = append(out, kv{k: "tls-crypt-v2", v: quoted(p.TLSCryptV2)})
	}
	if p.KeyDirection != "" {
		out = append(out, kv{k: "key-direction", v: p.KeyDirection})
	}
	if p.CompLZO != "" {
		out = append(out, kv{k: "comp-lzo", v: p.CompLZO})
	}
	if p.MTU > 0 {
		out = append(out, kv{k: "mtu", v: p.MTU})
	}
	if p.Ping > 0 {
		out = append(out, kv{k: "ping", v: p.Ping})
	}
	if p.PingRestart > 0 {
		out = append(out, kv{k: "ping-restart", v: p.PingRestart})
	}
	// udp: true advertises the outbound's UDP relay capability to mihomo; it is
	// not the transport (proto is). handshake-timeout is the outbound's own
	// ceiling, detached from the inbound's 5s dial timeout.
	return append(out,
		kv{k: "udp", v: true},
		kv{k: "handshake-timeout", v: openvpnHandshakeTimeout},
	)
}

func normalizeOVPNProfile(p ovpnProfile) ovpnProfile {
	if p.Dev == "" {
		p.Dev = "tun"
	}
	if p.Proto != "udp" {
		p.Proto = "tcp"
	}
	if p.CompLZO == "no" {
		p.CompLZO = ""
	}
	return p
}

const (
	// mihomoPsiphonName is the socks5 outbound (and, for clients, the exit).
	mihomoPsiphonName = "Psiphon"
	// mihomoBaseGroup is the selector that carries the base protocol's outbound.
	// It is the underlay: Psiphon's own server dials go through it.
	mihomoBaseGroup = "WARP"
	// mihomoExitGroup is the selector clients land on (Psiphon's socks5).
	mihomoExitGroup = "PSIPHON"
	// OpenVPN exit (V2): one native openvpn outbound chained behind the base
	// protocol. The group and proxy names must differ — mihomo rejects a
	// selector that lists itself ("loop is detected in ProxyGroup").
	mihomoOpenVPNName  = "OpenVPN Exit"
	mihomoOpenVPNGroup = "OPENVPN"
	// openvpnHandshakeTimeout is the outbound's own ceiling. mihomo detaches it
	// from the inbound dial timeout, so a slow public relay still completes the
	// handshake while the first client request has already given up; the
	// connect flow warms the tunnel with retries inside this window.
	//
	// 30s, not 20s: the relays that actually answer are carried through a tunnel
	// and often need 20-28s to link (measured: 2s direct, 5-8s typical, 20s+ on a
	// jittery volunteer line). At 20s those were killed mid-handshake and
	// reported as dead. cfnew (same VPN Gate source, same mihomo outbound) uses
	// 30. openvpnWarmupWindow follows this value automatically, so the connect
	// path waits exactly as long as the outbound is willing to try.
	openvpnHandshakeTimeout = 30
	// psiphonUnderlayPortGap is the offset of the dedicated SOCKS inbound that
	// exists only for Psiphon's own dials. Routing that inbound to the base
	// protocol — instead of relying on process detection — is what makes the
	// loop guard deterministic (Psiphon never reaches itself).
	psiphonUnderlayPortGap = 1
)

// underlaySocksPort is the localhost SOCKS port reserved for Psiphon's upstream.
func underlaySocksPort(mixedPort int) int { return mixedPort + psiphonUnderlayPortGap }

func mihomoProxies(o options, endpoint string, run protoRun) ([][]kv, error) {
	if o.psiphonMode {
		// Two-axis V1 exit: Psiphon rides ON the base protocol. The base
		// outbound carries Psiphon's own server dials; the localhost socks5 node
		// is the final exit the client traffic lands on. The endpoint-less shape
		// is the legacy "Psiphon direct" (wrong plan 2) — production always pins
		// an endpoint, so this branch only feeds the render helper.
		if endpoint == "" {
			return [][]kv{mihomoSocksProxy(o.psiphonSocksPort)}, nil
		}
		base, err := mihomoProxy(o, mihomoName(run), endpoint, run, o.mtu, confDNSList(o))
		if err != nil {
			return nil, err
		}
		return [][]kv{base, mihomoSocksProxy(o.psiphonSocksPort)}, nil
	}
	if outer == nil {
		p, err := mihomoProxy(o, mihomoName(run), endpoint, run, o.mtu, confDNSList(o))
		if err != nil {
			return nil, err
		}
		return [][]kv{p}, nil
	}

	// mihomo expresses the chain itself: the outer tunnel is a proxy of its own
	// and the inner one dials through it. The outer carries no DNS - it is only
	// the carrier, and the resolvers belong at the end of the chain.
	outerName := mihomoName(outer.run) + mihomoOuterSuffix
	renderOuter := func() ([]kv, error) {
		return mihomoProxy(o, outerName, outer.endpoint, outer.run, o.mtu, nil)
	}
	var op []kv
	var err error
	if outer.run.isMASQUE() {
		// MASQUE in MASQUE: both hops authenticate with the same enrolled
		// device, so the outer must NOT be rendered under the WireGuard
		// account keys (withOuterKeys would hand mihomo an unrelated key pair
		// and the outer tunnel would fail its CONNECT-IP request).
		op, err = renderOuter()
	} else {
		err = withOuterKeys(func() error {
			var rerr error
			op, rerr = renderOuter()
			return rerr
		})
	}
	if err != nil {
		return nil, err
	}

	// The inner half keeps its account IPv4 (172.16.0.2). Unlike the .conf
	// render — where two kernel interfaces on one host genuinely collide and
	// withChainAddr moves the inner one off — mihomo gives every wireguard
	// adapter its own gVisor stack, so the addresses never meet. Offsetting the
	// inner here would only make Cloudflare drop the inner tunnel's packets: it
	// routes the 172.16.0.2 every WARP device is assigned, nothing else. The
	// in-process scan nests two 172.16.0.2 netstacks the same way and works.
	innerSuffix := mihomoChainSuffix
	if outer.run.isMASQUE() {
		// "MASQUE H3 WARP-in-MASQUE" tells the reader which hop type is nested;
		// "-in-WARP" would describe a wwarp pair even when both hops are masque.
		innerSuffix = "-in-MASQUE"
	}
	inner, err := mihomoProxy(o, mihomoName(run)+innerSuffix, endpoint, run, nestedMTU(o.mtu), confDNSList(o))
	if err != nil {
		return nil, err
	}
	return [][]kv{op, append(inner, kv{"dialer-proxy", quoted(outerName)})}, nil
}

// The list-of-maps case wants "- " on the first key of each item and blanks
// under it, which is why the lead is separate from the indent.
func writeYAML(b *strings.Builder, node []kv, indent, lead string) {
	pad := indent + strings.Repeat(" ", len(lead))
	for i, e := range node {
		prefix := pad
		if i == 0 {
			prefix = indent + lead
		}
		switch v := e.v.(type) {
		case []kv:
			fmt.Fprintf(b, "%s%s:\n", prefix, e.k)
			writeYAML(b, v, pad+"  ", "")
		case [][]kv:
			fmt.Fprintf(b, "%s%s:\n", prefix, e.k)
			for _, item := range v {
				writeYAML(b, item, pad+"  ", "- ")
			}
		default:
			fmt.Fprintf(b, "%s%s: %s\n", prefix, e.k, yamlScalar(e.v))
		}
	}
}

func yamlScalar(v any) string {
	switch t := v.(type) {
	case quoted:
		return fmt.Sprintf("%q", string(t))
	case []string:
		return "['" + strings.Join(t, "', '") + "']"
	}
	return fmt.Sprint(v)
}

// Go maps have no order, so the JSON is written from the same []kv the YAML is
// rather than through map[string]any: the fields come out in the order
// mihomoProxy builds them, the same one -conf-type mihomo prints.
func mihomoJSON(proxies [][]kv) ([]byte, error) {
	var b strings.Builder
	b.WriteString("[\n  ")
	for i, p := range proxies {
		if i > 0 {
			b.WriteString(",\n  ")
		}
		if err := writeJSONObject(&b, p, "  "); err != nil {
			return nil, err
		}
	}
	b.WriteString("\n]\n")
	return []byte(b.String()), nil
}

func writeJSONObject(b *strings.Builder, node []kv, indent string) error {
	b.WriteString("{\n")
	for i, e := range node {
		if i > 0 {
			b.WriteString(",\n")
		}
		fmt.Fprintf(b, "%s  %q: ", indent, e.k)
		if err := writeJSONValue(b, e.v, indent+"  "); err != nil {
			return err
		}
	}
	fmt.Fprintf(b, "\n%s}", indent)
	return nil
}

func writeJSONValue(b *strings.Builder, v any, indent string) error {
	switch t := v.(type) {
	case []kv:
		return writeJSONObject(b, t, indent)
	case [][]kv:
		b.WriteString("[\n")
		for i, item := range t {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(indent + "  ")
			if err := writeJSONObject(b, item, indent+"  "); err != nil {
				return err
			}
		}
		fmt.Fprintf(b, "\n%s]", indent)
		return nil
	case []string:
		// Two resolvers or one allowed-ips entry: a line each reads worse than
		// the list inline.
		parts := make([]string, len(t))
		for i, item := range t {
			parts[i] = fmt.Sprintf("%q", item)
		}
		fmt.Fprintf(b, "[%s]", strings.Join(parts, ", "))
		return nil
	case quoted:
		v = string(t)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The awg i1 value is angle brackets all the way down, and the default
	// encoder would turn every one of them into \u003c.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	b.WriteString(strings.TrimSuffix(buf.String(), "\n"))
	return nil
}

// The inner WireGuard packet rides as UDP inside the outer tunnel, so it cannot
// be left at the client's default: at full MTU the handshake still completes and
// data dies silently (the same nestedOverhead tunnel.go subtracts).
func nestedMTU(mtu int) int {
	if mtu == 0 {
		mtu = tunnelMTU
	}
	return mtu - nestedOverhead
}

func mihomoProxy(o options, name, endpoint string, run protoRun, mtu int, dns []string) ([]kv, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", endpoint, err)
	}

	p, err := mihomoPeer(run, o.ipFamily(), host, port, effectiveStack(o), effectiveCC(o))
	if err != nil {
		return nil, err
	}
	p = append([]kv{{"name", quoted(name)}}, p...)
	// The MASQUE outbound's inner gVisor stack is 1280 bytes; mihomo uses
	// that as its fallback too, but spelling it out keeps the rendered config
	// identical in shape to the scan tunnel and capability probe, and keeps
	// it stable if a future core changes its default.
	effectiveMTU := mtu
	if effectiveMTU <= 0 && run.isMASQUE() {
		effectiveMTU = tunnelMTU
	}
	if effectiveMTU > 0 {
		p = append(p, kv{"mtu", effectiveMTU})
	}
	p = append(p, kv{"udp", true})
	if len(dns) > 0 {
		p = append(p, kv{"remote-dns-resolve", true}, kv{"dns", dns})
	}
	return p, nil
}

func mihomoPeer(run protoRun, family string, host string, port int, stack, cc string) ([]kv, error) {
	if run.isMASQUE() {
		if masqueAcct == nil {
			return nil, fmt.Errorf("no MASQUE device in the account file")
		}
		pub, err := pemBody(masqueAcct.PeerPublicKey)
		if err != nil {
			return nil, err
		}
		p := []kv{{"type", "masque"}, {"server", host}, {"port", port}}
		// mihomo's default is HTTP/3; the TCP transport is the same type with a
		// network selector rather than a type of its own.
		if run.isH2() {
			p = append(p, kv{"network", "h2"})
		}
		p = append(p,
			kv{"sni", masqueSNI},
			kv{"private-key", masqueAcct.PrivateKey},
			kv{"public-key", pub},
		)
		p = append(p, mihomoAddr(masqueAcct.IPv4, masqueAcct.IPv6, family)...)
		// Fast-fail on the data plane: mihomo's masque outbound takes an
		// integer handshake ceiling, and its default leaves a dark edge
		// hanging for tens of seconds. 5s is inside the 3-5s band that
		// Gool.txt's P0 asks for, and it is verified against this core:
		// `handshake-timeout` is the connect-latency knob it actually parses
		// (idle-timeout / keepalive are accepted but ignored).
		//
		// Throughput tuning for an exit carried inside this tunnel: QUIC
		// defaults to CUBIC, and one lost datagram then costs both the outer
		// window and the inner TCP retransmit, which is what pinned a
		// VPN Gate exit to a few Mbps here. BBR rides out loss instead.
		// The inner packets default to mihomo's minimal mips stack; the
		// bundled core ships with_gvisor, whose TCP stack is the more
		// complete of the two. Both are optionized (S1-5): the shipped
		// defaults are bbr/gvisor, and the connect's capability gate falls
		// back to them when the running core rejects an override.
		return append(p,
			kv{"congestion-controller", cc},
			kv{"ip-stack", []kv{{"mode", stack}}},
			kv{"handshake-timeout", 5},
		), nil
	}

	// The single-peer fields mihomo still accepts at the top level are its legacy
	// syntax; a peers list is the current one.
	peer := []kv{
		{"server", host},
		{"port", port},
		{"public-key", warpPublicKey},
		{"allowed-ips", allowedIPsList(family)},
		{"persistent-keepalive", keepalive},
	}
	p := []kv{
		{"type", "wireguard"},
		{"private-key", warpPrivateKey},
	}
	p = append(p, mihomoAddr(warpAddress, warpAddressV6, family)...)
	p = append(p, kv{"peers", [][]kv{peer}})
	if !run.isAWG() {
		return p, nil
	}

	awg := []kv{{"jc", awgJc}, {"jmin", awgJmin}, {"jmax", awgJmax}, {"s1", 0}, {"s2", 0}}
	for i, h := range []int{1, 2, 3, 4} {
		awg = append(awg, kv{fmt.Sprintf("h%d", i+1), h})
	}
	if awgI1 != "" {
		awg = append(awg, kv{"i1", awgI1})
	}
	return append(p, kv{"amnezia-wg-option", awg}), nil
}

func pemBody(key string) (string, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return "", fmt.Errorf("peer public key is not PEM")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}
