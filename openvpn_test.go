package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xhwarp/warp-client/internal/core"
)

// testOVPNProfile is a minimal VPN Gate-shaped profile: inline credentials and
// tls-auth, tcp transport. The PEM bodies are placeholders — parsing keeps the
// block verbatim, and only a real core parses the certificate itself.
const testOVPNProfile = `client
dev tun
proto tcp
remote 203.0.113.7 443
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
auth SHA1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIBfakeCA
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBfakeCert
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIBfakeKey
-----END PRIVATE KEY-----
</key>
key-direction 1
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
deadbeef
-----END OpenVPN Static key V1-----
</tls-auth>
`

func TestParseOVPNProfile(t *testing.T) {
	p, err := parseOVPNProfile(testOVPNProfile)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Remote != "203.0.113.7" || p.Port != 443 {
		t.Fatalf("remote = %s:%d", p.Remote, p.Port)
	}
	if p.Proto != "tcp" || p.Dev != "tun" {
		t.Fatalf("proto/dev = %s/%s", p.Proto, p.Dev)
	}
	if !strings.Contains(p.CA, "fakeCA") || !strings.Contains(p.Cert, "fakeCert") ||
		!strings.Contains(p.Key, "fakeKey") || !strings.Contains(p.TLSAuth, "deadbeef") {
		t.Fatalf("inline blocks missing: %+v", p)
	}
	if p.KeyDirection != "1" {
		t.Fatalf("key-direction = %q", p.KeyDirection)
	}
}

func TestParseVPNGateCSV(t *testing.T) {
	line := strings.Join([]string{
		"vpn123456.opengw.net", "203.0.113.7", "1234567", "1234", "5000000",
		"Japan", "JP", "1", "1", "1", "1", "1", "1", "",
		base64.StdEncoding.EncodeToString([]byte(testOVPNProfile)),
	}, ",")
	body := "*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" + line + "\n"
	nodes := parseVPNGateCSV([]byte(body))
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	n := nodes[0]
	if n.IP != "203.0.113.7" || n.Port != 443 || n.Proto != "tcp" {
		t.Fatalf("node = %+v", n)
	}
	if n.CountryShort != "JP" || n.CountryLong != "Japan" || n.Score != 1234567 {
		t.Fatalf("node metadata = %+v", n)
	}
	if _, err := parseOVPNProfile(n.Profile); err != nil {
		t.Fatalf("stored profile: %v", err)
	}
}

// TestOpenVPNMTUNestedCap pins the MTU policy: mihomo defaults the openvpn
// outbound to 1500 and VPN Gate profiles carry no MTU, so a UDP relay inside a
// ~1280-byte base tunnel must be capped; a TCP relay rides a byte stream and
// keeps the default; a profile that asks for less keeps its own value.
func TestOpenVPNMTUNestedCap(t *testing.T) {
	udp := strings.Replace(testOVPNProfile, "proto tcp", "proto udp", 1)
	p, err := parseOVPNProfile(udp)
	if err != nil {
		t.Fatal(err)
	}
	out := renderProxiesYAML([][]kv{mihomoOpenVPNProxy(p, 1220)})
	if !strings.Contains(out, "mtu: 1220") {
		t.Fatalf("UDP relay must be capped to the nested budget:\n%s", out)
	}

	tcp, err := parseOVPNProfile(testOVPNProfile)
	if err != nil {
		t.Fatal(err)
	}
	out = renderProxiesYAML([][]kv{mihomoOpenVPNProxy(tcp, 1220)})
	if strings.Contains(out, "mtu:") {
		t.Fatalf("TCP relay must keep mihomo's default MTU:\n%s", out)
	}

	small := strings.Replace(udp, "dev tun", "dev tun\nmtu 1200", 1)
	sp, err := parseOVPNProfile(small)
	if err != nil {
		t.Fatal(err)
	}
	out = renderProxiesYAML([][]kv{mihomoOpenVPNProxy(sp, 1220)})
	if !strings.Contains(out, "mtu: 1200") {
		t.Fatalf("a smaller profile MTU must win:\n%s", out)
	}
}

// TestVPNGateSpeedRanking pins the speed memory's order: measured-fast first,
// untested next, measured-slow last — so a relay that once carried traffic but
// now crawls cannot stay in front of candidates nobody has measured.
func TestVPNGateSpeedRanking(t *testing.T) {
	nodes := []vpnGateNode{
		{CountryShort: "JP", IP: "198.51.100.1", Port: 443, Proto: "tcp", Class: "residential", MeasuredBps: 50 * 1024},
		{CountryShort: "JP", IP: "198.51.100.2", Port: 443, Proto: "tcp", Class: "residential"},
		{CountryShort: "JP", IP: "198.51.100.3", Port: 443, Proto: "tcp", Class: "residential", MeasuredBps: 1024 * 1024},
	}
	sortVPNGateNodesByLatency(nodes)
	want := []string{"198.51.100.3", "198.51.100.2", "198.51.100.1"}
	for i, ip := range want {
		if nodes[i].IP != ip {
			t.Fatalf("order[%d] = %s, want %s (full: %+v)", i, nodes[i].IP, ip, nodes)
		}
	}
}

func TestVPNGateCountries(t *testing.T) {
	nodes := []vpnGateNode{
		{CountryShort: "JP", CountryLong: "Japan"},
		{CountryShort: "jp", CountryLong: "Japan"},
		{CountryShort: "US", CountryLong: "United States"},
	}
	cs := vpnGateCountries(nodes)
	if len(cs) != 2 || cs[0].CC != "JP" || cs[0].Count != 2 {
		t.Fatalf("countries = %+v", cs)
	}
}

func TestVPNGateCountryLatencyOrder(t *testing.T) {
	nodes := []vpnGateNode{
		{CountryShort: "US", CountryLong: "United States"},
		{CountryShort: "JP", CountryLong: "Japan", LatencyMS: 120},
		{CountryShort: "JP", CountryLong: "Japan", LatencyMS: 80},
	}
	cs := vpnGateCountries(nodes)
	if len(cs) != 2 || cs[0].CC != "JP" || cs[1].CC != "US" {
		t.Fatalf("measured country must sort first: %+v", cs)
	}
	if cs[0].MinLatency != 80 || cs[0].Responded != 2 {
		t.Fatalf("country stats = %+v", cs[0])
	}
}

func TestVPNGateCountrySelfReportedOrder(t *testing.T) {
	nodes := []vpnGateNode{
		{CountryShort: "US", CountryLong: "United States", PingMS: 90},
		{CountryShort: "JP", CountryLong: "Japan", PingMS: 40},
	}
	cs := vpnGateCountries(nodes)
	if len(cs) != 2 || cs[0].CC != "JP" || cs[0].MinLatency != 40 || cs[0].Responded != 0 {
		t.Fatalf("self-reported latency must order countries: %+v", cs)
	}
}

func TestParseVPNGateCSVQuotedComma(t *testing.T) {
	line := strings.Join([]string{
		"public-vpn-1.opengw.net", "203.0.113.9", "999", "55", "1000000",
		`"Korea, Republic of"`, "KR", "3", "1", "1", "1", "1", `"Operator, Inc."`, "",
		base64.StdEncoding.EncodeToString([]byte(testOVPNProfile)),
	}, ",")
	body := "*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" + line + "\n"
	nodes := parseVPNGateCSV([]byte(body))
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	n := nodes[0]
	if n.CountryLong != "Korea, Republic of" || n.Operator != "Operator, Inc." {
		t.Fatalf("quoted fields = %+v", n)
	}
	if n.CountryShort != "KR" || n.PingMS != 55 || n.Sessions != 3 || n.Class != "datacenter" {
		t.Fatalf("metadata = %+v", n)
	}
	// The profile's remote wins over the CSV IP column, matching the Android
	// parser; the id therefore uses the profile address.
	if n.id() != "kr-203.0.113.7-443" {
		t.Fatalf("id = %q", n.id())
	}
}

func TestVPNGateCandidatesPinFirst(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	nodes := []vpnGateNode{
		{IP: "203.0.113.1", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Score: 10},
		{IP: "203.0.113.2", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Score: 20},
		{IP: "203.0.113.3", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Score: 30},
	}
	// A cancelled probe context keeps the test off the network: the probe
	// returns instantly and the pin order is all that remains to check.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pin := nodes[2].id()
	got := vpnGateCandidates(ctx, nodes, "JP", pin, 3)
	if len(got) != 3 || got[0].id() != pin {
		t.Fatalf("pin not first: %+v", got)
	}
}

// TestVPNGateCandidatesClassFailover pins the phone client's ordering: a
// residential pin falls through to other residential relays, then the same
// country's other classes, then abroad; a datacenter pin does the mirror image.
func TestVPNGateCandidatesClassFailover(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	nodes := []vpnGateNode{
		{IP: "203.0.113.10", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Class: "datacenter", LatencyMS: 10},
		{IP: "203.0.113.11", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Class: "residential", LatencyMS: 70},
		{IP: "203.0.113.12", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Class: "residential", LatencyMS: 50},
		{IP: "203.0.113.13", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Class: "unknown", LatencyMS: 20},
		{IP: "203.0.113.14", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "US", Class: "residential", LatencyMS: 40},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ids := func(ns []vpnGateNode) []string {
		out := make([]string, len(ns))
		for i := range ns {
			out[i] = ns[i].IP
		}
		return out
	}
	check := func(label string, got []vpnGateNode, want ...string) {
		have := ids(got)
		if len(have) != len(want) {
			t.Fatalf("%s: got %v, want %v", label, have, want)
		}
		for i := range want {
			if have[i] != want[i] {
				t.Fatalf("%s: got %v, want %v", label, have, want)
			}
		}
	}

	// Residential pin: other JP residential (legacy "unknown" included, latency
	// order), then JP datacenter, then abroad same class.
	check("residential pin",
		vpnGateCandidates(ctx, nodes, "JP", nodes[1].id(), 24),
		"203.0.113.11", "203.0.113.13", "203.0.113.12", "203.0.113.10", "203.0.113.14")
	// Datacenter pin: no other JP datacenter, so the JP residential block, then
	// abroad (same class first, none) and the rest.
	check("datacenter pin",
		vpnGateCandidates(ctx, nodes, "JP", nodes[0].id(), 24),
		"203.0.113.10", "203.0.113.13", "203.0.113.12", "203.0.113.11", "203.0.113.14")
	// Country only: the country's residential block before its datacenter, then abroad.
	check("country",
		vpnGateCandidates(ctx, nodes, "JP", "", 24),
		"203.0.113.13", "203.0.113.12", "203.0.113.11", "203.0.113.10", "203.0.113.14")
	// Auto: one global class order, latency inside each block.
	check("auto",
		vpnGateCandidates(ctx, nodes, "", "", 24),
		"203.0.113.13", "203.0.113.14", "203.0.113.12", "203.0.113.11", "203.0.113.10")
}

// TestVPNGateFailureMemory checks that a relay that just failed is skipped, and
// that clearing the failure makes it eligible again.
func TestVPNGateFailureMemory(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	nodes := []vpnGateNode{
		{IP: "203.0.113.21", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Class: "residential", LatencyMS: 10},
		{IP: "203.0.113.22", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Class: "residential", LatencyMS: 20},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	markVPNGateFailed(nodes[0].id())
	got := vpnGateCandidates(ctx, nodes, "JP", "", 24)
	if len(got) != 1 || got[0].id() != nodes[1].id() {
		t.Fatalf("failed relay not skipped: %+v", got)
	}
	clearVPNGateFailure(nodes[0].id())
	got = vpnGateCandidates(ctx, nodes, "JP", "", 24)
	if len(got) != 2 || got[0].id() != nodes[0].id() {
		t.Fatalf("cleared relay not restored: %+v", got)
	}
}

// TestVPNGatePinBypassesFailureMemory pins the rule that an explicit pin is
// always tried first even right after a failure: the memory serves auto
// selection and must never silently replace the user's choice (the "I pinned
// X but it connected through Y" report).
func TestVPNGatePinBypassesFailureMemory(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	nodes := []vpnGateNode{
		{IP: "203.0.113.41", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Class: "residential", LatencyMS: 10},
		{IP: "203.0.113.42", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP", Class: "residential", LatencyMS: 20},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	markVPNGateFailed(nodes[0].id())
	got := vpnGateCandidates(ctx, nodes, "JP", nodes[0].id(), 24)
	if len(got) != 2 || got[0].id() != nodes[0].id() {
		t.Fatalf("pinned relay must stay first despite the failure memory: %+v", got)
	}
	// Auto selection still skips the failed relay.
	got = vpnGateCandidates(ctx, nodes, "JP", "", 24)
	if len(got) != 1 || got[0].id() != nodes[1].id() {
		t.Fatalf("auto mode must still skip the failed relay: %+v", got)
	}
}

// TestAuthRejectError pins the classification the connect loop relies on: an
// AUTH_FAILED rejection is its own type (so the loop drops the relay on every
// base at once) and is not a local core error (which would abort the run).
func TestAuthRejectError(t *testing.T) {
	err := fmt.Errorf("wrap: %w", &authRejectError{reason: "AUTH_FAILED"})
	var auth *authRejectError
	if !errors.As(err, &auth) || auth.reason != "AUTH_FAILED" {
		t.Fatalf("errors.As lost the auth rejection: %v", err)
	}
	if localCoreError(err) {
		t.Fatal("auth rejection must not be treated as a local core error")
	}
	if !strings.Contains(err.Error(), "AUTH_FAILED") {
		t.Fatalf("message lost the reason: %v", err)
	}
}

func TestPreferLastGoodVPNGate(t *testing.T) {
	t.Setenv("WARP_CLIENT_HOME", t.TempDir())
	nodes := []vpnGateNode{
		{IP: "203.0.113.31", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "JP"},
		{IP: "203.0.113.32", Port: 443, Proto: "tcp", Profile: "p", CountryShort: "US"},
	}
	rememberLastGoodVPNGate(nodes[1])
	clone := func() []vpnGateNode { return append([]vpnGateNode(nil), nodes...) }

	if got := preferLastGoodVPNGate(clone(), "", ""); got[0].id() != nodes[1].id() {
		t.Fatalf("auto mode must reuse last good relay: %+v", got)
	}
	if got := preferLastGoodVPNGate(clone(), "pin", ""); got[0].id() != nodes[0].id() {
		t.Fatalf("manual pin must win: %+v", got)
	}
	if got := preferLastGoodVPNGate(clone(), "", "JP"); got[0].id() != nodes[0].id() {
		t.Fatalf("region with candidates must keep its order: %+v", got)
	}
	if got := preferLastGoodVPNGate(clone(), "", "TH"); got[0].id() != nodes[1].id() {
		t.Fatalf("region with no candidates may use the last good relay: %+v", got)
	}
}

func TestVPNAuthFailure(t *testing.T) {
	line := `{"type":"error","payload":"[TCP] dial OPENVPN error: make OpenVPN handshake: openvpn authentication failed: AUTH_FAILED"}`
	if got := vpnAuthFailure(line); got != "AUTH_FAILED" {
		t.Fatalf("AUTH_FAILED line not recognised: %q", got)
	}
	if got := vpnAuthFailure("dial OPENVPN error: context deadline exceeded"); got != "" {
		t.Fatalf("handshake timeout must stay retryable, got %q", got)
	}
}

func TestWatchOpenVPNLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs" {
			http.NotFound(w, r)
			return
		}
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, `{"type":"info","payload":"start"}`+"\n")
		fl.Flush()
		_, _ = io.WriteString(w, `{"type":"error","payload":"openvpn authentication failed: AUTH_FAILED"}`+"\n")
		fl.Flush()
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	fatal, stop := watchOpenVPNLogs(ctx, port)
	defer stop()
	select {
	case reason := <-fatal:
		if reason != "AUTH_FAILED" {
			t.Fatalf("reason = %q", reason)
		}
	case <-ctx.Done():
		t.Fatal("auth failure was not surfaced from the log stream")
	}
}

func TestEnrichClassify(t *testing.T) {
	cases := []struct {
		name string
		r    ipAPIResult
		want string
	}{
		{"brand", ipAPIResult{Status: "success", ISP: "Korea Telecom", AS: "AS4766"}, "residential"},
		{"mobile", ipAPIResult{Status: "success", ISP: "Some Wireless", Mobile: true}, "residential"},
		{"hosting", ipAPIResult{Status: "success", ISP: "Some Hosting LLC", Hosting: true}, "datacenter"},
		{"hard asn", ipAPIResult{Status: "success", ISP: "Quiet Network", AS: "AS9009"}, "datacenter"},
		{"conflict", ipAPIResult{Status: "success", ISP: "Comcast Cable", Hosting: true}, "datacenter"},
		{"no signal", ipAPIResult{Status: "success", ISP: "Some Network"}, "residential"},
	}
	for _, c := range cases {
		n := vpnGateNode{Class: "public-vpn-prior"}
		enrichClassify(&n, c.r)
		if n.Class != c.want {
			t.Fatalf("%s: class = %q, want %q", c.name, n.Class, c.want)
		}
	}
	n := vpnGateNode{Class: "datacenter"}
	enrichClassify(&n, ipAPIResult{Status: "fail"})
	if n.Class != "datacenter" {
		t.Fatalf("failed lookup must keep the offline prior, got %q", n.Class)
	}
	// ip-api reports the author's public relays without a hosting flag; the
	// host prior must survive that inconclusive answer instead of turning into
	// the old "unknown" label.
	n = vpnGateNode{Class: "unknown", HostName: "public-vpn-184"}
	enrichClassify(&n, ipAPIResult{Status: "success", ISP: "Daiyuu Nobori", Org: "Japan. Academic Use Only."})
	if n.Class != "datacenter" {
		t.Fatalf("public-vpn prior was overwritten: class = %q", n.Class)
	}
	// Whatever a cache written by an older version says, the picker only ever
	// shows two labels.
	for _, c := range []struct {
		n    vpnGateNode
		want string
	}{
		{vpnGateNode{HostName: "public-vpn-1", Class: "unknown"}, "datacenter"},
		{vpnGateNode{HostName: "vpn123", Class: "unknown"}, "residential"},
		{vpnGateNode{HostName: "vpn123", Class: "datacenter"}, "datacenter"},
	} {
		if got := c.n.classKey(); got != c.want {
			t.Fatalf("classKey(%+v) = %q, want %q", c.n, got, c.want)
		}
	}
	if got := parseASN("AS13335 "); got != 13335 {
		t.Fatalf("parseASN = %d", got)
	}
}

func TestOpenVPNSettingsNormalize(t *testing.T) {
	s := defaultSettings()
	s.OpenVPN = true
	s.Psiphon = true
	s.IPFamily = famBoth
	s.OpenVPNRegion = " jp "
	s.normalize()
	if s.Psiphon {
		t.Fatalf("Psiphon must be off when OpenVPN is on")
	}
	if s.IPFamily != famV4 {
		t.Fatalf("family = %s, want v4", s.IPFamily)
	}
	if s.OpenVPNRegion != "JP" {
		t.Fatalf("region = %q", s.OpenVPNRegion)
	}
}

// TestOpenVPNRender feeds the rendered two-outbound config to a real mihomo.
// Gated on WARP_TEST_MIHOMO like the other real-binary tests.
func TestOpenVPNRender(t *testing.T) {
	bin := os.Getenv("WARP_TEST_MIHOMO")
	if bin == "" {
		t.Skip("set WARP_TEST_MIHOMO to a mihomo binary to run this test")
	}
	ca, cert, key, err := probePEMCredentials()
	if err != nil {
		t.Fatal(err)
	}
	// A real core parses the PEM itself, so this profile carries a genuinely
	// self-signed pair (unlike the parser fixture above). tls-auth is omitted:
	// its body is an OpenVPN static key, not a certificate.
	profile := "client\ndev tun\nproto tcp\nremote 203.0.113.7 443\n" +
		"cipher AES-128-CBC\nauth SHA1\n" +
		"<ca>\n" + ca + "</ca>\n" +
		"<cert>\n" + cert + "</cert>\n" +
		"<key>\n" + key + "</key>\n"

	p, err := parseOVPNProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	opts := defaultConnectOptions(protoWG, false, false)
	opts.openvpnMode = true
	opts.openvpnNode = &vpnGateNode{IP: "203.0.113.7", Port: p.Port, Proto: p.Proto, Profile: profile}
	out, err := renderClientConfig(opts, cachedEndpoint{Endpoint: "162.159.192.1:2408"}, mustParseProto(protoWG))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	yaml := string(out)
	for _, want := range []string{"type: openvpn", "dialer-proxy:", "OPENVPN", "handshake-timeout: 20"} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("render missing %q:\n%s", want, yaml)
		}
	}
	if strings.Contains(yaml, "type: socks5") {
		t.Fatalf("OpenVPN render must not contain the Psiphon sidecar:\n%s", yaml)
	}
	if err := core.TestConfig(bin, t.TempDir(), out); err != nil {
		t.Fatalf("mihomo rejects the rendered config: %v\n%s", err, yaml)
	}
}
