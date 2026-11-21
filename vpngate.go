package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OpenVPN egress (V2): the exit is a VPN Gate public relay, dialled by mihomo's
// native openvpn outbound from inside the WARP underlay. The node list is the
// same public API the Android client uses; a profile carries everything mihomo
// needs inline (CA, client cert and key), so there is no sidecar and no external
// OpenVPN binary.
const (
	vpnGateAPIURL    = "https://www.vpngate.net/api/iphone/"
	vpnGateHost      = "www.vpngate.net"
	vpnGateCacheName = "vpngate-nodes-v2.json"
	// vpnGateUnderlayName remembers the last WARP endpoint that carried a
	// successful fetch, so the fallback does not depend on a fresh scan cache
	// being present (same role as the Android client's last-endpoint.json).
	vpnGateUnderlayName = "vpngate-underlay.json"
	// vpnGateCacheTTL is how long a fetched list is served before a refresh.
	// VPN Gate nodes churn fast, but re-fetching on every dropdown open would
	// hammer the API for a list that is only minutes stale.
	vpnGateCacheTTL = 3 * time.Hour
	// vpnGateMaxNodes caps the cached pool: the API can return hundreds of
	// entries, most of them dead, and the cache file is read on UI paths.
	vpnGateMaxNodes = 200
	// vpnGateConnectNodes is the candidate cap handed to one connect, matching
	// the phone client's OPENVPN_CANDIDATE_CAP. The attempt cap is smaller; the
	// 10-minute failure memory moves later retries down this list.
	vpnGateConnectNodes = 24
	// vpnGateFetchTimeout bounds the direct fetch; the WARP fallback has its
	// own, longer budget because a handshake and a TLS round-trip ride on it.
	//
	// 6s, not 12: on a blocked network the direct attempt fails fast (RST or
	// DNS poison) and every extra second is pure wait before the fallback that
	// actually works. A reachable network answers well inside this window.
	vpnGateFetchTimeout = 6 * time.Second
	// vpnGateProbeJobs / vpnGateProbeTimeout match the Android client: eight
	// concurrent TCP probes, three seconds each. Only TCP profiles are probed;
	// a UDP node keeps the API's self-reported ping.
	vpnGateProbeJobs    = 8
	vpnGateProbeTimeout = 3 * time.Second
	// ipAPIEndpoint is the batch enrichment endpoint the phone client uses. One
	// request covers 100 IPs and returns the ISP/AS/hosting flags that the node
	// classification is built from.
	ipAPIEndpoint = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,mobile,proxy,hosting,query"
	// vpnGateFailTTL is how long a relay that just failed is kept out of the
	// candidate list. Ten minutes is the phone client's window: long enough that
	// a manual retry does not walk straight back into the same dead node, short
	// enough that a transient outage does not blacklist a node for the session.
	vpnGateFailTTL  = 10 * time.Minute
	vpnGateFailName = "vpngate-failed.json"
	// vpnGateLastTTL bounds the last known-good relay hint. Long enough to make
	// a reconnect fast, short enough that a relay that disappeared from the pool
	// is not chased after the cache has refreshed several times.
	vpnGateLastTTL  = 6 * time.Hour
	vpnGateLastName = "vpngate-last.json"
	// vpnGateSpeedTTL bounds the measured-throughput memory. VPN Gate relays are
	// volunteer lines whose speed moves by the hour; a stale "fast" verdict must
	// not outlive the cache it was measured against.
	vpnGateSpeedTTL  = 6 * time.Hour
	vpnGateSpeedName = "vpngate-speeds.json"
)

// vpnGateNode is one VPN Gate relay with its decoded OpenVPN profile.
type vpnGateNode struct {
	HostName     string `json:"host_name"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Proto        string `json:"proto"`
	CountryLong  string `json:"country_long"`
	CountryShort string `json:"country_short"`
	Score        int    `json:"score"`
	Speed        int64  `json:"speed"`
	// PingMS is the API's own measurement (CSV "Ping"), kept as a fallback for
	// nodes the local probe cannot reach.
	PingMS   int    `json:"ping_ms"`
	Sessions int    `json:"sessions"`
	Operator string `json:"operator"`
	// Class is the two-way line classification (residential or datacenter).
	// public-vpn-* is the author's datacenter fleet; every other volunteer
	// relay stays residential unless ip-api proves hosting.
	Class   string `json:"class"`
	Profile string `json:"profile"`
	// LatencyMS is measured locally (through the WARP underlay when the list
	// itself had to be fetched that way); never persisted.
	LatencyMS int64 `json:"-"`
	// MeasuredBps is this client's own connect-time throughput for the relay
	// (vpngate-speeds.json), not the API's self-reported speed. It only ranks
	// candidates; it never excludes one.
	MeasuredBps int64 `json:"-"`
	// ProbeState / ProbeMS come from the MANUAL OpenVPN handshake test only:
	// "" = 未检测, "ok" = real handshake + download passed, "fail" = failed.
	// Session-local on purpose: a pool refresh resets every row to 未检测.
	ProbeState string `json:"-"`
	ProbeMS    int64  `json:"-"`
	// ProbeErr is the short reason a row failed (端口不可达 / 握手超时 / 下载中断).
	// A bare 「失败」 left the user unable to tell a dead relay from a slow one.
	ProbeErr string `json:"-"`
}

func (n vpnGateNode) endpoint() string { return net.JoinHostPort(n.IP, strconv.Itoa(n.Port)) }

// id is the stable pick key shared with the settings file, in the same
// country-ip-port shape the Android client uses.
func (n vpnGateNode) id() string {
	return strings.ToLower(n.CountryShort) + "-" + n.IP + "-" + strconv.Itoa(n.Port)
}

// classKey is the class the picker groups and numbers by, and it only ever
// answers 家宽 or 机房. The host prefix is checked first because public-vpn-*
// is the project author's own datacenter fleet; older caches may still carry it
// as "unknown" (ip-api enrichment used to downgrade the offline prior), and
// that host is authoritative either way. Everything not proven hosting is a
// volunteer relay and stays residential - there is no third bucket to show.
func (n vpnGateNode) classKey() string {
	if strings.HasPrefix(strings.ToLower(n.HostName), "public-vpn") {
		return "datacenter"
	}
	if n.Class == "datacenter" {
		return "datacenter"
	}
	return "residential"
}

// classTag is the short node-class label used in slot names (JP家宽01).
func (n vpnGateNode) classTag() string {
	if n.classKey() == "datacenter" {
		return tr("机房")
	}
	return tr("家宽")
}

// classRank is the display order: the residential block first, the datacenter
// fleet second. No class is ever hidden; the rank only decides what is tried
// first.
func (n vpnGateNode) classRank() int {
	if n.classKey() == "residential" {
		return 0
	}
	return 1
}

// ---- classification (ported verbatim from the phone client) ----

// hardDCASN is the hard datacenter ASN table. A hit here is conclusive.
var hardDCASN = map[int]bool{
	16509: true, 14618: true, 15169: true, 396982: true, 8075: true,
	13335: true, 14061: true, 20473: true, 63949: true, 16276: true,
	24940: true, 51167: true, 9009: true, 36352: true, 53667: true,
	29802: true, 40676: true, 46844: true, 62240: true,
}

// residentialBrands is the consumer-ISP brand list. A brand hit is strong
// evidence of a residential access line; "telecom"/"broadband" alone is not,
// because carriers and transit providers would be mislabelled.
var residentialBrands = []string{
	"korea telecom", "kt corporation", "sk broadband", "skb-as-kr", "lg u+", "lgu+", "lg uplus",
	"softbank", "kddi", "comcast", "charter", "spectrum", "frontier", "fidium",
	"consolidated communications", "so-net", "sony network communications", "jcom",
	"chubu telecommunications", "commufa", "ctcx", "asahi net", "asahi-net", "ocn",
	"ntt-me", "wakwak", "xephion", "rostelecom", "er-telecom", "wave broadband",
	"cable & wireless panama", "lg powercomm", "powervis", "lg hellovision",
	"hellovision", "cjckn", "cmb kwangju", "biglobe", "plala", "nifty", "@nifty",
	"orange", "etisalat", "arteria", "hawaiian telcom", "tt dotcom", "ttnet",
}

var dcKeywords = []string{
	"hosting", "cloud", "server", "datacenter", "data center", "data-centre", "colocation",
	" vps", "vps ", "dedicated", " idc", "amazon", "google llc", "microsoft", "oracle",
	"digitalocean", "linode", "vultr", "hetzner", "ovh", "contabo", "alibaba", "tencent",
	"cloudflare", "choopa", "leaseweb", "m247", "psychz", "quadranet", "colocrossing",
}

// ipAPIResult is one row of an ip-api batch response.
type ipAPIResult struct {
	Status  string `json:"status"`
	Query   string `json:"query"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	Mobile  bool   `json:"mobile"`
	Proxy   bool   `json:"proxy"`
	Hosting bool   `json:"hosting"`
}

// enrichClassify resolves a node into one of the two classes from the ip-api
// evidence. The public-vpn-* host prior is re-asserted before anything else:
// ip-api reports those relays' ISP without a hosting flag, so the old
// three-way code overwrote a conclusive datacenter prior with "unknown" and the
// picker showed the author's own VPS fleet as unknown.
//
// Datacenter evidence is the hosting flag, a hard datacenter ASN, two
// independent hosting signals, or a single hosting keyword that no consumer
// brand or mobile network contradicts. Everything else is residential: the
// VPN Gate pool is volunteer-run, and with no third label a line that cannot be
// proven hosting is better shown as 家宽 than as a made-up datacenter.
func enrichClassify(n *vpnGateNode, r ipAPIResult) {
	if r.Status != "success" {
		return
	}
	if strings.HasPrefix(strings.ToLower(n.HostName), "public-vpn") {
		n.Class = "datacenter"
		return
	}
	blob := strings.ToLower(strings.TrimSpace(r.ISP) + " " + r.Org + " " + r.AS)
	dcGroups := 0
	if r.Hosting {
		dcGroups++
	}
	if containsAny(blob, dcKeywords) {
		dcGroups++
	}
	if asn := parseASN(r.AS); asn > 0 && hardDCASN[asn] {
		n.Class = "datacenter"
		return
	}
	residential := containsAny(blob, residentialBrands) || r.Mobile
	if dcGroups >= 2 || r.Hosting || (dcGroups >= 1 && !residential) {
		n.Class = "datacenter"
		return
	}
	n.Class = "residential"
}

func parseASN(s string) int {
	s = strings.TrimSpace(strings.ToUpper(s))
	if !strings.HasPrefix(s, "AS") {
		return 0
	}
	s = s[2:]
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	v, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return v
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// newStackHTTPClient routes ordinary net/http requests through a temporary WARP
// netstack, so ip-api is enriched over the same route that delivered the list.
func newStackHTTPClient(stack *ipStack, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return stack.tnet.DialContext(ctx, network, addr)
			},
		},
	}
}

// enrichVPNGateClasses batches up to 100 IPs per request. A failure is not
// fatal: offline priors stay in place and the count reports how many IPs were
// actually enriched.
func enrichVPNGateClasses(ctx context.Context, client *http.Client, nodes []vpnGateNode) (int, error) {
	if client == nil || len(nodes) == 0 {
		return 0, nil
	}
	uniq := make([]string, 0, 128)
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.IP == "" || seen[n.IP] {
			continue
		}
		seen[n.IP] = true
		uniq = append(uniq, n.IP)
	}
	if len(uniq) == 0 {
		return 0, nil
	}
	byIP := map[string]ipAPIResult{}
	for start := 0; start < len(uniq); start += 100 {
		end := start + 100
		if end > len(uniq) {
			end = len(uniq)
		}
		payload, err := json.Marshal(uniq[start:end])
		if err != nil {
			return len(byIP), err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ipAPIEndpoint, bytes.NewReader(payload))
		if err != nil {
			return len(byIP), err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return len(byIP), err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return len(byIP), fmt.Errorf("ip-api HTTP %d", resp.StatusCode)
		}
		var rows []ipAPIResult
		if err := json.Unmarshal(body, &rows); err != nil {
			return len(byIP), err
		}
		for _, r := range rows {
			if r.Query != "" {
				byIP[r.Query] = r
			}
		}
	}
	for i := range nodes {
		if r, ok := byIP[nodes[i].IP]; ok {
			enrichClassify(&nodes[i], r)
		}
	}
	// Second, independent source. Two APIs are required so a single stale or
	// failed classification cannot mislabel a relay, and the merged verdict is
	// always one of the two labels the picker knows.
	crossCheckClasses(ctx, client, nodes)
	return len(byIP), nil
}

// ipWhoEndpoint is the independent second source for the IP class cross-check.
// It is keyless and returns the connection's ISP/Org/ASN, so the same
// datacenter heuristics can be applied from a different data provider than
// ip-api.com.
const ipWhoEndpoint = "https://ipwho.is/"

type ipWhoResult struct {
	Success    bool `json:"success"`
	Connection struct {
		ASN int    `json:"asn"`
		Org string `json:"org"`
		ISP string `json:"isp"`
	} `json:"connection"`
}

// crossCheckClasses asks the second source about every IP the first source
// left as residential, then merges the two verdicts. A datacenter claim from
// EITHER source wins: hosting flags and DC ASNs are strong positive evidence,
// while "residential" is only the absence of such evidence. There is
// deliberately no third bucket - no API answer, timeout or disagreement can
// ever produce 未知. The picker only ever shows 家宽 or 机房.
func crossCheckClasses(ctx context.Context, client *http.Client, nodes []vpnGateNode) {
	ips := make([]string, 0, 64)
	seen := map[string]bool{}
	for i := range nodes {
		if nodes[i].classKey() == "datacenter" || seen[nodes[i].IP] {
			continue
		}
		seen[nodes[i].IP] = true
		ips = append(ips, nodes[i].IP)
	}
	if len(ips) == 0 {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	var mu sync.Mutex
	dcIPs := map[string]bool{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-checkCtx.Done():
				return
			}
			defer func() { <-sem }()
			req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, ipWhoEndpoint+ip, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			var r ipWhoResult
			if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r); err != nil || !r.Success {
				return
			}
			blob := strings.ToLower(strings.TrimSpace(r.Connection.ISP + " " + r.Connection.Org))
			if containsAny(blob, dcKeywords) || hardDCASN[r.Connection.ASN] {
				mu.Lock()
				dcIPs[ip] = true
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	// Final normalisation: only two labels survive, whatever either API said.
	for i := range nodes {
		if dcIPs[nodes[i].IP] || strings.HasPrefix(strings.ToLower(nodes[i].HostName), "public-vpn") {
			nodes[i].Class = "datacenter"
		} else if nodes[i].Class != "datacenter" {
			nodes[i].Class = "residential"
		}
	}
}

// ovpnProfile is the subset of OpenVPN directives mihomo's outbound parses. A
// VPN Gate profile always carries its certificates inline.
type ovpnProfile struct {
	Remote        string
	Port          int
	Proto         string
	Dev           string
	Cipher        string
	DataCiphers   []string
	Auth          string
	CA            string
	Cert          string
	Key           string
	TLSAuth       string
	TLSCrypt      string
	TLSCryptV2    string
	KeyDirection  string
	CompLZO       string
	MTU           int
	Ping          int
	PingRestart   int
	RemoteCertTLS string
}

// parseOVPNProfile reads the directives this client renders. Inline <ca>,
// <cert>, <key>, <tls-auth>, <tls-crypt> and <tls-crypt-v2> blocks are kept
// verbatim; file references are ignored because VPN Gate never uses them.
func parseOVPNProfile(raw string) (ovpnProfile, error) {
	var p ovpnProfile
	blocks := map[string]string{}
	var cur string
	var body strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			cur = strings.ToLower(strings.Trim(line, "<>"))
			body.Reset()
			continue
		}
		if strings.HasPrefix(line, "</") {
			if cur != "" {
				blocks[cur] = body.String()
			}
			cur = ""
			continue
		}
		if cur != "" {
			body.WriteString(line)
			body.WriteString("\n")
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "remote":
			if len(fields) >= 3 && p.Remote == "" {
				if port, err := strconv.Atoi(fields[2]); err == nil {
					p.Remote, p.Port = fields[1], port
				}
			}
		case "proto":
			if len(fields) >= 2 {
				p.Proto = normalizeOVPNProto(fields[1])
			}
		case "dev":
			if len(fields) >= 2 {
				p.Dev = fields[1]
			}
		case "cipher":
			if len(fields) >= 2 {
				p.Cipher = fields[1]
			}
		case "data-ciphers":
			if len(fields) >= 2 {
				p.DataCiphers = strings.Split(fields[1], ":")
			}
		case "auth":
			if len(fields) >= 2 {
				p.Auth = fields[1]
			}
		case "key-direction":
			if len(fields) >= 2 {
				p.KeyDirection = fields[1]
			}
		case "comp-lzo":
			if len(fields) >= 2 {
				p.CompLZO = fields[1]
			} else {
				p.CompLZO = "yes"
			}
		case "mtu":
			if len(fields) >= 2 {
				p.MTU, _ = strconv.Atoi(fields[1])
			}
		case "ping":
			if len(fields) >= 2 {
				p.Ping, _ = strconv.Atoi(fields[1])
			}
		case "ping-restart":
			if len(fields) >= 2 {
				p.PingRestart, _ = strconv.Atoi(fields[1])
			}
		case "remote-cert-tls":
			if len(fields) >= 2 {
				p.RemoteCertTLS = fields[1]
			}
		}
	}
	p.CA = blocks["ca"]
	p.Cert = blocks["cert"]
	p.Key = blocks["key"]
	p.TLSAuth = blocks["tls-auth"]
	p.TLSCrypt = blocks["tls-crypt"]
	p.TLSCryptV2 = blocks["tls-crypt-v2"]
	if p.Dev == "" {
		p.Dev = "tun"
	}
	if p.Proto == "" {
		p.Proto = "tcp"
	}
	if p.Remote == "" || p.Port <= 0 {
		return p, fmt.Errorf("profile has no remote")
	}
	if p.CA == "" || p.Cert == "" || p.Key == "" {
		return p, fmt.Errorf("profile is missing inline credentials")
	}
	return p, nil
}

func normalizeOVPNProto(v string) string {
	switch strings.ToLower(v) {
	case "tcp", "tcp-client", "tcp4", "tcp6":
		return "tcp"
	case "udp", "udp4", "udp6":
		return "udp"
	}
	return "tcp"
}

// vpnGateCacheFile is the on-disk list with its fetch time.
type vpnGateCacheFile struct {
	At    time.Time     `json:"at"`
	Nodes []vpnGateNode `json:"nodes"`
}

func vpnGateCachePath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, vpnGateCacheName), nil
}

// loadVPNGateCache returns the cached list and its age. A missing or corrupt
// file is not an error: it just means "nothing cached yet".
func loadVPNGateCache() ([]vpnGateNode, time.Time) {
	p, err := vpnGateCachePath()
	if err != nil {
		return nil, time.Time{}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, time.Time{}
	}
	var f vpnGateCacheFile
	if json.Unmarshal(raw, &f) != nil {
		return nil, time.Time{}
	}
	return f.Nodes, f.At
}

func saveVPNGateCache(nodes []vpnGateNode) {
	p, err := vpnGateCachePath()
	if err != nil {
		return
	}
	raw, err := json.MarshalIndent(vpnGateCacheFile{At: time.Now(), Nodes: nodes}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, raw, 0o600)
}

// vpnGateUnderlayFile is the last endpoint that carried a successful WARP
// fetch. It is deliberately independent of the scan cache's TTL: VPN Gate is
// blocked on exactly the networks where a fetch matters, and reusing a known
// good endpoint avoids a one-to-two minute scan just to read the country list.
type vpnGateUnderlayFile struct {
	Endpoint string    `json:"endpoint"`
	At       time.Time `json:"at"`
}

func vpnGateUnderlayPath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, vpnGateUnderlayName), nil
}

func loadVPNGateUnderlay() string {
	p, err := vpnGateUnderlayPath()
	if err != nil {
		return ""
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var f vpnGateUnderlayFile
	if json.Unmarshal(raw, &f) != nil {
		return ""
	}
	return f.Endpoint
}

func saveVPNGateUnderlay(endpoint string) {
	if endpoint == "" {
		return
	}
	p, err := vpnGateUnderlayPath()
	if err != nil {
		return
	}
	raw, err := json.MarshalIndent(vpnGateUnderlayFile{Endpoint: endpoint, At: time.Now()}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, raw, 0o600)
}

// vpnGateNodesFor returns the pool a connect runs with: a fresh cache when it
// has one, otherwise a live fetch. A stale cache is still preferable to no
// nodes when the network blocks the API, so the fetch failure path falls back
// to it. force skips the cache entirely — a retry after every relay failed must
// not re-pick the same stale nodes.
func vpnGateNodesFor(ctx context.Context, results []cachedEndpoint, run protoRun, force bool) ([]vpnGateNode, error) {
	nodes, at := loadVPNGateCache()
	if !force && len(nodes) > 0 && time.Since(at) < vpnGateCacheTTL {
		return nodes, nil
	}
	var fresh []vpnGateNode
	var err error
	raw, derr := fetchVPNGateDirect(ctx)
	if derr == nil {
		fresh = parseVPNGateCSV(raw)
		if len(fresh) > 0 {
			// Classify before the latency probe so the connect ordering knows
			// which relays are residential. Enrichment failure is non-fatal.
			enrichCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, _ = enrichVPNGateClasses(enrichCtx, &http.Client{Timeout: 15 * time.Second}, fresh)
			cancel()
		} else {
			derr = fmt.Errorf("VPN Gate 节点列表为空")
		}
	}
	if len(fresh) == 0 {
		err = derr
		if len(results) > 0 {
			stageMsg("VPN Gate 直连不可用，经 WARP 底座获取节点列表…")
			var wn []vpnGateNode
			wn, werr := fetchVPNGateNodesViaWARP(ctx, results, run, loadVPNGateUnderlay())
			if werr == nil && len(wn) > 0 {
				fresh = wn
			} else if werr != nil {
				err = werr
			}
		}
	}
	if len(fresh) == 0 {
		if len(nodes) > 0 {
			stageMsg("VPN Gate 获取失败，使用缓存节点列表")
			return nodes, nil
		}
		if err == nil {
			err = fmt.Errorf("VPN Gate 节点列表为空")
		}
		return nil, err
	}
	saveVPNGateCache(fresh)
	return fresh, nil
}

// fetchVPNGateDirect is the ordinary HTTPS fetch. It is tried first because it
// is cheap when the network allows it; the WARP fallback exists for networks
// that block the API outright (mainland China is the normal case here).
func fetchVPNGateDirect(ctx context.Context) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, vpnGateFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, vpnGateAPIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xehn/"+shortVersion())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPN Gate API: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// fetchVPNGateViaProxy asks the API through the running core's mixed port. The
// GUI uses it to refresh the country list once a session exists: on networks
// that block vpngate.net directly, the just-verified tunnel is already the
// working route and no in-process netstack has to be built.
func fetchVPNGateViaProxy(ctx context.Context, mixedPort int) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, vpnGateFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, vpnGateAPIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xehn/"+shortVersion())
	client := vpnGateProxyClient(mixedPort, vpnGateFetchTimeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPN Gate API: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// vpnGateProxyClient routes requests through the running core's mixed port; it
// is also what lets ip-api enrichment ride the already-verified tunnel.
func vpnGateProxyClient(mixedPort int, timeout time.Duration) *http.Client {
	proxyURL := "http://127.0.0.1:" + strconv.Itoa(mixedPort)
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyURL)),
		},
	}
}

// fetchVPNGateNodesViaWARP is the GUI/refresh variant: it fetches the CSV
// through a throwaway WARP tunnel, then measures every node's TCP latency
// through that same netstack before closing it. Measuring through the tunnel is
// what makes the numbers usable on a network that blocks direct TCP, and it is
// exactly what the Android client does.
func fetchVPNGateNodesViaWARP(ctx context.Context, results []cachedEndpoint, run protoRun, prefer string) ([]vpnGateNode, error) {
	outer = nil
	t, err := newTunnel(run)
	if err != nil {
		return nil, err
	}
	defer t.Close()

	var lastErr error
	tried := 0
	for _, ce := range orderVPNGateEndpoints(results, prefer) {
		if !ce.Working || ce.Endpoint == "" {
			continue
		}
		if tried >= 3 {
			break
		}
		tried++
		hctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		ok := t.handshake(hctx, ce.Endpoint, 6*time.Second)
		cancel()
		if !ok {
			lastErr = fmt.Errorf("endpoint %s handshake failed", ce.Endpoint)
			continue
		}
		body, ferr := fetchVPNGateOverStack(ctx, t)
		if ferr != nil {
			lastErr = ferr
			continue
		}
		nodes := parseVPNGateCSV(body)
		if len(nodes) == 0 {
			lastErr = fmt.Errorf("VPN Gate 节点列表为空")
			continue
		}
		if stack := t.stack(); stack != nil && stack.tnet != nil {
			// 8s, not 20: this only labels each relay as 家宽/机房. It ran after
			// the list was already parsed, so its full budget was pure wait on the
			// "正在获取节点" spinner — a 39-second fetch was mostly this. A relay
			// that misses the window just shows without the tag.
			enrichCtx, enrichCancel := context.WithTimeout(ctx, 8*time.Second)
			_, _ = enrichVPNGateClasses(enrichCtx, newStackHTTPClient(stack, 15*time.Second), nodes)
			enrichCancel()
			probeVPNGateLatency(ctx, nodes, func(c context.Context, addr string) (net.Conn, error) {
				return stack.tnet.DialContext(c, "tcp", addr)
			})
		}
		sortVPNGateNodesByLatency(nodes)
		saveVPNGateUnderlay(ce.Endpoint)
		return nodes, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no working endpoint for WARP fetch")
	}
	return nil, lastErr
}

// orderVPNGateEndpoints puts the user's selected endpoint first, then the last
// endpoint that worked for a fetch, then the cached scan order. Duplicates are
// dropped so a preference never costs one of the three handshake slots.
func orderVPNGateEndpoints(results []cachedEndpoint, prefer string) []cachedEndpoint {
	var ordered []cachedEndpoint
	seen := map[string]bool{}
	hostOf := func(ep string) string {
		if h, _, err := net.SplitHostPort(ep); err == nil {
			return h
		}
		return ep
	}
	add := func(ce cachedEndpoint) {
		if ce.Endpoint == "" || seen[ce.Endpoint] {
			return
		}
		seen[ce.Endpoint] = true
		ordered = append(ordered, ce)
	}
	prefs := []string{prefer, loadVPNGateUnderlay()}
	for _, ep := range prefs {
		if ep == "" {
			continue
		}
		found := false
		for _, ce := range results {
			if ce.Endpoint == ep || ce.IP == hostOf(ep) {
				ce.Working = true
				add(ce)
				found = true
				break
			}
		}
		if !found {
			host := hostOf(ep)
			if _, _, err := net.SplitHostPort(ep); err != nil {
				// A bare address has no port to dial; let the cached scan
				// supply that endpoint instead of guessing a wireguard port.
				continue
			}
			add(cachedEndpoint{Endpoint: ep, IP: host, Working: true})
		}
	}
	for _, ce := range results {
		if ce.Working {
			add(ce)
		}
	}
	return ordered
}

// fetchVPNGateOverStack performs one HTTPS round-trip through the tunnel's
// gVisor stack. The URL is fixed, so the request is written directly instead of
// plumbing a netstack dialer through net/http.
func fetchVPNGateOverStack(ctx context.Context, t tunnel) ([]byte, error) {
	stack := t.stack()
	if stack == nil || stack.tnet == nil {
		return nil, fmt.Errorf("tunnel has no netstack")
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := stack.tnet.DialContext(dctx, "tcp", net.JoinHostPort(vpnGateHost, "443"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: vpnGateHost, MinVersion: tls.VersionTLS12})
	deadline, ok := dctx.Deadline()
	if ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	req := "GET /api/iphone/ HTTP/1.1\r\nHost: " + vpnGateHost +
		"\r\nUser-Agent: xehn/" + shortVersion() +
		"\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return nil, err
	}
	hr := &http.Request{Method: http.MethodGet}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPN Gate API: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// parseVPNGateCSV turns the API body into nodes. A real CSV reader is used
// because CountryLong and Operator are free text: a comma inside them would
// silently shift every later column under a naive SplitN, moving a valid node
// into the profile field or dropping it entirely.
func parseVPNGateCSV(raw []byte) []vpnGateNode {
	var clean strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "*") {
			continue
		}
		clean.WriteString(line)
		clean.WriteString("\n")
	}
	r := csv.NewReader(strings.NewReader(clean.String()))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	var out []vpnGateNode
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) < 15 {
			continue
		}
		if strings.HasPrefix(rec[0], "#") || strings.EqualFold(strings.TrimSpace(rec[1]), "IP") {
			continue
		}
		rawProfile := strings.TrimSpace(rec[14])
		if rawProfile == "" {
			continue
		}
		prof, err := base64.StdEncoding.DecodeString(rawProfile)
		if err != nil {
			continue
		}
		ovpn, err := parseOVPNProfile(string(prof))
		if err != nil {
			continue
		}
		host := strings.TrimSpace(rec[0])
		ip := strings.TrimSpace(rec[1])
		// The config's remote is the real landing address; the CSV IP column
		// occasionally disagrees (same rule as the Android parser).
		if ovpn.Remote != "" && net.ParseIP(ovpn.Remote) != nil {
			ip = ovpn.Remote
		}
		if ip == "" || ovpn.Port <= 0 {
			continue
		}
		score, _ := strconv.Atoi(strings.TrimSpace(rec[2]))
		ping, _ := strconv.Atoi(strings.TrimSpace(rec[3]))
		speed, _ := strconv.ParseInt(strings.TrimSpace(rec[4]), 10, 64)
		sessions, _ := strconv.Atoi(strings.TrimSpace(rec[7]))
		// Default to residential and let ip-api promote to datacenter: the pool
		// is volunteer-run home lines first, and the picker has no unknown
		// bucket, so enrichment failure must not leave the label blank.
		// public-vpn-* is the author's datacenter VPS fleet and needs no
		// round-trip at all.
		class := "residential"
		if strings.HasPrefix(strings.ToLower(host), "public-vpn") {
			class = "datacenter"
		}
		out = append(out, vpnGateNode{
			HostName:     host,
			IP:           ip,
			Port:         ovpn.Port,
			Proto:        ovpn.Proto,
			CountryLong:  strings.TrimSpace(rec[5]),
			CountryShort: strings.ToUpper(strings.TrimSpace(rec[6])),
			Score:        score,
			Speed:        speed,
			PingMS:       ping,
			Sessions:     sessions,
			Operator:     strings.TrimSpace(rec[12]),
			Class:        class,
			Profile:      string(prof),
		})
		if len(out) >= vpnGateMaxNodes {
			break
		}
	}
	sortVPNGateNodes(out)
	return out
}

// sortVPNGateNodes orders by the API's own quality score, then speed. TCP
// nodes come first: mihomo's OpenVPN outbound handles both, but TCP survives
// more networks and VPN Gate's UDP nodes are the ones most often rate-limited.
func sortVPNGateNodes(nodes []vpnGateNode) {
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if (a.Proto == "tcp") != (b.Proto == "tcp") {
			return a.Proto == "tcp"
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Speed > b.Speed
	})
}

// vpnGateCandidates filters by country (empty = all), measures reachability and
// orders the nodes a connect will try, using the phone client's failover logic:
//
//   - a pinned relay first;
//   - then the same country, same class (another residential for a residential
//     pin, another datacenter for a datacenter pin);
//   - then the same country's other classes;
//   - then abroad, same class first, then everything else.
//
// Without a pin, a country preference gets its own country (residential, then
// datacenter, latency inside each block) before abroad; auto mode
// orders the whole pool the same way. Nothing is ever excluded by class: the
// rank only decides what is tried first.
//
// The local TCP probe is only an ordering aid: what matters is that the relay
// answers from inside the WARP underlay, which the connect itself proves. A
// node that fails to answer locally is kept as a late candidate — the API is
// reachable through WARP even when direct TCP is blocked, and dropping every
// such node would contradict the fallback fetch.
func vpnGateCandidates(ctx context.Context, nodes []vpnGateNode, region, pin string, max int) []vpnGateNode {
	region = strings.ToUpper(strings.TrimSpace(region))
	valid := make([]vpnGateNode, 0, len(nodes))
	var pinNode *vpnGateNode
	for i := range nodes {
		n := nodes[i]
		if n.IP == "" || n.Port <= 0 || n.Profile == "" {
			continue
		}
		valid = append(valid, n)
		if pin != "" && n.id() == pin && pinNode == nil {
			pn := n
			pinNode = &pn
		}
	}
	if len(valid) == 0 {
		return nil
	}
	// Attach this client's own measurements before anything sorts or probes:
	// the sort below ranks measured-fast relays first and measured-slow ones
	// behind untested candidates, and the pinned node must carry its speed too.
	speeds := vpnGateSpeedSnapshot()
	for i := range valid {
		if bps, ok := speeds[valid[i].id()]; ok {
			valid[i].MeasuredBps = bps
		}
	}
	if pinNode != nil {
		if bps, ok := speeds[pinNode.id()]; ok {
			pinNode.MeasuredBps = bps
		}
	}
	targetCC := region
	targetCls := ""
	if pinNode != nil {
		targetCC = strings.ToUpper(pinNode.CountryShort)
		targetCls = pinNode.classKey()
	}

	// Probe the head of the target country, chosen by class + API ping so the
	// probe budget is spent on the blocks that would actually be tried first.
	// A pinned node outside that head is probed too.
	probePool := valid
	if targetCC != "" {
		var in []vpnGateNode
		for _, n := range valid {
			if strings.EqualFold(n.CountryShort, targetCC) {
				in = append(in, n)
			}
		}
		if len(in) > 0 {
			probePool = in
		}
	}
	probePool = append([]vpnGateNode(nil), probePool...)
	sortVPNGateNodesByLatency(probePool)
	const probeMax = 18
	n := len(probePool)
	if n > probeMax {
		n = probeMax
	}
	probe := append([]vpnGateNode(nil), probePool[:n]...)
	if pinNode != nil {
		found := false
		for _, p := range probe {
			if p.id() == pinNode.id() {
				found = true
				break
			}
		}
		if !found {
			probe = append(probe, *pinNode)
		}
	}
	measureVPNGateLatency(ctx, probe)
	lat := make(map[string]int64, len(probe))
	for _, p := range probe {
		if p.LatencyMS > 0 {
			lat[p.id()] = p.LatencyMS
		}
	}
	for i := range valid {
		if l, ok := lat[valid[i].id()]; ok {
			valid[i].LatencyMS = l
		}
	}

	var ordered []vpnGateNode
	seen := make(map[string]bool, len(valid))
	add := func(n vpnGateNode) {
		if n.id() == "" || seen[n.id()] {
			return
		}
		seen[n.id()] = true
		ordered = append(ordered, n)
	}
	addAll := func(pool []vpnGateNode) {
		pool = append([]vpnGateNode(nil), pool...)
		sortVPNGateNodesByLatency(pool)
		for _, n := range pool {
			add(n)
		}
	}
	if pinNode != nil {
		add(*pinNode)
	}
	var inCountry, abroad []vpnGateNode
	for _, n := range valid {
		if targetCC != "" && strings.EqualFold(n.CountryShort, targetCC) {
			inCountry = append(inCountry, n)
		} else {
			abroad = append(abroad, n)
		}
	}
	sameCls := func(pool []vpnGateNode) []vpnGateNode {
		var out []vpnGateNode
		for _, n := range pool {
			if n.classKey() == targetCls {
				out = append(out, n)
			}
		}
		return out
	}
	otherCls := func(pool []vpnGateNode) []vpnGateNode {
		var out []vpnGateNode
		for _, n := range pool {
			if n.classKey() != targetCls {
				out = append(out, n)
			}
		}
		return out
	}
	switch {
	case targetCls != "":
		addAll(sameCls(inCountry))
		addAll(otherCls(inCountry))
		addAll(sameCls(abroad))
		addAll(abroad)
	case targetCC != "":
		addAll(inCountry)
		addAll(abroad)
	default:
		addAll(valid)
	}
	ordered = freshVPNGateNodes(ordered)
	// Failure memory must never empty the country the user picked. Six relays
	// that failed in the last ten minutes are not a reason to connect to another
	// country behind the user's back: retry them first and say so. This is the
	// "I chose the US and it went to Japan" report — every US relay had a recent
	// failure, so the filter dropped them all and the last-good JP relay took
	// the front of the list.
	if targetCC != "" && !hasCountry(ordered, targetCC) {
		if retry := nodesInCountry(valid, targetCC); len(retry) > 0 {
			sortVPNGateNodesByLatency(retry)
			stageMsg(fmt.Sprintf("所选地区（%s）的节点都在 %s 内失败过，仍优先重试该地区",
				targetCC, vpnGateFailTTL))
			ordered = append(retry, ordered...)
		}
	}
	// A pinned relay is an explicit user choice: the failure memory serves auto
	// selection and must never overrule it. When the memory just filtered the
	// pin out, put it back at the front and say so — the connect tries it first
	// and reports clearly if it has to fall back, instead of asking mid-connect
	// or silently moving to a different relay while the UI still shows the pin.
	if pinNode != nil {
		found := false
		for _, n := range ordered {
			if n.id() == pinNode.id() {
				found = true
				break
			}
		}
		if !found {
			ordered = append([]vpnGateNode{*pinNode}, ordered...)
			stageMsg(fmt.Sprintf("固定节点 %s 在 %s 内失败过，仍按你的固定选择优先尝试", pinNode.id(), vpnGateFailTTL))
		}
	}
	if max > 0 && len(ordered) > max {
		ordered = ordered[:max]
	}
	return ordered
}

// hasCountry reports whether the list still has a relay in cc.
func hasCountry(nodes []vpnGateNode, cc string) bool {
	for _, n := range nodes {
		if strings.EqualFold(n.CountryShort, cc) {
			return true
		}
	}
	return false
}

// nodesInCountry filters the pool by country, keeping the caller's order.
func nodesInCountry(nodes []vpnGateNode, cc string) []vpnGateNode {
	var out []vpnGateNode
	for _, n := range nodes {
		if strings.EqualFold(n.CountryShort, cc) {
			out = append(out, n)
		}
	}
	return out
}

// ---- failure memory ----

// vpnGateFailFile persists the 10-minute failure memory. The phone client keeps
// it in RAM; a file lets a CLI retry (a fresh process) avoid the relay that just
// failed, which is exactly the manual "reconnect" case.
type vpnGateFailFile struct {
	At map[string]time.Time `json:"at"`
}

var vpnGateFailMu sync.Mutex

func vpnGateFailPath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, vpnGateFailName), nil
}

// loadVPNGateFailuresLocked reads the memory; the caller holds vpnGateFailMu.
func loadVPNGateFailuresLocked() map[string]time.Time {
	p, err := vpnGateFailPath()
	if err != nil {
		return map[string]time.Time{}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return map[string]time.Time{}
	}
	var f vpnGateFailFile
	if json.Unmarshal(raw, &f) != nil || f.At == nil {
		return map[string]time.Time{}
	}
	return f.At
}

func saveVPNGateFailuresLocked(m map[string]time.Time) {
	p, err := vpnGateFailPath()
	if err != nil {
		return
	}
	raw, err := json.MarshalIndent(vpnGateFailFile{At: m}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, raw, 0o600)
}

// markVPNGateFailed remembers one relay failure for vpnGateFailTTL.
func markVPNGateFailed(id string) {
	if id == "" {
		return
	}
	vpnGateFailMu.Lock()
	defer vpnGateFailMu.Unlock()
	m := loadVPNGateFailuresLocked()
	now := time.Now()
	for k, at := range m {
		if now.Sub(at) >= vpnGateFailTTL {
			delete(m, k)
		}
	}
	m[id] = now
	saveVPNGateFailuresLocked(m)
}

// clearVPNGateFailure forgets a relay that just worked.
func clearVPNGateFailure(id string) {
	if id == "" {
		return
	}
	vpnGateFailMu.Lock()
	defer vpnGateFailMu.Unlock()
	m := loadVPNGateFailuresLocked()
	if _, ok := m[id]; !ok {
		return
	}
	delete(m, id)
	saveVPNGateFailuresLocked(m)
}

// freshVPNGateNodes drops relays that failed within vpnGateFailTTL. If every
// candidate is in that window the memory is cleared and the full list returned:
// a retry must never end up with zero candidates.
func freshVPNGateNodes(nodes []vpnGateNode) []vpnGateNode {
	if len(nodes) == 0 {
		return nodes
	}
	vpnGateFailMu.Lock()
	defer vpnGateFailMu.Unlock()
	failed := loadVPNGateFailuresLocked()
	if len(failed) == 0 {
		return nodes
	}
	now := time.Now()
	fresh := make([]vpnGateNode, 0, len(nodes))
	skipped := 0
	for _, n := range nodes {
		if at, ok := failed[n.id()]; ok && now.Sub(at) < vpnGateFailTTL {
			skipped++
			continue
		}
		fresh = append(fresh, n)
	}
	if skipped == 0 {
		return nodes
	}
	if len(fresh) == 0 {
		stageMsg(fmt.Sprintf("全部 %d 个出口候选都在 %s 内失败过，清空失败记忆后重试", len(nodes), vpnGateFailTTL))
		saveVPNGateFailuresLocked(map[string]time.Time{})
		return nodes
	}
	return fresh
}

// ---- measured-speed memory ----

// vpnGateSpeedFile persists this client's own measurements so the next connect
// ranks relays by what they actually delivered, not by VPN Gate's self-reported
// speed or a latency that says nothing about throughput.
type vpnGateSpeedFile struct {
	At map[string]vpnGateSpeedEntry `json:"at"`
}

type vpnGateSpeedEntry struct {
	Bps int64     `json:"bps"`
	At  time.Time `json:"at"`
}

var vpnGateSpeedMu sync.Mutex

func vpnGateSpeedPath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, vpnGateSpeedName), nil
}

func loadVPNGateSpeedsLocked() map[string]vpnGateSpeedEntry {
	p, err := vpnGateSpeedPath()
	if err != nil {
		return map[string]vpnGateSpeedEntry{}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return map[string]vpnGateSpeedEntry{}
	}
	var f vpnGateSpeedFile
	if json.Unmarshal(raw, &f) != nil || f.At == nil {
		return map[string]vpnGateSpeedEntry{}
	}
	return f.At
}

func saveVPNGateSpeedsLocked(m map[string]vpnGateSpeedEntry) {
	p, err := vpnGateSpeedPath()
	if err != nil {
		return
	}
	raw, err := json.MarshalIndent(vpnGateSpeedFile{At: m}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, raw, 0o600)
}

// rememberVPNGateSpeed records one usable measurement. A relay rejected as slow
// is recorded too: the ranking needs to know it is slow, not forget it exists.
func rememberVPNGateSpeed(id string, bps int64) {
	if id == "" || bps <= 0 {
		return
	}
	vpnGateSpeedMu.Lock()
	defer vpnGateSpeedMu.Unlock()
	m := loadVPNGateSpeedsLocked()
	now := time.Now()
	for k, v := range m {
		if now.Sub(v.At) >= vpnGateSpeedTTL {
			delete(m, k)
		}
	}
	m[id] = vpnGateSpeedEntry{Bps: bps, At: now}
	saveVPNGateSpeedsLocked(m)
}

// vpnGateSpeedSnapshot returns the unexpired bps per relay id. Expired entries
// are ignored here and pruned on the next write.
func vpnGateSpeedSnapshot() map[string]int64 {
	vpnGateSpeedMu.Lock()
	defer vpnGateSpeedMu.Unlock()
	out := map[string]int64{}
	now := time.Now()
	for id, v := range loadVPNGateSpeedsLocked() {
		if now.Sub(v.At) < vpnGateSpeedTTL {
			out[id] = v.Bps
		}
	}
	return out
}

// vpnGateSpeedTier buckets a relay by its measured throughput: fast, untested,
// slow. Untested sits between the two so a fresh candidate gets a chance, while
// a relay measured below the usable floor can never outrank it — including the
// last known-good relay, which used to pin a slow node to the front.
func vpnGateSpeedTier(bps int64) int {
	switch {
	case bps <= 0:
		return 1
	case bps >= openvpnMinBps:
		return 0
	default:
		return 2
	}
}

// vpnGateLastFile is the last relay that carried real traffic. Only the id is
// stored: the profile still comes from the current pool, so a stale file can
// never resurrect a relay that is no longer offered.
type vpnGateLastFile struct {
	ID      string    `json:"id"`
	Country string    `json:"country"`
	At      time.Time `json:"at"`
}

func vpnGateLastPath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, vpnGateLastName), nil
}

func rememberLastGoodVPNGate(n vpnGateNode) {
	id := n.id()
	if id == "" {
		return
	}
	p, err := vpnGateLastPath()
	if err != nil {
		return
	}
	raw, err := json.Marshal(vpnGateLastFile{
		ID:      id,
		Country: strings.ToUpper(n.CountryShort),
		At:      time.Now(),
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(p, raw, 0o600)
}

func loadLastGoodVPNGate() (vpnGateLastFile, bool) {
	p, err := vpnGateLastPath()
	if err != nil {
		return vpnGateLastFile{}, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return vpnGateLastFile{}, false
	}
	var f vpnGateLastFile
	if json.Unmarshal(raw, &f) != nil || f.ID == "" {
		return vpnGateLastFile{}, false
	}
	if time.Since(f.At) > vpnGateLastTTL {
		return vpnGateLastFile{}, false
	}
	return f, true
}

// preferLastGoodVPNGate moves the relay that last succeeded to the front. A
// manual pin already leads the list and is never overridden. A country choice
// is also respected while that country still has candidates; only when the
// region has none at all (the abroad fallback the phone client uses) does the
// hint win, which is exactly the case where the region preference is moot.
func preferLastGoodVPNGate(relays []vpnGateNode, pin, region string) []vpnGateNode {
	if pin != "" || len(relays) < 2 {
		return relays
	}
	last, ok := loadLastGoodVPNGate()
	if !ok {
		return relays
	}
	if region != "" && !strings.EqualFold(last.Country, region) {
		// A relay from another country is only promoted when the chosen region
		// has nothing to offer at all. That is now the rare case: the candidate
		// builder keeps the region's relays even when the failure memory has
		// recently dropped them, so "empty" here means the pool genuinely has no
		// node for that country — and connecting somewhere is better than
		// failing outright, as long as connect.go says which country it used.
		for _, n := range relays {
			if strings.EqualFold(n.CountryShort, region) {
				return relays
			}
		}
	}
	for i, n := range relays {
		if n.id() != last.ID {
			continue
		}
		// "Last good" only remembers that a relay carried traffic, not that it
		// was fast. A node measured below the floor must not be promoted over
		// untested relays: that is exactly how the slow node stayed sticky.
		if n.MeasuredBps > 0 && n.MeasuredBps < openvpnMinBps {
			return relays
		}
		if i == 0 {
			return relays
		}
		out := make([]vpnGateNode, 0, len(relays))
		out = append(out, n)
		out = append(out, relays[:i]...)
		out = append(out, relays[i+1:]...)
		return out
	}
	return relays
}

// probeVPNGateLatency measures TCP connect time for every TCP-profiled node.
// UDP profiles are skipped: a TCP handshake says nothing about them, and the
// API's self-reported Ping stays as the ordering fallback. dial is either the
// host's direct dialer or the temporary WARP netstack's, depending on which
// route actually delivered the list.
func probeVPNGateLatency(ctx context.Context, nodes []vpnGateNode, dial func(context.Context, string) (net.Conn, error)) {
	sem := make(chan struct{}, vpnGateProbeJobs)
	var wg sync.WaitGroup
	for i := range nodes {
		if nodes[i].Proto != "tcp" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(n *vpnGateNode) {
			defer wg.Done()
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, vpnGateProbeTimeout)
			defer cancel()
			start := time.Now()
			conn, err := dial(pctx, n.endpoint())
			if err != nil {
				return
			}
			_ = conn.Close()
			n.LatencyMS = time.Since(start).Milliseconds()
		}(&nodes[i])
	}
	wg.Wait()
}

// measureVPNGateLatency probes over the host's own route (the direct-fetch and
// cached-list cases).
func measureVPNGateLatency(ctx context.Context, nodes []vpnGateNode) {
	probeVPNGateLatency(ctx, nodes, func(c context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(c, "tcp", addr)
	})
}

// sortVPNGateNodesByLatency is the picker's order: the residential block before
// the datacenter fleet, then this client's own measured throughput (fast,
// untested, slow), then measured latency, then the API's own ping/score for
// anything the probe could not reach.
func sortVPNGateNodesByLatency(nodes []vpnGateNode) {
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		// Reachability outranks every quality signal. A 家宽 node that timed out
		// is not better than a 机房 node that answered: ranking class first put
		// eight dead relays above two working ones, which reads as "the list is
		// mostly broken".
		am, bm := a.LatencyMS > 0, b.LatencyMS > 0
		if am != bm {
			return am
		}
		if ra, rb := a.classRank(), b.classRank(); ra != rb {
			return ra < rb
		}
		at, bt := vpnGateSpeedTier(a.MeasuredBps), vpnGateSpeedTier(b.MeasuredBps)
		if at != bt {
			return at < bt
		}
		if at != 1 && a.MeasuredBps != b.MeasuredBps {
			return a.MeasuredBps > b.MeasuredBps
		}
		if am && a.LatencyMS != b.LatencyMS {
			return a.LatencyMS < b.LatencyMS
		}
		if !am {
			ap, bp := a.PingMS, b.PingMS
			if ap > 0 && bp > 0 && ap != bp {
				return ap < bp
			}
		}
		if (a.Proto == "tcp") != (b.Proto == "tcp") {
			return a.Proto == "tcp"
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Speed > b.Speed
	})
}

// vpnShortErr trims an error for the one-line popup note.
func vpnShortErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if r := []rune(s); len(r) > 60 {
		s = string(r[:60]) + "…"
	}
	return s
}

// vpnGateCountry is one selectable egress country, derived from the pool rather
// than a hardcoded list: offering a country no live node serves would only
// produce a connect that fails after a full candidate round.
type vpnGateCountry struct {
	CC    string
	Name  string
	Count int
	// Responded is how many nodes answered the local TCP probe, and MinLatency
	// is the best measured round-trip. Countries with a measurement sort ahead
	// of the ones that could not be probed, exactly like the phone client.
	Responded  int
	MinLatency int64
}

func vpnGateCountries(nodes []vpnGateNode) []vpnGateCountry {
	byCC := map[string]*vpnGateCountry{}
	for _, n := range nodes {
		cc := strings.ToUpper(n.CountryShort)
		if cc == "" {
			continue
		}
		c, ok := byCC[cc]
		if !ok {
			c = &vpnGateCountry{CC: cc, Name: n.CountryLong}
			byCC[cc] = c
		}
		c.Count++
		if n.LatencyMS > 0 {
			c.Responded++
		}
		// Ordering uses the same display latency as the phone picker: the
		// measured handshake when there is one, otherwise the self-reported
		// value, so countries sort sensibly before the probe finishes. The
		// responded count stays measured-only.
		lat := n.LatencyMS
		if lat <= 0 {
			lat = int64(n.PingMS)
		}
		if lat > 0 && (c.MinLatency == 0 || lat < c.MinLatency) {
			c.MinLatency = lat
		}
	}
	out := make([]vpnGateCountry, 0, len(byCC))
	for _, c := range byCC {
		out = append(out, *c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		am, bm := a.MinLatency > 0, b.MinLatency > 0
		if am != bm {
			return am
		}
		if am && a.MinLatency != b.MinLatency {
			return a.MinLatency < b.MinLatency
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Name < b.Name
	})
	return out
}

// probeResult is one node's measured state for this session, keyed by id so a
// pool rebuild (which recreates every vpnGateNode) cannot lose it.
type probeResult struct {
	State string // "ok" | "fail"
	MS    int64
	Bps   int64
	Err   string
}

// fetchVPNGateViaSubscription fetches the VPN Gate list through an imported
// node. It is the subscription-mode counterpart of fetchVPNGateNodesViaWARP:
// the same subscription node the session will use carries the request, so a
// network where vpngate.net is blocked directly still gets a fresh list, and
// the mode never has to build a WARP tunnel it promised not to use.
//
// The list is returned WITHOUT a latency column on purpose. A SOCKS handshake
// through one subscription node answers in ~1 ms because mihomo replies as soon
// as the outbound is accepted, not when the tunnel's first byte lands; painting
// that as "1ms" would rank dead relays first. The pool is ordered by line class
// + this client's measured speed + the API's own ping, and 延迟测试 fills exact
// numbers with a real OpenVPN handshake.
func fetchVPNGateViaSubscription(ctx context.Context, proxies []ProxySpec, active string) ([]vpnGateNode, error) {
	if len(proxies) == 0 {
		return nil, fmt.Errorf("订阅模式还没有导入节点，请先在「节点」页导入订阅")
	}
	var out []vpnGateNode
	err := withTempCore(ctx, "订阅节点抓取", func(mixedPort, apiPort int) []byte {
		return subscriptionCarrierConfig(proxies, active, mixedPort, apiPort)
	}, func(mixedPort, _ int) error {
		raw, err := fetchVPNGateViaProxy(ctx, mixedPort)
		if err != nil {
			return err
		}
		nodes := parseVPNGateCSV(raw)
		if len(nodes) == 0 {
			return fmt.Errorf("VPN Gate 返回的列表为空")
		}
		_, _ = enrichVPNGateClasses(ctx, vpnGateProxyClient(mixedPort, 15*time.Second), nodes)
		sortVPNGateNodesByLatency(nodes)
		out = nodes
		return nil
	})
	return out, err
}
