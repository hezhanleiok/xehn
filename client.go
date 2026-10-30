package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xhwarp/warp-client/internal/cache"
	"github.com/xhwarp/warp-client/internal/core"
)

// ---------------------------------------------------------------------------
// The client layer: a thin state machine on top of the warpscout engine
// (register + scan) and the embedded mihomo core. It is what the upcoming GUI
// will drive, so everything here is written against the cache and core packages
// rather than the terminal.
// ---------------------------------------------------------------------------

const (
	// appName is the program's identity on disk and on the wire: the log file,
	// the %APPDATA% fallback folder and the User-Agent all use it, so it stays
	// lower case and free of spaces.
	appName = "xehn"
	// productName is what the user reads — About page, diagnostics header.
	productName = "XEHN"
	coreDirName = "core"
	stateName   = "state.json"
	// scanTTL is how long a scan result stays "fresh" before a connect re-scans.
	scanTTL = 6 * time.Hour
)

// appDir returns the client's working directory (created on demand).
//
// It honours the WARP_CLIENT_HOME environment variable first, so the client can
// run portably (e.g. from a USB stick or alongside the binary) and so tests can
// point it at a sandbox-writable path. With it unset it falls back to the OS
// config dir: %APPDATA%\xehn on Windows.
func appDir() (string, error) {
	if home := os.Getenv("WARP_CLIENT_HOME"); home != "" {
		if err := os.MkdirAll(home, 0o755); err != nil {
			return "", err
		}
		return home, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(dir, appName)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

func accountPath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "warpscout-account.json"), nil
}

func coreDir() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, coreDirName), nil
}

func statePath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, stateName), nil
}

// clientState is persisted between invocations so status can report the active
// endpoint and the disconnect can restore the exact prior system-proxy state.
type clientState struct {
	Proto     string `json:"proto"`
	Endpoint  string `json:"endpoint"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Country   string `json:"country,omitempty"`
	Colo      string `json:"colo,omitempty"`
	NodeCity  string `json:"node_city,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	TunLatMS  int64  `json:"tun_latency_ms,omitempty"`
	LossPct   string `json:"loss,omitempty"`
	Connected bool   `json:"connected"`
	MixedPort int    `json:"mixed_port"`
	APIPort   int    `json:"api_port"`
	CorePID   int    `json:"core_pid,omitempty"`
	TUN       bool   `json:"tun"`
	AllowLan  bool   `json:"allow_lan,omitempty"`
	Family    string `json:"family,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
	ProxySnap []byte `json:"proxy_snapshot,omitempty"`
	// ProxyWarn records why the WinINET proxy edit failed while the tunnel
	// itself is verified working (e.g. antivirus proxy-hijack heuristics
	// blocking the registry write). Empty means the proxy was set normally.
	ProxyWarn string `json:"proxy_warn,omitempty"`
	// NoProxy records that -no-proxy deliberately left the host's own proxy
	// alone. The health guard must not read "the system proxy is not ours" as
	// "the session was taken over" for such a session — it never was ours.
	NoProxy bool `json:"no_proxy,omitempty"`
	// Routing and DNS belong to the session, not to the process that started
	// it: the health guard rebuilds a session from state.json alone, and
	// without these a repair quietly fell back to "everything proxied" and
	// dropped DNS leak protection — the browser kept working, the split
	// tunnelling and the tunnelled resolver did not.
	ProxyMode    string `json:"proxy_mode,omitempty"`
	DNS          string `json:"dns,omitempty"`
	DNSLeak      bool   `json:"dns_leak,omitempty"`
	DomainDirect string `json:"domain_direct,omitempty"`
	DomainProxy  string `json:"domain_proxy,omitempty"`
	// Psiphon exit mode (V1): recorded so disconnect can stop the external
	// Psiphon process and the status loop can surface its state.
	PsiphonMode      bool `json:"psiphon_mode,omitempty"`
	PsiphonPID       int  `json:"psiphon_pid,omitempty"`
	PsiphonSocksPort int  `json:"psiphon_socks_port,omitempty"`
	// PsiphonRegion is the egress region this session's Psiphon was launched
	// with ("" = automatic), so a guard restart rebuilds the same exit.
	PsiphonRegion string `json:"psiphon_region,omitempty"`
	// OpenVPN exit (V2): the relay this session exits through. The node carries
	// its whole profile, so a guard repair can re-render the same tunnel even
	// if the VPN Gate cache has rotated since the connect.
	OpenVPNMode   bool         `json:"openvpn_mode,omitempty"`
	OpenVPNRegion string       `json:"openvpn_region,omitempty"`
	OpenVPNNode   *vpnGateNode `json:"openvpn_node,omitempty"`
	// MeasuredBps is the connect-time throughput of this session's exit. It is
	// runtime-only: state.json must not carry a stale speed into a later status
	// read, and the cross-connect speed memory lives in vpngate-speeds.json.
	MeasuredBps int64 `json:"-"`
}

func loadState() (clientState, error) {
	var s clientState
	p, err := statePath()
	if err != nil {
		return s, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, err
	}
	return s, nil
}

func saveState(s clientState) error {
	p, err := statePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Write-then-rename: the GUI reads this file every two seconds, and a
	// truncate-then-write briefly exposes an empty/partial file. A parse error
	// there used to blank the connected state for a whole poll (tile fell back
	// to the LAN address, flag to the local region).
	tmp, err := os.CreateTemp(filepath.Dir(p), ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Chmod(0o600)
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

// ensureAccount loads the cached account, or registers a fresh one when none
// exists or the caller asks to rotate. Loading means applying: the connect
// pipeline renders configs from the package globals (warpPrivateKey and
// friends), so an account that is merely validated but never applied leaves
// the hardcoded default device in place — every "warm" connect would silently
// ride a stranger's shared key instead of the registered one.
func ensureAccount(ctx context.Context, opts options) error {
	path, err := accountPath()
	if err != nil {
		return err
	}
	opts.accountPath = path
	if opts.freshAccount {
		return runRegisterCmd(ctx, opts)
	}
	if a, err := loadAccount(path); err == nil {
		applyAccount(a)
		return nil
	}
	return runRegisterCmd(ctx, opts)
}

// scanResult is the cacheable projection of a scan we keep for reconnect.
type cachedEndpoint struct {
	Endpoint  string  `json:"endpoint"`
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	Colo      string  `json:"colo"`
	NodeCity  string  `json:"node_city"`
	NodeISO   string  `json:"node_iso"`
	EpPingMS  int64   `json:"endpoint_ping_ms"`
	TunPingMS int64   `json:"tun_ping_ms"`
	Loss      float32 `json:"loss"`
	Speed     float64 `json:"speed_mbps"`
	Working   bool    `json:"working"`
}

type cachedScan struct {
	Proto   string           `json:"proto"`
	IPv6    bool             `json:"ipv6"`
	At      time.Time        `json:"at"`
	Results []cachedEndpoint `json:"results"`
}

func scanCacheKey(proto string, ipv6 bool) string {
	fam := "v4"
	if ipv6 {
		fam = "v6"
	}
	return "scan-" + proto + "-" + fam
}

// scanKeyFor is the cache identity of a scan: the plain protocol for ordinary
// runs, but "wwarp" for any chained scan (-through set), because the numbers
// mean something different there — endpoints measured from inside the outer
// tunnel, not from the host. Sharing one key would let a chained scan overwrite
// the plain cache (and a plain connect then dial endpoints it never measured
// the way it uses them).
func scanKeyFor(opts options) string {
	if opts.through != "" {
		return protoWWarp
	}
	return opts.proto
}

// runCachedScan returns endpoints from a fresh cache, or scans and caches them.
// The returned run is the run the *connect config* renders: the inner protocol
// for a chain (the outer half comes from the `outer` nest), the protocol
// itself otherwise.
func runCachedScan(ctx context.Context, opts options) ([]cachedEndpoint, protoRun, error) {
	store, err := cache.Open(cache.Options{TTL: scanTTL})
	if err != nil {
		return nil, protoRun{}, err
	}
	key := scanCacheKey(scanKeyFor(opts), opts.ipv6)
	if !opts.scanNow {
		if raw, ok := store.Get(key); ok {
			var cs cachedScan
			if json.Unmarshal(raw, &cs) == nil {
				if opts.through != "" {
					stageMsg(fmt.Sprintf("[%s] 使用缓存端点（%d 个，扫描于 %s）",
						protoLabel(opts.proto), len(cs.Results), cs.At.Format("01-02 15:04")))
					return cs.Results, mustParseProto(opts.innerProto), nil
				}
				if cs.Proto == opts.proto {
					stageMsg(fmt.Sprintf("[%s] 使用缓存端点（%d 个，扫描于 %s）",
						protoLabel(opts.proto), len(cs.Results), cs.At.Format("01-02 15:04")))
					return cs.Results, mustParseProto(opts.proto), nil
				}
			}
		}
	}

	results, run, err := doScan(ctx, opts)
	if err != nil {
		return nil, run, err
	}
	stageMsg(fmt.Sprintf("[%s] 端点扫描完成（%d 个结果）", protoLabel(opts.proto), len(results)))
	// The cache's Proto records the user-facing protocol the scan ran under
	// ("wwarp" for chains) so a later read can tell the two apart.
	cs := cachedScan{Proto: scanKeyFor(opts), IPv6: opts.ipv6, At: time.Now(), Results: results}
	if raw, err := json.Marshal(cs); err == nil {
		_ = store.Put(key, raw)
	}
	return results, run, nil
}

func mustParseProto(p string) protoRun {
	r, err := parseProto(p)
	if err != nil {
		return protoRuns[0]
	}
	return r
}

// doScan runs the existing warpscout scan headlessly and projects the working
// endpoints into cachedEndpoint records.
func doScan(ctx context.Context, opts options) ([]cachedEndpoint, protoRun, error) {
	if err := ensureAccount(ctx, opts); err != nil {
		return nil, protoRun{}, err
	}
	run, ips, err := setupScan(opts)
	if err != nil {
		return nil, run, err
	}
	if run.isMASQUE() && masqueAcct == nil {
		return nil, run, fmt.Errorf("%s holds no MASQUE device: run \"register\" again", opts.accountPath)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if opts.through != "" {
		n, err := dialOuter(ctx, opts, time.Duration(opts.timeoutSec)*time.Second)
		if err != nil {
			return nil, run, err
		}
		defer func() {
			n.tunnel.Close()
			// A closed nest must not capture later dials in this process:
			// newWGTunnel routes through the `outer` global when set, so a
			// stale one makes the next chained scan bind inside a torn
			// netstack ("bind udp 172.16.0.2:0: bad local address").
			outer = nil
		}()
		outer = n
	}

	ph, err := runScan(ctx, opts, run, ips, time.Duration(opts.timeoutSec)*time.Second, plainEmit)
	if err != nil {
		return nil, run, err
	}
	if filtered(opts) {
		ph = applyFilters(ph, opts)
	}

	return projectCacheEndpoints(ph), run, nil
}

// projectCacheEndpoints projects a finished scan into the cacheable records
// connect consumes, best endpoint first — the order connect tries them in.
// Shared by the connect pipeline's internal scan and the standalone scan
// command so both write identical entries.
func projectCacheEndpoints(ph phaseResult) []cachedEndpoint {
	working := workingSorted(ph.results)
	out := make([]cachedEndpoint, 0, len(working))
	for _, r := range working {
		out = append(out, cachedEndpoint{
			Endpoint:  r.endpoint,
			IP:        r.ip.String(),
			Country:   exitRegion(r.exit),
			Colo:      exitColo(r.exit),
			NodeCity:  r.exit.coloCity,
			NodeISO:   r.exit.coloISO,
			EpPingMS:  r.epPing.Milliseconds(),
			TunPingMS: r.tunPing.Milliseconds(),
			Loss:      r.loss,
			Speed:     r.speed,
			Working:   r.ok,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Full mihomo config rendering. warpscout already renders the `proxies:` block
// for a single endpoint; a running client needs mixed-port, proxy-groups,
// rules, dns and optionally a tun block around it.
// ---------------------------------------------------------------------------

// renderClientConfig builds a complete config.yaml from the selected endpoint.
func renderClientConfig(opts options, ce cachedEndpoint, run protoRun) ([]byte, error) {
	if opts.mixedPort == 0 {
		opts.mixedPort = core.DefaultMixedPort
	}
	if opts.apiPort == 0 {
		opts.apiPort = core.DefaultAPIPort
	}

	// Reuse warpscout's proxy renderer for one endpoint by rebuilding an
	// options struct with the endpoint pinned and mihomo type selected.
	renderOpts := opts
	renderOpts.confType = confTypeMihomo

	var (
		proxyBody  string
		egressName string
		// baseName is non-empty exactly when the two-axis shape is rendered:
		// Psiphon/OpenVPN ride ON this base-protocol outbound, which carries
		// their own dials. Empty means the legacy endpoint-less render.
		baseName string
	)
	switch {
	case opts.openvpnMode:
		// V2 OpenVPN exit: the final egress is a VPN Gate relay rendered as
		// mihomo's native openvpn outbound, dialled through the base protocol.
		// A chain would need a third outbound and none of the VPN Gate relays
		// is worth that complexity; the connect path refuses it, and this guard
		// keeps a stale chain from producing an unparsable config.
		if outer != nil {
			return nil, fmt.Errorf("OpenVPN 出口不支持嵌套协议")
		}
		if opts.openvpnNode == nil {
			return nil, fmt.Errorf("OpenVPN 出口缺少节点")
		}
		profile, perr := parseOVPNProfile(opts.openvpnNode.Profile)
		if perr != nil {
			return nil, fmt.Errorf("OpenVPN 节点配置无效: %w", perr)
		}
		endpoint := ce.Endpoint
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			endpoint = net.JoinHostPort(endpoint, strconv.Itoa(primaryWarpPorts[0]))
		}
		baseName = mihomoName(run)
		base, err := mihomoProxy(renderOpts, baseName, endpoint, run, opts.mtu, confDNSList(opts))
		if err != nil {
			return nil, err
		}
		exit := append(mihomoOpenVPNProxy(profile, nestedMTU(opts.mtu)), kv{"dialer-proxy", quoted(baseName)})
		proxyBody = renderProxiesYAML([][]kv{base, exit})
		egressName = mihomoOpenVPNName
	case opts.psiphonMode:
		// V1 Psiphon exit: the client's egress is Psiphon's localhost socks5,
		// rendered alongside the base protocol that Psiphon dials its own
		// servers through (without it Psiphon is a direct dial, which the
		// networks V1 targets block outright).
		endpoint := ""
		if ce.Endpoint != "" {
			endpoint = ce.Endpoint
			if _, _, err := net.SplitHostPort(endpoint); err != nil {
				endpoint = net.JoinHostPort(endpoint, strconv.Itoa(primaryWarpPorts[0]))
			}
		}
		proxies, err := mihomoProxies(renderOpts, endpoint, run)
		if err != nil {
			return nil, err
		}
		proxyBody = renderProxiesYAML(proxies)
		egressName = mihomoPsiphonName
		if endpoint != "" {
			baseName = mihomoName(run)
			if outer != nil {
				baseName += mihomoChainSuffix
			}
		}
	default:
		endpoint := ce.Endpoint
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			endpoint = net.JoinHostPort(endpoint, strconv.Itoa(primaryWarpPorts[0]))
		}
		proxYAML, err := renderMihomoConf(renderOpts, endpoint, run)
		if err != nil {
			return nil, err
		}
		proxyBody = strings.TrimPrefix(string(proxYAML), "proxies:\n")
		egressName = mihomoName(run)
		if outer != nil {
			egressName += mihomoChainSuffix
		}
	}

	var b strings.Builder
	b.WriteString("# generated by xehn (" + appName + ")\n")
	fmt.Fprintf(&b, "mixed-port: %d\n", opts.mixedPort)
	if opts.psiphonMode && baseName != "" {
		// Dedicated inbound for Psiphon's upstream. Routing by inbound is a
		// deterministic loop guard (Psiphon never reaches itself), independent
		// of whether mihomo can resolve the connecting process on this host.
		fmt.Fprintf(&b, "socks-port: %d\n", underlaySocksPort(opts.mixedPort))
	}
	fmt.Fprintf(&b, "allow-lan: %t\n", opts.allowLan)
	if opts.allowLan {
		b.WriteString("bind-address: \"*\"\n")
	}
	fmt.Fprintf(&b, "mode: %s\n", mihomoMode(opts))
	b.WriteString("log-level: info\n")
	fmt.Fprintf(&b, "ipv6: %t\n", opts.ipFamily() != famV4)
	fmt.Fprintf(&b, "external-controller: 127.0.0.1:%d\n", opts.apiPort)
	if dns := confDNSList(opts); len(dns) > 0 {
		b.WriteString("dns:\n  enable: true\n")
		fmt.Fprintf(&b, "  ipv6: %t\n", opts.ipFamily() != famV4)
		if dnsLeakProtected(opts) {
			// Resolver queries follow the rule set, and the resolvers used to
			// reach the proxy servers are declared separately. Without this,
			// mihomo answers upstream directly even while traffic is proxied.
			b.WriteString("  respect-rules: true\n  proxy-server-nameserver:\n")
			for _, s := range dns {
				fmt.Fprintf(&b, "    - %s\n", s)
			}
		}
		b.WriteString("  nameserver:\n")
		for _, s := range dns {
			fmt.Fprintf(&b, "    - %s\n", s)
		}
		// Bypass mode splits resolution as well as traffic: CN domains are
		// answered by a domestic resolver, directly. Without this every lookup —
		// baidu.com included — is answered through the tunnel, which costs a
		// round trip per domain and returns answers computed for an overseas
		// client, so "direct" traffic still feels slow.
		if opts.proxyMode == modeBypass && geoDataReady() {
			cn, intl := domesticDNS(opts), foreignDNS(opts)
			if cn != "" || intl != "" {
				b.WriteString("  nameserver-policy:\n")
				if cn != "" {
					fmt.Fprintf(&b, "    \"geosite:cn\": %s\n", cn)
				}
				if intl != "" {
					fmt.Fprintf(&b, "    \"geosite:geolocation-!cn\": %s\n", intl)
				}
			}
		}
		// An external DNS listener is only useful for TUN-mode hijack, and a
		// fixed 5353 bind fails outright on hosts with reserved port ranges —
		// mihomo's internal resolver works without it.
		if opts.tunMode {
			b.WriteString("  listen: 127.0.0.1:1053\n")
		}
	}
	if opts.tunMode {
		b.WriteString("tun:\n  enable: true\n  stack: gvisor\n  auto-route: true\n  auto-detect-interface: true\n")
		if dnsLeakProtected(opts) {
			// Covers applications that ignore the system resolver: their port
			// 53 traffic enters the tunnel and is answered by mihomo instead
			// of escaping to the local network's DNS.
			b.WriteString("  dns-hijack:\n    - any:53\n")
		}
	}

	b.WriteString("proxies:\n")
	b.WriteString(proxyBody)
	b.WriteString("\nproxy-groups:\n")
	if opts.openvpnMode {
		fmt.Fprintf(&b, "  - name: %s\n    type: select\n    proxies:\n      - %s\n", mihomoOpenVPNGroup, egressName)
		b.WriteString("rules:\n")
		for _, r := range routeRules(opts, mihomoOpenVPNGroup) {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
		fmt.Fprintf(&b, "  - MATCH,%s\n", routingFallback(opts, mihomoOpenVPNGroup))
		return []byte(b.String()), nil
	}
	if opts.psiphonMode {
		if baseName != "" {
			fmt.Fprintf(&b, "  - name: %s\n    type: select\n    proxies:\n      - %s\n      - DIRECT\n", mihomoBaseGroup, baseName)
		}
		fmt.Fprintf(&b, "  - name: %s\n    type: select\n    proxies:\n      - %s\n", mihomoExitGroup, egressName)
		b.WriteString("rules:\n")
		if baseName != "" {
			// Psiphon's own dials (its dedicated inbound) go to the base
			// protocol; everything else — client traffic — exits via Psiphon.
			fmt.Fprintf(&b, "  - IN-TYPE,SOCKS,%s\n", mihomoBaseGroup)
			fmt.Fprintf(&b, "  - PROCESS-NAME,psiphon.exe,%s\n", mihomoBaseGroup)
		}
		for _, r := range routeRules(opts, mihomoExitGroup) {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
		fmt.Fprintf(&b, "  - MATCH,%s\n", routingFallback(opts, mihomoExitGroup))
		return []byte(b.String()), nil
	}
	fmt.Fprintf(&b, "  - name: WARP\n    type: select\n    proxies:\n      - %s\n      - DIRECT\n", egressName)
	fmt.Fprintf(&b, "  - name: auto\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies:\n      - %s\n", egressName)
	b.WriteString("rules:\n")
	for _, r := range routeRules(opts, "WARP") {
		fmt.Fprintf(&b, "  - %s\n", r)
	}
	fmt.Fprintf(&b, "  - MATCH,%s\n", routingFallback(opts, "WARP"))
	return []byte(b.String()), nil
}

// mihomoMode is the core's routing mode. "Direct" is the only value the core
// needs to be told: it bypasses the proxy entirely. Everything else runs as
// "rule", where the rules below — and, when there are none, the MATCH fallback
// — send traffic to the exit. Global is deliberately NOT the core's `global`
// mode: that mode routes through mihomo's own GLOBAL selector, whose default
// pick is the first proxy in the file, which for a Psiphon session is the
// underlay rather than the exit.
func mihomoMode(o options) string {
	if o.proxyMode == modeDirect {
		return "direct"
	}
	return "rule"
}

// dnsLeakProtected is the precondition for the DNS hardening block: there has
// to be a resolver to send and a proxy path for it to follow.
func dnsLeakProtected(o options) bool {
	return o.dnsLeak && !o.noDNS && o.proxyMode != modeDirect
}

// routeRules renders the rules the selected preset describes. The order is
// DNS-server routes, proxy domains, direct domains, then the region split;
// blacklisted-only mode is the one preset whose fallback is DIRECT.
// quicBlockRule drops QUIC (HTTP/3) for everything that is not a mainland
// destination. A UDP flow cannot be matched by domain, so HTTP/3 either slips
// past the rule set or performs badly over the tunnel; the CN exclusion keeps
// HTTP/3 working for the sites where it is actually an improvement (Bilibili
// and friends). This is the rule the community configs ship, and v2rayN blocks
// udp/443 in every preset.
const quicBlockRule = "AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT"

// quicBlockRuleAll is the version without the CN exclusion, for global mode:
// there is no geo rule set to ask, and everything not local belongs in the
// tunnel anyway.
const quicBlockRuleAll = "AND,(AND,(DST-PORT,443),(NETWORK,UDP)),REJECT"

// privateRules keep the LAN local. A router page, a NAS or a printer does not
// exist at the exit, and routing them through it is the difference between
// "works" and "works until you open 192.168.1.1". Explicit CIDRs rather than
// GEOIP,private: no dependency on a database, and the list is short enough to
// read.
func privateRules() []string {
	return []string{
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR6,fc00::/7,DIRECT,no-resolve",
		"IP-CIDR6,fe80::/10,DIRECT,no-resolve",
		"DOMAIN-SUFFIX,local,DIRECT",
		"DOMAIN-SUFFIX,lan,DIRECT",
		"DOMAIN-SUFFIX,home.arpa,DIRECT",
	}
}

// cnDNSDomains are the DoH/DoT hostnames of the public DNS services in mainland
// China. They have to be reached directly for the same reason their IPs do:
// resolving the resolver through the tunnel defeats the split.
var cnDNSDomains = []string{"alidns.com", "doh.pub", "dot.pub", "360.cn", "onedns.net"}

func routeRules(o options, egress string) []string {
	if o.proxyMode == modeDirect {
		// The core bypasses every rule in direct mode: no rule set of its own.
		return nil
	}
	geo := geoDataReady()
	var rules []string
	if o.proxyMode == modeGlobal {
		// Global keeps the LAN and the QUIC block; the MATCH fallback sends
		// everything else to the exit.
		rules = append(rules, quicBlockRuleAll)
		return append(rules, privateRules()...)
	}
	if geo {
		rules = append(rules, quicBlockRule)
	}
	if dnsLeakProtected(o) {
		rules = append(rules, dnsServerRules(o, egress)...)
	}
	rules = append(rules, privateRules()...)
	for _, d := range o.domainProxy {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+","+egress)
	}
	if o.proxyMode != modeBlacklist {
		// Blacklist mode's fallback is already DIRECT, so a direct-domain rule
		// would be dead weight there; the field is disabled to match.
		for _, d := range o.domainDirect {
			rules = append(rules, "DOMAIN-SUFFIX,"+d+",DIRECT")
		}
	}
	if o.proxyMode == modeBypass && geo {
		// The whitelist v2rayN ships, in mihomo syntax: Google first (some of
		// its domains live in CN categories), then the CN DNS endpoints, then
		// mainland domains and IPs, then everything else through the exit.
		// Emitted only when the data is on disk: mihomo tries to download
		// geosite.dat when it is missing and then refuses the whole config,
		// which would read as "the client is broken".
		rules = append(rules, "GEOSITE,google,"+egress)
		for _, d := range cnDNSDomains {
			rules = append(rules, "DOMAIN-SUFFIX,"+d+",DIRECT")
		}
		rules = append(rules,
			"GEOSITE,cn,DIRECT",
			// no-resolve: without it mihomo resolves the target just to test
			// GeoIP, and that lookup travels through the tunnel — the exact
			// per-domain round trip this preset is supposed to avoid. GEOSITE
			// already covers CN domains; this rule is for literal IPs.
			"GEOIP,CN,DIRECT,no-resolve",
			"GEOSITE,geolocation-!cn,"+egress)
	}
	return rules
}

// routingFallback is where unmatched traffic goes for each preset.
func routingFallback(o options, egress string) string {
	if o.proxyMode == modeBlacklist || o.proxyMode == modeDirect {
		return "DIRECT"
	}
	return egress
}

// dnsServerRules pins the configured resolvers' own addresses to the tunnel.
// respect-rules only routes the DNS *connection* by rules, so in blacklist mode
// the MATCH,DIRECT fallback would otherwise send upstream queries out directly
// and defeat the leak protection. Private resolvers stay direct - a LAN DNS box
// is not reachable from the exit.
func dnsServerRules(o options, egress string) []string {
	var rules []string
	for _, s := range confDNSList(o) {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		target := egress
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
			target = "DIRECT"
		}
		// A domestic resolver has to stay reachable directly: bypass mode asks it
		// for CN domains, and tunnelling that query is the slowness the preset
		// exists to avoid.
		if o.proxyMode == modeBypass && isDomesticResolver(addr.String()) {
			target = "DIRECT"
		}
		if addr.Is6() {
			rules = append(rules, "IP-CIDR6,"+addr.String()+"/128,"+target)
		} else {
			rules = append(rules, "IP-CIDR,"+addr.String()+"/32,"+target)
		}
	}
	return rules
}

// domesticResolvers are the public DNS services inside mainland China. Only
// these are trusted to answer CN lookups directly; everything else keeps
// following the tunnel so foreign answers stay unpoisoned.
var domesticResolvers = map[string]bool{
	"223.5.5.5":         true,
	"223.6.6.6":         true,
	"119.29.29.29":      true,
	"182.254.116.116":   true,
	"114.114.114.114":   true,
	"114.114.115.115":   true,
	"180.76.76.76":      true,
	"2400:3200::1":      true,
	"2400:3200:baba::1": true,
}

func isDomesticResolver(s string) bool { return domesticResolvers[s] }

// domesticDNS returns the first configured resolver that lives in mainland
// China, or "" when the user configured only foreign ones (in which case there
// is nothing to split with and the policy is skipped).
func domesticDNS(o options) string {
	for _, s := range confDNSList(o) {
		if domesticResolvers[s] {
			return s
		}
	}
	return ""
}

// foreignDNS is the mirror image: the first configured resolver outside
// mainland China, used for the domains this preset sends through the tunnel. A
// CN resolver answers those with CN-optimised (and sometimes poisoned) results,
// so the lookup has to travel with the traffic.
func foreignDNS(o options) string {
	for _, s := range confDNSList(o) {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if domesticResolvers[s] || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		return s
	}
	return ""
}

// geoDataReady reports whether the geo databases the rules need are on disk.
// GEOSITE and GEOIP are separate files; requiring both is what keeps a half
// installed database from failing the whole config at load time.
//
// The size floor matters: a failed download leaves a truncated file, and a
// present-but-empty database fails the config exactly like a missing one —
// only later, at connect time, with a much worse error message.
func geoDataReady() bool {
	dir, err := coreDir()
	if err != nil {
		return false
	}
	if core.GeoDataReady(dir) {
		return true
	}
	// Older installs may carry the legacy geoip.dat instead of geoip.metadb.
	const floor = 512 * 1024
	bigEnough := func(name string) bool {
		fi, err := os.Stat(filepath.Join(dir, name))
		return err == nil && fi.Size() >= floor
	}
	return bigEnough("geosite.dat") && bigEnough("geoip.dat")
}

// dataPlaneSources are the URLs a data-plane probe proves itself with, tried in
// order until one answers. Every one is a hostname, so a completed request
// through the mixed port exercises DNS + TCP + TLS + HTTP inside the tunnel in
// one round-trip - the only kind of evidence that distinguishes a live tunnel
// from one whose handshake succeeded and whose packets then went nowhere.
//
// Three of them because each can refuse a given egress for reasons that have
// nothing to do with the tunnel: Cloudflare 403s some CN exits, and an echo
// service can simply be down. One answered request is proof; three refusals
// are not proof of anything, which is why all three failing is a failure.
var dataPlaneSources = []string{
	"https://speed.cloudflare.com/meta",
	// The IP echo sits before Cloudflare's trace on purpose: VPN Gate exits
	// intermittently cannot reach Cloudflare at all, and the probe budget used
	// to be spent entirely on the two Cloudflare sources before this one was
	// tried. ipify answers with the exit IP, which is what the home tile needs;
	// the trace only adds colo/city when Cloudflare is reachable.
	"https://api.ipify.org",
	"https://www.cloudflare.com/cdn-cgi/trace",
}

// probeTimeout bounds one source's round-trip. Deliberately short: with a dead
// endpoint the attempt hangs for the whole timeout, and a probe that walks
// three sources is otherwise long enough to look like a stalled connect.
const probeTimeout = 5 * time.Second

// probeBudget caps one whole probe regardless of how many sources it walks. A
// healthy tunnel answers the first source in well under a second, so the budget
// only ever bites on the failing path - and there it is what decides how soon a
// torn-down endpoint is noticed: every second of extra per-probe time is a
// second of "connected" over a browser that loads nothing.
const probeBudget = 9 * time.Second

// fetchExitProbe queries the live tunnel's exit metadata (IP, colo, country)
// through the local mixed port, so status reflects the running connection.
//
// It answers exactly one question: does a real request through this proxy
// complete? Every mihomo state short of that - a black-holed tunnel answering
// the CONNECT with its own 502/504, an edge 403ing this egress, a resolver that
// cannot resolve - is a failure here, never a "connected" whose payload is a
// browser that cannot load a page. Returning without an error means at least
// one source answered 2xx through the tunnel.
func fetchExitProbe(mixedPort int) (clientState, error) {
	var out clientState
	proxyURL := "http://127.0.0.1:" + strconv.Itoa(mixedPort)
	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyURL)),
		},
	}
	var (
		lastErr  error
		lastCode int
		proven   bool
	)
	started := time.Now()
	for _, u := range dataPlaneSources {
		if time.Since(started) > probeBudget {
			// Out of budget: whatever else the sources might have said, the
			// answer a user waiting for the internet can use is already no.
			if lastErr == nil && lastCode == 0 {
				lastErr = fmt.Errorf("probe via tunnel: no source answered within %s", probeBudget)
			}
			break
		}
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		// speed.cloudflare.com/meta answers 403 (or an empty {}) without a
		// Referer; every other /meta caller (fetchMeta, the speed test) sets
		// metaReferer. Without it the primary source always refuses, so the
		// probe could never populate colo/country/city from a live tunnel.
		if strings.HasPrefix(u, "https://speed.cloudflare.com") {
			req.Header.Set("Referer", metaReferer)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		raw := string(body[:n])
		code := resp.StatusCode
		if code < 200 || code >= 300 {
			// Not evidence. 502/504 is mihomo reporting that its own dial
			// through the tunnel timed out - the canonical dark tunnel - and
			// a 4xx is an edge refusing this exit. Try the next source
			// instead of either trusting or dooming the tunnel on it.
			if lastErr == nil {
				lastCode = code
			}
			continue
		}
		proven = true
		m := parseMeta(raw)
		if m.colo != "" {
			out.Country, out.Colo, out.NodeCity = m.loc, m.colo, m.coloCity
		}
		if m.ip != "" {
			// Cloudflare's meta body carries clientIp, so the primary source
			// alone answers IP + colo + country and we can stop here.
			out.ExitIP = m.ip
		}
		if out.ExitIP == "" {
			if ip := traceField(raw, "ip"); ip != "" {
				out.ExitIP = ip
			}
		}
		if out.ExitIP == "" {
			// ipify answers with the bare address as the whole body.
			if ip := strings.TrimSpace(raw); net.ParseIP(ip) != nil {
				out.ExitIP = ip
			}
		}
		if out.ExitIP != "" {
			break
		}
	}
	if !proven {
		if lastErr != nil {
			return out, lastErr
		}
		return out, fmt.Errorf("probe via tunnel: HTTP %d", lastCode)
	}
	return out, nil
}

// traceField pulls one "key=value" line out of Cloudflare's /cdn-cgi/trace body.
func traceField(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// probeDNSTunnel proves the DNS path through the proxy, which the round-trip
// above only proves implicitly: every source there is a hostname, so a failed
// lookup surfaces as the same generic error a dead tunnel gives. Resolving
// explicitly separates the two, because DNS failing while TCP still connects
// has a different fix (the resolver list) from the tunnel being torn down.
func probeDNSTunnel(mixedPort int) error {
	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL("http://127.0.0.1:" + strconv.Itoa(mixedPort))),
		},
	}
	resp, err := client.Get("https://dns.google/resolve?name=cloudflare.com&type=A")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("DNS over proxy: HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(string(body[:n]), "\"Answer\"") {
		return fmt.Errorf("DNS over proxy: no answer record")
	}
	return nil
}

// fetchV6Probe proves the tunnel carries IPv6 by fetching cloudflare's trace
// from a v6-only literal address through the proxy: no DNS involved, so the
// round-trip exercises exactly the v6 data path.
func fetchV6Probe(mixedPort int) (string, error) {
	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL("http://127.0.0.1:" + strconv.Itoa(mixedPort))),
		},
	}
	resp, err := client.Get("https://[2606:4700:4700::1111]/cdn-cgi/trace")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	for _, line := range strings.Split(string(body[:n]), "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			ip := strings.TrimSpace(v)
			if strings.Contains(ip, ":") {
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("no IPv6 exit in trace reply")
}

// fetchSessionProbe probes a live session with a source its tunnel can reach:
// v6-only sessions use the v6 literal, everything else the hostname sources.
func fetchSessionProbe(mixedPort int, family string) (clientState, error) {
	if family == famV6 {
		ip, err := fetchV6Probe(mixedPort)
		if err != nil {
			return clientState{}, err
		}
		return clientState{ExitIP: ip}, nil
	}
	return fetchExitProbe(mixedPort)
}

// verifyTunnel is the data-plane gate between "the core process is listening"
// and "Connected": a tunnel counts only after a real HTTPS round-trip through
// the mixed port, an IPv6 round-trip when the config asked for v6, and an exit
// IP query. logf receives one line per check so the GUI log can narrate the
// state machine (Handshaking → Tunnel Ready → Data Plane Verification).
func verifyTunnel(opts options, logf func(string)) (clientState, error) {
	family := opts.ipFamily()
	if family == famV6 {
		return verifyTunnelV6Only(opts, logf)
	}
	logf("数据面验证：HTTPS 经隧道访问…")
	probe, perr := fetchExitProbe(opts.mixedPort)
	if perr != nil {
		// The first probe races the WG handshake (whose trigger packet is
		// dropped), so one retry absorbs a healthy-but-slow endpoint.
		time.Sleep(verifyRetryDelay)
		logf("首次探测未通过，重试…")
		probe, perr = fetchExitProbe(opts.mixedPort)
	}
	if perr != nil {
		// Say which half broke. Every probe source is a hostname, so a
		// completed request already implies the resolver worked; an explicit
		// lookup here only separates "DNS is dead" from "the tunnel is dark",
		// which need different fixes and used to look identical in the log.
		if derr := probeDNSTunnel(opts.mixedPort); derr != nil {
			return probe, fmt.Errorf("HTTPS 请求超时/失败（且隧道内 DNS 不可用）: %w (DNS: %v)", perr, derr)
		}
		return probe, fmt.Errorf("HTTPS 请求超时/失败（隧道内 DNS 正常）: %w", perr)
	}
	logf("HTTPS 数据面验证成功")

	// Throughput gate: a tunnel that answers a tiny request but cannot carry a
	// real payload is the "connected but nothing loads" state — a half-dead
	// endpoint that handshakes and then stalls, or an exit throttled to nothing.
	// One meaningful transfer has to complete, so such a tunnel fails HERE, where
	// the candidate loop can rotate, instead of reaching the user as Connected.
	// An OpenVPN exit downloads a larger payload: the same transfer also feeds
	// the speed ranking, and 128 KiB cannot tell a healthy relay from one that
	// merely avoided stalling.
	payloadBytes, payloadTimeout := verifyPayloadBytes, verifyPayloadTimeout
	if opts.openvpnMode {
		payloadBytes, payloadTimeout = openvpnSpeedProbeBytes, openvpnSpeedProbeTimeout
	}
	logf("数据面验证：吞吐（下载载荷）…")
	bps, terr := probeThroughput(opts.mixedPort, payloadBytes, payloadTimeout)
	if terr != nil {
		return probe, fmt.Errorf("隧道能握手但无法传输数据: %w", terr)
	}
	probe.MeasuredBps = bps
	logf("吞吐验证成功")

	// DNS, as its own line: the round-trip above proves it implicitly (every
	// source is a hostname resolved inside the tunnel), so this is a report,
	// not a gate - a third-party lookup service being unreachable must not
	// fail a tunnel that just carried traffic.
	if derr := probeDNSTunnel(opts.mixedPort); derr == nil {
		logf("DNS 数据面验证成功")
	} else {
		logf("提示：DNS 复核服务不可用（" + derr.Error() + "）")
	}

	if family != famV4 {
		logf("数据面验证：IPv6 经隧道访问…")
		if v6, err := fetchV6Probe(opts.mixedPort); err == nil {
			logf("IPv6 数据面验证成功，出口 " + v6)
		} else {
			return probe, fmt.Errorf("IPv6 验证失败: %w", err)
		}
	}

	if probe.ExitIP == "" {
		// The tunnel itself is proven (HTTPS crossed it); only the echo
		// services refused. Report it honestly instead of failing a live
		// tunnel — the status loop keeps retrying the exit fields.
		logf("警告：出口 IP 获取失败（探测源站拒绝），隧道已验证存活")
	} else {
		logf("出口 IP: " + probe.ExitIP)
	}
	return probe, nil
}

// verifyTunnelV6Only is the v6-only gate. The shared probe sources are v4
// hostnames, so a v6-only tunnel would fail them by design; the gate is a
// request to a v6 literal instead, which exercises DNS-free IPv6 end to end.
// Throughput is not re-probed here: the v6 trace round-trip already crossed the
// tunnel with a real TLS payload, and the only v6-literal transfer available is
// that same trace, so a second copy would measure nothing new.
func verifyTunnelV6Only(opts options, logf func(string)) (clientState, error) {
	logf("数据面验证：IPv6 经隧道访问…")
	v6, err := fetchV6Probe(opts.mixedPort)
	if err != nil {
		// Same race as the v4 path: the first packet wakes the WG handshake.
		time.Sleep(verifyRetryDelay)
		logf("首次 IPv6 探测未通过，重试…")
		v6, err = fetchV6Probe(opts.mixedPort)
	}
	if err != nil {
		if derr := probeDNSTunnel(opts.mixedPort); derr != nil {
			return clientState{}, fmt.Errorf("IPv6 请求超时/失败（且隧道内 DNS 不可用）: %w (DNS: %v)", err, derr)
		}
		return clientState{}, fmt.Errorf("IPv6 请求超时/失败（隧道内 DNS 正常）: %w", err)
	}
	logf("IPv6 数据面验证成功，出口 " + v6)
	if derr := probeDNSTunnel(opts.mixedPort); derr == nil {
		logf("DNS 数据面验证成功")
	} else {
		logf("提示：DNS 复核服务不可用（" + derr.Error() + "）")
	}
	return clientState{ExitIP: v6}, nil
}

// verifyPayloadBytes / verifyPayloadTimeout are the throughput floor the connect
// gate enforces: 128 KiB within 12s ≈ 11 KiB/s. Deliberately low — a slow but
// usable tunnel must pass, while a stalled one (which delivers ~0) must not.
const (
	verifyPayloadBytes   = 128 * 1024
	verifyPayloadTimeout = 12 * time.Second
)

// Psiphon exit speed floor. The exit server decides its own throughput, and the
// measured spread on ONE underlay was ~150 KB/s to ~700 KB/s — a fast underlay
// behind a slow Psiphon server is still unusably slow for browsing. Below this
// floor one bounded restart buys another draw; slow-but-working is kept, never
// failed, because slow beats nothing.
const (
	psiphonSpeedProbeBytes   = 3 * 1024 * 1024
	psiphonSpeedProbeTimeout = 10 * time.Second
	psiphonMinBps            = 150 * 1024
	psiphonSpeedRetries      = 1
)

// measureDownBps downloads through the tunnel and returns the achieved bytes per
// second (0 when the probe could not run at all).
func measureDownBps(mixedPort, bytes int, timeout time.Duration) int64 {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL("http://127.0.0.1:" + strconv.Itoa(mixedPort))),
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytes))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0
	}
	start := time.Now()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(bytes)))
	el := time.Since(start).Seconds()
	if el <= 0 || n <= 0 {
		return 0
	}
	return int64(float64(n) / el)
}

// probeThroughput downloads want bytes through the tunnel and requires the full
// amount inside the timeout, so a stalled or half-dead data plane is caught at
// connect time rather than surfacing as "connected, but pages never load". The
// returned bits per second cover the body transfer only (TLS setup and the
// request are already done), which is what the speed floor compares.
func probeThroughput(mixedPort, want int, timeout time.Duration) (int64, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL("http://127.0.0.1:" + strconv.Itoa(mixedPort))),
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", want))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	start := time.Now()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(want)))
	elapsed := time.Since(start).Seconds()
	var bps int64
	if elapsed > 0 && n > 0 {
		bps = int64(float64(n) / elapsed)
	}
	if err != nil {
		return bps, fmt.Errorf("传输中断于 %d/%d 字节: %w", n, want, err)
	}
	if n < int64(want) {
		return bps, fmt.Errorf("仅收到 %d/%d 字节", n, want)
	}
	return bps, nil
}

func mustParseURL(u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		return nil
	}
	return parsed
}

// pickBest chooses the best working endpoint per the client's criteria.
func pickBest(results []cachedEndpoint) (cachedEndpoint, bool) {
	best := cachedEndpoint{}
	found := false
	for _, ce := range results {
		if !ce.Working || ce.Endpoint == "" {
			continue
		}
		if !found || betterEndpoint(ce, best) {
			best, found = ce, true
		}
	}
	return best, found
}

// pickForced selects the cached endpoint matching addr (bare host or host:port,
// the form -best prints); it must be a working entry.
func pickForced(results []cachedEndpoint, addr string) (cachedEndpoint, bool) {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	for _, ce := range results {
		if !ce.Working {
			continue
		}
		if ce.Endpoint == addr || ce.IP == host {
			return ce, true
		}
	}
	return cachedEndpoint{}, false
}

// cachedScanFor returns the stored scan for proto, when one exists and is fresh.
func cachedScanFor(proto string, ipv6 bool) (cachedScan, bool) {
	store, err := cache.Open(cache.Options{TTL: scanTTL})
	if err != nil {
		return cachedScan{}, false
	}
	raw, ok := store.Get(scanCacheKey(proto, ipv6))
	if !ok {
		return cachedScan{}, false
	}
	var cs cachedScan
	if json.Unmarshal(raw, &cs) != nil {
		return cachedScan{}, false
	}
	return cs, true
}

func betterEndpoint(a, b cachedEndpoint) bool {
	// Prefer lower in-tunnel latency when present, else endpoint ping.
	al := a.TunPingMS
	bl := b.TunPingMS
	if al <= 0 {
		al = a.EpPingMS
	}
	if bl <= 0 {
		bl = b.EpPingMS
	}
	if al <= 0 {
		return false
	}
	if bl <= 0 {
		return true
	}
	if a.Loss != b.Loss {
		return a.Loss < b.Loss
	}
	return al < bl
}

// sessionProtocolLabel is the user-facing name of the base protocol stored in
// clientState.Proto. It is deliberately separate from protoLabel (which stamps
// a run's stage logs): MASQUE-H3 reads as MASQUEH3 in the composed session name,
// matching the product's WG/AWG/MASQUE naming.
func sessionProtocolLabel(proto string) string {
	switch proto {
	case protoMASQUE:
		return "MASQUEH3"
	case protoMASQUEH2:
		return "MASQUEH2"
	case protoMASQUEMASQUE:
		return "MASQUE-in-MASQUE"
	case protoWWarp:
		return "GOOL"
	}
	if proto == "" {
		return "?"
	}
	return protoLabel(proto)
}

// sessionLabel is the composed name of the whole session: the base protocol with
// the Psiphon exit switch appended when it is on. The two axes stay distinct — a
// "WG-Psiphon" session is Proto=wg plus PsiphonMode=true, never a protocol of its
// own, which is exactly what keeps health/repair from mis-routing it.
func (s clientState) sessionLabel() string {
	label := sessionProtocolLabel(s.Proto)
	if s.PsiphonMode {
		label += "-Psiphon"
	}
	if s.OpenVPNMode {
		label += "-OpenVPN"
	}
	return label
}

// relayRow is the VPN Gate relay in host:port (country) form, or "" for a
// session without an OpenVPN exit. It is a helper because status prints the
// relay in both of its layouts.
func relayRow(s clientState) string {
	if !s.OpenVPNMode || s.OpenVPNNode == nil {
		return ""
	}
	id := s.OpenVPNNode.id()
	if s.OpenVPNNode.CountryShort != "" {
		id += " (" + s.OpenVPNNode.CountryShort + ")"
	}
	return id
}

// statusLine renders the human-readable one-line status shown by `status`.
func (s clientState) statusLine() string {
	if !s.Connected {
		return "disconnected"
	}
	parts := []string{"connected"}
	parts = append(parts, "session="+s.sessionLabel())
	parts = append(parts, "proto="+s.Proto)
	if s.Endpoint != "" {
		parts = append(parts, "endpoint="+s.Endpoint)
	}
	if s.ExitIP != "" {
		parts = append(parts, "exit="+s.ExitIP)
	}
	if s.OpenVPNMode && s.OpenVPNNode != nil {
		parts = append(parts, "relay="+s.OpenVPNNode.id())
	}
	if s.Country != "" {
		parts = append(parts, "country="+s.Country)
	}
	if s.Colo != "" {
		parts = append(parts, "colo="+s.Colo)
	}
	if s.LatencyMS > 0 {
		parts = append(parts, fmt.Sprintf("latency=%dms", s.LatencyMS))
	}
	if s.ProxyWarn != "" {
		parts = append(parts, "proxy=manual")
	}
	return strings.Join(parts, " ")
}
