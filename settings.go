package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/xhwarp/warp-client/internal/core"
)

// Pages of the shell. The window opens on the page the user left, so these
// values are persisted and must stay stable across releases.
const (
	pageHome     = "home"
	pageNodes    = "nodes"
	pageRules    = "rules"
	pageSettings = "settings"
	pageAbout    = "about"
	pageLogs     = "logs"
)

// Appearance. ThemeAuto follows the system's light/dark setting.
const (
	themeLight = "light"
	themeDark  = "dark"
	themeAuto  = "auto"
)

// UI languages.
const (
	langZH = "zh"
	langEN = "en"
)

// Routing presets. Four map onto rule sets around the exit; direct is the
// core's own `mode: direct`. legacyModeRule is what the old "rule" choice was
// called on disk and is migrated to custom when read.
const (
	modeBypass     = "bypass"
	modeBlacklist  = "blacklist"
	modeGlobal     = "global"
	modeDirect     = "direct"
	modeCustom     = "custom"
	legacyModeRule = "rule"
)

// Traffic capture: how applications reach the tunnel. The system proxy only
// catches apps that honour WinINET; a TUN device routes the whole machine and
// needs administrator rights (the core embeds wintun, so no extra DLL is needed).
const (
	captureProxy = "proxy"
	captureTun   = "tun"
)

// Tunnel address families. v4 and v6 restrict the tunnel to one family; both
// carries the two side by side. Nested protocols (wwarp, masque-mm) cannot use
// anything but v4: their inner MTU is below IPv6's 1280-byte minimum.
const (
	famV4   = "v4"
	famV6   = "v6"
	famBoth = "both"
)

// clientSettings is the persisted preference set. It is deliberately separate
// from clientState: a session is ephemeral (it can end at any moment, and
// disconnect clears it), while these choices are the user's and must survive a
// restart, a crash, or a reconnect. Everything a settings page can change lives
// here, so the file is also the single place to look when asking "what is this
// install configured to do".
type clientSettings struct {
	// Appearance. Applied live — switching theme or language repaints the
	// window, it does not restart it.
	Theme string `json:"theme"`
	Lang  string `json:"lang"`

	// Session choices, remembered so a restart starts where you left off.
	Proto      string `json:"proto"`
	OuterProto string `json:"outer_proto"`
	InnerProto string `json:"inner_proto"`
	Rescan     bool   `json:"rescan"`
	Psiphon    bool   `json:"psiphon"`
	// OpenVPN is the V2 egress switch: a VPN Gate relay dialled from inside the
	// base protocol. Mutually exclusive with Psiphon — both replace the final
	// exit, and a session can only land in one place.
	OpenVPN    bool `json:"openvpn"`
	AutoRepair bool `json:"auto_repair"`
	// PsiphonRegion is the preferred Psiphon exit country (ISO alpha-2, upper
	// case). Empty means "automatic" — Psiphon picks the region itself.
	PsiphonRegion string `json:"psiphon_region"`
	// OpenVPNRegion is the preferred VPN Gate exit country (ISO alpha-2, upper
	// case). Empty means "automatic" — the fastest reachable node wins.
	OpenVPNRegion string `json:"openvpn_region"`
	// OpenVPNNode pins one relay inside that country (country-ip-port, the same
	// id the picker shows). Empty means "auto": the connect picks by latency.
	OpenVPNNode string `json:"openvpn_node"`
	// Pin is the endpoint the user picked as the default node; empty means the
	// fastest cached endpoint wins.
	Pin string `json:"pin"`

	// Mode B (Clash subscription): imported proxies are the base outbound.
	// ConnMode empty or "warp" keeps the original WARP pipeline untouched, so
	// an upgraded 1.0.4 install behaves exactly as before.
	ConnMode      string      `json:"conn_mode,omitempty"`
	Subscriptions []string    `json:"subscriptions,omitempty"`
	CustomProxies []ProxySpec `json:"custom_proxies,omitempty"`
	ActiveProxy   string      `json:"active_proxy,omitempty"`
	// SubAutoSelect makes the connect pick the lowest-latency measured proxy
	// instead of the one the user clicked. DelayMS is filled by the node
	// page's "延迟测试" action.
	SubAutoSelect bool `json:"sub_auto_select,omitempty"`
	// SubSources are the managed subscriptions (name + group + origin). Each
	// imported node carries the matching SubID. Subscriptions []string above is
	// the legacy URL-only list, kept so an old file still loads; loadSettings
	// migrates it into SubSources and normalize keeps the two in sync.
	SubSources []SubSource `json:"sub_sources,omitempty"`
	// ActiveSub is the subscription the node page is filtered to ("" = all).
	// It is a VIEW filter only: the connect pipeline still uses ActiveProxy
	// over the full CustomProxies, so switching the view never drops a tunnel.
	ActiveSub string `json:"active_sub,omitempty"`

	// Local proxy: where clients point, where the core's API listens, and
	// whether other devices on the LAN may use the mixed port.
	MixedPort int  `json:"mixed_port"`
	APIPort   int  `json:"api_port"`
	AllowLan  bool `json:"allow_lan"`
	// LanUser/LanPass gate the LAN listener. Empty means "no auth", which is the
	// common case on a home network; setting both makes mihomo demand
	// user:password on the mixed port.
	LanUser     string `json:"lan_user,omitempty"`
	LanPass     string `json:"lan_pass,omitempty"`
	CaptureMode string `json:"capture_mode"`

	// Network. IPFamily is the tunnel's address family (v4/v6/both); it is
	// separate from the endpoint scan family, which only ever asks whether the
	// cached endpoint pool is v4 or v6.
	IPFamily   string `json:"ip_family"`
	MTU        int    `json:"mtu"`
	TimeoutSec int    `json:"timeout_sec"`

	// Performance tuning. EndpointRank orders the working endpoints a connect
	// tries: "ping" (lowest latency, the historical default) or "speed"
	// (steady-state throughput tiers, latency only within a tier). Empty keeps
	// ping, so an upgraded install behaves exactly as before until opted in.
	EndpointRank string `json:"endpoint_rank,omitempty"`
	// IPStack and Congestion override the MASQUE inner gVisor stack and the QUIC
	// congestion controller. Empty keeps the shipped defaults (gvisor / bbr);
	// the renderer falls back to those if the running core rejects a choice.
	IPStack    string `json:"ip_stack,omitempty"`
	Congestion string `json:"congestion_controller,omitempty"`

	// DNS: DNSCustom is a comma separated resolver list (empty = not set);
	// DNSOff stops the client from handing any resolver to the tunnel at all;
	// DNSLeak routes resolver queries through the tunnel and, in TUN mode,
	// hijacks every port-53 packet so no query escapes outside the tunnel.
	DNSCustom string `json:"dns_custom"`
	DNSOff    bool   `json:"dns_off"`
	DNSLeak   bool   `json:"dns_leak"`

	// ProxyMode is the routing preset: bypass (mainland direct, rest proxied),
	// blacklist (only DomainProxy is proxied), global (everything proxied),
	// direct (nothing proxied), or custom (domain lists, rest proxied).
	ProxyMode string `json:"proxy_mode"`

	// Domain lists: comma separated suffixes routed straight (DomainDirect) or
	// through the exit (DomainProxy). They become DOMAIN-SUFFIX rules, which
	// need no geo data. The list order decides: proxy rules are emitted first,
	// so a domain in both lists goes through the tunnel.
	DomainDirect string `json:"domain_direct"`
	DomainProxy  string `json:"domain_proxy"`

	// Behaviour.
	AutoConnect bool `json:"auto_connect"`
	AutoStart   bool `json:"auto_start"`

	// ControlCode is this install's remote-control identity: derived from the
	// machine on Windows, shown on the About page, and checked against the
	// published stop list so a build can be switched off without shipping a
	// new release. It is persisted only so the About page can show it before
	// the first check and so a non-Windows build has something stable.
	ControlCode string `json:"control_code"`

	// Starred holds endpoints marked as favourites; the node list shows them
	// first and they survive a rescan.
	Starred []string `json:"starred"`

	// Pre-capture-mode fields: read once to migrate an old settings.json, then
	// cleared by normalize so they are never written again. Pointers keep
	// "absent" distinguishable from an explicit false.
	Tun         *bool `json:"tun,omitempty"`
	SystemProxy *bool `json:"system_proxy,omitempty"`
	IPv6        *bool `json:"ipv6,omitempty"`
}

const settingsName = "settings.json"

func defaultSettings() clientSettings {
	return clientSettings{
		Theme:       themeLight,
		Lang:        langZH,
		Proto:       protoAWG,
		OuterProto:  protoWG,
		InnerProto:  protoWG,
		AutoRepair:  true,
		MixedPort:   core.DefaultMixedPort,
		APIPort:     core.DefaultAPIPort,
		CaptureMode: captureProxy,
		IPFamily:    famV4,
		TimeoutSec:  2,
		DNSLeak:     true,
		ProxyMode:   modeCustom,
	}
}

func settingsPath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, settingsName), nil
}

// loadSettings returns the persisted preferences. A missing file is normal (a
// fresh install), and a corrupt one is never fatal: either way the caller gets
// defaults and the next save rewrites the file.
func loadSettings() clientSettings {
	s := defaultSettings()
	p, err := settingsPath()
	if err != nil {
		return s
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return defaultSettings()
	}
	// A file written before capture modes and IP families existed carries the
	// old independent switches instead. Migrate only when the new key is truly
	// absent: after this release writes the file, an explicit value wins even
	// when it matches the default.
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) == nil {
		if _, ok := keys["capture_mode"]; !ok && s.Tun != nil && *s.Tun {
			s.CaptureMode = captureTun
		}
		if _, ok := keys["ip_family"]; !ok && s.IPv6 != nil && *s.IPv6 {
			s.IPFamily = famV6
		}
	}
	// The old rule mode plus the geo switch is today's bypass preset; plain
	// rule mode becomes custom (normalize handles that mapping).
	var legacy struct {
		GeoSplit bool `json:"geo_split"`
	}
	if json.Unmarshal(raw, &legacy) == nil && legacy.GeoSplit && s.ProxyMode == legacyModeRule {
		s.ProxyMode = modeBypass
	}
	// Subscriptions used to be a URL-only list with no names or groups. Migrate
	// each remembered URL into a managed SubSource once; normalize then clears
	// the legacy list so it is never written again.
	if len(s.SubSources) == 0 && len(s.Subscriptions) > 0 {
		for _, u := range s.Subscriptions {
			if u = strings.TrimSpace(u); u != "" {
				s.SubSources = append(s.SubSources, SubSource{
					ID: newSubID(), Name: subNameFromURL(u), URL: u, Kind: "url",
				})
			}
		}
		// Legacy nodes carry no source link. With exactly one migrated source
		// they almost certainly all came from it, so adopt them; with several
		// there is no honest way to tell, so they stay ungrouped under "全部".
		if len(s.SubSources) == 1 {
			id := s.SubSources[0].ID
			for i := range s.CustomProxies {
				if s.CustomProxies[i].SubID == "" {
					s.CustomProxies[i].SubID = id
				}
			}
		}
	}
	s.normalize()
	return s
}

func saveSettings(s clientSettings) error {
	p, err := settingsPath()
	if err != nil {
		return err
	}
	s.normalize()
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0o600)
}

// normalize clamps everything that reaches the renderer. A hand-edited file
// must not be able to produce a core config that fails to parse, nor an
// unopenable window — a bad port, MTU or page name here would look like "the
// client is broken", not "the file is wrong".
func (s *clientSettings) normalize() {
	// Mode B defaults to off: an upgraded install must keep the WARP path.
	if s.ConnMode != "subscription" {
		s.ConnMode = "warp"
	}
	if len(s.SubSources) > 64 {
		s.SubSources = s.SubSources[:64]
	}
	seenSub := make(map[string]bool, len(s.SubSources))
	subs := s.SubSources[:0]
	for _, src := range s.SubSources {
		src.Name = strings.TrimSpace(src.Name)
		src.Group = strings.TrimSpace(src.Group)
		src.URL = strings.TrimSpace(src.URL)
		if src.ID == "" || seenSub[src.ID] {
			src.ID = newSubID()
		}
		seenSub[src.ID] = true
		if src.Name == "" {
			if src.URL != "" {
				src.Name = subNameFromURL(src.URL)
			} else {
				src.Name = "订阅"
			}
		}
		switch src.Kind {
		case "url", "file", "clipboard", "qr", "single":
		default:
			if src.URL != "" {
				src.Kind = "url"
			} else {
				src.Kind = "single"
			}
		}
		subs = append(subs, src)
	}
	s.SubSources = subs
	// The legacy URL-only list is migration input only; never persist it again.
	s.Subscriptions = nil
	// ActiveSub is a view filter: keep it only when it names a live source.
	if s.ActiveSub != "" && s.subSourceByID(s.ActiveSub) == nil {
		s.ActiveSub = ""
	}
	if len(s.CustomProxies) > 512 {
		s.CustomProxies = s.CustomProxies[:512]
	}
	switch s.Theme {
	case themeLight, themeDark, themeAuto:
	default:
		s.Theme = themeLight
	}
	switch s.Lang {
	case langZH, langEN:
	default:
		s.Lang = langZH
	}
	if s.Proto == "" {
		s.Proto = protoAWG
	}
	if _, err := parseProto(s.Proto); err != nil {
		s.Proto = protoAWG
	}
	if s.OuterProto == "" {
		s.OuterProto = protoWG
	}
	if s.InnerProto == "" {
		s.InnerProto = protoWG
	}
	if s.CaptureMode == "" {
		if s.Tun != nil && *s.Tun {
			s.CaptureMode = captureTun
		} else {
			s.CaptureMode = captureProxy
		}
	}
	switch s.CaptureMode {
	case captureProxy, captureTun:
	default:
		s.CaptureMode = captureProxy
	}
	if s.IPFamily == "" {
		if s.IPv6 != nil && *s.IPv6 {
			s.IPFamily = famV6
		} else {
			s.IPFamily = famV4
		}
	}
	switch s.IPFamily {
	case famV4, famV6, famBoth:
	default:
		s.IPFamily = famV4
	}
	// A nested tunnel's inner MTU (1220) is below IPv6's 1280-byte minimum, so
	// those protocols cannot carry v6 at all. Clamp rather than render a
	// config whose v6 half silently blackholes. Subscription mode has no WARP
	// tunnel: the imported node decides what it carries, so the proto gate
	// does not apply there.
	if s.ConnMode != "subscription" && !protoV6Capable(s.Proto) {
		s.IPFamily = famV4
	}
	// OpenVPN is IPv4-only end to end: VPN Gate hands out v4 relays and mihomo's
	// openvpn outbound carries no v6 half. Psiphon's exit is likewise v4 in
	// practice and unverified for v6, so both stacked exits lock the family.
	// The two exits also replace the same thing, so a file with both on is
	// resolved to the newer switch.
	if s.OpenVPN {
		s.Psiphon = false
	}
	if s.OpenVPN || s.Psiphon {
		s.IPFamily = famV4
	}
	s.Pin = strings.TrimSpace(s.Pin)
	if s.Pin != "" && s.IPFamily != famBoth {
		v6 := endpointIsV6(s.Pin)
		if (s.IPFamily == famV4 && v6) || (s.IPFamily == famV6 && !v6) {
			s.Pin = ""
		}
	}
	s.Tun, s.SystemProxy, s.IPv6 = nil, nil, nil
	switch s.ProxyMode {
	case modeBypass, modeBlacklist, modeGlobal, modeDirect, modeCustom:
	case legacyModeRule:
		s.ProxyMode = modeCustom
	default:
		s.ProxyMode = modeCustom
	}
	// Internalized choices: the settings page no longer exposes these, so the
	// shipped defaults are forced on every load and save. A hand-edited file
	// cannot re-enable a knob the UI can no longer show or explain.
	s.APIPort = core.DefaultAPIPort
	s.MTU = 0
	s.TimeoutSec = 2
	s.Rescan = false
	s.AutoRepair = true
	s.DNSCustom = ""
	s.DNSOff = false
	s.DNSLeak = true

	// LAN credentials: a colon is the user/password separator inside mihomo's
	// single "user:pass" entry, so it cannot appear in either half; both are
	// trimmed so a stray space in the dialog does not silently change the
	// password. A half-filled pair is kept in the file (the user is midway
	// through filling it in) but apply() only renders a complete one.
	s.LanUser = strings.TrimSpace(strings.ReplaceAll(s.LanUser, ":", ""))
	s.LanPass = strings.TrimSpace(strings.ReplaceAll(s.LanPass, ":", ""))
	if s.MixedPort < 1 || s.MixedPort > 65535 {
		s.MixedPort = core.DefaultMixedPort
	}
	if s.APIPort == s.MixedPort {
		s.APIPort = s.MixedPort + 1
	}
	// Performance tuning: clamp to the known spellings so a hand-edited file
	// cannot render a transport the core rejects. Empty keeps the defaults.
	s.EndpointRank = normalizeRank(s.EndpointRank)
	s.IPStack = normalizeStack(s.IPStack)
	s.Congestion = normalizeCC(s.Congestion)
	// The egress region is an ISO alpha-2 hint or empty for automatic.
	s.PsiphonRegion = strings.ToUpper(strings.TrimSpace(s.PsiphonRegion))
	if len(s.PsiphonRegion) != 2 {
		s.PsiphonRegion = ""
	}
	s.OpenVPNRegion = strings.ToUpper(strings.TrimSpace(s.OpenVPNRegion))
	if len(s.OpenVPNRegion) != 2 {
		s.OpenVPNRegion = ""
	}
	s.OpenVPNNode = strings.TrimSpace(s.OpenVPNNode)
	// The control code is compared against a hand-written list, so it is kept
	// in one spelling: upper case, four-character groups, nothing else.
	if s.ControlCode != "" {
		s.ControlCode = normalizeControlCode(s.ControlCode)
	}
	out := s.Starred[:0]
	for _, e := range s.Starred {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	s.Starred = out
}

// domainDirectList / domainProxyList are the two domain suffix lists.
func (s clientSettings) domainDirectList() []string { return fieldList(s.DomainDirect) }
func (s clientSettings) domainProxyList() []string  { return fieldList(s.DomainProxy) }

// subSourceByID returns the managed subscription with this id, or nil. The
// pointer addresses the live slice element so callers may edit it in place.
func (s *clientSettings) subSourceByID(id string) *SubSource {
	if id == "" {
		return nil
	}
	for i := range s.SubSources {
		if s.SubSources[i].ID == id {
			return &s.SubSources[i]
		}
	}
	return nil
}

// nodesOfSub counts the imported nodes belonging to one subscription.
func (s *clientSettings) nodesOfSub(id string) int {
	n := 0
	for i := range s.CustomProxies {
		if s.CustomProxies[i].SubID == id {
			n++
		}
	}
	return n
}

// fieldList splits a comma/semicolon/whitespace separated list, de-duplicated.
func fieldList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		key := strings.ToLower(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// starred reports whether an endpoint is a favourite.
func (s clientSettings) starred(endpoint string) bool {
	for _, e := range s.Starred {
		if e == endpoint {
			return true
		}
	}
	return false
}

// toggleStar adds or removes an endpoint from the favourites, returning the new
// list. Sorted on write so the file stays diff-friendly.
func toggleStar(list []string, endpoint string) []string {
	out := make([]string, 0, len(list)+1)
	found := false
	for _, e := range list {
		if e == endpoint {
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		out = append(out, endpoint)
	}
	sortStrings(out)
	return out
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// apply folds the preference file into the options a connect will run with.
// Session choices (proto, rescan, psiphon, pinned endpoint, protocol pair)
// stay the caller's: they describe this connect, not the preference file.
func (s clientSettings) apply(o *options) {
	if s.MixedPort > 0 {
		o.mixedPort = s.MixedPort
	}
	if s.APIPort > 0 {
		o.apiPort = s.APIPort
	}
	o.allowLan = s.AllowLan
	// Only a complete pair becomes an authentication entry; normalize already
	// cleared half-filled ones.
	if s.AllowLan && s.LanUser != "" && s.LanPass != "" {
		o.lanAuth = s.LanUser + ":" + s.LanPass
	}
	o.family = s.IPFamily
	// The scan cache and the endpoint pools are keyed by a single family; a
	// dual-stack tunnel still scans v4 endpoints (it carries both either way).
	o.ipv6 = s.IPFamily == famV6
	o.mtu = s.MTU
	if s.TimeoutSec > 0 {
		o.timeoutSec = s.TimeoutSec
	}
	o.dns = strings.TrimSpace(s.DNSCustom)
	o.noDNS = s.DNSOff
	o.dnsLeak = s.DNSLeak && !s.DNSOff
	// Capture mode, not the old proxy switch: TUN also leaves WinINET alone.
	o.tunMode = s.CaptureMode == captureTun
	o.noProxy = s.CaptureMode != captureProxy
	o.proxyMode = s.ProxyMode
	o.domainDirect = s.domainDirectList()
	o.domainProxy = s.domainProxyList()
	o.noGuard = !s.AutoRepair
	o.endpointRank = normalizeRank(s.EndpointRank)
	o.ipStack = normalizeStack(s.IPStack)
	o.congestion = normalizeCC(s.Congestion)
	overrideTuningFromEnv(o)
	o.psiphonRegion = s.PsiphonRegion
	o.openvpnRegion = s.OpenVPNRegion
	o.openvpnNodePin = s.OpenVPNNode
	// Mode B: imported Clash proxies become the base outbound. Leaving these
	// empty in mode A is exactly the previous behaviour.
	o.connMode = s.ConnMode
	o.customProxies = s.CustomProxies
	o.activeProxy = s.ActiveProxy
	if s.ConnMode == "subscription" && s.SubAutoSelect {
		if best := bestMeasuredProxy(s.CustomProxies); best != "" {
			o.activeProxy = best
		}
	}
}
