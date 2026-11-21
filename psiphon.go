package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// errPsiphonPolicyBlocked marks a Windows Smart App Control / WDAC refusal to
// load psiphon.exe. This is environmental and permanent for that file: rotating
// WARP endpoints or rescanning cannot fix it, so the connect loop aborts at
// once instead of burning every candidate (and confusing the user with a wall
// of "underlay 数据面不可用" follow-on errors).
var errPsiphonPolicyBlocked = errors.New("psiphon.exe blocked by Windows code integrity policy")

// isPolicyBlocked recognises the forms CreateProcess reports when a code
// integrity policy refuses an unsigned image: WinError 4551, "An Application
// Control policy has blocked this file", or a Device Guard message.
func isPolicyBlocked(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "application control policy") ||
		strings.Contains(s, "blocked this file") ||
		strings.Contains(s, "device guard") ||
		strings.Contains(s, "4551")
}

// Psiphon wraps the external Psiphon executable as a localhost SOCKS5 proxy
// (V1 exit). xehn starts it, learns the dynamic SOCKS port from the
// ListeningSocksProxyPort notice, renders a mihomo config that egresses through
// that port, and stops it on disconnect. Psiphon itself owns server discovery,
// selection, protocol, obfuscation, tactics and the tunnel — xehn does
// none of that. This file is the lifecycle only: no health guard, no repair
// loop, no endpoint manager, no GUI.
type Psiphon struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	pid       int
	socksPort int
	state     psiphonState
	dataDir   string
	exePath   string
	upstream  string
	done      chan struct{}
}

type psiphonState int

const (
	psiphonStopped psiphonState = iota
	psiphonStarting
	psiphonSocksReady
	psiphonTunnelReady
	psiphonRealTrafficReady
	psiphonFailed
	psiphonStopping
)

// resolvePsiphonExe locates the Psiphon executable without inventing a second
// binary directory: it reuses the same core dir mihomo lives in. Resolution
// order: explicit --psiphon-exe > PSIPHON_EXE env > <coreDir>/psiphon.exe.
func resolvePsiphonExe(opts options, cDir string) (string, error) {
	if opts.psiphonExe != "" {
		if isExecutableFile(opts.psiphonExe) {
			return opts.psiphonExe, nil
		}
		return "", fmt.Errorf("psiphon: --psiphon-exe %s is not an executable", opts.psiphonExe)
	}
	if e := os.Getenv("PSIPHON_EXE"); e != "" {
		if isExecutableFile(e) {
			return e, nil
		}
		return "", fmt.Errorf("psiphon: PSIPHON_EXE %s is not an executable", e)
	}
	cand := filepath.Join(cDir, "psiphon.exe")
	if isExecutableFile(cand) {
		return cand, nil
	}
	return "", fmt.Errorf("psiphon executable not found: place psiphon.exe in %s, set --psiphon-exe, or set PSIPHON_EXE", cDir)
}

func isExecutableFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

func isReadableFile(p string) bool { return isExecutableFile(p) }

// resolvePsiphonClientConfig locates the official client config Psiphon needs
// (SponsorId, PropagationChannelId, the server-list URLs and their signature
// keys). V1 has no flag for it. Resolution order: PSIPHON_CONFIG env >
// <coreDir>/client.config > <coreDir>/psiphon.config. A missing file is a hard
// error, not a silent fallback: a Psiphon started without these credentials
// discovers zero servers and can never establish a tunnel.
func resolvePsiphonClientConfig(cDir string) (string, error) {
	if p := os.Getenv("PSIPHON_CONFIG"); p != "" {
		if isReadableFile(p) {
			return p, nil
		}
		return "", fmt.Errorf("psiphon: PSIPHON_CONFIG %s 不可读", p)
	}
	for _, n := range []string{"client.config", "psiphon.config"} {
		p := filepath.Join(cDir, n)
		if isReadableFile(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("psiphon: 未找到官方 client.config（应放在 %s/client.config，或设置 PSIPHON_CONFIG）；它是 Psiphon 的官方凭据，必须随包提供", cDir)
}

// psiphonLaunch is everything Start needs to render a config that can actually
// establish a tunnel. The V1 exit is NOT self-contained: it carries the official
// client credentials (BaseConfigPath) and it rides on an underlay (Upstream).
// A bare config with only a SOCKS port has no SponsorId / PropagationChannelId /
// server-list URLs and can never discover a single server. SocksPort is fixed so
// mihomo's config — which names the Psiphon SOCKS port — can be rendered before
// Psiphon starts: the two are mutually dependent and a fixed port breaks the tie.
type psiphonLaunch struct {
	ExePath        string
	DataDir        string
	BaseConfigPath string
	Upstream       string
	SocksPort      int
	// EgressRegion is the ISO alpha-2 country the exit should be in; empty
	// lets Psiphon pick automatically. It is a preference, not a guarantee —
	// Psiphon falls back to any region when the requested one has no servers.
	EgressRegion string
}

// psiphonV1Protocols is the TCP-only tunnel-protocol set V1 limits Psiphon to.
// It mirrors the proven-working extracted client.config; the QUIC/UDP protocols
// are deliberately absent because they are the first to be blocked on hostile
// networks (and V1's underlay is a TCP SOCKS anyway).
var psiphonV1Protocols = []string{
	"OSSH",
	"TLS-OSSH",
	"SHADOWSOCKS-OSSH",
	"UNFRONTED-MEEK-OSSH",
	"UNFRONTED-MEEK-HTTPS-OSSH",
	"UNFRONTED-MEEK-SESSION-TICKET-OSSH",
	"FRONTED-MEEK-OSSH",
	"FRONTED-MEEK-HTTP-OSSH",
}

// buildPsiphonConfig starts from the official client config and overlays only the
// runtime fields. The credentials — SponsorId, PropagationChannelId, the
// RemoteServerListURLs / ObfuscatedServerListRootURLs and their signature keys —
// come entirely from that file: without them Psiphon reports zero capable servers.
// The Migrate* pointers at the machine's other Psiphon install are dropped so we
// never adopt (and lock) a foreign datastore.
func buildPsiphonConfig(l psiphonLaunch) (map[string]any, error) {
	if strings.TrimSpace(l.BaseConfigPath) == "" {
		return nil, fmt.Errorf("psiphon: 缺少官方 client.config（需 SponsorId/PropagationChannelId/服务器源 URL）；请放到 core 目录或设置 PSIPHON_CONFIG")
	}
	raw, err := os.ReadFile(l.BaseConfigPath)
	if err != nil {
		return nil, fmt.Errorf("psiphon: 读取 client.config %s: %w", l.BaseConfigPath, err)
	}
	cfg := map[string]any{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("psiphon: 解析 client.config %s: %w", l.BaseConfigPath, err)
	}
	cfg["LocalSocksProxyPort"] = l.SocksPort
	cfg["LocalHttpProxyPort"] = 0
	cfg["DataRootDirectory"] = l.DataDir
	for _, k := range []string{
		"MigrateDataStoreDirectory",
		"MigrateObfuscatedServerListDownloadDirectory",
		"MigrateRemoteServerListDownloadFilename",
		"MigrateUpgradeDownloadFilename",
	} {
		delete(cfg, k)
	}
	// The underlay. Psiphon dials its own servers through the base protocol's
	// local SOCKS; empty means direct, which is blocked on the networks V1 targets.
	cfg["UpstreamProxyUrl"] = l.Upstream
	cfg["EmitDiagnosticNotices"] = true
	// Exit region preference: empty means automatic (Psiphon's own default).
	// Set unconditionally so a region chosen in the UI also overrides anything
	// the base config happens to carry.
	cfg["EgressRegion"] = strings.ToUpper(strings.TrimSpace(l.EgressRegion))
	// Respect the base config's own protocol list when it has one; only fall back
	// to the V1 TCP set when it does not. Overwriting a list the config already
	// chose would silently overrule it — and can make Psiphon skip the faster
	// protocols its own tactics prefer.
	if _, ok := cfg["LimitTunnelProtocols"]; !ok {
		cfg["LimitTunnelProtocols"] = append([]string(nil), psiphonV1Protocols...)
	}
	return cfg, nil
}

// pickFreePort asks the OS for an unused localhost TCP port and hands it back.
// There is a benign race (the port is free now, not at bind time), but it only
// needs to be free long enough for Psiphon to bind it milliseconds later.
func pickFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("psiphon: 选本地端口: %w", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// Start launches Psiphon with the given launch parameters and begins parsing its
// notices. It does NOT block on readiness — call WaitForSocks and then
// WaitForTunnel. On failure it cleans up and returns an error.
func (p *Psiphon) Start(ctx context.Context, l psiphonLaunch) error {
	p.mu.Lock()
	if p.cmd != nil {
		p.mu.Unlock()
		return fmt.Errorf("psiphon: already running")
	}
	p.state = psiphonStarting
	p.dataDir = l.DataDir
	p.exePath = l.ExePath
	p.upstream = l.Upstream
	p.socksPort = l.SocksPort
	p.pid = 0

	if err := os.MkdirAll(l.DataDir, 0o755); err != nil {
		p.mu.Unlock()
		return fmt.Errorf("psiphon: data dir: %w", err)
	}
	cfg, err := buildPsiphonConfig(l)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	cb, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		p.mu.Unlock()
		return fmt.Errorf("psiphon: config marshal: %w", err)
	}
	cfgPath := filepath.Join(l.DataDir, "psiphon-config.json")
	if err := os.WriteFile(cfgPath, cb, 0o600); err != nil {
		p.mu.Unlock()
		return fmt.Errorf("psiphon: write config: %w", err)
	}

	cmdCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(cmdCtx, l.ExePath, "-config", cfgPath, "-dataRootDirectory", l.DataDir)
	cmd.Dir = l.DataDir
	// psiphon.exe is a console application; spawned from the windowsgui build it
	// would pop its own black console window on every connect (and every guard
	// restart). Suppress it exactly as the core and the guard do.
	hideGuard(cmd)
	stdout, err1 := cmd.StdoutPipe()
	stderr, err2 := cmd.StderrPipe()
	if err1 != nil || err2 != nil {
		cancel()
		p.mu.Unlock()
		return fmt.Errorf("psiphon: pipe: %v/%v", err1, err2)
	}
	p.cmd = cmd
	p.cancel = cancel
	p.done = make(chan struct{})
	p.mu.Unlock()

	if err := cmd.Start(); err != nil {
		cancel()
		p.mu.Lock()
		p.cmd = nil
		p.cancel = nil
		p.done = nil
		p.mu.Unlock()
		if isPolicyBlocked(err) {
			return fmt.Errorf("%w: Windows 智能应用控制/代码完整性策略阻止加载 %s（psiphon.exe 未签名、无发布者信誉）。请在 Windows 安全中心关闭智能应用控制、换用已签名的 psiphon.exe，或暂时改用 OpenVPN 出口（不依赖该进程）: %v",
				errPsiphonPolicyBlocked, l.ExePath, err)
		}
		return fmt.Errorf("psiphon: start %s: %w", l.ExePath, err)
	}
	p.mu.Lock()
	p.pid = cmd.Process.Pid
	p.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); p.scanNotices(stdout) }()
	go func() { defer wg.Done(); p.scanNotices(stderr) }()
	go func() {
		wg.Wait()
		p.mu.Lock()
		if p.done != nil {
			close(p.done)
		}
		p.mu.Unlock()
	}()
	return nil
}

// scanNotices reads Psiphon JSON notice lines (one per line on stdout/stderr)
// and updates state. Non-JSON lines (plain logs) are ignored.
func (p *Psiphon) scanNotices(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		p.handleNotice(strings.TrimSpace(sc.Text()))
	}
}

// Verified against real official Psiphon ConsoleClient output: notices are
// JSON lines on stdout AND stderr, shaped
// {"data":{"port":58431},"noticeType":"ListeningSocksProxyPort","timestamp":"..."}
// The key is "noticeType" (not "notice").
type psiphonNotice struct {
	Notice  string          `json:"noticeType"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

func (p *Psiphon) handleNotice(line string) {
	if line == "" {
		return
	}
	var n psiphonNotice
	if err := json.Unmarshal([]byte(line), &n); err != nil {
		return
	}
	// Any notice carrying a positive established count means a real tunnel
	// exists. Reading the count here, not only in the switch below, keeps
	// readiness correct across Psiphon versions that report it under a
	// differently-named notice.
	if count := noticeTunnelCount(n.Data); count > 0 {
		p.mu.Lock()
		if p.state < psiphonTunnelReady {
			p.state = psiphonTunnelReady
		}
		p.mu.Unlock()
	}
	switch n.Notice {
	case "ListeningSocksProxyPort":
		if port := noticePort(n.Data); port > 0 {
			p.mu.Lock()
			p.socksPort = port
			if p.state < psiphonSocksReady {
				p.state = psiphonSocksReady
			}
			p.mu.Unlock()
		}
	case "Tunnels":
		// Any established tunnel counts as TUNNEL_READY.
		p.mu.Lock()
		if p.state < psiphonTunnelReady {
			p.state = psiphonTunnelReady
		}
		p.mu.Unlock()
	case "ListeningHttpProxyPort":
		// ignored for V1 (we use the SOCKS port)
	case "AvailableEgressRegions":
		// Psiphon emits this whenever it refreshes its server list (it checks
		// for updates on every run), so the UI's region dropdown tracks the
		// live egress set without a timer of our own.
		if regions := noticeRegions(n.Data); len(regions) > 0 {
			savePsiphonRegions(regions)
		}
	}
}

// noticeRegions parses the AvailableEgressRegions payload: {"regions":["US",…]}.
func noticeRegions(raw json.RawMessage) []string {
	var m struct {
		Regions []string `json:"regions"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m.Regions
}

// psiphonRegionsFile is the cached egress-region list (psiphon-regions.json in
// the app dir). It survives between runs so the dropdown shows the latest known
// set even before the first connect of a session.
type psiphonRegionsFile struct {
	At      time.Time `json:"at"`
	Regions []string  `json:"regions"`
}

func psiphonRegionsPath() string {
	dir, err := appDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "psiphon-regions.json")
}

// savePsiphonRegions normalises (trim, upper-case, 2-letter, dedupe, sort) and
// writes the cache. Best effort: it runs on the notice-reader goroutine and
// must never disturb the connect path. An unchanged list keeps the old file so
// the recorded timestamp stays "when the set last changed".
func savePsiphonRegions(regions []string) {
	p := psiphonRegionsPath()
	if p == "" {
		return
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range regions {
		r = strings.ToUpper(strings.TrimSpace(r))
		if len(r) != 2 || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	if len(out) == 0 {
		return
	}
	sort.Strings(out)
	if old := loadPsiphonRegions(); len(old) == len(out) {
		same := true
		for i := range out {
			if old[i] != out[i] {
				same = false
				break
			}
		}
		if same {
			return
		}
	}
	b, err := json.MarshalIndent(psiphonRegionsFile{At: time.Now(), Regions: out}, "", "  ")
	if err != nil {
		return
	}
	// Atomic replace: the GUI and the connect path read this file concurrently.
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o644) != nil {
		return
	}
	if os.Rename(tmp, p) != nil {
		_ = os.Remove(tmp)
	}
}

// loadPsiphonRegions reads the cached list; nil when absent or unreadable.
func loadPsiphonRegions() []string {
	p := psiphonRegionsPath()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var f psiphonRegionsFile
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return f.Regions
}

// guardPsiphonRegion drops a saved region the latest server list no longer
// offers: Psiphon would silently ignore it anyway, so say so once and fall back
// to automatic. An empty cache (first run / offline) never overrides the pick.
func guardPsiphonRegion(label, region string) string {
	region = strings.ToUpper(strings.TrimSpace(region))
	if region == "" {
		return ""
	}
	regions := loadPsiphonRegions()
	if len(regions) == 0 {
		return region
	}
	for _, r := range regions {
		if r == region {
			return region
		}
	}
	stageMsg(fmt.Sprintf("[%s] 出口地区 %s 已不在 Psiphon 最新地区列表中，本次改用自动选择", label, region))
	return ""
}

// psiphonDataStoreRegionRE matches the plaintext region fields inside Psiphon's
// bolt datastore: server entries are stored as JSON values ("region":"US").
var psiphonDataStoreRegionRE = regexp.MustCompile(`"region"\s*:\s*"([A-Za-z]{2})"`)

// refreshPsiphonRegionsFromDataStore rebuilds the region cache from Psiphon's
// own server-list datastore. The AvailableEgressRegions notice fires before
// the server list finishes downloading (and arrives empty in current builds),
// so notices alone never fill the list; the datastore holds every discovered
// server's region in plaintext once the list is loaded. Best effort: a locked
// or absent file simply keeps the previous cache.
func refreshPsiphonRegionsFromDataStore(dataDir string) {
	if dataDir == "" {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(dataDir, "*", "datastore", "psiphon.boltdb"))
	var regions []string
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		for _, hit := range psiphonDataStoreRegionRE.FindAllSubmatch(b, -1) {
			regions = append(regions, string(hit[1]))
		}
	}
	if len(regions) > 0 {
		savePsiphonRegions(regions)
	}
}

// noticeTunnelCount extracts establishedTunnelsCount from a notice payload when
// present (0 otherwise). Real Psiphon reports it as a plain JSON number.
func noticeTunnelCount(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var m struct {
		EstablishedTunnelsCount int `json:"establishedTunnelsCount"`
	}
	if json.Unmarshal(raw, &m) == nil {
		return m.EstablishedTunnelsCount
	}
	return 0
}

// noticePort parses the port payload of the ListeningSocksProxyPort notice.
// VERIFIED against real official Psiphon output: the payload is {"port":N}.
// The bare-integer and {"socksPort":N} shapes are kept as tolerance for other
// Psiphon versions.
func noticePort(raw json.RawMessage) int {
	var i int
	if json.Unmarshal(raw, &i) == nil && i > 0 {
		return i
	}
	var m map[string]int
	if json.Unmarshal(raw, &m) == nil {
		if m["port"] > 0 {
			return m["port"]
		}
		if m["socksPort"] > 0 {
			return m["socksPort"]
		}
	}
	return 0
}

// WaitForSocks blocks until Psiphon reports its SOCKS port, or the process
// exits, or the deadline passes. On timeout/exit it stops Psiphon and returns an
// error so the caller never believes it is CONNECTED on a dead listener.
func (p *Psiphon) WaitForSocks(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		port := p.socksPort
		ready := p.state >= psiphonSocksReady
		done := p.done
		p.mu.Unlock()
		if port > 0 && ready {
			return nil
		}
		if done != nil {
			select {
			case <-done:
				p.fail()
				p.Stop()
				return fmt.Errorf("psiphon process exited before SOCKS was ready")
			default:
			}
		}
		select {
		case <-ctx.Done():
			p.fail()
			p.Stop()
			return fmt.Errorf("psiphon wait cancelled: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			p.fail()
			p.Stop()
			return fmt.Errorf("psiphon SOCKS not ready within %s", timeout)
		}
	}
}

// WaitForTunnel blocks until Psiphon reports a real established tunnel (the
// `Tunnels` notice), or the process exits, or the deadline passes. This is the
// difference between "the SOCKS listener is up" and "Psiphon actually reached a
// server": a listening SOCKS port with no tunnel accepts CONNECT and then drops
// every request, which is exactly the "connected, nothing loads" lie this guard
// exists to prevent. On timeout the caller decides whether to retry or stop.
func (p *Psiphon) WaitForTunnel(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		ready := p.state >= psiphonTunnelReady
		done := p.done
		upstream := p.upstream
		p.mu.Unlock()
		if ready {
			return nil
		}
		if done != nil {
			select {
			case <-done:
				p.fail()
				return fmt.Errorf("psiphon 进程在建起隧道前退出")
			default:
			}
		}
		select {
		case <-ctx.Done():
			p.fail()
			return fmt.Errorf("psiphon 等待隧道被取消: %w", ctx.Err())
		case <-time.After(150 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			p.fail()
			u := upstream
			if u == "" {
				u = "(直连)"
			}
			return fmt.Errorf("psiphon 在 %s 内未建立隧道（上游 %s）：检查 underlay 是否可用", timeout, u)
		}
	}
}

// Upstream reports the underlay Psiphon dials through ("" = direct), for logs.
func (p *Psiphon) Upstream() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.upstream
}

// Port returns the dynamic SOCKS port Psiphon reported (0 until ready).
func (p *Psiphon) Port() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.socksPort
}

// PID returns the OS process id of the running Psiphon (0 if not started).
func (p *Psiphon) PID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pid
}

// IsRunning reports whether the Psiphon process was started in this instance.
func (p *Psiphon) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil
}

// Stop terminates the Psiphon process (via its context) and waits for exit.
func (p *Psiphon) Stop() error {
	p.mu.Lock()
	cancel := p.cancel
	cmd := p.cmd
	done := p.done
	dataDir := p.dataDir
	p.state = psiphonStopping
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}
	p.mu.Lock()
	p.cmd = nil
	p.cancel = nil
	p.pid = 0
	p.socksPort = 0
	// psiphonFailed is terminal: a launch that never built a tunnel stays
	// marked as failed even after the process is reaped, so callers and logs
	// can tell "torn down after working" from "never worked".
	if p.state != psiphonFailed {
		p.state = psiphonStopped
	}
	p.mu.Unlock()
	// The process is gone, so its bolt datastore lock is released: refresh the
	// region list from the server entries it just downloaded. Per-run cadence —
	// every connect cycle leaves the dropdown with the latest known set.
	refreshPsiphonRegionsFromDataStore(dataDir)
	return nil
}

// fail records that this launch will never reach tunnel readiness.
func (p *Psiphon) fail() {
	p.mu.Lock()
	p.state = psiphonFailed
	p.mu.Unlock()
}

// MarkRealTrafficReady records that a real request completed through the tunnel
// (the caller's data-plane proof). It is the only state that means "usable",
// as opposed to "the SOCKS listener is up" or "a tunnel handshake succeeded".
func (p *Psiphon) MarkRealTrafficReady() {
	p.mu.Lock()
	if p.state < psiphonRealTrafficReady {
		p.state = psiphonRealTrafficReady
	}
	p.mu.Unlock()
}

// State reports the launch lifecycle state, for logs and diagnostics.
func (p *Psiphon) State() psiphonState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}
