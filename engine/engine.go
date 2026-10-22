// Package engine is the Go half of the Android app: everything the Kotlin UI
// calls goes through Engine, and gomobile turns this package into an .aar.
//
// Layering (see docs/porting-analysis.md):
//
//	Kotlin / Compose  ──▶  Engine (this package)  ──▶  Backend (tunnel work)
//	                                                        │
//	                          warpscout engine (wg/awg/masque + gVisor) ─┘
//
// The Backend seam exists on purpose. It lets the whole app - VpnService,
// notification, state machine, log plumbing - be built and tested against a
// fake before the warpscout code is moved into this module, which is a
// mechanical but non-trivial step (warpscout is `package main` with package
// level globals; see the migration table in docs/porting-analysis.md).
//
// Deliberate divergences from the Windows client:
//   - No external processes. mihomo.exe and psiphon.exe have no place in an
//     APK; the tunnels are the engine's own.
//   - No state file, no pid lease, no health-guard subprocess. One process, one
//     mutex, one Service lifetime.
//   - No system-proxy code. Android routes through VpnService, so
//     ProxySnapshot/ProxyWarn/NoProxy simply do not exist here.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xhwarp/android-engine/warp"
)

// Version is reported to the UI and written into the bug-report header.
//
// P1: the warpscout engine (WG/AWG + gVisor netstack) is compiled in, so the app
// can build a real tunnel and read the real exit IP. Before this it was a
// placeholder that only reported ErrNotWired.
//
// Keep the doc comments of *bound* symbols ASCII: gomobile copies them into the
// generated Java, and javac on a Chinese Windows defaults to GBK, which turns
// any non-ASCII byte into "unmappable character" and fails the whole bind.
const Version = "0.2.0-android-p1"

// ErrNotWired is returned by the default backend: the UI and the state machine
// are in place, the warpscout engine has not been moved in yet.
var ErrNotWired = errors.New("引擎尚未接入：见 docs/porting-analysis.md 的 P1 步骤")

// LogSink receives one line per engine event. Kotlin implements it and the
// method is called from the engine goroutine, so the implementation must not
// touch the UI directly (post to a handler/coroutine instead).
type LogSink interface {
	OnLog(line string)
}

// Protector excludes one socket from the system VPN. Kotlin implements it with
// VpnService.protect(fd).
//
// This is not optional plumbing. Once VpnService is up, every packet the phone
// sends is routed into our own tun - including the encrypted UDP the tunnel uses
// to reach Cloudflare. Without this the tunnel swallows its own transport: the
// VPN key appears, the app says connected, and no page loads.
//
// Keep the doc comment ASCII: gomobile copies it into the generated Java, and
// javac on a Chinese Windows reads sources as GBK (see build-engine.ps1).
type Protector interface {
	// Protect returns true when the socket was successfully excluded.
	Protect(fd int) bool
}

// TunProvider builds the Android system VPN from parameters the OpenVPN server
// pushed (address/prefix/routes/dns/mtu) and returns the detached tun fd, or a
// value <= 0 on failure.
//
// This exists because an OpenVPN server routes replies to the ifconfig address
// it assigned; establishing the tun with the WARP address (172.16.0.2) makes the
// server drop every returning packet. The address is only known after the
// handshake, while VpnService.Builder must run before the fd exists - hence a
// callback from Go into Java in the middle of connect.
//
// Keep this comment ASCII: gomobile copies it into Java sources that javac may
// read as GBK.
type TunProvider interface {
	EstablishTun(address string, prefixLen int, routesCSV string, dnsCSV string, mtu int) int
}

// Request is one connect attempt. gomobile binds this as a plain class; every
// field is a basic type on purpose.
type Request struct {
	Proto    string // wg | awg | masque | masque-h2
	Endpoint string // ip:port, empty means "pick from the cached scan"
	Psiphon  bool   // stack a Psiphon exit on top of the base protocol
	IPv6     bool
	MTU      int
}

// Result is what a successful backend hands back.
type Result struct {
	ExitIP           string
	Country          string
	Endpoint         string
	PsiphonSocksPort int
	// Egress is the final exit kind: "" for the base protocol itself,
	// "psiphon" or "openvpn" when a second hop terminates the session.
	Egress string
}

// tunnelBackend establishes and tears down the tunnel. Implemented by the
// warpscout port; faked in tests.
//
// Deliberately unexported. gomobile generates a Java proxy for every exported
// interface so Kotlin could implement it, and this one cannot be expressed in
// Java - it takes a func(string) and returns a struct. Leaving it exported made
// gobind emit an incomplete proxy and fail the whole bind with
// "missing method Connect". Kotlin must never provide a tunnel anyway.
type tunnelBackend interface {
	// Connect blocks until the tunnel carries traffic, ctx is cancelled, or it
	// fails. The context is what makes a connect abortable: closing the tunnel
	// is not enough, because a dial that is already in flight has to be told to
	// give up.
	Connect(ctx context.Context, req Request, report func(string)) (Result, error)
	// Close releases the tunnel, the netstack and any listening port.
	Close() error
}

// Engine is the gomobile-visible object. Create exactly one and keep it for the
// process lifetime (the VpnService owns it).
type Engine struct {
	workDir string
	sess    *session

	mu          sync.Mutex
	backend     tunnelBackend
	cancel      context.CancelFunc
	tunFD       int
	statsStop   chan struct{}
	tunProvider TunProvider
}

// statsInterval is how often the data plane is sampled for the home screen's
// throughput and latency. The desktop UI used 2s as well.
const statsInterval = 2 * time.Second

// NewEngine wires an engine to a writable directory (the app's filesDir). The
// directory replaces the Windows client's WARP_CLIENT_HOME: account, cache and
// logs live there.
func NewEngine(workDir string) *Engine {
	e := &Engine{workDir: workDir, sess: newSession()}
	// 真正的数据面：WARP 账号 + WG/AWG 隧道 + gVisor netstack。
	// 装不上（workDir 不可写等）也只影响连不上，不影响 UI。
	e.setBackend(newWarpBackend(workDir))
	return e
}

// warpBackendOf 取出真实后端，用于账号导入与本地 SOCKS 端口查询。
// 测试里装的是假后端，这时返回 nil。
func (e *Engine) warpBackendOf() *warpBackend {
	e.mu.Lock()
	defer e.mu.Unlock()
	wb, _ := e.backend.(*warpBackend)
	return wb
}

// SetAccountJSON 让 Kotlin 直接喂一份账号（例如放在 assets 里的 account.json），
// 绕开 api.cloudflareclient.com 不可达时的注册步骤。
func (e *Engine) SetAccountJSON(raw string) {
	if wb := e.warpBackendOf(); wb != nil {
		wb.SetAccountJSON(raw)
		e.sess.logf("[engine] 已导入外部账号")
	}
}

// SetPsiphonConfig hands the engine the official Psiphon client config and the
// DNS servers to use. Both are plain strings so gomobile binds the method.
//
// The config JSON is required for the Psiphon exit: it carries the SponsorId,
// server-list URLs and signature keys. dnsServers is comma-delimited.
func (e *Engine) SetPsiphonConfig(clientConfigJSON, dnsServers string) {
	if wb := e.warpBackendOf(); wb != nil {
		wb.SetPsiphonConfig(clientConfigJSON, dnsServers)
		e.sess.logf("[engine] 已导入 Psiphon 客户端配置（%d 字节）", len(clientConfigJSON))
	}
}

// SetPsiphonRegion 设置 Psiphon 的落地地区："" 或 "auto" = 自动，否则 ISO-2（如 "JP"）。
// 只影响下一次连接 —— EgressRegion 是 tunnel-core 的启动参数。
func (e *Engine) SetPsiphonRegion(region string) {
	if wb := e.warpBackendOf(); wb != nil {
		wb.SetPsiphonRegion(region)
	}
}

// SetTunProvider installs the callback that builds the Android system VPN for
// the OpenVPN exit. Must be called before Connect; without it the OpenVPN exit
// reports a clear error instead of silently falling back to WARP.
func (e *Engine) SetTunProvider(p TunProvider) {
	e.mu.Lock()
	e.tunProvider = p
	wb, _ := e.backend.(*warpBackend)
	e.mu.Unlock()
	if wb == nil || p == nil {
		return
	}
	wb.SetOpenVPNTunProvider(func(t warp.OpenVPNTun) (int, error) {
		fd := p.EstablishTun(t.Address, t.PrefixLen,
			strings.Join(t.Routes, ","), strings.Join(t.DNS, ","), t.MTU)
		if fd <= 0 {
			return 0, fmt.Errorf("Android 侧建 tun 失败（address %s/%d）", t.Address, t.PrefixLen)
		}
		return fd, nil
	})
	e.sess.logf("[engine] 已安装 OpenVPN 建 tun 回调")
}

// SetOpenVPNExit selects the OpenVPN nodes to try, in order, as the final exit.
// idsCSV holds VPN Gate node IDs; the .ovpn configs stay inside the engine.
// An empty idsCSV turns the exit off. Only takes effect on the next Connect.
func (e *Engine) SetOpenVPNExit(idsCSV, label, country string) {
	wb := e.warpBackendOf()
	if wb == nil {
		return
	}
	ids := splitCSV(idsCSV)
	if len(ids) == 0 {
		wb.SetOpenVPNExit(false, nil, "", "")
		e.sess.logf("[engine] OpenVPN 出口已关闭（未选择节点）")
		return
	}
	// 过滤掉缓存里已经不存在的节点：列表刷新后旧的固定节点会失效，
	// 直接拿它连只会得到一个看不懂的报错。
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		if wb.VPNGateNodeConfig(id) == "" {
			e.sess.logf("[engine] 节点 %s 的配置不在缓存里，已跳过", id)
			continue
		}
		kept = append(kept, id)
	}
	if len(kept) == 0 {
		// 保持「用户要 OpenVPN 出口」这个意图，让 Connect 明确失败；不能把它
		// 当成「关闭 OpenVPN」——那样界面会显示「已连接」，出口却是 WARP。
		wb.SetOpenVPNExit(true, nil, label, country)
		e.sess.logf(
			"[engine] 选中的 %d 个节点都没有配置（节点列表可能已被刷新），本次连接会直接失败；"+
				"请到设置 → OpenVPN 出口 刷新节点列表", len(ids))
		return
	}
	wb.SetOpenVPNExit(true, kept, label, country)
	e.sess.logf("[engine] OpenVPN 出口 = %s（%s），候选 %d 个", label, country, len(kept))
}

// splitCSV 是 idsCSV 的解析：去空白、去空项、去重（顺序保持）。
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// VPNGateNodesJSON returns the cached VPN Gate node list, configs stripped:
// {"fetchedAt":<ms>,"nodes":[{id,host,ip,port,proto,cc,country,class,...}]}
func (e *Engine) VPNGateNodesJSON() string {
	if wb := e.warpBackendOf(); wb != nil {
		return wb.VPNGateNodesJSON()
	}
	return `{"fetchedAt":0,"nodes":[]}`
}

// RefreshVPNGateNodes fetches a fresh node list. BLOCKING: call it from a
// background thread. It may take tens of seconds because the API is blocked on
// some networks and the fallback establishes a temporary WARP tunnel.
func (e *Engine) RefreshVPNGateNodes() string {
	wb := e.warpBackendOf()
	if wb == nil {
		return "引擎未安装"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	n, err := wb.RefreshVPNGateNodes(ctx, func(s string) { e.sess.logf("[vpngate] %s", s) })
	if err != nil {
		e.sess.logf("[engine] 刷新节点失败: %v", err)
		return "刷新失败：" + err.Error()
	}
	return fmt.Sprintf("已刷新 %d 个节点", n)
}

// SetSocksListen 设置本地 SOCKS5 监听地址，形如 "127.0.0.1:1080"；"" 表示不开。
//
// 只有「仅代理」模式需要：VPN 模式整个系统已经在隧道里，没有本地入口这回事。
// 传 "0.0.0.0:port" 就是允许局域网访问（SOCKS5 无认证，调用方要提醒用户）。
func (e *Engine) SetSocksListen(addr string) {
	if wb := e.warpBackendOf(); wb != nil {
		wb.SetSocksListen(addr)
	}
}

// RefreshCNRoutes 立即拉一次大陆路由表（**阻塞**，调用方要放到后台线程）。
//
// 手动刷新用它。注意：在「仅代理」模式下这个请求走本机网络，在 VPN 模式下它会
// 走隧道 —— 被墙时只有后者的数据源能拉到。
func (e *Engine) RefreshCNRoutes() string {
	wb := e.warpBackendOf()
	if wb == nil {
		return "引擎未安装"
	}
	n, err := wb.refreshCNRoutes(context.Background(), func(s string) {
		e.sess.logf("[engine] %s", s)
	})
	if err != nil {
		return "刷新失败：" + err.Error()
	}
	return fmt.Sprintf("已更新 %d 条大陆网段", n)
}

// CNRoutesInfoJSON 返回大陆路由表缓存状态（count / fetched / stale），设置页用它
// 显示「有没有数据、是什么时候的」。没数据时 count=0、stale=true。
func (e *Engine) CNRoutesInfoJSON() string {
	if wb := e.warpBackendOf(); wb != nil {
		return wb.CNRoutesInfoJSON()
	}
	return "{}"
}

// SetRules 设置分流策略与自定义规则（只在「仅代理」模式执行）。
//
// policy 取 global / bypass-cn / blacklist；text 每行一条，格式见
// warp.NewRuleSet（`direct,example.com` / `proxy,1.2.3.0/24`）。
// 解析失败的行会被跳过并在这里写一行日志 —— 规则写错不能静默。
func (e *Engine) SetRules(policy, text string) {
	wb := e.warpBackendOf()
	if wb == nil {
		return
	}
	skipped := wb.SetRules(policy, text)
	if skipped > 0 {
		e.sess.logf("[engine] 分流规则有 %d 行无法解析，已跳过（格式：direct,example.com）", skipped)
	}
}

// PsiphonRegionsJSON 返回 Psiphon 可用出口地区，形如 ["AT","AU",…]。
//
// 用 JSON 而不是 []string：gobind 不支持切片返回值（会把整个方法静默跳过，
// Kotlin 侧表现为 "Unresolved reference"）。列表优先用它自己上报的，没连过时
// 用内置兜底表，所以选择器永远有东西可选。
func (e *Engine) PsiphonRegionsJSON() string {
	b, err := json.Marshal(warp.PsiphonRegions())
	if err != nil {
		return "[]"
	}
	return string(b)
}

// AccountJSON 返回当前账号 JSON（没有则为空串）。存下来下次导入即可免注册。
func (e *Engine) AccountJSON() string {
	if wb := e.warpBackendOf(); wb != nil {
		return wb.AccountJSON()
	}
	return ""
}

// SocksAddr 返回隧道自带的本地 SOCKS5 监听地址（未连接时为空）。
func (e *Engine) SocksAddr() string {
	if wb := e.warpBackendOf(); wb != nil {
		return wb.SocksAddr()
	}
	return ""
}

// setBackend installs the tunnel implementation. Called once at startup by the
// Android backend itself (same package); the scaffold's default refuses to
// connect with ErrNotWired. Unexported for the reason on tunnelBackend.
func (e *Engine) setBackend(b tunnelBackend) {
	e.mu.Lock()
	e.backend = b
	e.mu.Unlock()
}

// SetLogSink installs the Kotlin log callback.
func (e *Engine) SetLogSink(sink LogSink) { e.sess.setSink(sink) }

// SetTunFD hands the file descriptor of the tun device that Android's
// VpnService already created to the engine.
//
// This is the one thing the warpscout engine cannot do for itself: VpnService
// owns the interface and gives the app a fully configured fd, while
// amneziawg-go ships tun_darwin/tun_linux/tun_windows but no tun_android. The
// Android backend therefore wraps *this* fd as its tun.Device instead of
// asking the kernel for a new interface (see docs/porting-analysis.md, P1).
func (e *Engine) SetTunFD(fd int) {
	e.mu.Lock()
	e.tunFD = fd
	backend := e.backend
	e.mu.Unlock()
	if wb, ok := backend.(*warpBackend); ok {
		wb.SetTunFD(fd)
	}
	e.sess.logf("[engine] tun fd = %d", fd)
}

// SetVPNState tells the engine whether the Android system VPN is up. The UI
// shows it, and a tunnel is never reported as usable while it is false.
func (e *Engine) SetVPNState(up bool) {
	e.sess.setVPN(up)
}

// SetProtector installs the socket excluder. Must be called before Connect, and
// must stay installed for the whole session: every new socket the tunnel opens
// needs it.
func (e *Engine) SetProtector(p Protector) {
	if p == nil {
		warp.SetProtector(nil)
		return
	}
	warp.SetProtector(protectorFunc(func(fd int) bool { return p.Protect(fd) }))
	e.sess.logf("[engine] socket protector 已安装")
}

// protectorFunc adapts the bound interface to the package-internal one without
// exporting anything else to gomobile.
type protectorFunc func(fd int) bool

func (f protectorFunc) Protect(fd int) bool { return f(fd) }

// ProbeLocalJSON reports the address the internet currently sees for this phone,
// as {"ok":true,"ip":"...","country":"XX"}.
//
// It blocks for up to a few seconds, so Kotlin must call it off the UI thread.
// The disconnected home screen shows this as "your IP": it is the same probe the
// exit readout uses, so the two numbers are always comparable.
func (e *Engine) ProbeLocalJSON() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ip, country, ok := warp.ProbeNetwork(ctx, 8*time.Second)
	if !ok {
		return `{"ok":false}`
	}
	b, err := json.Marshal(map[string]any{"ok": true, "ip": ip, "country": country})
	if err != nil {
		return `{"ok":false}`
	}
	return string(b)
}

// SetTimeout sets the per-endpoint handshake timeout in seconds (0 = default).
// Comes from the settings screen's "connection timeout".
func (e *Engine) SetTimeout(sec int) {
	if wb := e.warpBackendOf(); wb != nil {
		wb.SetTimeout(sec)
	}
}

// MTU reports the device MTU the engine will use. The VpnService.Builder must
// set the same value: a tun whose MTU disagrees with what the device expects
// makes the kernel hand up packets the tunnel then has to fragment or drop.
func (e *Engine) MTU() int { return defaultMTU }

const defaultMTU = 1280

// TunFD reports the fd installed by SetTunFD (0 when there is none).
func (e *Engine) TunFD() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tunFD
}

// VersionString reports the engine build.
func (e *Engine) VersionString() string { return Version }

// dataCounters reads the tun device's cumulative byte counters.
func (e *Engine) dataCounters() (uint64, uint64) {
	e.mu.Lock()
	backend := e.backend
	e.mu.Unlock()
	if wb, ok := backend.(*warpBackend); ok {
		return wb.Counters()
	}
	return 0, 0
}

// startStats samples the data plane while a session is up: bytes in and out for
// the throughput readout, plus one round trip through the tunnel for the latency.
//
// The desktop client read these from mihomo's REST API (/traffic,
// /proxies/WARP/delay). There is no mihomo on Android, so the numbers come from
// the tun device itself - which is the better source anyway: it counts what the
// phone really sent, not what a proxy says it forwarded.
func (e *Engine) startStats() {
	e.mu.Lock()
	if e.statsStop != nil {
		e.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	e.statsStop = stop
	// Latency is only meaningful with the system VPN up: without it the request
	// never enters the tunnel and we would be measuring the phone's own uplink
	// while labelling it "connection latency".
	throughVPN := e.tunFD > 0
	e.mu.Unlock()

	// 探测参数。判「出口不可达」必须慢、且必须有旁证，否则会把「刚连上还在
	// 预热」「探测包被丢」写成断线 —— 现场就是这样：连上 6s 就报不可达，而
	// 界面延迟还有数值、上网也正常。三条约束缺一不可：
	//   1) 连上后先静默 probeGrace，别在隧道还没热的时候下结论；
	//   2) 单次超时给到 5s（移动网络 + 隧道，3s 太紧）；
	//   3) 只要 tun 还在进出字节（flowed），探测失败就不计数 —— 那是探测包
	//      被丢（DNS/ICMP/端口被拦都会这样），不是隧道死了。
	const (
		probeTimeout   = 5 * time.Second
		probeGrace     = 12 * time.Second
		probeFailLimit = 5
		probeFlowSlack = 512
	)
	started := time.Now()
	go func() {
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		var lastTx, lastRx uint64
		var lastAt time.Time
		var latency int64
		// 连续探测失败计数 / 是否已经就这次故障写过日志（只在状态翻转时写一行，
		// 免得日志被刷屏）。
		var probeFails int
		var probeWarned bool
		for {
			select {
			case <-stop:
				// 断开后清零：界面上「共 0 B」才是真的没在传，留着上次会话的
				// 累计值会让人以为还在跑。
				e.sess.setStats(0, 0, 0, 0, 0)
				return
			case <-ticker.C:
			}
			tx, rx := e.dataCounters()
			now := time.Now()
			var up, down int64
			if !lastAt.IsZero() {
				if secs := now.Sub(lastAt).Seconds(); secs > 0 {
					up = int64(float64(tx-lastTx) / secs)
					down = int64(float64(rx-lastRx) / secs)
				}
			}
			// 这一轮里数据面有没有真的动过（两个方向都算）。
			flowed := (tx-lastTx)+(rx-lastRx) > probeFlowSlack
			lastTx, lastRx, lastAt = tx, rx, now

			if throughVPN && now.Sub(started) >= probeGrace {
				if ms, ok := warp.ProbeLatency(context.Background(), probeTimeout); ok {
					latency = ms
					probeFails = 0
					if probeWarned {
						probeWarned = false
						e.sess.logf("[engine] 隧道探测恢复")
					}
					// 隧道自己缓过来了：撤掉「等重连」标记，别让看门狗白断开一次。
					e.sess.clearNeedsRecover()
				} else if flowed {
					// 探测失败但隧道在传数据：探针被丢，不是出口不可达。
					probeFails = 0
				} else {
					// 「已连接但上不了网」最难查的就是分不清「隧道从没通过」和
					// 「通了一会儿被切断」。连续失败且完全没有数据流动才写一行。
					probeFails++
					if probeFails >= probeFailLimit {
						// 判定为断：清掉延迟，界面上显示「—」，别留一个早就
						// 过期的数字骗人。
						latency = 0
						if !probeWarned {
							probeWarned = true
							e.sess.logf("[engine] 隧道连续 %d 次探测失败且无数据流动：出口已不可达（可能被切断）", probeFails)
						}
						// 只写日志不够：界面会一直显示「已连接」，而实际上一个网页
						// 都打不开（用户实测就是这样，39 分钟零流量）。标记出来，
						// 由 WarpVpnService 的看门狗断开并**换端点**重连。
						e.sess.markNeedsRecover()
					}
				}
			}
			e.sess.setStats(latency, up, down, int64(tx), int64(rx))
		}
	}()
}

func (e *Engine) stopStats() {
	e.mu.Lock()
	stop := e.statsStop
	e.statsStop = nil
	e.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

// StatusJSON returns the current snapshot as a JSON object. The UI polls this
// (or the engine pushes through LogSink); polling is what makes the Android
// port need no state file.
//
// JSON and not a struct: gobind skips a method whose parameter or return type is
// a Go struct passed by value (it writes "skipped method ... with unsupported
// parameter or return types" into the generated Java and binds nothing), so a
// bound Status() Snapshot would simply not exist on the Kotlin side. Kotlin
// parses this with the platform's org.json - no extra dependency.
func (e *Engine) StatusJSON() string {
	b, err := json.Marshal(e.sess.snapshot())
	if err != nil {
		// A Snapshot is all basic types; failing to encode it is not something
		// the UI could act on, so answer with a valid object carrying the state.
		return `{"state":"error","message":"snapshot encode failed"}`
	}
	return string(b)
}

// status is the typed view, for this package and its tests.
func (e *Engine) status() Snapshot { return e.sess.snapshot() }

// Logs returns the in-memory log ring as one string, for the log screen.
func (e *Engine) Logs() string { return e.sess.logs() }

// Connect starts a tunnel and returns immediately: Android's UI thread must not
// block, and a connect can take tens of seconds. Progress arrives through
// StatusJSON() and the LogSink.
//
// Cancellation is a first-class path (unlike the desktop GUI, where a click
// during "connecting" used to be swallowed): Disconnect during connecting moves
// the session to stopping and cancels the attempt.
//
// Every parameter is a basic type on purpose. An earlier signature took a
// Request struct by value and gobind dropped the whole method - it binds struct
// fields as accessors on a generated class but refuses a struct in a method
// signature ("skipped method Engine_.Connect with unsupported parameter or
// return types"), which surfaced as "Unresolved reference 'connect'" in Kotlin.
func (e *Engine) Connect(proto, endpoint string, psiphon, ipv6 bool, mtu int) error {
	req := Request{Proto: proto, Endpoint: endpoint, Psiphon: psiphon, IPv6: ipv6, MTU: mtu}

	// 这是「看门狗判定死亡后自动重连」的那一轮：把刚死掉的端点从「下次优先」缓存
	// 里删掉，否则新一轮还会先试同一个端点 —— 表现就是「不会换断点」。
	if prev := e.sess.snapshot(); prev.NeedRecover {
		if wb := e.warpBackendOf(); wb != nil {
			wb.forgetEndpoint(req.Proto)
		}
		e.sess.logf("[engine] 自动重连：%s 端点 %s 已从优选缓存移除，本轮会用新端点", req.Proto, prev.Endpoint)
	}
	e.sess.clearNeedsRecover()

	e.mu.Lock()
	backend := e.backend
	e.mu.Unlock()

	if backend == nil {
		backend = unwiredBackend{}
		e.sess.logf("[engine] 未安装 Backend，使用占位实现")
	}
	if err := e.sess.transition(StateConnecting, func(s *Snapshot) {
		s.Proto, s.Endpoint, s.Message = req.Proto, req.Endpoint, "连接中…"
		s.ExitIP, s.Country, s.SinceMS = "", "", 0
		// 上一次会话若是 Psiphon/OpenVPN，不在这里清掉的话，新会话握手期间
		// 首页会继续显示「最终出口：OpenVPN」——那是上一轮的结论。
		s.Egress = ""
	}); err != nil {
		return err
	}

	// 一次连接一个可取消的 context：Disconnect 调它，正在飞的拨号/握手/探测
	// 都会立刻收手，而不是等它自己跑完。
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.cancel = cancel
	e.mu.Unlock()

	go func() {
		defer cancel()
		e.sess.logf("[engine] Connect proto=%s endpoint=%s psiphon=%v", req.Proto, req.Endpoint, req.Psiphon)
		res, err := backend.Connect(ctx, req, func(msg string) { e.sess.logf("[tunnel] %s", msg) })
		cancelled := ctx.Err() != nil

		if err != nil {
			// A cancelled connect is an expected outcome, not a failure.
			if cancelled {
				e.sess.logf("[engine] 连接已取消")
				_ = e.sess.transition(StateStopping, func(s *Snapshot) { s.Message = "正在取消…" })
				_ = e.sess.transition(StateIdle, func(s *Snapshot) { s.Message = "未连接" })
				return
			}
			e.sess.logf("[engine] 连接失败: %v", err)
			_ = e.sess.transition(StateError, func(s *Snapshot) { s.Message = err.Error() })
			return
		}

		if cancelled {
			// The cancel raced a connect that had already committed: undo it
			// rather than leaving a tunnel the user asked to abandon.
			e.sess.logf("[engine] 取消请求已到，正在回收刚建立的隧道")
			_ = backend.Close()
			_ = e.sess.transition(StateStopping, func(s *Snapshot) { s.Message = "正在取消…" })
			_ = e.sess.transition(StateIdle, func(s *Snapshot) { s.Message = "未连接" })
			return
		}

		e.sess.setExit(req.Proto, res.Endpoint, res.ExitIP, res.Country)
		e.sess.setEgress(res.Egress)
		if err := e.sess.transition(StateConnected, nil); err != nil {
			e.sess.logf("[engine] %v", err)
		}
		e.startStats()
		e.sess.logf("[engine] 已连接，出口 %s (%s)", res.ExitIP, res.Country)
		// 大陆路由表只给「绕过大陆」用，且缓存过期才拉。必须放在**连上之后**：
		// fd 模式下这个请求会被系统路由进 tun，也就是「用当前隧道拉」——
		// 被墙的网络里这是唯一能拿到数据源的路径（见 cnroutes.go）。
		if wb := e.warpBackendOf(); wb != nil && wb.needsCNRoutes() {
			go func() {
				_, _ = wb.refreshCNRoutes(context.Background(), func(s string) {
					e.sess.logf("[engine] %s", s)
				})
			}()
		}
	}()
	return nil
}

// Disconnect tears the tunnel down. Safe to call in any state: from idle it is
// a no-op, from connecting it cancels the attempt.
func (e *Engine) Disconnect() error {
	snap := e.sess.snapshot()
	if snap.State == StateIdle {
		return nil
	}
	// The sampler only makes sense while a session exists; leaving it running
	// would keep probing a tunnel that is on its way down and paint a stale
	// latency back onto the disconnected screen.
	e.stopStats()
	e.mu.Lock()
	backend := e.backend
	cancel := e.cancel
	e.cancel = nil
	e.mu.Unlock()

	if err := e.sess.transition(StateStopping, func(s *Snapshot) { s.Message = "断开中…" }); err != nil {
		// Already stopping or in error: still make sure the resources go.
		e.sess.logf("[engine] Disconnect: %v", err)
	}
	if cancel != nil {
		cancel()
	}
	if backend != nil {
		if err := backend.Close(); err != nil {
			e.sess.logf("[engine] 关闭隧道失败: %v", err)
			_ = e.sess.transition(StateError, func(s *Snapshot) { s.Message = err.Error() })
			return err
		}
	}
	err := e.sess.transition(StateIdle, func(s *Snapshot) {
		s.Message = "未连接"
		s.ExitIP, s.Country, s.SinceMS, s.Proto, s.Endpoint = "", "", 0, "", ""
	})
	if err != nil {
		// Stopping -> Idle is the only legal move here; anything else means a
		// bug worth seeing in the log rather than hiding.
		e.sess.logf("[engine] 状态收敛失败: %v", err)
	}
	return nil
}

// unwiredBackend is the placeholder until the warpscout port lands. It fails
// loudly instead of pretending to connect, so the UI's error path is exercised
// from day one.
type unwiredBackend struct{}

func (unwiredBackend) Connect(context.Context, Request, func(string)) (Result, error) {
	return Result{}, fmt.Errorf("%w", ErrNotWired)
}

func (unwiredBackend) Close() error { return nil }
