package warp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
	"golang.org/x/net/proxy"
)

// Psiphon 出口（协议层的「叠加」开关，不是一条独立传输）。
//
// 桌面版是起一个 psiphon.exe 子进程 + 本地 SOCKS 端口驱动；APK 里没有可执行
// 文件，所以这里改成**进程内**跑官方的 psiphon-tunnel-core（用户已确认接受
// GPL-3.0）。数据面用的是 tunnel-core 自带的 packet tunnel：
//
//	系统 tun fd ──▶ Psiphon packet tunnel ──▶ Psiphon 服务器 ──▶ 互联网
//	                       ▲
//	                     上游 = 基础协议隧道暴露的本地 SOCKS（默认 WARP）
//
// 也就是说，tun fd 归 Psiphon 所有，基础 WARP 隧道退到 netstack 模式只当上游
// 载体 —— 这正是桌面版「mihomo 做数据面 + Psiphon 做出口」的等价形态，出口
// 国家/城市也就真的是 Psiphon 的出口，而不是 WARP 端点的。
//
// 为什么要有上游：在受限网络里 Psiphon 直连它的服务器同样会被拦，桌面版一直
// 是「WARP 打底、Psiphon 做出口」。UpstreamProxyURL 指向基础隧道的本地 SOCKS，
// Psiphon 自己的 socket 被 BindingToDevice 排除出系统 VPN 后连到 127.0.0.1，
// 环回不进 tun，所以不会绕回自己。

// psiphonUnderlayListen 是基础协议隧道为 Psiphon 暴露的本地 SOCKS 地址。
//
// 端口必须写 0，让内核分配一个空闲端口。以前钉死 1081，结果是一整类「赛风
// 连不上」的现场：上一次会话的监听还没收干净（或者别的进程正好占着 1081）时，
// bind 失败只写一行日志就继续，于是 Psiphon 的 UpstreamProxyURL 指向一个
// 没有监听（或指向别人的监听）的端口，tunnel-core 就一遍遍地拨它、一遍遍地
// 失败 —— 日志里只有一堆 meek/TLS 错误，看不出根因是本地端口。
// 每次拨号都开新的临时端口，这类冲突就彻底消失了。
//
// 不用 1080：那是（netstack 模式下）给用户自测用的常规入口，两个监听撞一起
// 会让「谁是谁」彻底说不清。
const psiphonUnderlayListen = "127.0.0.1:0"

// psiphonNetworkID 是给 tunnel-core 的「当前网络标识」。官方接口要求必须始终
// 返回一个值（取不到就 "UNKNOWN"），因为用它的逻辑（含 tactics）无论如何都要
// 继续走下去。
const psiphonNetworkID = "UNKNOWN"

// noticeTypeLimit 是每种 notice 最多写几行日志。诊断 notice 每个协议、每个端点
// 都会来一条，不限流会把日志刷满；但一条都不记就变成「连不上且不知道为什么」。
const noticeTypeLimit = 6

// psiphonReadyTimeout 是「下完 tun fd 到第一条隧道可用」的上限。Psiphon 要先取
// 服务器列表（Tactics + RemoteServerList）、再逐个协议试拨，在受限网络里比 WARP
// 慢一个量级；桌面版也是这个量级。给太短会把「慢」误判成「失败」。
const psiphonReadyTimeout = 180 * time.Second

// 上游看门狗（见 DialPsiphon）：探针间隔与「算死」次数。6s × 2 的取舍是
// 「宁可多等一轮也不要误杀」—— psiphon 启动本身就要几十秒，误杀一次代价更大。
const (
	psiphonUnderlayProbeGap  = 6 * time.Second
	psiphonUnderlayFailLimit = 2
)

// 叠加失败后的重试。
//
// 0.2.20 起从「3 次 / 150s」收紧到「2 次 / 90s」：之前那次 14 个端点全「数据面
// 不通」，根因是提前建了系统 VPN（已修），不是端点不够多。用户明确要求连接时间
// 要短，那就不能再用 150 秒去赌第三个端点。
const (
	psiphonMaxAttempts = 2
	psiphonTotalBudget = 90 * time.Second
)

// errUnderlayUnstable 标记「上游数据面不稳/被掐断」这一类失败：它值得换端点重试。
// 配置缺失、地区不提供、Psiphon 服务器一个都连不上 —— 这些换端点没用，直接报。
var errUnderlayUnstable = errors.New("上游数据面不稳")

// underlayHint 给「上游失败」补一句可操作的建议。
//
// WireGuard 在受限网络里最容易被识别/掐断（这也正是 AmneziaWG 存在的理由：
// 多几个混淆参数）。踩过的现场就是 wg 通不了、换成 awg 一次过。
func underlayHint(proto string) string {
	if proto == protoWG {
		return "；WireGuard 在这里最容易被识别，建议把协议换成 AmneziaWG 再试"
	}
	return ""
}

// PsiphonOptions 是一次「基础隧道 + Psiphon 出口」会话的参数。
type PsiphonOptions struct {
	// ClientConfigJSON 是官方 client.config 的内容（SponsorId / 服务器列表 URL /
	// 签名公钥都在里面）。缺它就没有服务器可拨，必须由调用方提供。
	ClientConfigJSON string
	// DNS 是给 tunnel-core 用的 DNS 服务器（逗号分隔）。空则让它用系统解析器。
	DNS string
	// EgressRegion 是期望的落地地区（ISO-3166-1 alpha-2，大写）。空串 = 自动，
	// 由 Psiphon 自己挑。只在「它本次确实提供该地区」时才下发（见 RegionOffered）。
	EgressRegion string
	// DataDir 是 tunnel-core 的 DataRootDirectory：datastore、服务器列表缓存都在
	// 这里。必须可写，否则 Commit 直接失败。
	DataDir string
	// TunFD 是 VpnService 建好的 tun 设备 fd，交给 Psiphon 的 packet tunnel。
	// 0 表示"上游建好后再向 Android 要"（见 psiphonTunProvider）。
	TunFD int
	// RegionsOnly 只启动隧道、不接管流量、不做出口测速，拿到可用地区列表就返回。
	// 用于「出口地区」里的「更新国家列表」：不需要 tun fd，也不需要真的上网。
	RegionsOnly bool

	// ---- 上游（基础协议隧道）----
	UnderlayProto    string // wg | awg | masque | masque-h2 | wwarp，默认 awg
	UnderlayEndpoint string // 可选：钉死 ip:port
	// UnderlayPrefer 是上游上一次成功的端点，会被排到候选最前（见 Options.Prefer）。
	UnderlayPrefer   string
	IPv6             bool
	HandshakeTimeout time.Duration
	VerifyTimeout    time.Duration
	Budget           time.Duration
	Report           func(string)
}

func (o *PsiphonOptions) report(msg string) {
	if o.Report != nil {
		o.Report(msg)
	}
}

// psiphonExit 是一次 Psiphon 运行的句柄：SOCKS 端口、就绪信号、以及最近一次
// 出错原因（失败时要能说出「为什么」而不是干等超时）。
type psiphonExit struct {
	socksPort atomic.Int32
	ready     chan struct{}
	readyOnce sync.Once
	lastErr   atomic.Pointer[string]
	// reqRegion 是本会话请求的落地地区（"" = 自动）。
	reqRegion string
	// regionErr 非空表示「选中的地区本次它根本不去」：waitReady 立刻失败，
	// 不必干等 psiphonReadyTimeout（默认 180s）。
	regionErr atomic.Pointer[string]

	// 每种 notice 已经写过多少行（限流用）。
	noticeMu   sync.Mutex
	noticeSeen map[string]int
}

func newPsiphonExit(reqRegion string) *psiphonExit {
	return &psiphonExit{ready: make(chan struct{}), reqRegion: NormalizeRegion(reqRegion)}
}

// regionErrNow 返回「选中的地区本次不可用」的原因（没有则为空）。
func (p *psiphonExit) regionErrNow() string {
	if e := p.regionErr.Load(); e != nil {
		return *e
	}
	return ""
}

// SocksAddr 是 Psiphon 本地 SOCKS 的地址（就绪前为空）。
func (p *psiphonExit) SocksAddr() string {
	port := p.socksPort.Load()
	if port <= 0 {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}

// stop 停掉进程内的 controller（幂等：psi.Stop 对未启动的 controller 是 no-op）。
func (p *psiphonExit) stop() { psi.Stop() }

func (p *psiphonExit) readyNow() bool {
	if p.socksPort.Load() <= 0 {
		return false
	}
	select {
	case <-p.ready:
		return true
	default:
		return false
	}
}

func (p *psiphonExit) lastError() string {
	if e := p.lastErr.Load(); e != nil {
		return *e
	}
	return ""
}

// forwardNotice 把一条 notice 写进 App 日志，按类型限流（错误类不限）。
func (p *psiphonExit) forwardNotice(kind, raw string, report func(string)) {
	if report == nil || kind == "" {
		return
	}
	p.noticeMu.Lock()
	if p.noticeSeen == nil {
		p.noticeSeen = map[string]int{}
	}
	p.noticeSeen[kind]++
	n := p.noticeSeen[kind]
	p.noticeMu.Unlock()

	loud := kind == "Error" || kind == "InternalError" || kind == "Warning" ||
		kind == "Tunnels" || kind == "ListeningSocksProxyPort"
	if !loud && n > noticeTypeLimit {
		return
	}
	report("Psiphon[" + kind + "] " + trimNotice(raw))
}

// trimNotice 只取 notice 里的 message / data，并截断：完整的一条诊断 notice 可以
// 带上整组网络参数，直接塞进日志面板会淹掉别的东西。
func trimNotice(raw string) string {
	var n struct {
		Data    json.RawMessage `json:"data"`
		Message string          `json:"message"`
	}
	if json.Unmarshal([]byte(raw), &n) != nil {
		return clipText(raw, 240)
	}
	if n.Message != "" {
		return clipText(n.Message, 240)
	}
	if len(n.Data) > 0 {
		return clipText(string(n.Data), 240)
	}
	return ""
}

func clipText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// handleNotice 解析一条 notice。这里是「就绪」的唯一判据，形状与官方一致：
//
//	{"noticeType":"ListeningSocksProxyPort","data":{"port":N},"timestamp":"..."}
//	{"noticeType":"Tunnels","data":{"count":N},"timestamp":"..."}
//
// 只有 SOCKS 端口**和**至少一条隧道同时到齐才算就绪：只听端口会得到一个
// 「端口开着、每个请求都被丢弃」的假成功，正是出口读数最容易骗人的形态。
func (p *psiphonExit) handleNotice(raw string, report func(string)) {
	var n struct {
		Notice string          `json:"noticeType"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		return
	}
	// 先把 notice 本身写进日志（按类型限流）：Psiphon 的失败原因几乎全部只出现在
	// notice 里 —— 服务器列表抓不到、tactics 失败、每个协议的拨号失败。之前关掉
	// 诊断 notice 又不记录，等于把唯一能定位问题的信息丢了。
	p.forwardNotice(n.Notice, raw, report)

	switch n.Notice {
	case "ListeningSocksProxyPort":
		var d struct {
			Port int `json:"port"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Port > 0 {
			p.socksPort.Store(int32(d.Port))
			if report != nil {
				report(fmt.Sprintf("Psiphon 本地 SOCKS 已监听 127.0.0.1:%d", d.Port))
			}
		}
	case "Tunnels":
		var d struct {
			Count int `json:"count"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Count > 0 {
			p.readyOnce.Do(func() { close(p.ready) })
			if report != nil {
				report(fmt.Sprintf("Psiphon 隧道已建立（%d 条）", d.Count))
			}
		}
	case "ConnectingServer":
		// 这一条带 establishedTunnelsCount，是「已经有隧道在跑」的另一个来源；
		// 版本之间 notice 名字变过，多认一个就少一种「明明通了却报超时」。
		var d struct {
			Count    int    `json:"establishedTunnelsCount"`
			Protocol string `json:"protocol"`
			Region   string `json:"region"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Count > 0 {
			p.readyOnce.Do(func() { close(p.ready) })
			if report != nil {
				report(fmt.Sprintf("Psiphon 出口 %s (%s)", d.Region, d.Protocol))
			}
		}
	case "AvailableEgressRegions":
		// 这是「它这次能去哪些国家」的唯一权威来源：登录后约 6s 到达，早于隧道。
		// 记下来给选择器用（并落盘），同时立刻校验用户选的地区 —— 不再等服务端
		// 一个个候选拨完才报超时。
		var d struct {
			Regions []string `json:"regions"`
		}
		if json.Unmarshal(n.Data, &d) == nil && len(d.Regions) > 0 {
			set := normalizeRegions(d.Regions)
			SetPsiphonRegions(set)
			if report != nil {
				report(fmt.Sprintf("Psiphon 可用出口地区 %d 个：%s", len(set), strings.Join(set, " ")))
			}
			if r := p.reqRegion; r != "" && !RegionOffered(set, r) {
				msg := fmt.Sprintf("Psiphon 本次不提供 %s 地区的出口（它现在只会从 %s 落地）；"+
					"请改选列表里的地区，或把出口地区设为「自动」", r, strings.Join(set, " "))
				p.regionErr.Store(&msg)
				if report != nil {
					report(msg)
				}
			}
		}
	case "Error", "InternalError", "Warning":
		var d struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(n.Data, &d)
		msg := d.Message
		if msg == "" {
			msg = string(n.Data)
		}
		s := n.Notice + ": " + msg
		p.lastErr.Store(&s)
		if report != nil {
			report("Psiphon " + s)
		}
	}
}

// waitReady 等到「有隧道 + SOCKS 端口」都就绪，或超时/取消。
func (p *psiphonExit) waitReady(ctx context.Context, timeout time.Duration, report func(string)) error {
	deadline := time.Now().Add(timeout)
	for {
		if p.readyNow() {
			return nil
		}
		// 「选中的地区它不去」是确定性失败：越早说越好，别耗满 180s。
		if e := p.regionErrNow(); e != "" {
			return errors.New(e)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			if e := p.lastError(); e != "" {
				return fmt.Errorf("Psiphon 在 %s 内没有建立隧道（最近错误：%s）", timeout, e)
			}
			return fmt.Errorf("Psiphon 在 %s 内没有建立隧道", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// psiphonProvider 是 tunnel-core 回调宿主的实现（官方 MobileLibrary 里那一套的
// 进程内版本）。BindToDevice 是其中唯一不能省的一个：Psiphon 自己的 socket 若不
// 排除出系统 VPN，它会连到我们自己的 tun 上，形成自噬环，表现为「已连接、什么都
// 打不开」。这里直接复用引擎里已经装好的 VpnService.protect。
type psiphonProvider struct {
	ex     *psiphonExit
	dns    string
	report func(string)
}

func (p *psiphonProvider) Notice(noticeJSON string) { p.ex.handleNotice(noticeJSON, p.report) }

func (p *psiphonProvider) OnAccessToken(string) {}

// 1 = 有网络。宿主侧的联通性判断在安卓上没有额外信息可用，而 tunnel-core 自己
// 会按 notice 重试。
func (p *psiphonProvider) HasNetworkConnectivity() int { return 1 }

func (p *psiphonProvider) BindToDevice(fd int) (string, error) {
	if pr := currentProtector(); pr != nil && pr.Protect(fd) {
		return "", nil
	}
	// 保护失败仍返回 nil：让 tunnel-core 自己按拨号失败去报错，比在这里把
	// 整条链路打断更容易看出「到底哪一步不通」。
	return "", nil
}

func (p *psiphonProvider) IPv6Synthesize(string) string { return "" }

func (p *psiphonProvider) HasIPv6Route() int { return 0 }

// 网络标识（用于 tactics 选择与缓存键）。
//
// 官方接口文档写得很死：**必须始终返回一个值**，取不到就返回 "UNKNOWN" ——
// 因为用它的逻辑（含 tactics）无论如何都要继续。之前这里返回空串，属于违约。
func (p *psiphonProvider) GetNetworkID() string { return psiphonNetworkID }

func (p *psiphonProvider) GetDNSServersAsString() string { return p.dns }

// buildPsiphonConfig 从官方 client.config 出发，只覆盖运行期必须改的字段。
//
// 凭据（SponsorId / PropagationChannelId / 服务器列表 URL 与签名公钥）全部沿用
// 官方文件，一个字都不动 —— 少了它们 Psiphon 会报「零个可用服务器」。
func buildPsiphonConfig(baseJSON string, tunFD int, dataDir, upstream, dns, region string) (string, error) {
	if baseJSON == "" {
		return "", fmt.Errorf("缺少官方 client.config（SponsorId / 服务器列表 URL / 签名公钥都在里面）")
	}
	cfg := map[string]any{}
	if err := json.Unmarshal([]byte(baseJSON), &cfg); err != nil {
		return "", fmt.Errorf("解析 client.config: %w", err)
	}

	// 数据面：packet tunnel 直接吃 VpnService 的 tun fd。TunnelPoolSize 必须为 1。
	cfg["PacketTunnelTunFileDescriptor"] = tunFD
	cfg["TunnelPoolSize"] = 1

	// 本地 SOCKS 端口交给系统选，端口从 ListeningSocksProxyPort notice 读回来；
	// HTTP 代理关掉，没有消费者，少一个监听少一份出错面。
	cfg["LocalSocksProxyPort"] = 0
	cfg["LocalHttpProxyPort"] = 0
	cfg["DisableLocalHTTPProxy"] = true

	cfg["DataRootDirectory"] = dataDir
	cfg["UpstreamProxyURL"] = upstream

	// 落地地区。选了才下发；选「自动」时必须把官方 config 里可能带的 EgressRegion
	// 删掉 —— 留着就会出现「界面上是自动、实际被钉在某个国家」，正是要修的那类错觉。
	if r := NormalizeRegion(region); r != "" {
		cfg["EgressRegion"] = r
	} else {
		delete(cfg, "EgressRegion")
	}

	// 诊断 notice 必须打开。关掉它 = 把「为什么连不上」全部藏起来：服务器列表抓取
	// 失败、Tactics 失败、每个协议的拨号失败都在诊断 notice 里，只剩一句「没建立
	// 隧道」。日志量由 handleNotice 的按类型限流兜住。
	cfg["EmitDiagnosticNotices"] = true
	cfg["EmitDiagnosticNetworkParameters"] = false

	// 迁移字段指向本机其它 Psiphon 安装的 datastore，安卓上必然不存在，
	// 留着只会让它去 adopt 一个不该碰的目录。
	for _, k := range []string{
		"MigrateDataStoreDirectory",
		"MigrateObfuscatedServerListDownloadDirectory",
		"MigrateRemoteServerListDownloadFilename",
		"MigrateUpgradeDownloadFilename",
	} {
		delete(cfg, k)
	}

	b, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// startPsiphon 装配配置、启动 controller 并等到就绪。
//
// readyTimeout 由调用方给：Psiphon 叠加会重试上游端点，单次尝试不能吃掉全部预算。
// psiphonTunProvider 在**上游已经建好之后**才向 Android 要一个 tun fd。
//
// 顺序很重要：系统 VPN 一旦建立，VpnService 立刻接管全部路由，而我们这条
// WARP 上游的 UDP 虽然被 protect，实测在「VPN 刚建立」的窗口里仍然会被丢掉
// —— 真机日志里 Psiphon 上游连续 14 个端点全部「握手成功、数据面不通」，而同
// 一刻 OpenVPN 出口（不提前建 tun）用的是同一条 awg 上游却是通的。
// 所以 Psiphon 也改成「先建上游、再建 tun」。
var psiphonTunProvider func() (int, error)

// SetPsiphonTunProvider 安装「按需建系统 VPN」的回调（Kotlin 侧实现）。
func SetPsiphonTunProvider(f func() (int, error)) { psiphonTunProvider = f }

func startPsiphon(ctx context.Context, o PsiphonOptions, underlaySocks string, readyTimeout time.Duration) (*psiphonExit, error) {
	if o.TunFD <= 0 && !o.RegionsOnly {
		// 上游已经通了，现在才接管流量。
		if psiphonTunProvider == nil {
			return nil, fmt.Errorf("Psiphon 需要系统 tun fd，但 Android 侧没有安装建 tun 回调（当前 fd=%d）", o.TunFD)
		}
		fd, err := psiphonTunProvider()
		if err != nil {
			return nil, fmt.Errorf("建立系统 VPN 失败: %w", err)
		}
		if fd <= 0 {
			return nil, fmt.Errorf("建立系统 VPN 失败（fd=%d）", fd)
		}
		o.TunFD = fd
		o.report(fmt.Sprintf("系统 VPN 已建立（tun fd=%d），把流量交给 Psiphon", fd))
	}
	if o.DataDir == "" {
		return nil, fmt.Errorf("Psiphon 缺少可写的数据目录")
	}
	if err := os.MkdirAll(o.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建 Psiphon 数据目录: %w", err)
	}

	upstream := ""
	if underlaySocks != "" {
		upstream = "socks5://" + underlaySocks
	}
	cfgJSON, err := buildPsiphonConfig(o.ClientConfigJSON, o.TunFD, o.DataDir, upstream, o.DNS, o.EgressRegion)
	if err != nil {
		return nil, err
	}
	if r := NormalizeRegion(o.EgressRegion); r != "" {
		o.report("Psiphon 出口地区 = " + r)
	}

	ex := newPsiphonExit(o.EgressRegion)
	provider := &psiphonProvider{ex: ex, dns: o.DNS, report: o.report}
	o.report("启动 Psiphon（进程内）…")
	// 第四个参数 useDeviceBinder=true：Psiphon 的 socket 必须被排除出系统 VPN。
	// 后两个 false：不使用 IPv6 合成器与 IPv6 路由探测。
	if err := psi.Start(cfgJSON, "", "", provider, true, false, false); err != nil {
		return nil, fmt.Errorf("启动 Psiphon 失败: %w", err)
	}
	// 这里**不要** ClaimTunFD：Psiphon 的 packet tunnel 是 dup 一份 fd 自己用
	// （psiphon/common/tun/tun_unix.go:fileFromFD），原 fd 始终留在我们手上。
	// 所以它既是失败路径要关的对象，也是 Session.Close 要关的对象 —— 之前误以为
	// 「已接管」，结果失败/断开后系统 VPN 一直挂着（实测只有杀进程才恢复）。
	stopOnError := true
	defer func() {
		if stopOnError {
			psi.Stop()
		}
	}()

	if err := ex.waitReady(ctx, readyTimeout, o.report); err != nil {
		return nil, err
	}
	stopOnError = false
	return ex, nil
}

// underlayProtos 给出 Psiphon 上游要按顺序试的协议。
//
// 用户选的协议先试；它没建起来就自动退到 AmneziaWG —— 这台网络里唯一
// 「加了混淆、能过 DPI」的传输。真机日志里的典型现场：wg 的 6 个端点全部
// 「握手成功但数据面不通」（握手能过、数据一到就被掐），Psiphon 因此一个隧道
// 都起不来，而同一时刻 awg 是通的。不自动退的话，用户看到的就是「赛风永远连
// 不上」，还得自己去猜要换协议 —— 这不该由用户来猜。
func underlayProtos(proto string) []string {
	if proto == "" {
		proto = protoAWG
	}
	if proto == protoAWG {
		return []string{protoAWG}
	}
	return []string{proto, protoAWG}
}

// DialPsiphon establishes "underlay tunnel + in-process Psiphon exit" and makes
// one real exit measurement through the Psiphon SOCKS.
//
// Exported for the engine package, which binds it to the Psiphon switch.
func DialPsiphon(ctx context.Context, o PsiphonOptions) (*Session, error) {
	if o.UnderlayProto == "" {
		o.UnderlayProto = protoAWG
	}
	deadline := time.Now().Add(psiphonTotalBudget)
	protos := underlayProtos(o.UnderlayProto)
	var lastErr error
	tried := 0

	// 只走 WARP 前置：不用直连。
	//
	// 用户明确要求（2026-11-09）。实测直连虽然也能把 Psiphon 隧道拉起来，
	// 但它走的是本机裸网络，在这张网里经常刚建立就被掐、出口验证吃不到数据，
	// 观感是「时好时坏」。统一走 WARP 前置至少是同一条已知可用的链路。
	for pi, proto := range protos {
		o.UnderlayProto = proto
		skip := ""
		perProto := 0
		for attempt := 1; attempt <= psiphonMaxAttempts; attempt++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			tried++
			perProto++
			sess, used, err := dialPsiphonOnce(ctx, o, skip, remaining)
			if err == nil {
				return sess, nil
			}
			lastErr = err
			// 只有「上游不稳」值得换端点重试。地区不提供、缺 client.config、
			// Psiphon 服务器一个都连不上 —— 换端点不会有任何区别。
			if !errors.Is(err, errUnderlayUnstable) {
				break
			}
			// 下一次跳过刚死掉的端点：同一个端点再试，大概率还是一样。
			skip = used
			if attempt == psiphonMaxAttempts {
				break
			}
			o.report(fmt.Sprintf("第 %d 次叠加没稳住，换一个上游端点再试…", perProto))
		}
		if lastErr != nil && !errors.Is(lastErr, errUnderlayUnstable) {
			// 硬错误（缺 client.config、地区不提供、Psiphon 侧起不来）：换协议
			// 不会有任何区别，别再白等一轮。
			return nil, fmt.Errorf("（共试了 %d 次上游）%w", tried, lastErr)
		}
		if pi+1 < len(protos) {
			o.report(fmt.Sprintf("Psiphon 上游（%s）没建起来：%v；改用 %s 再试…",
				proto, lastErr, protos[pi+1]))
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("预算 %s 内没等到可用的上游", psiphonTotalBudget)
	}
	return nil, fmt.Errorf("%w（共试了 %d 次上游）%s", lastErr, tried, underlayHint(o.UnderlayProto))
}

// dialPsiphonOnce 是一次完整的「拨上游 → 叠加 Psiphon → 出口实测」。
//
// 返回的 used 是本次用到的上游端点：失败时上层要靠它把端点排除掉再重试。
func dialPsiphonOnce(ctx context.Context, o PsiphonOptions, skip string, remaining time.Duration) (*Session, string, error) {
	underlayProto := o.UnderlayProto

	// 上游可以是**任意一种**传输：它们的职责只是「把出口做成一个本地 SOCKS 端口」，
	// WG / AWG / MASQUE / WARP-in-WARP 都能做到（netstack 模式下各自会开 SOCKS）。
	//
	// 这里必须走 Dial 而不是直接调某个具体拨号函数：Dial 才做协议分派，也才会
	// 调 Options.fill() 补默认值。踩过：直接调 dialWGTunnel 时 Ports 是空的，
	// 一个候选都不试就报「0 次尝试都没握手成功」——Psiphon 开着时连 WG 都连不上。
	// 单次尝试不能吃掉全部预算：外面还有「换端点 / 换协议」的重试（见 DialPsiphon）。
	budget := o.Budget
	if budget <= 0 || (remaining > 0 && remaining < budget) {
		budget = remaining
	}
	savedTunFD := tunFD
	savedMTU := tunMTU
	tunFD = 0 // 系统 tun fd 这一轮归 Psiphon 的 packet tunnel，上游退成 netstack
	// 上游是 WARP：netstack 必须按 WARP 的 **1280** 建。
	//
	// 绝不能沿用 Psiphon 自己 tun 的 1500：1500 的包 WARP 封不进去，握手（小包）
	// 能过、数据（大包）一个字节都发不出。真机日志就是这一条 ——
	// `netstack 数据面（全局 tunFD 0→0, tunMTU 1500）` 之后 14 个端点全部
	// 「握手成功、数据面不通」；而同一批端点在没有 Psiphon 会话残留时（tunMTU
	// 还是 1280）是通的。
	tunMTU = 1280
	defer func() { tunMTU = savedMTU }()
	o.report(fmt.Sprintf("Psiphon 上游：netstack 数据面（全局 tunFD %d→0, tunMTU %d）", savedTunFD, tunMTU))
	under, err := Dial(ctx, Options{
		Proto:            underlayProto,
		Endpoint:         o.UnderlayEndpoint,
		Prefer:           o.UnderlayPrefer,
		Skip:             skip,
		IPv6:             o.IPv6,
		Sample:           2,
		HandshakeTimeout: o.HandshakeTimeout,
		VerifyTimeout:    o.VerifyTimeout,
		Budget:           budget,
		SocksListen:      psiphonUnderlayListen,
		// 这个端口是 Psiphon 唯一的上游入口：bind 失败必须让整次尝试失败，
		// 否则隧道看起来通了、Psiphon 却一个字节也发不出去。
		SocksRequired: true,
		// 上游只有一个本地 SOCKS 端口，不能并发拨号（见 Options.NoHedge）。
		NoHedge: true,
		Report:  o.Report,
	})
	tunFD = savedTunFD
	if err != nil {
		// 上游建不起来大多是「这个端点 / 这个协议在这张网里过不去」，值得换端点
		// 甚至换协议再试 —— 这正是「赛风一直连不上」最常见的根因。
		return nil, "", fmt.Errorf("%w: Psiphon 上游（%s）建立失败: %v",
			errUnderlayUnstable, underlayProto, err)
	}
	used := under.Endpoint
	upSocks := under.SocksAddr()
	if upSocks == "" {
		under.Close()
		return nil, used, fmt.Errorf("%w: 上游隧道握手成功但本地 SOCKS 端口没起来（Psiphon 没有可用载体）",
			errUnderlayUnstable)
	}
	o.report(fmt.Sprintf("上游就绪（%s 出口 %s，本地 SOCKS %s），叠加 Psiphon…",
		underlayProto, under.ExitIP, upSocks))

	// 上游看门狗：这是 WG + Psiphon「等很久才失败」的根因。
	//
	// 端点常见的死法不是「握手失败」，而是握手成功、连出口验证都过了，然后十几秒
	// 后被掐断。Psiphon 偏偏就栽在这十几秒里：它刚拿到上游 SOCKS，正在逐个协议
	// 试拨，所有 TCP 都打空，最后报「180s 内没有建立隧道」—— 用户看到的是漫长
	// 等待后的失败，日志里还只有一堆 meek/TLS 错误，看不出是上游已经死了。
	//
	// 这里每 6s 经上游自己的 SOCKS 探一次；连续 2 次不通就中止叠加，并把原因
	// 直接写进错误里。成功路径零代价（探测在后台，不阻塞 Psiphon 启动）。
	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	var underlayDead atomic.Bool
	go func() {
		fails := 0
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-time.After(psiphonUnderlayProbeGap):
			}
			if _, _, ok := probeViaSocks(watchCtx, upSocks, 6*time.Second); ok {
				fails = 0
				continue
			}
			fails++
			o.report(fmt.Sprintf("上游探测失败 %d/%d", fails, psiphonUnderlayFailLimit))
			if fails >= psiphonUnderlayFailLimit {
				underlayDead.Store(true)
				watchCancel()
				return
			}
		}
	}()

	// 单次尝试等 Psiphon 就绪的上限不能吃掉全部预算，否则一次就把三次机会耗光。
	readyTimeout := psiphonReadyTimeout
	if remaining < readyTimeout {
		readyTimeout = remaining
	}
	ex, err := startPsiphon(watchCtx, o, upSocks, readyTimeout)
	if err != nil {
		under.Close()
		if underlayDead.Load() {
			return nil, used, fmt.Errorf("%w: 上游（%s）在 Psiphon 建立前被掐断（连续 %d 次探测无响应）: %v",
				errUnderlayUnstable, underlayProto, psiphonUnderlayFailLimit, err)
		}
		// 其余都是硬错误（缺 client.config、地区不提供、Psiphon 侧起不来）。
		return nil, used, err
	}
	// 就绪之后看门狗收工：之后「出口还在不在」由会话自身的探测负责，
	// 这里再探只会重复，还会把预算烧在一次已经成功的连接上。
	watchCancel()

	// 「只取地区列表」：隧道已就绪，列表已经上报，没必要接管流量或测出口。
	if o.RegionsOnly {
		under.psiphon = ex
		under.tunFD = 0
		o.report(fmt.Sprintf("Psiphon 上报可用地区 %d 个", len(PsiphonRegions())))
		return under, used, nil
	}

	// 出口实测必须走 Psiphon 的 SOCKS：这样界面上的 IP/国家就是 Psiphon 的出口，
	// 而不是上游 WARP 的 —— 桌面版历史上正是把这两个混在一起才「显示的不是」。
	ip, country, ok := probeViaSocks(ctx, ex.SocksAddr(), o.VerifyTimeout)
	if !ok {
		// 分清两种死法：上游同时也不通 → 端点被掐，换端点有意义；
		// 上游还通 → Psiphon 那一侧的问题，换端点没用，直接报。
		_, _, upOK := probeViaSocks(ctx, upSocks, 8*time.Second)
		psi.Stop()
		under.Close()
		if !upOK {
			return nil, used, fmt.Errorf("%w: Psiphon 隧道建立后随即失联，且上游（%s）同时不通", errUnderlayUnstable, underlayProto)
		}
		return nil, used, fmt.Errorf("Psiphon 已连接但出口验证失败（/meta 与 /trace 都没通过 SOCKS %s）", ex.SocksAddr())
	}

	under.ExitIP, under.Country = ip, country
	under.psiphon = ex
	// 原 tun fd 归我们（Psiphon 只 dup 了副本），会话结束时必须由我们关掉，
	// 否则断开后系统 VPN 一直挂着 —— 见 session.go 的 Session.tunFD。
	under.tunFD = o.TunFD
	o.report(fmt.Sprintf("Psiphon 出口 %s (%s)", ip, country))
	return under, used, nil
}

// ProbePsiphonRegion 用**一条已经就绪的上游 SOCKS** 把 Psiphon 拉到指定地区，
// 测一次下载速度后停掉。返回 (就绪耗时 ms, 字节/秒, error)。
//
// 为什么要复用上游：真机日志（2026-11-09 15:22）里，逐个地区各建一条上游测完
// 27 个之后，紧接着连接就失败了 —— `RemoteServerListResourceDownloadedBytes
// bytes:0`、候选只剩 13 个、1m29s 建不起隧道。27 次「建上游 + 起 Psiphon + 停」
// 把 socket / netstack / tunnel-core 的全局状态全耗掉了。
func ProbePsiphonRegion(
	ctx context.Context, cfg, dns, dataDir, upSocks, region string,
	timeout time.Duration, report func(string),
) (int64, int64, error) {
	o := PsiphonOptions{
		ClientConfigJSON: cfg,
		DNS:              dns,
		DataDir:          dataDir,
		// RegionsOnly：不建 tun、不接管流量，只借 Psiphon 的 SOCKS 测一次。
		RegionsOnly:   true,
		EgressRegion:  region,
		VerifyTimeout: 8 * time.Second,
		Report:        report,
	}
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	started := time.Now()
	ex, err := startPsiphon(ctx, o, upSocks, timeout)
	if err != nil {
		return time.Since(started).Milliseconds(), 0, err
	}
	ms := time.Since(started).Milliseconds()
	bps := ProbeSpeedViaSocks(ctx, ex.SocksAddr(), 512<<10, 8*time.Second)
	ex.stop()
	return ms, bps, nil
}

// ProbeSpeedViaSocks 经一个 SOCKS5 下载最多 limit 字节，返回字节/秒（0 = 测不出）。
//
// 用于「出口地区」里的测速：RegionsOnly 模式下 Psiphon 只有 SOCKS、没有 tun，
// 但经 SOCKS 下载就是它真实落地时能给到的速度。
func ProbeSpeedViaSocks(ctx context.Context, socksAddr string, limit int64, timeout time.Duration) int64 {
	if socksAddr == "" || limit <= 0 {
		return 0
	}
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return 0
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return 0
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				return cd.DialContext(dctx, network, addr)
			},
		},
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, probeSpeedURL, nil)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	start := time.Now()
	var got int64
	buf := make([]byte, 64<<10)
	for got < limit {
		n, rerr := resp.Body.Read(buf)
		got += int64(n)
		if rerr != nil {
			break
		}
	}
	d := time.Since(start).Seconds()
	if got <= 0 || d < 0.3 {
		return 0
	}
	return int64(float64(got) / d)
}

// probeViaSocks 通过一个本地 SOCKS5 真发一次请求，拿回出口 IP 与归属。
//
// 用 x/net/proxy 而不是自己写握手：它对域名走 ATYP_DOMAIN，也就是 DNS 在出口侧
// 解析，不会把查询泄漏到本机网络。
func probeViaSocks(ctx context.Context, socksAddr string, timeout time.Duration) (string, string, bool) {
	if socksAddr == "" {
		return "", "", false
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return "", "", false
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return "", "", false
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return cd.DialContext(ctx, network, addr)
			},
		},
	}
	// 三档端点，最后一档是 IP 字面量（不需要 DNS）。
	//
	// 只试前两档会误判：Psiphon 刚 ready 的一两秒里，域名请求常常吃不到数据
	//（真机日志：`TotalBytesTransferred received=62 sent=20693`，随即被判
	// 「出口验证失败」）。1.1.1.1 只要隧道真的在转发就一定能通。
	body, ok := fetchMeta(reqCtx, client, metaURL)
	if !ok {
		body, ok = fetchMeta(reqCtx, client, traceURL)
	}
	if !ok {
		for _, u := range traceIPURLs {
			if body, ok = fetchMeta(reqCtx, client, u); ok {
				break
			}
		}
	}
	if !ok {
		return "", "", false
	}
	s := &Session{}
	s.applyMeta(body)
	if s.ExitIP == "" && s.Country == "" {
		return "", "", false
	}
	return s.ExitIP, s.Country, true
}
