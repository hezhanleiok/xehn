package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xhwarp/android-engine/warp"
)

// warpBackend 是真正干活的 tunnelBackend：读/注册 WARP 账号 → 建 WG/AWG 隧道
// → 真实请求一次 Cloudflare 拿出口 IP 与归属。
//
// 它是从桌面版 warpscout 引擎搬过来的（见 docs/porting-analysis.md 的 P1）：
// 数据面是 amneziawg-go 的 device + gVisor netstack，**不需要 TUN 设备、
// 不需要 root**。桌面版把这一层交给 mihomo.exe 子进程，安卓上没有子进程可用。
type warpBackend struct {
	workDir string

	mu      sync.Mutex
	session *warp.Session
	tunFD   int
	// 单端点握手超时，来自设置里的「连接超时（秒）」。
	handshake time.Duration
	// 账号在第一次连接时解析并缓存；后续连接（换端点、重连）不再走注册。
	accountJSON string
	// 连续整体失败次数。达到 2 就重置本地账号缓存（下次自动重新注册）——
	// Cloudflare 注销设备后的表象和「网络不通」一模一样，只能靠这个兜底。
	accountFailStreak int
	// Psiphon 出口的官方 client.config 内容与系统 DNS，由 Kotlin 随包喂入。
	// 为空表示没有随包配置，这时选 Psiphon 会明确报错而不是静默按基础协议走。
	psiphonConfig string
	psiphonDNS    string
	// Psiphon 期望的落地地区（"" = 自动，否则 ISO-2 大写）。只影响下一次连接：
	// tunnel-core 的 EgressRegion 是启动参数，改不了运行中的会话。
	psiphonRegion string
	// 本地 SOCKS5 监听地址（"host:port"，"" = 不开）。只有 netstack 模式才有意义：
	// 「仅代理」模式靠它给用户一个入口；VPN 模式整个系统已经在隧道里，多开端口没用。
	socksListen string
	// 分流规则（仅代理模式执行）。nil = 全部走隧道。
	rules *warp.RuleSet
	// OpenVPN 出口（VPN Gate）的候选节点 ID 列表（按尝试顺序）。
	// 空 = 未选择该出口。与 psiphonConfig 一样只在连接前由 Kotlin 下发。
	//
	// 为什么是「列表」而不是单个节点：电脑版实测 VPN Gate 的握手成功率只有
	// 37.5%，只试一个节点的话用户有一多半机会看到「连接失败」。这里按顺序
	// 逐个真握手，第一个能过数据的胜出。
	openvpnIDs     []string
	openvpnLabel   string
	openvpnCountry string
	// openvpnWanted = 用户要求 OpenVPN 出口（与实际有没有可用配置无关）。
	// 分开的原因见 SetOpenVPNExit / Connect 里的注释：不能让「有列表没配置」
	// 变成静默降级。
	openvpnWanted bool
	// ovpnFailed 记录最近失败过的节点（id → 失败时间）。Kotlin 侧给的候选顺序是稳定的，
	// 靠这里把它们跳过去，下一轮才会落到「同国同类的下一个」。
	ovpnFailed map[string]time.Time
	// 注：曾经有过「直连节点 / 经 WARP」两种上游（openvpnUpstream + directBlockedAt），
	// 0.2.3 起只剩经 WARP 一条 —— 见 warp/openvpn.go 里 dialOpenVPNUpstream 的注释。
	// 建系统 VPN 的回调。OpenVPN 必须先握手拿到服务器下发的 ifconfig，
	// 才能用那个地址 establish —— 所以 tun 要由引擎在连接过程中回调 Kotlin 建。
	openvpnTun func(warp.OpenVPNTun) (int, error)
	// 每个协议上一次成功用过的端点（proto -> "ip:port"），落盘在 workDir。
	// 下次连接把它排到候选最前面，避免每次重扫一遍才碰上能过数据的端点。
	lastGood map[string]string
	// VPN Gate 节点缓存（OpenVPN 出口的候选池）。懒加载，落盘在 workDir。
	vpnGate *warp.VPNGateCache
}

// vpnGatePath 是 VPN Gate 节点缓存文件。
//
// 节点接口 30 分钟就会变一轮，但配置原文有 1 MB 上下，不适合塞进
// SharedPreferences；放 filesDir 下的 JSON，随 App 卸载消失。
func (b *warpBackend) vpnGatePath() string {
	return filepath.Join(b.workDir, "vpn-gate-nodes.json")
}

// VPNGateNodesJSON 返回节点列表（不含配置原文），首次调用时读磁盘缓存。
func (b *warpBackend) VPNGateNodesJSON() string {
	b.mu.Lock()
	c := b.vpnGate
	b.mu.Unlock()
	if c == nil {
		c = warp.LoadVPNGateCache(b.vpnGatePath())
		if c == nil {
			return `{"fetchedAt":0,"nodes":[]}`
		}
		b.mu.Lock()
		b.vpnGate = c
		b.mu.Unlock()
	}
	return c.NodesJSON()
}

// VPNGateNodeConfig 按节点 ID 取 .ovpn 原文（连接时用）。
func (b *warpBackend) VPNGateNodeConfig(id string) string {
	b.mu.Lock()
	c := b.vpnGate
	b.mu.Unlock()
	if c == nil {
		c = warp.LoadVPNGateCache(b.vpnGatePath())
		b.mu.Lock()
		b.vpnGate = c
		b.mu.Unlock()
	}
	if c == nil {
		return ""
	}
	for _, n := range c.Nodes {
		if n.ID == id {
			return n.Config
		}
	}
	return ""
}

// RefreshVPNGateNodes 抓一轮节点并落盘。**阻塞**，调用方要放到后台线程。
func (b *warpBackend) RefreshVPNGateNodes(ctx context.Context, report func(string)) (int, error) {
	b.mu.Lock()
	handshake := b.handshake
	accountJSON := b.accountJSON
	b.mu.Unlock()
	if handshake <= 0 {
		handshake = defaultHandshakeTimeout
	}

	// 抓取要起一条临时 WARP 隧道，而隧道需要账号。用户可能在「从没连过」的
	// 状态下第一次打开节点选择器 —— 这时账号还没注册，直接 Dial 只会得到
	// 一个看不懂的握手失败。
	raw, err := warp.LoadOrRegisterAccount(ctx, b.accountPath(), accountJSON)
	if err != nil {
		return 0, err
	}
	b.mu.Lock()
	b.accountJSON = raw
	b.mu.Unlock()

	nodes, err := warp.FetchVPNGate(ctx, warp.VPNGateFetchOptions{
		UnderlayProto:    "awg",
		UnderlayPrefer:   b.preferEndpoint("awg"),
		HandshakeTimeout: handshake,
		// 40s：vpngate.net 经 WARP 到日本再回源，实测经常 20s 以上；
		// 20s 会在「其实能拉到」的情况下报超时。
		Timeout: 40 * time.Second,
		Report:  report,
	})
	if err != nil {
		return 0, err
	}
	// 抓取用的临时隧道会把 awg 的成功端点记下来吗？没有 —— 它不落 lastGood，
	// 这里也不必补记：它只是抓列表，不代表用户接下来要走这个端点。
	c := &warp.VPNGateCache{FetchedAt: time.Now().UnixMilli(), Nodes: nodes}
	if err := warp.SaveVPNGateCache(b.vpnGatePath(), c); err != nil {
		return len(nodes), fmt.Errorf("节点已抓取（%d 个）但写缓存失败: %w", len(nodes), err)
	}
	b.mu.Lock()
	b.vpnGate = c
	b.mu.Unlock()
	return len(nodes), nil
}

// PrepareAccounts 在建系统 VPN **之前**把账号准备好（必要时注册）。
//
// 顺序很重要：VpnService.establish() 之后，系统的 DNS 查询会被路由进 tun，而
// 那时隧道还没通 —— 注册请求的域名解析直接失败。真机日志里 MASQUE 连不上就是
// 这一条（`lookup api.cloudflareclient.com: no such host`）。
func (b *warpBackend) PrepareAccounts(ctx context.Context, proto string, report func(string)) error {
	if proto == "" {
		proto = "awg"
	}
	// 只为让 EnsureMasqueAccount 知道凭据路径；不动 tunFD（连接前本来就是 0）。
	warp.Apply(warp.Config{
		MasqueCredsPath:      filepath.Join(b.workDir, "masque.json"),
		MasqueOuterCredsPath: filepath.Join(b.workDir, "masque-outer.json"),
		OuterCredsPath:       filepath.Join(b.workDir, "outer.json"),
	})

	b.mu.Lock()
	accountJSON := b.accountJSON
	b.mu.Unlock()
	raw, err := warp.LoadOrRegisterAccount(ctx, b.accountPath(), accountJSON)
	if err != nil {
		return fmt.Errorf("注册 WARP 账号失败：%w", err)
	}
	b.mu.Lock()
	b.accountJSON = raw
	b.mu.Unlock()

	if strings.HasPrefix(proto, "masque") {
		if err := warp.EnsureMasqueAccount(ctx, report); err != nil {
			return fmt.Errorf("注册 MASQUE 账号失败：%w", err)
		}
	}
	return nil
}

// SetOpenVPNExit 选择 OpenVPN 出口。enabled=false 时清空，回到普通会话。
//
// ids 是 VPN Gate 节点 ID（按尝试顺序）；配置原文由引擎自己从节点缓存里取，
// 不需要经过 Kotlin（一份 .ovpn 约 13 KB，来回搬没有意义）。

func (b *warpBackend) SetOpenVPNExit(enabled bool, ids []string, label, country string) {
	b.mu.Lock()
	// enabled 记的是「用户要 OpenVPN 出口」这件事，ids 记的是「眼下有几份能用的
	// 配置」。两者必须分开：ids 为空时若把 enabled 也当 false，连接就会静默
	// 退回普通隧道（见 connect 里的同名判断）。
	b.openvpnWanted = enabled
	if enabled {
		b.openvpnIDs = append([]string(nil), ids...)
		b.openvpnLabel, b.openvpnCountry = label, country
	} else {
		b.openvpnIDs, b.openvpnLabel, b.openvpnCountry = nil, "", ""
	}
	b.mu.Unlock()
}

// SetOpenVPNTunProvider 装上「用服务器下发参数建系统 VPN」的回调。
func (b *warpBackend) SetOpenVPNTunProvider(fn func(warp.OpenVPNTun) (int, error)) {
	b.mu.Lock()
	b.openvpnTun = fn
	b.mu.Unlock()
}

// connectOpenVPN 建「基础隧道（WARP）+ OpenVPN 节点」出口。
//
// 出口 IP/国家来自经新 tun 的一次真实 HTTPS（见 warp/openvpn.go），
// 所以界面显示的是节点自己的出口，而不是 WARP 的。
func (b *warpBackend) connectOpenVPN(
	ctx context.Context, req Request, report func(string),
	handshake time.Duration, tunFD int) (Result, error) {

	b.mu.Lock()
	ids := append([]string(nil), b.openvpnIDs...)
	country := b.openvpnCountry
	prepare := b.openvpnTun
	b.mu.Unlock()

	if len(ids) == 0 {
		return Result{}, fmt.Errorf("没有选择 OpenVPN 节点")
	}
	if prepare == nil {
		return Result{}, fmt.Errorf("引擎没有装 OpenVPN 建 tun 回调（Kotlin 侧未设置 TunProvider）")
	}

	// 按顺序逐个真握手。实测 VPN Gate 只有约四成节点能完成握手，只试一个
	// 等于把网络质量的随机性直接甩给用户；这里最多试 openvpnMaxTries 个。
	const openvpnMaxTries = 5
	prefer := b.preferEndpoint(req.Proto)
	ids = b.freshOpenVPNIDs(ids, report)

	tried := 0
	var lastErr error
	for _, id := range ids {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if tried >= openvpnMaxTries {
			break
		}
		cfg := b.VPNGateNodeConfig(id)
		if cfg == "" {
			report(fmt.Sprintf("节点 %s 的配置不在缓存里，跳过", id))
			continue
		}
		tried++
		report(fmt.Sprintf("尝试 OpenVPN 节点 %s（第 %d/%d 个）", id, tried, min(len(ids), openvpnMaxTries)))
		sess, err := warp.DialOpenVPN(ctx, warp.OpenVPNOptions{
			Config:           cfg,
			Label:            id,
			UnderlayProto:    req.Proto,
			UnderlayEndpoint: req.Endpoint,
			UnderlayPrefer:   prefer,
			IPv6:             req.IPv6,
			HandshakeTimeout: handshake,
			VerifyTimeout:    10 * time.Second,
			Budget:           60 * time.Second,
			PrepareTun:       prepare,
			Report:           report,
		})
		if err == nil {
			b.rememberEndpoint(req.Proto, sess.Endpoint)
			b.clearOpenVPNFailure(id)

			// 出口国家以实测为准；节点列表里自报的国家只在实测解析不到时兜底。
			exitCountry := sess.Country
			if exitCountry == "" {
				exitCountry = country
			}
			b.mu.Lock()
			b.session = sess
			b.mu.Unlock()
			return Result{
				ExitIP:   sess.ExitIP,
				Country:  exitCountry,
				Endpoint: sess.Endpoint,
				Egress:   "openvpn",
			}, nil
		}
		lastErr = err
		report(fmt.Sprintf("节点 %s 失败：%v", id, err))
		b.markOpenVPNFailed(id)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有任何可用节点配置")
	}
	return Result{}, fmt.Errorf("试了 %d 个 OpenVPN 节点都失败（最后一个错误：%v）", tried, lastErr)
}

// openvpnFailTTL 是节点失败记忆的有效期。
//
// 太短（比如 1 分钟）等于没有：用户手动重连会立刻又撞上同一个死节点；
// 太长（比如 1 小时）会把只是临时抖动的节点长期拉黑。
const openvpnFailTTL = 10 * time.Minute

func (b *warpBackend) markOpenVPNFailed(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ovpnFailed == nil {
		b.ovpnFailed = make(map[string]time.Time, 8)
	}
	b.ovpnFailed[id] = time.Now()
}

func (b *warpBackend) clearOpenVPNFailure(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.ovpnFailed, id)
}

// freshOpenVPNIDs 过滤掉 openvpnFailTTL 内失败过的节点。
//
// 全都失败过时（例如用户刚切到一个整体不可用的国家）清空记忆、原样返回：
// 宁可再试一遍，也不要让「再点一次连接」变成永远没有候选。
func (b *warpBackend) freshOpenVPNIDs(ids []string, report func(string)) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.ovpnFailed) == 0 {
		return ids
	}
	now := time.Now()
	fresh := make([]string, 0, len(ids))
	skipped := 0
	for _, id := range ids {
		if at, ok := b.ovpnFailed[id]; ok && now.Sub(at) < openvpnFailTTL {
			skipped++
			continue
		}
		fresh = append(fresh, id)
	}
	if len(fresh) == 0 {
		report(fmt.Sprintf("全部 %d 个候选都在 %v 内失败过，清空失败记忆后重试", len(ids), openvpnFailTTL))
		b.ovpnFailed = make(map[string]time.Time, 8)
		return ids
	}
	if skipped > 0 {
		report(fmt.Sprintf("跳过 %d 个最近失败过的节点（%v 内不重试）", skipped, openvpnFailTTL))
	}
	return fresh
}

// OpenVPNProbe 是一次「真握手 + 真下载」的结果。
type OpenVPNProbe struct {
	ID string `json:"id"`
	// MS 是真实 OpenVPN 握手耗时。
	MS int64 `json:"ms"`
	// Bps 是握手后经该节点下载实测的吞吐（字节/秒）；0 = 握手成功但测不出。
	Bps   int64  `json:"bps,omitempty"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// TestOpenVPNNodes 对一组节点做**真实 OpenVPN 握手**测试：只握手，不建系统 VPN、
// 不验证数据面、不动当前连接。
//
// 为什么需要它：列表里显示的「延迟」是 api/iphone 同域名的 TCP 连接时间，
// 跟这个节点能不能握手、握手多久基本无关。2026-11-01 用户实测：列表显示
// 193~214ms 的三个美国节点全部连不上（两个控制通道无响应、一个握手成功但
// 不转发流量），而 JP/KR 节点多的国家能连上 —— 只有真握手才分得清。
//
// 一条 WARP 上游复用到所有节点上（见 warp.OpenUnderlay）：重拨一次要扫 28 个
// 端点、最多 60s，为每个节点各拨一次完全没必要。
//
// 结果同时记账：握手失败的进 10 分钟失败记忆，连接时直接跳过；成功的清掉记忆。
func (b *warpBackend) TestOpenVPNNodes(
	ctx context.Context, ids []string, proto string,
	handshake time.Duration, report func(string),
) ([]OpenVPNProbe, error) {
	if len(ids) == 0 {
		return nil, errors.New("没有要测试的节点")
	}
	cfgByID := make(map[string]string, len(ids))
	order := make([]string, 0, len(ids))
	for _, id := range ids {
		cfg := b.VPNGateNodeConfig(id)
		if cfg == "" {
			continue
		}
		cfgByID[id] = cfg
		order = append(order, id)
	}
	if len(order) == 0 {
		return nil, errors.New("这些节点的配置都不在缓存里，先刷新节点列表")
	}
	if handshake <= 0 {
		handshake = defaultHandshakeTimeout
	}
	report(fmt.Sprintf("准备测 %d 个节点的真实握手（先建一条 WARP 上游，随后复用）…", len(order)))
	under, err := warp.OpenUnderlay(ctx, warp.OpenVPNOptions{
		UnderlayProto:    proto,
		UnderlayPrefer:   b.preferEndpoint(proto),
		HandshakeTimeout: handshake,
		VerifyTimeout:    8 * time.Second,
		Budget:           60 * time.Second,
		Report:           report,
	})
	if err != nil {
		return nil, err
	}
	defer under.Close()

	// 并发 6、单节点 10s：真机实测好看的节点握手 2.8–4.9s，10s 足够分辨；
	// 而「控制通道无响应」的节点一定要等满超时，所以并发数直接决定总时长 ——
	// 98 个节点最坏 98×10/6 ≈ 2.7 分钟，实际大多在 1 分钟内。
	const probeTimeout = 10 * time.Second
	// 并发 8：每个节点是「握手 + 2s 测速」，98 个最坏约 98×(10+2)/8 ≈ 2.5 分钟。
	const workers = 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	results := make(map[string]OpenVPNProbe, len(order))
	for _, id := range order {
		id, cfg := id, cfgByID[id]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// 握手 + 真下载：只测握手的话，界面上「3341ms」这种数字看不出
			// 「能握手但只有几 KB/s」的节点，而那正是用户最需要筛掉的。
			//
			// 预算 8s 是**整条 HTTP 请求**（DNS+TCP+TLS+首字节+2s 下载窗口）：
			// 经「WARP → 日本节点 → CF」，光 TLS 就要好几秒，2s 一定测不出来
			//（0.2.16 之前就是这么全变成「速度未测」的）。
			d, bps, perr := warp.ProbeOpenVPNSpeed(ctx, under, cfg, probeTimeout, 8*time.Second)
			p := OpenVPNProbe{ID: id, MS: d.Milliseconds(), Bps: bps, OK: perr == nil}
			if perr != nil {
				p.Error = perr.Error()
				b.markOpenVPNFailed(id)
			} else {
				b.clearOpenVPNFailure(id)
			}
			mu.Lock()
			results[id] = p
			done++
			n := done
			mu.Unlock()
			report(fmt.Sprintf("握手测试 %d/%d：%s %s", n, len(order), id, probeSummary(p)))
		}()
	}
	wg.Wait()

	out := make([]OpenVPNProbe, 0, len(order))
	for _, id := range order {
		if p, ok := results[id]; ok {
			out = append(out, p)
		}
	}
	okCount := 0
	for _, p := range out {
		if p.OK {
			okCount++
		}
	}
	report(fmt.Sprintf("握手测试完成：%d 个节点里 %d 个能握手", len(out), okCount))
	return out, nil
}

// probeSummary 是日志里每个节点的一句话结果。
func probeSummary(p OpenVPNProbe) string {
	if p.OK {
		if p.Bps > 0 {
			return fmt.Sprintf("握手成功 %dms · ≈%d KB/s", p.MS, p.Bps/1024)
		}
		return fmt.Sprintf("握手成功 %dms · 速度未测", p.MS)
	}
	return "失败：" + p.Error
}

// lastGoodPath 是「上次成功端点」缓存文件。放在 App 私有目录，随 App 卸载消失。
func (b *warpBackend) lastGoodPath() string {
	return filepath.Join(b.workDir, "last-endpoint.json")
}

// preferEndpoint 取出某协议上次成功的端点（没有则为空串）。
func (b *warpBackend) preferEndpoint(proto string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lastGood == nil {
		b.lastGood = loadEndpointCache(b.lastGoodPath())
	}
	return b.lastGood[proto]
}

// rememberEndpoint 记下某协议本次成功的端点并落盘。
func (b *warpBackend) rememberEndpoint(proto, endpoint string) {
	if proto == "" || endpoint == "" {
		return
	}
	b.mu.Lock()
	if b.lastGood == nil {
		b.lastGood = loadEndpointCache(b.lastGoodPath())
	}
	if b.lastGood[proto] == endpoint {
		b.mu.Unlock()
		return
	}
	b.lastGood[proto] = endpoint
	snapshot := make(map[string]string, len(b.lastGood))
	for k, v := range b.lastGood {
		snapshot[k] = v
	}
	b.mu.Unlock()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(b.lastGoodPath()), 0o755)
	_ = os.WriteFile(b.lastGoodPath(), data, 0o600)
}

// forgetEndpoint 把某协议的上次成功端点从缓存里删掉。
//
// 自动重连时用它：那个端点刚刚被判定死掉，还留着它只会让下一轮**先试同一个**
// —— 用户看到的就是「一直卡在同一个断点上，不会自动换点」。
func (b *warpBackend) forgetEndpoint(proto string) {
	if proto == "" {
		return
	}
	b.mu.Lock()
	if b.lastGood == nil {
		b.lastGood = loadEndpointCache(b.lastGoodPath())
	}
	if _, ok := b.lastGood[proto]; !ok {
		b.mu.Unlock()
		return
	}
	delete(b.lastGood, proto)
	snapshot := make(map[string]string, len(b.lastGood))
	for k, v := range b.lastGood {
		snapshot[k] = v
	}
	b.mu.Unlock()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(b.lastGoodPath()), 0o755)
	_ = os.WriteFile(b.lastGoodPath(), data, 0o600)
}

// loadEndpointCache 读缓存；文件不存在或损坏都当作空（下次重新记住即可）。
func loadEndpointCache(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]string{}
	}
	return out
}

// defaultHandshakeTimeout 与电脑版 TimeoutSec 的默认值（2s）同量级，但手机
// 网络 RTT 更大，给到 3s，否则好端点会被自己的超时误判掉。
const defaultHandshakeTimeout = 3 * time.Second

// SetTimeout 设置单端点握手超时（秒）。0 表示用默认值。
func (b *warpBackend) SetTimeout(sec int) {
	b.mu.Lock()
	if sec <= 0 {
		b.handshake = 0
	} else {
		b.handshake = time.Duration(sec) * time.Second
	}
	b.mu.Unlock()
}

// SetTunFD 记录 VpnService 建好的 tun 设备 fd。fd 为 0 表示退回 netstack
// 模式（进程内隧道，系统看不到），只有自测才这么用。
func (b *warpBackend) SetTunFD(fd int) {
	// 覆盖之前先把上一次遗留的、没人接管的 fd 收掉：引用一旦被覆盖就再也找不到
	// 它了，而 VpnService 的接口只要还有 fd 打开就一直挂着（只有杀进程才恢复）。
	_, _ = b.releaseLeftoverTunFD()
	b.mu.Lock()
	b.tunFD = fd
	b.mu.Unlock()
}

// Counters 报告 tun 设备累计进出的字节数（fd 模式下才有）。
func (b *warpBackend) Counters() (uint64, uint64) {
	b.mu.Lock()
	sess := b.session
	b.mu.Unlock()
	if sess == nil {
		return 0, 0
	}
	return sess.Counters()
}

func newWarpBackend(workDir string) *warpBackend {
	b := &warpBackend{workDir: workDir, socksListen: "127.0.0.1:1080"}
	b.loadPsiphonRegions()
	return b
}

// SetSocksListen 设置本地 SOCKS5 监听地址（仅代理模式用；"" = 不开）。
// addr 形如 "127.0.0.1:1080" 或 "0.0.0.0:1080"（允许局域网访问）。
func (b *warpBackend) SetSocksListen(addr string) {
	b.mu.Lock()
	b.socksListen = addr
	b.mu.Unlock()
}

// SetRules 设置分流策略与自定义规则（仅代理模式执行）。
//
// policy：global / bypass-cn / blacklist；text 每行一条 `direct|proxy,域名或CIDR`。
// 返回解析时跳过的行数（写错的行不能静默丢弃，由调用方写进日志）。
func (b *warpBackend) SetRules(policy, text string) int {
	rs, skipped := warp.NewRuleSet(policy, text)
	b.mu.Lock()
	b.rules = rs
	b.mu.Unlock()
	return skipped
}

// psiphonRegionsPath 是「上次 Psiphon 上报的可用地区」缓存。
func (b *warpBackend) psiphonRegionsPath() string {
	return filepath.Join(b.workDir, "psiphon-regions.json")
}

// loadPsiphonRegions 用磁盘缓存预置地区表：这样在「还没连过一次」或离线打开
// 设置页时，地区选择器列出来的也是它真能去的地方，而不是只有内置兜底表。
func (b *warpBackend) loadPsiphonRegions() {
	raw, err := os.ReadFile(b.psiphonRegionsPath())
	if err != nil {
		return
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		return
	}
	warp.SetPsiphonRegions(list)
}

// savePsiphonRegions 在 Psiphon 起来之后落盘。只存真实上报的列表：
// 把兜底表当「上报」存下来会让下次启动误以为上次连过。
func (b *warpBackend) savePsiphonRegions() {
	if !warp.PsiphonRegionsReported() {
		return
	}
	raw, err := json.Marshal(warp.PsiphonRegions())
	if err != nil {
		return
	}
	_ = os.MkdirAll(b.workDir, 0o755)
	_ = os.WriteFile(b.psiphonRegionsPath(), raw, 0o644)
}

// SetPsiphonRegion 设置 Psiphon 的落地地区：""（或 "auto"）= 自动，否则 ISO-2。
// 只影响下一次连接，理由见字段注释。
func (b *warpBackend) SetPsiphonRegion(region string) {
	b.mu.Lock()
	b.psiphonRegion = warp.NormalizeRegion(region)
	b.mu.Unlock()
}

// accountPath 是缓存的账号文件。放在 App 的 filesDir 下，
// 对应桌面版的 WARP_CLIENT_HOME/warpscout-account.json。
func (b *warpBackend) accountPath() string {
	return filepath.Join(b.workDir, "account.json")
}

// SetAccountJSON 让上层（Kotlin）直接喂一份账号，跳过网络注册。
//
// 这份 JSON 还可以内嵌 masque / outer 两台附加设备（见 assets/account.json）。
// 拆出来落盘后，MASQUE 与 WARP-in-WARP 也能复用随包凭据，而不是在被墙的网络里
// 现注册 —— 那一步几乎必然失败。
func (b *warpBackend) SetAccountJSON(raw string) {
	b.mu.Lock()
	b.accountJSON = raw
	workDir := b.workDir
	b.mu.Unlock()
	warp.SplitEmbeddedAccounts(workDir, raw)
}

// AccountJSON 返回当前账号（可能为空），供上层持久化或展示。
func (b *warpBackend) AccountJSON() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.accountJSON
}

// SetPsiphonConfig 喂入官方的 Psiphon client.config 与系统 DNS。
//
// 这是进程内 Psiphon 能不能起来的唯一前提：client.config 里带着 SponsorId、
// 服务器列表 URL 与签名公钥，缺了它 tunnel-core 会报「零个可用服务器」。
//
//	dns 逗号分隔（gobind 不支持切片），空则让 tunnel-core 用系统解析器。
func (b *warpBackend) SetPsiphonConfig(clientConfigJSON, dns string) {
	b.mu.Lock()
	b.psiphonConfig = clientConfigJSON
	b.psiphonDNS = dns
	b.mu.Unlock()
}

// connectPsiphon 建「基础隧道（上游）+ 进程内 Psiphon 出口」。
//
// 这里的出口 IP/国家来自**通过 Psiphon SOCKS 的实测**，所以界面显示的就是
// Psiphon 的出口，而不是上游 WARP 端点的 —— 桌面版历史上正是把两者混在一起，
// 才出现「Psiphon 出口在澳洲，显示的却不是」。
func (b *warpBackend) connectPsiphon(
	ctx context.Context, req Request, report func(string),
	handshake time.Duration, tunFD int) (Result, error) {

	// 上游可以是任意一种传输：它在这里的角色只是「一个能出网的本地 SOCKS」，
	// WG / AWG / MASQUE / WARP-in-WARP 都满足（见 warp/psiphon.go 的 DialPsiphon）。
	// 空 proto 由 warp 侧按 awg 处理。
	b.mu.Lock()
	clientConfig := b.psiphonConfig
	dns := b.psiphonDNS
	region := b.psiphonRegion
	b.mu.Unlock()
	if clientConfig == "" {
		return Result{}, fmt.Errorf("缺少官方 Psiphon client.config（需随包提供，并调用 SetPsiphonConfig 喂入）")
	}
	if tunFD <= 0 {
		return Result{}, fmt.Errorf("Psiphon 需要系统 VPN 的 tun fd，当前为 %d", tunFD)
	}
	// 地区预检：拿「最近一次上报」的列表先判一次。选了个它根本不去的国家，
	// 这里直接说清楚并给出可选值，而不是等 tun 起来、180s 之后再失败。
	// （连接过程中还会用本次会话上报的列表再判一次 —— 见 warp/psiphon.go。）
	if region != "" {
		available := warp.PsiphonRegions()
		if !warp.RegionOffered(available, region) {
			return Result{}, fmt.Errorf("Psiphon 不提供 %s 地区的出口；可选：%s（列表来自上一次连接时它自己上报的，重新连接一次可刷新）",
				region, strings.Join(available, " "))
		}
	}

	sess, err := warp.DialPsiphon(ctx, warp.PsiphonOptions{
		ClientConfigJSON: clientConfig,
		DNS:              dns,
		EgressRegion:     region,
		DataDir:          filepath.Join(b.workDir, "psiphon"),
		TunFD:            tunFD,
		UnderlayProto:    req.Proto,
		UnderlayEndpoint: req.Endpoint,
		UnderlayPrefer:   b.preferEndpoint(req.Proto),
		IPv6:             req.IPv6,
		HandshakeTimeout: handshake,
		VerifyTimeout:    8 * time.Second,
		Budget:           60 * time.Second,
		Report:           report,
	})
	if err != nil {
		return Result{}, err
	}
	b.rememberEndpoint(req.Proto, sess.Endpoint)
	// 这一次它自己报的可用地区已经留在 warp 里了：落盘给下次的选择器用。
	b.savePsiphonRegions()

	b.mu.Lock()
	b.session = sess
	b.mu.Unlock()

	return Result{
		ExitIP:   sess.ExitIP,
		Country:  sess.Country,
		Endpoint: sess.Endpoint,
		Egress:   "psiphon",
	}, nil
}

// Connect 建隧道。失败时**必须**把系统 VPN 一起收掉 —— 见下面 defer 里的说明。
func (b *warpBackend) Connect(ctx context.Context, req Request, report func(string)) (result Result, err error) {
	// 连接失败时收掉还挂在系统 VPN 上的 tun fd。
	//
	// VpnService 的接口是「只要还有 fd 打开就一直挂着」。建立成功时 fd 会交给
	// 隧道设备或 Psiphon 的 packet tunnel（由它们在自己的 Close 里关），但失败时
	// 可能谁都还没接管 —— 例如带 Psiphon 时上游在 netstack 里就失败了。这时没人
	// 关 fd，表现就是**界面显示未连接、系统 VPN 却一直开着**，手机所有流量都流进
	// 一个没人读的 tun；用户实测只有退出 App 才恢复（进程消失，fd 被系统回收）。
	defer func() {
		if err == nil {
			b.mu.Lock()
			b.accountFailStreak = 0
			b.mu.Unlock()
			return
		}
		if fd, released := b.releaseLeftoverTunFD(); released {
			report(fmt.Sprintf("已关闭系统 tun（fd %d）：没人接管的 fd 会让系统 VPN 一直挂着", fd))
		}
		// 账号失效的兜底：Cloudflare 注销设备后，用旧凭据握手会一直失败，
		// 表象和「网络不通」完全一样。连续两次整体失败就把本地账号缓存删掉，
		// 下次连接自动重新注册一台设备 —— 用户不需要知道有「账号」这回事。
		b.mu.Lock()
		b.accountFailStreak++
		streak := b.accountFailStreak
		b.mu.Unlock()
		if streak >= 2 {
			if p := b.accountPath(); p != "" {
				if rmErr := os.Remove(p); rmErr == nil {
					report("连续 2 次连接失败，已重置本地 WARP 账号；下次连接会自动重新注册")
					b.mu.Lock()
					b.accountFailStreak = 0
					b.mu.Unlock()
				}
			}
		}
	}()

	if req.Proto == "" {
		req.Proto = "awg"
	}
	mtu := req.MTU
	if mtu <= 0 {
		mtu = 1280
	}

	b.mu.Lock()
	accountJSON := b.accountJSON
	b.mu.Unlock()

	// 1) 账号：本地缓存 → 外部喂入 → 现注册。注册要联网，在部分网络里会失败，
	//    所以错误里必须写清「怎么办」。
	report("准备 WARP 账号…")
	raw, err := warp.LoadOrRegisterAccount(ctx, b.accountPath(), accountJSON)
	if err != nil {
		return Result{}, err
	}
	b.mu.Lock()
	b.accountJSON = raw
	b.mu.Unlock()
	report("账号就绪")

	// 2) 隧道参数。TunFD 决定数据面：有 fd 就是系统 VPN（系统负责路由，
	//    我们只加解密），没有就是 netstack（进程内隧道，系统看不到）。
	b.mu.Lock()
	tunFD := b.tunFD
	handshake := b.handshake
	socksListen := b.socksListen
	rules := b.rules
	b.mu.Unlock()
	if handshake <= 0 {
		handshake = defaultHandshakeTimeout
	}
	b.mu.Lock()
	openvpnOn := len(b.openvpnIDs) > 0
	openvpnWanted := b.openvpnWanted
	b.mu.Unlock()
	// 选了 OpenVPN 出口但一个可用节点都没有时**必须失败**，不能悄悄退回普通隧道：
	// 那样界面会显示「已连接」，出口却是 WARP 的 104.28.x，用户以为自己在走节点。
	// 真机就是这么踩到的 —— 进程重启后配置丢了，列表还在，于是连上去的是 WARP。
	if openvpnWanted && !openvpnOn {
		return Result{}, fmt.Errorf("OpenVPN 出口已开启，但没有可用的节点配置（到设置 → OpenVPN 出口 → 刷新节点列表）")
	}
	if req.Psiphon && openvpnOn {
		return Result{}, fmt.Errorf("Psiphon 与 OpenVPN 都是最终出口，只能选一个")
	}

	// Psiphon 出口时系统 tun fd 归 tunnel-core 的 packet tunnel：基础隧道必须退成
	// 进程内 netstack，只当 Psiphon 的上游载体（见 warp/psiphon.go）。
	// OpenVPN 同理：fd 归它自己的包泵，基础协议只当外层载体（见 warp/openvpn.go）。
	backendTunFD := tunFD
	if req.Psiphon || openvpnOn {
		backendTunFD = 0
	}
	warp.Apply(warp.Config{
		IPv6:            req.IPv6,
		TunFD:           backendTunFD,
		MTU:             mtu,
		MasqueCredsPath: filepath.Join(b.workDir, "masque.json"),
		// MASQUEX2 的外层还要第三套设备（masque 家族的第二台）。和 outer.json
		// 分开存：那一份是 WARP( curve25519 ) 设备，不能拿去登 MASQUE。
		MasqueOuterCredsPath: filepath.Join(b.workDir, "masque-outer.json"),
		OuterCredsPath:       filepath.Join(b.workDir, "outer.json"),
	})
	if req.Psiphon {
		return b.connectPsiphon(ctx, req, report, handshake, tunFD)
	}
	if openvpnOn {
		return b.connectOpenVPN(ctx, req, report, handshake, tunFD)
	}
	if tunFD > 0 {
		report(fmt.Sprintf("数据面 = 系统 VPN（tun fd %d, MTU %d）", tunFD, mtu))
	} else {
		report("数据面 = 进程内 netstack（系统 VPN 未启用）")
	}

	// 3) 拨号 + 验证。fd 模式下这一步的出口验证是走**真实系统网络**做的，
	//    所以它同时证明了「系统 VPN 真的在路由」，而不只是握手成功。
	sess, err := warp.Dial(ctx, warp.Options{
		Proto:    req.Proto,
		Endpoint: req.Endpoint,
		Prefer:   b.preferEndpoint(req.Proto),
		IPv6:     req.IPv6,
		Sample:   2, // 14 个 /24 × 2 = 28 个候选
		// 单次尝试短一点，才能在被墙的端口上快速换下一个；具体值来自设置。
		HandshakeTimeout: handshake,
		VerifyTimeout:    8 * time.Second,
		// 到点就报失败，不能让界面一直转。
		Budget: 60 * time.Second,
		// 只有 netstack 模式（「仅代理」）才会真的开这个监听；fd 模式下 Dial 会
		// 自己跳过（整个系统已经在隧道里，多开一个端口没人用）。
		SocksListen: socksListen,
		// 规则只在本地 SOCKS 上执行；VPN 模式的规则（IP 级路由表）还没做。
		Rules:  rules,
		Report: report,
	})
	if err != nil {
		return Result{}, err
	}
	// 记住这个能用的端点，下次连接直接先试它。
	b.rememberEndpoint(req.Proto, sess.Endpoint)

	b.mu.Lock()
	b.session = sess
	b.mu.Unlock()

	return Result{
		ExitIP:   sess.ExitIP,
		Country:  sess.Country,
		Endpoint: sess.Endpoint,
	}, nil
}

// releaseLeftoverTunFD 关掉一个**还没有被隧道设备/Psiphon 接管**的 tun fd，
// 返回 (fd, 是否真的关了)。接线见 warp.ReleaseTunFD 与 warp/tunfd_owner.go。
//
// 关成功后把记录清成 0：这个 fd 号随时可能被系统复用给别的 socket，留着它
// 就等于留了一次「重复关闭无关 fd」的机会。
func (b *warpBackend) releaseLeftoverTunFD() (int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fd := b.tunFD
	if !warp.ReleaseTunFD(fd) {
		return fd, false
	}
	b.tunFD = 0
	return fd, true
}

func (b *warpBackend) Close() error {
	b.mu.Lock()
	sess := b.session
	b.session = nil
	b.mu.Unlock()
	if sess == nil {
		// 没有会话 = 上一次连接是失败的：失败路径已经尽力关过 fd，这里是第二道
		// 保险（例如用户在「连接失败」状态下直接点断开）。已经被设备接管时
		// ReleaseTunFD 是空操作，不会误关别人的 fd。
		_, _ = b.releaseLeftoverTunFD()
		return nil
	}
	sess.Close()
	return nil
}

// SocksAddr 报告本地 SOCKS 监听地址（没有会话时为空）。
func (b *warpBackend) SocksAddr() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == nil {
		return ""
	}
	return b.session.SocksAddr()
}
