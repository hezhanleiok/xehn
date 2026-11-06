package warp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// 协议 id 与桌面版 flags.go 里的常量逐字一致 —— 以后两边要互相转发配置时
// 不会因为字符串不同而失效。
//
// protoWG/protoAWG/protoMASQUE/protoMASQUEH2 已由 warp.go 定义（它在同一包里
// 维护 protoRuns 与 parseProto，是这些常量的唯一归属）；这里只补 WARP-in-WARP
// 这一个「会话层」才有的协议名，避免重复声明。
const protoWWARP = "wwarp"

// isMasqueProto 判断是否走 MASQUE（CONNECT-IP；h3 与 h2 只是底层传输不同，
// 上层隧道与拨号流程完全一样）。masque-x2（H3 套 H3）也在这里分派，它的内外
// 两层用的都是同一套 CONNECT-IP 流程，见 masque_nest.go。
func isMasqueProto(p string) bool {
	return p == protoMASQUE || p == protoMASQUEH2 || p == protoMASQUEX2
}

// protoRunFor 只放行库里真的实现了的两种协议。默认 awg：WARP 的 AZWG/混淆参数
// 在受限网络里比裸 WG 更容易出去，桌面版也是这个默认。
func protoRunFor(p string) (protoRun, error) {
	if p == "" {
		p = protoAWG
	}
	switch p {
	case protoWG, protoAWG:
		return parseProto(p)
	}
	return protoRun{}, fmt.Errorf("不支持的协议 %q（安卓版当前支持 %s / %s）", p, protoWG, protoAWG)
}

// Options 是一次拨号尝试的参数。
type Options struct {
	Proto    string // "wg" | "awg" | "masque" | "masque-h2" | "wwarp"
	Endpoint string // 可选：钉死 ip:port；空则从内置端点池里试
	// Prefer 是「上一次成功用过的端点」（ip:port）：它会被排到候选最前面，但**不是**
	// 唯一候选 —— 它也可能已经失效，后面的池子照试。受限网络里端点质量差异很大，
	// 不记这个的话每次连接都要重新扫一遍、试掉一大半预算才碰到能过数据的端点。
	Prefer string
	// Skip 是本次不要试的端点（ip 或 ip:port）。Psiphon 叠加失败后「换一个端点
	// 重试」用它跳过刚刚被掐断的那个 —— 同一个端点再试，大概率还是一样。
	Skip string
	// 端点地址族偏好：false = v4 优先（默认），true = v6 优先。MASQUE 的
	// 候选列表与 WG 的端点池都按它排序；与 Config.IPv6 语义一致。
	IPv6 bool
	// —— 以下只在 Proto == "wwarp"（WARP-in-WARP）时有意义 ——
	// InnerProto 是内层隧道协议（默认 wg）；外层协议用 ThroughProto（默认 wg）。
	// Through 可选，钉死外层端点 ip:port；空则按 v4/v6 偏好从池子里试。
	InnerProto   string
	ThroughProto string
	Through      string
	// 每个 /24 取几个候选。库里的池子每个 /24 有 256 个地址，全试一遍要很久，
	// 所以按需抽样（和桌面版 scan 的 -per-subnet 是同一个思路）。
	Sample int
	// 单个端点握手超时。太小会把好端点误判，太大又让失败很慢。
	HandshakeTimeout time.Duration
	// 出口验证超时（隧道内一次真实 HTTPS 往返）。
	VerifyTimeout time.Duration
	// 整次拨号的时间预算。手机网络里端点成功率不高（这个网络实测约 20%），
	// 如果不设上限，一个被墙的网络可以让界面转十几分钟。到点就老实报失败。
	Budget time.Duration
	// 端口尝试顺序；空则用 2408 → 500 → 1701 → 4500。
	Ports []int
	// 本地 SOCKS5 监听地址，例如 "127.0.0.1:1080"；空则不监听。
	// 端口写 0（"127.0.0.1:0"）就是让内核选一个空闲端口，实际端口用
	// Session.SocksAddr() 读回来 —— 固定端口在「上一个监听还没收干净」时
	// 会 bind 失败，而这正是 Psiphon 上游反复连不上端口的那类现场。
	SocksListen string
	// SocksRequired 表示「这个本地 SOCKS 是后续流程的必经之路」：bind 失败时
	// 整个拨号必须失败，而不是像仅代理模式那样写一行日志继续。
	//
	// Psiphon 的上游就是这种：它的 UpstreamProxyURL 指向这个端口，端口没开
	// 或者开在别人手里，tunnel-core 只会一遍遍拨一个死端口，最后报「隧道一个
	// 都建立不起来」，看不出真正原因是本地端口。
	SocksRequired bool
	// MTU 覆盖这次拨号的隧道 MTU（0 = 按协议默认）。
	// 只有 MASQUEX2 的外层用它：外层要装得下内层 1200 字节的 QUIC 初始包，
	// 必须比内层大，见 masque_nest.go 的 masqueX2OuterMTU。
	MTU int
	// NoHedge 关掉「并发拨号竞速」（目前只有 MASQUE 用）。
	//
	// Psiphon 的上游必须关：它只有一个本地 SOCKS 端口，同时拨三个端点等于让
	// Psiphon 自己跟自己抢那一条上游，只会更慢更不稳。
	NoHedge bool
	// Rules 是分流规则（仅代理模式用）。nil = 全部走隧道。
	// **不要**给 Psiphon 的上游 SOCKS 传规则：上游必须无条件全部走隧道。
	Rules *RuleSet
	// 进度回调，用于把每一步写进 App 日志。
	Report func(string)
}

// Session 是一条已经建立并验证过数据的隧道。
//
// ExitIP/Country/Colo 是通过隧道真实请求 Cloudflare /meta 得到的，不是猜的：
// 桌面版的历史 bug 就是拿「基础协议端点的国家」当出口国家，结果 Psiphon 出口
// 在澳洲却显示成别的国家。
type Session struct {
	tn       tunnel
	ln       net.Listener
	Endpoint string
	ExitIP   string
	Country  string
	Colo     string
	// 隧道内一次 HTTPS 往返的耗时。
	RTT time.Duration
	// outer 是 WARP-in-WARP 的外层隧道（普通会话为 nil）。它只承载内层
	// WireGuard 的 UDP，系统看不到，所以必须跟着本 Session 一起回收。
	outer *nest
	// tunFD 是本会话占用的系统 tun fd（只有 Psiphon 会话才有）。Psiphon 的
	// packet tunnel 会 dup 一份自己用（psiphon/common/tun/tun_unix.go 的
	// fileFromFD），**原 fd 始终留在我们手上**：不在这里关掉，系统 VPN 就会一直
	// 挂着 —— 实测断开后「设置 → VPN」仍是已连接，只有杀进程才恢复。
	tunFD int
	// psiphon 非 nil 时，本会话的最终出口是进程内 Psiphon（见 psiphon.go）：
	// tn 只是它的上游载体，系统 tun fd 归 Psiphon 的 packet tunnel。
	psiphon *psiphonExit
	// ovpn 非 nil 时，本会话的最终出口是 OpenVPN 节点（见 openvpn.go）：
	// tn 只是外层载体（netstack），系统 tun fd 由本文件的包泵读写。
	ovpn *openvpnExit
}

func (o *Options) fill() {
	if o.Sample <= 0 {
		o.Sample = 2
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 2500 * time.Millisecond
	}
	if o.VerifyTimeout <= 0 {
		o.VerifyTimeout = 8 * time.Second
	}
	if o.Budget <= 0 {
		o.Budget = 45 * time.Second
	}
	if len(o.Ports) == 0 {
		o.Ports = []int{2408, 500, 1701, 4500}
	}
}

func (o *Options) report(msg string) {
	if o.Report != nil {
		o.Report(msg)
	}
}

// Dial 建立并验证一条隧道。所有协议都从这里分派，WG/AWG 在 dialWGTunnel 里。
func Dial(ctx context.Context, o Options) (*Session, error) {
	o.fill()
	// WARP-in-WARP（wwarp）先拨外层、再把内层套进去，所以要在 protoRunFor
	// 之前分派：它不是一条独立传输，而是一种「组合」。
	if o.Proto == protoWWARP {
		return dialWWarp(ctx, o)
	}
	// MASQUE 是另一条传输：端点来自登记响应而不是扫描池，也不需要 amneziawg-go。
	// 所以它在协议分派这一层就分开走，WG 那条路一行都不用动。
	if isMasqueProto(o.Proto) {
		return dialMasque(ctx, o)
	}
	run, err := protoRunFor(o.Proto)
	if err != nil {
		return nil, err
	}
	return dialWGTunnel(ctx, o, run)
}

// dialWGTunnel 建立并验证一条 WG/AWG 隧道。它会依次尝试候选端点，第一个
// 「握手成功且能真正过数据」的端点胜出；只握手不传数据的端点会被跳过，
// 而不是报成功。WARP-in-WARP 的内层也走这里（此时全局 outer 非 nil，
// newWGTunnel 会把 bind 换成跑在外层 netstack 里的 socket）。
func dialWGTunnel(ctx context.Context, o Options, run protoRun) (*Session, error) {
	// 上次成功的端点优先试（IP 与端口都提前），见 Options.Prefer。
	o.Ports = preferPortFirst(o.Ports, o.Prefer)
	tn, err := newTunnel(run)
	if err != nil {
		return nil, fmt.Errorf("初始化 %s 隧道失败: %w", o.Proto, err)
	}
	// 出错路径统一由各自的 return 关闭；成功路径把 tn 交给 Session。
	ok := false
	defer func() {
		if !ok {
			tn.Close()
		}
	}()

	cands, err := candidates(o)
	if err != nil {
		return nil, err
	}
	o.report(fmt.Sprintf("候选端点 %d 个 × 端口 %v（%s），预算 %s", len(cands), o.Ports, o.Proto, o.Budget))

	// 端口在外层、端点在内存：先在同一个端口上把候选试一遍，再换端口。
	// 这样「端口被墙」的网络能在第一轮就排掉端口，而不用为每个端点把
	// 四个端口都等一遍。
	deadline := time.Now().Add(o.Budget)
	attempts := 0
	var lastErr error
	for _, port := range o.Ports {
		for _, ip := range cands {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if time.Now().After(deadline) {
				if lastErr != nil {
					return nil, fmt.Errorf("在 %s 内没有找到可用端点（最后一个错误：%v）", o.Budget, lastErr)
				}
				return nil, fmt.Errorf("在 %s 内没有找到可用端点（试了 %d 次）", o.Budget, attempts)
			}
			attempts++
			endpoint := net.JoinHostPort(ip.String(), strconv.Itoa(port))
			if !tn.handshake(ctx, endpoint, o.HandshakeTimeout) {
				continue
			}
			o.report(fmt.Sprintf("%s 握手成功，验证出口…", endpoint))
			start := time.Now()
			body, why, passed := egressProbeReason(ctx, tn, o.VerifyTimeout)
			if !passed {
				// 握手成功但过不了数据 —— 这正是「连上了却打不开网页」的那类
				// 半死端点，继续换下一个，绝不报成功。
				lastErr = fmt.Errorf("%s 握手成功但数据面不通（%s）", endpoint, why)
				o.report(fmt.Sprintf("%s 数据面不通（%s），换下一个", endpoint, why))
				continue
			}
			s := &Session{
				tn:       tn,
				Endpoint: endpoint,
				RTT:      time.Since(start),
			}
			s.applyMeta(body)
			if s.ExitIP == "" && s.Country == "" {
				o.report("警告：出口信息解析为空（/meta 被拒），但数据面已验证")
			} else {
				o.report(fmt.Sprintf("出口 %s (%s)", s.ExitIP, s.Country))
			}
			// 本地 SOCKS 只在 netstack 模式有意义：那时系统不知道隧道存在，
			// 需要一个本地入口。fd 模式下整个系统已经走隧道了，再开一个端口
			// 只是多一个没人用的监听。
			if o.SocksListen != "" && tn.stack() != nil {
				if !s.startSocks(ctx, o.SocksListen, o.report, o.Rules) && o.SocksRequired {
					// 端口是后续流程的必经之路（Psiphon 上游）：不能静默降级，
					// 否则调用方会拿到一条「隧道通了、但没人能用」的会话。
					return nil, fmt.Errorf("本地 SOCKS 端口 %s 起不来，而它这次是必需的（后续流程要连它）", o.SocksListen)
				}
			}
			ok = true
			return s, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("没有可用端点（%d 次尝试，最后一个错误：%v）", attempts, lastErr)
	}
	return nil, fmt.Errorf("没有可用端点：%d 次尝试都没握手成功", attempts)
}

// candidates 组装要试的端点 IP。钉了 Endpoint 就只试它。
func candidates(o Options) ([]netip.Addr, error) {
	if o.Endpoint != "" {
		host, _, err := net.SplitHostPort(o.Endpoint)
		if err != nil {
			host = o.Endpoint
		}
		a, perr := netip.ParseAddr(host)
		if perr != nil {
			return nil, fmt.Errorf("endpoint %q 不是合法的 IP 或 ip:port", o.Endpoint)
		}
		return []netip.Addr{a.Unmap()}, nil
	}
	ips := expandPools(o.Sample)
	if len(ips) == 0 {
		return nil, fmt.Errorf("端点池为空")
	}
	if a, ok := parseEndpointIP(o.Prefer); ok {
		out := make([]netip.Addr, 0, len(ips)+1)
		out = append(out, a)
		for _, ip := range ips {
			if ip != a {
				out = append(out, ip)
			}
		}
		ips = out
	}
	// 重试时排除刚死掉的端点。池子里只剩它一个时（钉死端点）就老实报空，
	// 不要退回「再试同一个」——那正是要避免的等待。
	if skip, ok := parseEndpointIP(o.Skip); ok {
		kept := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			if ip != skip {
				kept = append(kept, ip)
			}
		}
		if len(kept) == 0 {
			return nil, fmt.Errorf("候选端点已全部排除（刚失败的是 %s）", skip)
		}
		ips = kept
	}
	return ips, nil
}

// parseEndpointIP 从 "ip:port"（或裸 ip）里取出地址。
func parseEndpointIP(endpoint string) (netip.Addr, bool) {
	if endpoint == "" {
		return netip.Addr{}, false
	}
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// preferPortFirst 把上次成功端点用的端口挪到端口列表最前面：端口在外层循环，
// 先试它省一整轮候选，其余端口顺序不变。
func preferPortFirst(ports []int, endpoint string) []int {
	if endpoint == "" {
		return ports
	}
	_, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ports
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return ports
	}
	out := make([]int, 0, len(ports)+1)
	out = append(out, p)
	for _, x := range ports {
		if x != p {
			out = append(out, x)
		}
	}
	return out
}

// applyMeta 从隧道内拿到的 /meta 里读出真实出口。
func (s *Session) applyMeta(body string) {
	var m struct {
		ClientIP string `json:"clientIp"`
		Country  string `json:"country"`
		Colo     struct {
			IATA string `json:"iata"`
			CCA2 string `json:"cca2"`
		} `json:"colo"`
	}
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		s.ExitIP = m.ClientIP
		s.Country = m.Country
		s.Colo = m.Colo.IATA
		if s.Country == "" {
			s.Country = m.Colo.CCA2
		}
	}
	if s.Country == "" {
		// /meta 的 JSON 形状变过，用 trace 形式的解析兜一次。
		if loc := parseMeta(body).loc; loc != "" {
			s.Country = loc
		}
	}
	// 第二个来源是 /cdn-cgi/trace 的纯文本。它只在 /meta 被拒时才用得上，
	// 但被拒恰恰是某些 CN 出口的常态 —— 那时候界面不该空着。
	if s.ExitIP == "" {
		s.ExitIP = traceValue(body, "ip")
	}
	if s.Country == "" {
		s.Country = traceValue(body, "loc")
	}
}

// startSocks 在本地开一个 SOCKS5，把流量导进这条隧道的 netstack。
//
// 注意：没有 VpnService 之前，这只有 App 自己能连（别的应用不走它），
// 它的价值是「证明隧道真的能过真实流量」，以及给下一步 VpnService 复用。
// 返回 false 表示监听没起来（端口被占、地址不可用）。调用方按 SocksRequired
// 决定是「只写日志继续」还是「整次拨号失败」。
func (s *Session) startSocks(ctx context.Context, listen string, report func(string), rules *RuleSet) bool {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		report(fmt.Sprintf("本地 SOCKS 监听失败（%s：%v），隧道仍然可用", listen, err))
		return false
	}
	s.ln = ln
	report("本地 SOCKS5 已监听 " + ln.Addr().String())
	if rules.RuleCount() > 0 || rules.Policy() != PolicyGlobal {
		report(fmt.Sprintf("分流：策略=%s，自定义规则 %d 条", rules.Policy(), rules.RuleCount()))
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS(ctx, conn, s.tn.stack().tnet, rules)
		}
	}()
	return true
}

// SocksAddr 返回本地 SOCKS 监听地址（没开则为空）。
//
// Psiphon 会话返回的是 **Psiphon 自己的** SOCKS：那才是这一轮真正的出口入口，
// 上游那条只是它的载体，暴露给上层没有意义。
func (s *Session) SocksAddr() string {
	if s.psiphon != nil {
		return s.psiphon.SocksAddr()
	}
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Close 拆掉隧道与本地监听。
func (s *Session) Close() {
	if s == nil {
		return
	}
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
	// Psiphon 必须先停：它的 packet tunnel 还握着 tun fd，晚于上游停会让它在
	// 一个已经关掉的上游 SOCKS 上做重连/心跳。
	if s.psiphon != nil {
		s.psiphon.stop()
		s.psiphon = nil
	}
	// OpenVPN：泵只借用 tun fd，Close 不会关它。
	if s.ovpn != nil {
		s.ovpn.close()
		s.ovpn = nil
	}
	// 系统 tun fd **不在这里关**：它归 Kotlin 的 ParcelFileDescriptor 所有，
	// 由 WarpVpnService.closeTun() 统一关闭（见 tunfd_owner.go 的 fdsan 记录）。
	// 引擎这边关一次、Java 那边再关一次正是闪退的根源。
	s.tunFD = 0
	if s.tn != nil {
		s.tn.Close()
		s.tn = nil
	}
	if s.outer != nil {
		s.outer.tunnel.Close()
		s.outer = nil
	}
	// 全局状态也要收干净：newWGTunnel 靠 outer 非 nil 判断「这是内层隧道」，
	// 留着它会让下一次普通会话误用嵌套 bind。
	outer = nil
	outerAcct = nil
}
