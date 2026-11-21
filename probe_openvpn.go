package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhwarp/warp-client/internal/core"
)

// ---------------------------------------------------------------------------
// OpenVPN 出口地区弹窗的「延迟测试」。
//
// 为什么必须严格隔离端口 / WorkDir / 进程：
//   - 线上正在运行的内核占用 7890（mixed）与 9090（controller），并把配置写在
//     core/config.yaml。探针若复用这些端口或目录，轻则绑定失败，重则把线上
//     正在用的 config.yaml 覆盖成临时节点，导致用户正在使用的会话被打断。
//   - 因此每个节点都在 cfg.WorkDir 下开一个独立子目录，写自己的 config.yaml，
//     用独立的 mixed/api 端口另起一个 mihomo 进程。多个探针内核（并发 slot）
//     也用错开的端口，彼此不冲突。所有临时文件随子目录在节点结束时删除。
//   - 探针内核绝不 TieCoreToClient：一旦为 true，core.Start 会 spawnWatchdog()，
//     那个看门狗在客户端退出时会去改系统代理、写 state.json、清理会话——这
//     些宿主状态都是探针绝对不能碰的。探针内核一律由本文件显式 Stop() 回收。
//   - 同理不调用 warmupOpenVPN：它内部写包级全局 connectStage/stageMsg 钩子，
//     并发探测多个节点时进度文案会互相串扰。这里自带一个无全局状态的握手循环，
//     日志只走 cfg.Log。
// ---------------------------------------------------------------------------

// ProbeNode 是一个待探测的 OpenVPN 出口节点。ID 为 vpnGateNode.id()（例如
// "ca-179.194.130.222-995"），Region 仅用于日志展示；调用方应传入「当前地区
// Top N、已按优先级排好序」的候选，本文件只做截断 TopN，不做地区筛选。
type ProbeNode struct {
	ID     string
	Region string
	// Server / Port are the relay's own TCP endpoint. They are only used for a
	// cheap reachability pre-check: a relay whose port does not answer a SYN in
	// three seconds cannot complete an OpenVPN handshake either, and finding
	// that out by spending the full 30s node budget (plus a core start) is what
	// made an 8-node sweep look like "everything failed".
	Server string
	Port   int
	Proto  string
}

// ProbeOutcome 是单个节点的真实探测结果。
//   - HandshakeMS：从内核就绪到 generate_204 首次返回 2xx/3xx 的耗时（毫秒）。
//   - Bps / Bytes：真实下载测速；只有 probeThroughput 收满 BytesPerNode 字节
//     才会记为成功，Bytes 即收满的字节数，Bps 为这些字节/耗时。
//   - Stage：失败/结果所处阶段，取值 "start" / "handshake" / "download" / "ok"。
type ProbeOutcome struct {
	NodeID      string
	HandshakeMS int64
	Bps         int64
	Bytes       int64
	Stage       string
	Err         error
}

// ProbeConfig 是 RunOpenVPNProbe 的参数。MixedPort/APIPort/WorkDir 必须与线上
// 内核隔离；Render 由主代理注入，用于生成「订阅节点或 WARP 底座 + 该 OpenVPN
// 节点 dialer-proxy」的临时 mihomo config.yaml；Log 为日志出口（可为 nil）。
type ProbeConfig struct {
	TopN           int
	BytesPerNode   int
	TotalBytes     int64
	PerNodeTimeout time.Duration
	Concurrency    int
	MixedPort      int
	APIPort        int
	WorkDir        string
	CoreBin        string
	Render         func(nodeID string) ([]byte, error)
	Log            func(string)
	// Progress is called with (done, total, currentNodeID) before the first
	// node and after each completed node. Purely for UI; may be nil.
	Progress func(done, total int, current string)
	// SkipReachCheck turns off the direct TCP pre-check. It MUST be set when the
	// relay is probed through a carrier (WARP tunnel / subscription node): the
	// relay is often unreachable directly, and a direct SYN timeout says nothing
	// about whether the tunnel can reach it. That pre-check alone was killing
	// most of a 94-node list before any handshake was even attempted.
	SkipReachCheck bool
}

const (
	// 默认独立端口，刻意远离线上的 7890 / 9090；并发 slot 在此基础上 +slot。
	defaultProbeMixedPort = 47890
	defaultProbeAPIPort   = 49090
	// 单次握手探测请求的超时。必须大于 openvpn 出站自身的建链时间（实测
	// 直连 2s 左右，被隧道承载时 5-8s），否则每次请求都在握手途中被取消，
	// 重试还会把已经开始的握手打断——这正是「全部节点测速失败」的根因。
	probeHandshakeAttempt = 9 * time.Second
	// 端口可达性预检：连不上 TCP 的中继不可能握手成功，但也别判太早——
	// VPN Gate 的日本家宽节点从国内经 WARP 底座建 TCP 常要 3-5 秒，2 秒窗口
	// 会把大量本来能握手的节点直接标成「端口不可达」。用户实测同一批节点
	// 以往 80% 可用，现在只剩 5/46，主要就是这一条杀掉的。
	probeReachTimeout = 6 * time.Second
	// 下载采样下限：低于这个字节数算不出可信速率，高于它即使连接中途断掉
	// 也按「已实测」记录（VPN Gate 家宽节点经常传一半就断）。
	//
	// 8 KiB 而不是 64 KiB：4 秒窗口下 64 KiB 等于要求 ≥16 KB/s，一条实测
	// 11.6 KB/s 的家宽节点（4 秒收到 46,480 字节）会被判成「失败」——它其实
	// 能用，只是慢。慢节点该以低速率排在队尾，而不是从列表里消失。
	// 8 KiB 只是过滤噪声（<2 KB/s），不是可用性门槛。
	probeMinSampleBytes = 8 << 10
	// probeDownloadWindow is how long one relay's downlink is measured. Time
	// based, not byte based: a byte-count sample small enough to fit a slow relay
	// finishes inside TCP slow start and reports a burst as the sustained rate.
	probeDownloadWindow = 4 * time.Second
	// 明文 HTTP 即可证明出口转发了字节，避免高延迟链路上反复做 TLS 握手。
	probeHandshakeURL = "http://www.gstatic.com/generate_204"
)

// errProbeBudget 表示全局下载预算耗尽、该节点跳过下载（并非节点本身故障）。
var errProbeBudget = errors.New("总下载流量预算已用尽，跳过该节点下载")

// DefaultProbeConfig 返回默认参数：默认测全部节点（TopN=0）、单节点 48KiB、
// 总上限 16MiB、单节点 30s、并发 6、独立端口。
//
// 参数全部来自实测：VPN Gate 的匿名家宽中继握手要 10-16 秒（靠 10 秒的
// 请求超时接力重试才握上），下行常见 5-70 KB/s，单连接传到约 300KB 会被掐断。
// 所以单节点预算 30 秒、样本只取 48KiB、收到 16KiB 就按实测速率记：
// 握手必须是真的（一次完整的 generate_204 往返），但下载只取够算速率的一小段，
// 否则「握手成功但下载没跑完」会被误判成失败，整表看起来就是 0 成功。
// WorkDir / CoreBin / Render / Log 需由调用方补齐：WorkDir 为空时自动建系统
// 临时目录（绝不是 core/），CoreBin 为空时回退到可执行文件旁的 core/mihomo.exe。
func DefaultProbeConfig() ProbeConfig {
	return ProbeConfig{
		// TopN 0 = 测调用方给的全部节点。「全部」就该是全部：只测前 12 个时，
		// 用户看到的列表里其余节点仍是「未检测」，看上去就像整批失败。
		TopN:         0,
		BytesPerNode: 512 << 10,
		TotalBytes:   16 << 20,
		// 42s = 6s 端口预检 + 30s 握手窗口（openvpnHandshakeTimeout）+ 4s 下载采样
		// + 2s 余量。预检从 2s 提到 6s 后，原来的 35s 会把握手窗口挤到 25s，
		// 预检放过的节点又会在握手中途被 nodeCtx 截断——等于换个地方误杀。
		PerNodeTimeout: 42 * time.Second,
		// 10 rather than 6: every relay is mostly waiting on its own OpenVPN
		// handshake (5-17s), so extra slots cost no bandwidth and cut a 46-node
		// run from ~8 rounds to ~5. The 4s download window still measures each
		// node on its own connection; ten concurrent 48KiB samples do not
		// meaningfully compete for the uplink.
		Concurrency: 10,
		MixedPort:   defaultProbeMixedPort,
		APIPort:     defaultProbeAPIPort,
	}
}

// normalizeProbeConfig 用默认值补齐零值字段，并给出需在 RunOpenVPNProbe 结束时
// 调用的清理函数（仅在自动创建 WorkDir 时负责删除整个临时目录）。
//
// TopN 的语义：<0 用默认值，0 表示不截断（测全部），>0 只测前 N 个。
func normalizeProbeConfig(cfg ProbeConfig) (ProbeConfig, func()) {
	d := DefaultProbeConfig()
	if cfg.TopN < 0 {
		cfg.TopN = d.TopN
	}
	if cfg.BytesPerNode <= 0 {
		cfg.BytesPerNode = d.BytesPerNode
	}
	if cfg.TotalBytes <= 0 {
		cfg.TotalBytes = d.TotalBytes
	}
	if cfg.PerNodeTimeout <= 0 {
		cfg.PerNodeTimeout = d.PerNodeTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = d.Concurrency
	}
	if cfg.MixedPort <= 0 {
		cfg.MixedPort = d.MixedPort
	}
	if cfg.APIPort <= 0 {
		cfg.APIPort = d.APIPort
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	cleanup := func() {}
	if cfg.WorkDir == "" {
		// 绝不落到 core/（那里有线上正在运行的 config.yaml）。
		if dir, err := os.MkdirTemp("", "xehn-openvpn-probe-"); err == nil {
			cfg.WorkDir = dir
			cleanup = func() { _ = os.RemoveAll(dir) }
		}
	}
	if cfg.CoreBin == "" {
		if exe, err := os.Executable(); err == nil {
			cfg.CoreBin = filepath.Join(filepath.Dir(exe), "core", "mihomo.exe")
		}
	}
	return cfg, cleanup
}

// RunOpenVPNProbe 对 nodes 的前 TopN 个节点做真实 OpenVPN 握手 + 真实下载测速。
// 全程受 ctx 取消控制，返回与输入顺序一一对应的 []ProbeOutcome。
func RunOpenVPNProbe(ctx context.Context, cfg ProbeConfig, nodes []ProbeNode) []ProbeOutcome {
	cfg, cleanup := normalizeProbeConfig(cfg)
	defer cleanup()

	if cfg.TopN > 0 && len(nodes) > cfg.TopN {
		nodes = nodes[:cfg.TopN]
	}
	outcomes := make([]ProbeOutcome, len(nodes))
	if len(nodes) == 0 {
		return outcomes
	}
	if cfg.Progress != nil {
		cfg.Progress(0, len(nodes), "准备中")
	}
	failAll := func(err error) []ProbeOutcome {
		cfg.Log("[probe] " + err.Error())
		for i := range outcomes {
			outcomes[i] = ProbeOutcome{NodeID: nodes[i].ID, Stage: "start", Err: err}
		}
		return outcomes
	}
	if cfg.Render == nil {
		return failAll(errors.New("Render 回调未设置"))
	}
	if cfg.CoreBin == "" {
		return failAll(errors.New("未定位到 mihomo.exe（CoreBin 为空）"))
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		return failAll(fmt.Errorf("创建隔离 WorkDir 失败: %w", err))
	}

	// 全局下载预算，原子扣减，供所有并发 worker 共享。
	remaining := new(atomic.Int64)
	remaining.Store(cfg.TotalBytes)
	// 完成计数，供 UI 进度回调跨并发槽汇总。
	done := new(atomic.Int64)

	conc := cfg.Concurrency
	if conc > len(nodes) {
		conc = len(nodes)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for slot := 0; slot < conc; slot++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			for idx := range jobs {
				// 每个 slot 固定占用一组端口，节点在该 slot 内串行，端口可复用；
				// 不同 slot 端口错开，因此多个探针内核可真正并发而互不抢端口。
				if cfg.Progress != nil {
					cfg.Progress(int(done.Load()), len(nodes), nodes[idx].ID)
				}
				outcomes[idx] = runOneProbe(ctx, cfg, nodes[idx], idx, slot, remaining)
				if cfg.Progress != nil {
					cfg.Progress(int(done.Add(1)), len(nodes), nodes[idx].ID)
				}
			}
		}(slot)
	}

feed:
	for i := range nodes {
		select {
		case <-ctx.Done():
			break feed // 取消后不再领取新节点
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	// 因取消而从未被领取的节点，补一个明确的「已取消」结果。
	for i := range outcomes {
		if outcomes[i].Stage == "" {
			outcomes[i] = ProbeOutcome{NodeID: nodes[i].ID, Stage: "start", Err: ctx.Err()}
		}
	}
	ok := 0
	for _, o := range outcomes {
		if o.Stage == "ok" && o.Err == nil {
			ok++
		}
	}
	cfg.Log(fmt.Sprintf("[probe] 完成：%d/%d 个节点测速成功", ok, len(outcomes)))
	return outcomes
}

// runOneProbe 完成单个节点：起独立内核 → 就绪 → 真实握手 → 真实下载 → 回收。
// 任何失败路径都会通过 defer 保证 Stop() 内核并删除独立子目录。
func runOneProbe(ctx context.Context, cfg ProbeConfig, node ProbeNode, idx, slot int, remaining *atomic.Int64) ProbeOutcome {
	out := ProbeOutcome{NodeID: node.ID, Stage: "start"}

	// 单节点总超时覆盖启动 / 握手 / 下载全部阶段。
	nodeCtx, cancel := context.WithTimeout(ctx, cfg.PerNodeTimeout)
	defer cancel()

	// 每节点一个独立子目录 + 每 slot 一组独立端口，彻底与线上 7890/9090 隔离。
	subdir := filepath.Join(cfg.WorkDir, fmt.Sprintf("probe-%d", idx))
	mixedPort := cfg.MixedPort + slot
	apiPort := cfg.APIPort + slot

	if err := nodeCtx.Err(); err != nil {
		out.Err = err
		return out
	}
	if err := nodeCtx.Err(); err != nil {
		out.Err = err
		return out
	}
	// Cheap reachability gate first: no core, no config, no 30s budget. A relay
	// whose TCP port is silent cannot handshake, and most of a VPN Gate list is
	// exactly that from any given network.
	if !cfg.SkipReachCheck && node.Server != "" && node.Port > 0 && (node.Proto == "" || node.Proto == "tcp") {
		addr := net.JoinHostPort(node.Server, strconv.Itoa(node.Port))
		var derr error
		// Two attempts: a home router that is being hammered drops the odd SYN,
		// and one lost handshake must not disqualify a relay that would work.
		for attempt := 0; attempt < 2; attempt++ {
			var conn net.Conn
			d := net.Dialer{Timeout: probeReachTimeout}
			conn, derr = d.DialContext(nodeCtx, "tcp", addr)
			if derr == nil {
				_ = conn.Close()
				break
			}
		}
		if derr != nil {
			out.Err = fmt.Errorf("中继端口不可达（%s，%s 内无响应）: %w", addr, probeReachTimeout, derr)
			return out
		}
	}
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		out.Err = fmt.Errorf("创建隔离目录失败: %w", err)
		return out
	}
	// defer 顺序：先删目录、后 Stop，LIFO 执行时先 Stop 再删目录，避免文件被占用。
	defer func() { _ = os.RemoveAll(subdir) }()

	cfg.Log(fmt.Sprintf("[probe] %s (%s) 开始：slot %d, mixed %d / api %d",
		node.ID, node.Region, slot, mixedPort, apiPort))

	// 1) 主代理渲染该节点的 config.yaml，再覆盖监听端口（见 rewriteProbePorts）。
	yamlBytes, err := cfg.Render(node.ID)
	if err != nil {
		out.Err = fmt.Errorf("渲染配置失败: %w", err)
		return out
	}
	yamlBytes = rewriteProbePorts(yamlBytes, mixedPort, apiPort)

	// 2) 另起一个完全独立的 mihomo 进程。TieCoreToClient / TUN 保持 false：
	//    不启健康守护、不改系统代理、不写 state.json，进程由本函数 Stop 回收。
	c, err := core.New(core.Config{
		BinaryPath: cfg.CoreBin,
		WorkDir:    subdir,
		MixedPort:  mixedPort,
		APIPort:    apiPort,
	})
	if err != nil {
		out.Err = fmt.Errorf("初始化内核失败: %w", err)
		return out
	}
	defer func() { _ = c.Stop() }()
	if err := c.WriteConfig(yamlBytes); err != nil {
		out.Err = fmt.Errorf("写入独立 config.yaml 失败: %w", err)
		return out
	}
	if err := c.Start(); err != nil {
		out.Err = fmt.Errorf("启动独立内核失败: %w", err)
		return out
	}
	if err := c.WaitReady(nodeCtx); err != nil {
		out.Err = fmt.Errorf("内核未就绪: %w", err)
		return out
	}
	// 「core 就绪」时刻，HandshakeMS 从这里起算。
	readyAt := time.Now()

	if err := nodeCtx.Err(); err != nil {
		out.Err = err
		return out
	}

	// 3) 真实握手：请求经该独立 mixed 端口穿过 mihomo 的 openvpn 出站，
	//    反复 GET 直到 generate_204 首次返回 2xx/3xx，记录耗时。
	out.Stage = "handshake"
	hsMS, err := probeHandshake(nodeCtx, mixedPort, readyAt)
	if err != nil {
		out.Err = fmt.Errorf("OpenVPN 握手未完成: %w", err)
		return out
	}
	out.HandshakeMS = hsMS

	if err := nodeCtx.Err(); err != nil {
		out.Err = err
		return out
	}

	// 4) 全局预算：原子预留本次下载字节；接近 / 达到 TotalBytes 后停止后续下载。
	out.Stage = "download"
	if !reserveProbeBytes(remaining, int64(cfg.BytesPerNode)) {
		out.Err = errProbeBudget
		cfg.Log(fmt.Sprintf("[probe] %s 预算用尽，跳过下载（已完成握手 %dms）", node.ID, hsMS))
		return out
	}

	// 5) 真实下载：probeThroughput 必须收满 BytesPerNode 字节才算成功。
	//    它无 ctx 参数，只能用 client.Timeout 间接服从单节点剩余时间；若取消发生
	//    在下载中途，用 goroutine + select 让本节点及时退出，残留请求由 Timeout 收尾。
	dlTimeout := cfg.PerNodeTimeout
	if d, ok := nodeCtx.Deadline(); ok {
		dlTimeout = time.Until(d)
	}
	if dlTimeout <= 0 {
		out.Err = errors.New("单节点超时，未开始下载")
		return out
	}
	type dlResult struct {
		bps int64
		got int64
		err error
	}
	// The window is the node's remaining budget, capped: measuring for 4s gives
	// a sustained rate, and a relay that cannot deliver 64KB in that window is
	// too slow to be worth ranking.
	window := probeDownloadWindow
	if dlTimeout < window {
		window = dlTimeout
	}
	dlCh := make(chan dlResult, 1)
	go func() {
		bps, got, err := probeDownload(mixedPort, cfg.BytesPerNode, window, probeMinSampleBytes)
		dlCh <- dlResult{bps: bps, got: got, err: err}
	}()
	select {
	case <-nodeCtx.Done():
		out.Err = nodeCtx.Err()
		return out
	case r := <-dlCh:
		if r.err != nil {
			out.Err = fmt.Errorf("下载测速失败: %w", r.err)
			return out
		}
		// A partial transfer still yields a real rate; Bytes records what was
		// actually received so the number is never a fabricated full download.
		out.Bytes = r.got
		out.Bps = r.bps
		out.Stage = "ok"
		out.Err = nil
		cfg.Log(fmt.Sprintf("[probe] %s 完成：握手 %dms · %s（%d 字节）", node.ID, hsMS, formatProbeBps(r.bps), r.got))
		return out
	}
}

// probeHandshake 是 warmupOpenVPN 的无全局状态等价实现：所有 HTTP 都经该节点
// 专属的独立 mixed 端口，拿到 2xx/3xx 即视为 openvpn 出站已真正承载请求。
// 首个请求通常被 inbound 的 dial 超时丢弃、由出站继续握手，故短间隔重试直到
// nodeCtx（PerNodeTimeout / 取消）到期。进度不写 stageMsg，避免并发串扰。
func probeHandshake(ctx context.Context, mixedPort int, readyAt time.Time) (int64, error) {
	proxyURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixedPort))
	if err != nil {
		return 0, err
	}
	// One attempt has to outlast the outbound's own handshake. mihomo's inbound
	// drops a dial after 5s while the openvpn outbound keeps handshaking for
	// handshake-timeout seconds, and a relay needs 2-8s to link (more when it
	// is carried by another tunnel). The old 4s timeout + 300ms retry aborted
	// every attempt mid-handshake AND restarted it on each retry, so a healthy
	// relay could never link: the whole list reported 0/N.
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		attempt := probeHandshakeAttempt
		if d, ok := ctx.Deadline(); ok {
			if left := time.Until(d); left < attempt {
				attempt = left
			}
		}
		if attempt <= 0 {
			return 0, ctx.Err()
		}
		client := &http.Client{
			Timeout: attempt,
			// A kept-alive connection would be reused by a *previous* attempt's
			// dial; a fresh one per attempt is what makes the retry meaningful.
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		}
		resp, err := client.Get(probeHandshakeURL)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 { // 含 204
				return time.Since(readyAt).Milliseconds(), nil
			}
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// rewriteProbePorts 把 Render 生成的 mihomo 配置里的监听端口改成本节点专属的
// 隔离端口。Render 只拿到 nodeID、并不知道该用哪一组端口，所以必须由这里覆盖：
//   - 强制写入 mixed-port / external-controller（原配置缺失也补上）。否则 mihomo
//     会退回默认 7890/9090，正好撞上线上内核，且 WaitReady 也找不到 controller。
//   - 把 port / socks-port / redir-port / tproxy-port 置 0，避免它们额外监听
//     7890 等端口或与本节点端口冲突。
//
// 代理链（proxies / proxy-groups / rules）保持不动，由 Render 负责保证
// generate_204 与 speed.cloudflare.com 的流量经该 OpenVPN 出站转发（如
// MATCH,<openvpn>），否则测到的不是该节点。
func rewriteProbePorts(yamlBytes []byte, mixedPort, apiPort int) []byte {
	lines := strings.Split(string(yamlBytes), "\n")
	seenMixed, seenAPI, seenBind := false, false, false
	for i, ln := range lines {
		switch topLevelYAMLKey(ln) {
		case "mixed-port":
			lines[i] = fmt.Sprintf("mixed-port: %d", mixedPort)
			seenMixed = true
		case "external-controller":
			lines[i] = fmt.Sprintf("external-controller: 127.0.0.1:%d", apiPort)
			seenAPI = true
		case "port", "socks-port", "redir-port", "tproxy-port":
			lines[i] = topLevelYAMLKey(ln) + ": 0"
		case "bind-address":
			lines[i] = "bind-address: 127.0.0.1"
			seenBind = true
		}
	}
	header := make([]string, 0, 3)
	if !seenMixed {
		header = append(header, fmt.Sprintf("mixed-port: %d", mixedPort))
	}
	if !seenAPI {
		header = append(header, fmt.Sprintf("external-controller: 127.0.0.1:%d", apiPort))
	}
	if !seenBind {
		header = append(header, "bind-address: 127.0.0.1")
	}
	if len(header) > 0 {
		lines = append(header, lines...)
	}
	return []byte(strings.Join(lines, "\n"))
}

// topLevelYAMLKey 返回顶格（无缩进、非注释）YAML 行的键名；用于只改顶层监听
// 配置，绝不误伤 proxies 列表里缩进的同名字段。
func topLevelYAMLKey(ln string) string {
	if ln == "" || ln[0] == ' ' || ln[0] == '\t' {
		return ""
	}
	t := strings.TrimSpace(ln)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	idx := strings.IndexByte(t, ':')
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(t[:idx])
}

// reserveProbeBytes 原子地从剩余预算里预留 want 字节；不足则返回 false。
// 并发 worker 共享同一预算，CAS 保证累计下载不越过 TotalBytes。
func reserveProbeBytes(remaining *atomic.Int64, want int64) bool {
	for {
		cur := remaining.Load()
		if cur < want {
			return false
		}
		if remaining.CompareAndSwap(cur, cur-want) {
			return true
		}
	}
}

// Summary 给 UI 一行展示用：成功显示握手耗时 + 真实下载速率，失败显示阶段与原因。
func (o ProbeOutcome) Summary() string {
	if errors.Is(o.Err, errProbeBudget) {
		return "未测速：总流量预算已用尽"
	}
	if o.Err != nil {
		switch o.Stage {
		case "start":
			return "启动失败：" + o.Err.Error()
		case "handshake":
			return "握手失败：" + o.Err.Error()
		case "download":
			return "测速失败：" + o.Err.Error()
		default:
			return "失败：" + o.Err.Error()
		}
	}
	if o.Stage == "ok" {
		return fmt.Sprintf("握手 %.1fs · %s", float64(o.HandshakeMS)/1000, formatProbeBps(o.Bps))
	}
	if o.HandshakeMS > 0 {
		return fmt.Sprintf("握手 %.1fs · 未测速", float64(o.HandshakeMS)/1000)
	}
	return "无结果"
}

func formatProbeBps(bps int64) string {
	switch {
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", float64(bps)/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.0f KB/s", float64(bps)/(1<<10))
	case bps > 0:
		return fmt.Sprintf("%d B/s", bps)
	default:
		return "0 B/s"
	}
}

// probeDownload measures the relay's real downlink over a TIME window instead of
// a fixed byte count. A 48 KiB sample finishes in ~40 ms on a 1 MB/s relay, so
// the number was the TCP slow-start burst, not the sustained rate — the list
// promised 1.2 MB/s while the session measured 0.5 MB/s on the same class of
// relay. Reading for a fixed window (capped by bytes) reports what the relay
// actually sustains, and still fits the per-node budget.
//
// A partial transfer is accepted once it clears minBytes: a VPN Gate home router
// routinely drops the connection after a few hundred KB, and that measurement is
// still real.
func probeDownload(mixedPort int, maxBytes int, maxDuration time.Duration, minBytes int64) (bps, got int64, err error) {
	client := &http.Client{
		// One stall must not eat the whole node budget.
		Timeout: maxDuration + 3*time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(mustParseURL("http://127.0.0.1:" + strconv.Itoa(mixedPort))),
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", maxBytes))
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	start := time.Now()
	buf := make([]byte, 32<<10)
	var readErr error
	for {
		if time.Since(start) >= maxDuration {
			break
		}
		n, rerr := resp.Body.Read(buf)
		got += int64(n)
		if got >= int64(maxBytes) {
			break
		}
		if rerr != nil {
			readErr = rerr
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed > 0 && got > 0 {
		bps = int64(float64(got) / elapsed)
	}
	if got >= minBytes {
		// Enough bytes over enough time to trust the rate; a truncated tail is
		// the relay's own problem, not a reason to discard the measurement.
		return bps, got, nil
	}
	if readErr != nil {
		return bps, got, fmt.Errorf("传输中断于 %d 字节: %w", got, readErr)
	}
	return bps, got, fmt.Errorf("仅收到 %d 字节（低于 %d 的采样下限）", got, minBytes)
}
