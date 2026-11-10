package warp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tc "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// 并发地区测速。
//
// 为什么不能只靠串行（2026-11-09 用户要求：**必须全部地区都测**，时间不能更长）：
//
//	`MobileLibrary/psi` 里 `controller` 是一个**进程内全局变量**，同一个进程同时
//	只能有一条 Psiphon 隧道；串行测 27 个地区、每国 8–10 秒，110 秒预算只够跑
//	前 10 个，剩下的只能标「超时未测」。
//
// 这里绕开 psi 封装，直接用 tunnel-core 的 `psiphon` 包：`NewController` 是**实例**
// 级的，多个 controller 可以并存（datastore 是引用计数的：OpenDataStore/CloseDataStore
// 成对出现即可，见 psiphon/dataStore.go 的注释）。于是每个地区各跑一条 controller，
// 3–4 个并发，27 个地区 2 轮多一点就跑完 —— 总数不变，时间反而更短。
//
// 代价与边界：
//   - 只用于「测速」（不建 tun、不接管流量），和正式连接互斥（warpbackend 的
//     probingRegions 已经保证）；
//   - notice writer 是进程级的，测速期间静音（MutePsiphonNotices），正式连接时
//     psi.Start 会重新装上自己的 writer；
//   - 任何一条起不来都只是「该地区失败」，不会把整个功能带崩；如果**全部**都是
//     基础设施错误（datastore / controller 起不来），调用方要回退到串行实现。

// psiphonRegionStreams 是单个地区测速的并发流数。
//
// 比节点测速（4 流）少一条：3 个地区并发时同时有 9 条流在跑，再加就该抢 CPU 了。
const psiphonRegionStreams = 3

// PsiphonRegionResult 是一个地区的并发测速结果。
type PsiphonRegionResult struct {
	Region string
	MS     int64
	Bps    int64
	Err    string
	// Infra 表示这条失败是「并发测速的设施起不来」（配置/datastore/controller），
	// 不是这个地区本身不可用。全部都是 Infra 时调用方应回退到串行实现。
	Infra bool
}

// psiphonSetupMu 串行化「LoadConfig → Commit → OpenDataStore → NewController」。
//
// 并行建 controller 本身没问题，但 Commit 里有一段
// `if !FileExists(dir) { os.Mkdir(dir) }`，4 个地区同时提交会撞成
// "file exists" 而整条失败（那就全变成基础设施错误，被迫回退串行）。
// 这段只需要几十毫秒，串起来最省事；真正耗时的隧道建立仍然是并行的。
var psiphonSetupMu sync.Mutex

// psiphonProbeHost 是喂给 tunnel-core 的最小回调实现（测速不需要 device binder：
// 测速期间系统 VPN 不会建立，Psiphon 的 socket 直连本地上游 SOCKS）。
type psiphonProbeHost struct{ dns []string }

func (psiphonProbeHost) HasNetworkConnectivity() int { return 1 }

// GetNetworkID 必须始终有值（tunnel-core 的 tactics 依赖它），取不到就 "UNKNOWN"。
func (psiphonProbeHost) GetNetworkID() string { return psiphonNetworkID }

func (h psiphonProbeHost) GetDNSServers() []string { return h.dns }

// MutePsiphonNotices 把 tunnel-core 的 notice 输出静音。
//
// 只在「并发地区测速」期间调用：进程内只有一个 notice writer，多条 controller
// 并行时没法按实例分流，而测速阶段我们不需要那些诊断。正式连接前 psi.Start 会
// 重新装上自己的 writer。
func MutePsiphonNotices() {
	// 直接用语句形式调用：不同版本的 tunnel-core 里这个函数有的返回 error、
	// 有的什么都不返回，语句形式两边都能编译。
	tc.SetNoticeWriter(io.Discard)
}

// ProbePsiphonRegionsConcurrent 并发测多个地区，返回与 regions 同序的结果。
//
// 第二个返回值 ok=false 表示「并发设施整体不可用」，调用方应回退到串行实现。
func ProbePsiphonRegionsConcurrent(
	ctx context.Context,
	cfgJSON, dataDir, upSocks, dns string,
	regions []string,
	concurrency int,
	perRegion time.Duration,
	report func(string),
	onResult func(PsiphonRegionResult),
) ([]PsiphonRegionResult, bool) {
	if len(regions) == 0 {
		return nil, true
	}
	if concurrency <= 0 {
		concurrency = 3
	}
	if perRegion <= 0 {
		perRegion = 9 * time.Second
	}
	MutePsiphonNotices()

	out := make([]PsiphonRegionResult, len(regions))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var infra atomic.Int32
	var done atomic.Int32
	// 回调（尤其是 gomobile 的 Java 回调）不并发调用：并发进 JNI 会让
	// tunnel-core 那边疯狂起线程，进度行也没必要同时冒出来。
	var cbMu sync.Mutex

	for i, region := range regions {
		i, region := i, region
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				// 预算是 120 秒：到点还没轮到的地区明确标成「超时未测」，
				// 而不是含糊的「已取消」。
				msg := "已取消"
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					msg = "超时未测（2 分钟预算用尽）"
				}
				out[i] = PsiphonRegionResult{Region: region, Err: msg}
				if onResult != nil {
					cbMu.Lock()
					onResult(out[i])
					cbMu.Unlock()
				}
				return
			}
			defer func() { <-sem }()

			ms, bps, err, infraFail := probeOnePsiphonRegion(ctx, cfgJSON, dataDir, upSocks, dns, region, perRegion)
			res := PsiphonRegionResult{Region: region, MS: ms, Bps: bps, Infra: infraFail}
			if err != nil {
				res.Err = shortErr(err)
			} else if bps <= 0 {
				res.Err = "连上了但测不出速度"
			}
			out[i] = res
			if infraFail {
				infra.Add(1)
			}
			n := done.Add(1)
			cbMu.Lock()
			if report != nil {
				if res.Err != "" {
					report(fmt.Sprintf("地区测速 %d/%d：%s 失败：%s", n, len(regions), region, res.Err))
				} else {
					report(fmt.Sprintf("地区测速 %d/%d：%s ≈%d KB/s（就绪 %dms）",
						n, len(regions), region, bps/1024, ms))
				}
			}
			if onResult != nil {
				onResult(res)
			}
			cbMu.Unlock()
		}()
	}
	wg.Wait()

	// 全部地区都栽在「设施起不来」上时，说明这条路在当前进程状态里不可用，
	// 交给串行实现去跑（宁愿慢，也不能整块功能失效）。
	ok := infra.Load() < int32(len(regions))
	if !ok && report != nil {
		report("并发地区测速不可用（controller 起不来），回退到逐个国家串行测速…")
	}
	return out, ok
}

// probeOnePsiphonRegion 起一条**独立的** controller，等它建立到测速端点的隧道，
// 然后用多流并发量一次吞吐。返回 (就绪耗时 ms, 字节/秒, error, 是否基础设施错误)。
func probeOnePsiphonRegion(
	ctx context.Context,
	cfgJSON, dataDir, upSocks, dns, region string,
	timeout time.Duration,
) (int64, int64, error, bool) {
	started := time.Now()

	cfgText, err := buildPsiphonConfig(cfgJSON, 0, dataDir, "socks5://"+upSocks, dns, region)
	if err != nil {
		return 0, 0, err, true
	}
	cfg, err := tc.LoadConfig([]byte(cfgText))
	if err != nil {
		return 0, 0, fmt.Errorf("解析配置: %w", err), true
	}
	// 测速阶段只要隧道，不要诊断噪音（日志量会按地区数翻好几倍）。
	cfg.EmitDiagnosticNotices = false
	cfg.EmitDiagnosticNetworkParameters = false
	cfg.NetworkConnectivityChecker = psiphonProbeHost{}
	cfg.NetworkIDGetter = psiphonProbeHost{}
	cfg.DNSServerGetter = psiphonProbeHost{dns: splitDNSList(dns)}

	// 建 controller 的准备工作串行（见 psiphonSetupMu 的注释），隧道建立并行。
	psiphonSetupMu.Lock()
	if err := cfg.Commit(false); err != nil {
		psiphonSetupMu.Unlock()
		return 0, 0, fmt.Errorf("提交配置: %w", err), true
	}
	if err := tc.OpenDataStore(cfg); err != nil {
		psiphonSetupMu.Unlock()
		return 0, 0, fmt.Errorf("打开 datastore: %w", err), true
	}
	ctrl, err := tc.NewController(cfg)
	psiphonSetupMu.Unlock()
	if err != nil {
		tc.CloseDataStore()
		return 0, 0, fmt.Errorf("创建 controller: %w", err), true
	}
	// datastore 是引用计数的（见 psiphon/dataStore.go）：每个地区各持一份引用，
	// 只要还有一个 controller 在跑，它就不会被关掉。
	defer tc.CloseDataStore()

	runCtx, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ctrl.Run(runCtx)
	}()
	defer func() {
		cancel()
		<-stopped
	}()

	addr := net.JoinHostPort(probeSpeedHost, "443")

	// 等隧道就绪：反复 Dial 到测速端点，成功即说明这条地区的隧道已经能带流量。
	// 不用 notice 判就绪：并发时 notice writer 是静音的，而 Dial 成功本身就是
	// 「能落地」的硬证据。
	readyBy := started.Add(timeout)
	for {
		if ctx.Err() != nil {
			return time.Since(started).Milliseconds(), 0, ctx.Err(), false
		}
		c, derr := psiphonDial(runCtx, ctrl, addr, 4*time.Second)
		if derr == nil && c != nil {
			_ = c.Close()
			break
		}
		if time.Now().After(readyBy) {
			msg := "隧道建立超时（该地区本次没有可用服务器）"
			if derr != nil {
				msg = "隧道建立超时：" + shortErr(derr)
			}
			return time.Since(started).Milliseconds(), 0, errors.New(msg), false
		}
		if !sleepCtx(ctx, 300*time.Millisecond) {
			return time.Since(started).Milliseconds(), 0, ctx.Err(), false
		}
	}
	ms := time.Since(started).Milliseconds()

	bps, note := speedProbeVia(ctx, func(dctx context.Context) (net.Conn, error) {
		return psiphonDial(dctx, ctrl, addr, 6*time.Second)
	}, probeSpeedHost, psiphonRegionStreams, speedProbeWarmup, speedProbeWindow)
	if bps <= 0 {
		if note == "" {
			note = "测不出速度"
		}
		return ms, 0, errors.New(note), false
	}
	return ms, bps, nil, false
}

// psiphonDial 给 controller.Dial 套一个超时：它的签名没有 ctx，隧道刚起来或者
// 已经半死时可能长时间不返回，而测速线程不能被一个地区永久占住。
func psiphonDial(ctx context.Context, ctrl *tc.Controller, addr string, timeout time.Duration) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ctrl.Dial(addr, nil)
		ch <- result{conn: c, err: err}
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		return nil, errors.New("隧道内拨号超时")
	}
}

// splitDNSList 把 "1.1.1.1,8.8.8.8" 这样的字符串拆成 slice。
func splitDNSList(dns string) []string {
	f := strings.FieldsFunc(dns, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(f))
	for _, s := range f {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
