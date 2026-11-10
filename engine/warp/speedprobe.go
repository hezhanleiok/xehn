package warp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// 测速口径与 speedtest.net 对齐：**多条并发 TCP 流 + 丢掉慢启动再取稳态**。
//
// 为什么必须这样（2026-11-09 用户实测）：单流、2 秒窗口测出来日本家宽节点只有
// 70–80 KB/s，而同一节点用 speedtest 实测下行 17 Mbps（≈2 MB/s），差了 25 倍。
// 单流在「手机 → WARP → 跨境节点」这条 200–400ms RTT 的链路上会被三件事拖死：
//
//	① TCP 慢启动要几十个 RTT 才爬到线速，2 秒窗口基本全在爬坡段；
//	② 一个包丢了 cwnd 就腰斩，跨境链路这种丢包很常见；
//	③ 单流的窗口上限 = min(本端缓窗, 对端缓窗) / RTT，物理上封顶。
//
// speedtest 用的是 4–8 条并发流，所以它给出的数字才是「这条线路能给多少」。
// 这里照同一口径来：默认 4 流、预热 800ms、窗口 2s；窗口内每 250ms 采一次
// 累计字节，丢掉前两个区间后取**中位数**（见函数内注释：不能直接用总字节 ÷ 时长，
// 否则本端接收缓冲里预热阶段攒下的几 MB 会被算进窗口，读数虚高一个数量级）。
const (
	speedProbeStreams   = 4
	speedProbeWarmup    = 800 * time.Millisecond
	speedProbeWindow    = 2 * time.Second
	speedProbeConnectTO = 5 * time.Second
	// speedProbeBytes 是每条流申请的下载量：64 MiB 保证窗口内不会读完好
	// （读完会触发 EOF，样本就不完整了），又不会真的把流量跑超。
	speedProbeBytes = 64 << 20
)

// speedProbeDialer 打开一条到测速端点的**裸 TCP 连接**；TLS 由本文件负责，
// 这样各条路径（gVisor netstack / Psiphon 隧道 / SOCKS）只要会拨 TCP 就能复用。
type speedProbeDialer func(ctx context.Context) (net.Conn, error)

// speedProbeVia 用多流并发量一次稳态吞吐，返回字节/秒（0 = 没测出来，附原因）。
//
// open 负责拨到 host:443 的裸 TCP；tlsHost 是 TLS SNI（空串表示明文，只用于排错）。
// ctx 是整次测量的预算（覆盖「建连 + 预热 + 采样」）。
func speedProbeVia(
	ctx context.Context,
	open speedProbeDialer,
	tlsHost string,
	streams int,
	warmup, window time.Duration,
) (int64, string) {
	if open == nil {
		return 0, "没有拨号函数"
	}
	if streams <= 0 {
		streams = speedProbeStreams
	}
	if warmup <= 0 {
		warmup = speedProbeWarmup
	}
	if window <= 0 {
		window = speedProbeWindow
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		total  atomic.Int64
		live   atomic.Int32
		done   atomic.Int32
		mu     sync.Mutex
		conns  []net.Conn
		errs   []string
		wg     sync.WaitGroup
	)
	addConn := func(c net.Conn) {
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
	}
	addErr := func(stage string, err error) {
		mu.Lock()
		if len(errs) < streams {
			errs = append(errs, stage+": "+shortErr(err))
		}
		mu.Unlock()
	}
	firstErr := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(errs) == 0 {
			return ""
		}
		return errs[0]
	}
	stop := func() {
		mu.Lock()
		cs := conns
		conns = nil
		mu.Unlock()
		for _, c := range cs {
			_ = c.Close()
		}
	}

	reqLine := fmt.Sprintf(
		"GET /__down?bytes=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: xehn-speed/1\r\n"+
			"Accept: */*\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
		speedProbeBytes, tlsHost)

	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer done.Add(1)

			dctx, dcancel := context.WithTimeout(runCtx, speedProbeConnectTO)
			conn, err := open(dctx)
			if err != nil {
				dcancel()
				addErr("连接", err)
				return
			}
			addConn(conn)

			var rw net.Conn = conn
			if tlsHost != "" {
				tc := tls.Client(conn, &tls.Config{
					ServerName: tlsHost,
					NextProtos: []string{"http/1.1"},
				})
				if err := tc.HandshakeContext(dctx); err != nil {
					dcancel()
					addErr("TLS", err)
					return
				}
				rw = tc
			}
			// 建连/TLS 的 ctx 到这里就没用了。**不能** defer 到 goroutine 结束：
			// 部分 dialer 会把 ctx 取消当成「这条连接作废」，取消完就读不到数据。
			// 之后的读取只由 runCtx 与「测完统一 Close」控制。
			dcancel()
			if _, err := io.WriteString(rw, reqLine); err != nil {
				addErr("请求", err)
				return
			}
			br := bufio.NewReaderSize(rw, 32<<10)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
			if err != nil {
				addErr("响应", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				addErr("状态", fmt.Errorf("HTTP %d", resp.StatusCode))
				return
			}
			live.Add(1)
			buf := make([]byte, 32<<10)
			for {
				n, rerr := resp.Body.Read(buf)
				if n > 0 {
					total.Add(int64(n))
				}
				if rerr != nil {
					return
				}
				if runCtx.Err() != nil {
					return
				}
			}
		}()
	}

	// 等第一条流开始出数据。全部流都在建连阶段失败时立刻返回，不要白等。
	readyBy := time.Now().Add(speedProbeConnectTO + 2*time.Second)
	allDone := int32(0)
	for total.Load() == 0 {
		if ctx.Err() != nil {
			stop()
			wg.Wait()
			return 0, "测速被取消"
		}
		if done.Load() == int32(streams) && total.Load() == 0 {
			allDone = 1
			break
		}
		if time.Now().After(readyBy) {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	if total.Load() == 0 {
		stop()
		wg.Wait()
		if e := firstErr(); e != "" {
			return 0, "没有收到数据（" + e + "）"
		}
		if allDone == 1 {
			return 0, "所有测速流都没拿到数据"
		}
		return 0, "1 秒内没有收到首字节"
	}

	// 预热：丢掉慢启动段（时间维度比字节维度稳，慢的流也能被覆盖）。
	if !sleepCtx(ctx, warmup) {
		stop()
		wg.Wait()
		return 0, "测速被取消"
	}
	// 采样：每 250ms 取一次累计字节，算出**每个区间的瞬时速率**，最后取中位数。
	//
	// 为什么不再用「窗口总字节 ÷ 窗口时长」（0.2.30 的做法）：预热结束时，每条流在
	// 本端（gVisor / 内核）的接收缓冲里已经攒了几 MB（测速栈缓冲上限 4 MiB，4 条流
	// 就是十几 MB）。这些字节其实是**窗口开始前**就收到的，却会在窗口前半段被飞快
	// 读出来并计入窗口 —— 一条 2 MB/s 的链路能报出 17 MB/s（真机日志里一批 kr/jp
	// 节点都是这个量级，用户直接质疑「十几兆正常不」）。
	//
	// 逐区间采样后，前两个区间（排空缓冲）被丢掉，中位数只反映稳态速率；中位数对
	// 「某条流提前读完」这类掉速也免疫。
	const tick = 250 * time.Millisecond
	prev, prevAt := total.Load(), time.Now()
	rates := make([]float64, 0, 16)
	deadline := time.Now().Add(window)
	for {
		wait := tick
		if left := time.Until(deadline); left < wait {
			wait = left
		}
		if !sleepCtx(ctx, wait) {
			stop()
			wg.Wait()
			return 0, "测速被取消"
		}
		now := time.Now()
		cur := total.Load()
		// 只收长度正常的区间：窗口末尾那个「补零」的区间只有几微秒，除出来的
		// 速率会是几十 GB/s 的野值（中位数能挡住，但没必要留）。
		if dt := now.Sub(prevAt).Seconds(); dt >= 0.15 {
			rates = append(rates, float64(cur-prev)/dt)
		}
		prev, prevAt = cur, now
		if !now.Before(deadline) {
			break
		}
	}

	stop()
	wg.Wait()

	if len(rates) < 2 {
		return 0, "样本太短"
	}
	// 丢掉前两个区间（≈0.5s）：缓冲排空 + 慢启动尾巴。
	if len(rates) > 4 {
		rates = rates[2:]
	}
	med := medianRate(rates)
	if med <= 0 {
		return 0, "预热后没有新数据"
	}
	return int64(med), ""
}

// medianRate 取中位数：对偶发的掉速/抖动免疫，比平均值更接近「稳态能跑多少」。
func medianRate(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	cp := make([]float64, len(v))
	copy(cp, v)
	sort.Float64s(cp)
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}

// sleepCtx 睡满 d，ctx 提前结束就返回 false。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
