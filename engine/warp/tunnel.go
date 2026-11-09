package warp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	netstack "github.com/xhwarp/android-engine/warp/netstackx"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ipStack struct {
	tnet   *netstack.Net
	client *http.Client
}

// netstackTCPBufferMax 是外层 gVisor TCP 的收/发缓冲上限。
//
// 单程 RTT ~250ms 时，吞吐 ≈ 窗口/RTT：8MB ⇒ 理论上限 ~256 Mbps，远高于
// VPN Gate 节点本身能给到的带宽，所以再大只是白占内存（每条连接都可能吃满）。
// 上游默认在 1MB 量级，实测把「WARP → 节点」这条链锁在 17 Mbps。
// ⚠ 暂时关掉（0 = 用上游默认缓冲）。取值来自 2026-10-22 深夜的真机对照：
// 打开 8MB 之后的构建出现「握手成功但数据面不通」，关掉之后恢复。
// 要重新启用前必须先在真机验证：先 2MB 试，再逐步加，别直接上 8MB。
const netstackTCPBufferMax = 0

func newIPStack(local []netip.Addr, mtu int) (tun.Device, *ipStack, error) {
	// MTU 为 0 时 gVisor 连一个 IP 包都发不出去，表现正是「隧道握手成功、
	// 数据面全不通」——而调用方完全看不出原因。这里兜底成标准值。
	if mtu < 576 {
		mtu = 1280
	}
	tunDev, tnet, err := netstack.CreateNetTUNBuffered(
		local, []netip.Addr{netip.MustParseAddr(tunnelDNS)}, mtu, netstackTCPBufferMax)
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 有缓存就用缓存 IP（省一次 DNS），没有就用请求本身给的地址。
			//
			// 以前这里无条件用 metaDialAddr()：解析失败时它返回空串，于是
			// 连 `https://1.1.1.1/cdn-cgi/trace` 这种 IP 字面量也拨不出去 ——
			// 一条完全正常的隧道被判成「数据面不通（隧道内请求超时）」。
			// 真机日志里 14 个端点全被误判，就是这么来的。
			if m := metaDialAddr(); m != "" {
				addr = m
			}
			return tnet.DialContext(ctx, "tcp", addr)
		},
	}
	return tunDev, &ipStack{tnet: tnet, client: &http.Client{Transport: transport}}, nil
}

type tunnel interface {
	handshake(ctx context.Context, endpoint string, timeout time.Duration) bool
	ports() []int
	attempts() int
	// stack is nil when the data plane is the OS tun device (fd mode).
	stack() *ipStack
	// counters reports cumulative tx/rx bytes, or zeros without an OS device.
	counters() (tx, rx uint64)
	Close()
}

// newTunnel 建 WG/AWG（及嵌套模式的 WG/AWG）隧道。MASQUE 不走这里：
// Dial 在更早的一层就把 masque/masque-h2 分派给了 dialMasque → newMasqueTunnel，
// 所以 MASQUE 落到这里只可能是一个没被拦截的 bug —— 明确报错而不是悄悄退化。
// WARP-in-WARP（wwarp）也走这里：内层隧道用同一套 WG/AWG 设备，只是把 bind
// 换成跑在外层隧道 netstack 里的 tunnelBind（见 nest.go）。
func newTunnel(run protoRun) (tunnel, error) {
	if run.isMASQUE() {
		return nil, fmt.Errorf("MASQUE 必须经 newMasqueTunnel 创建，不应进入 newTunnel")
	}
	return newWGTunnel(run.isAWG())
}

type wgTunnel struct {
	// ipStack is nil in fd mode: there is no userspace netstack because the
	// packets come from the OS tun device instead.
	*ipStack
	dev *device.Device
	// byteCounter is the tun device's byte counter (nil in netstack mode).
	byteCounter tunCounter
}

func newWGTunnel(awg bool) (*wgTunnel, error) {
	base, err := baseUAPI(awg)
	if err != nil {
		return nil, err
	}

	// 内层隧道（WARP-in-WARP）要给外层封装留 MTU；外层本身用满 MTU。
	mtu := tunnelMTU
	if outer != nil {
		mtu -= nestedOverhead
	} else if tunMTU > 0 {
		mtu = tunMTU
	}

	// Two data planes, chosen by whether the platform gave us a tun device:
	//
	//   fd >= 1  → the Android system VPN. VpnService built the interface and
	//              handed over its fd, so the OS does routing and TCP/IP and our
	//              job is only to encrypt what appears in the device.
	//   fd == 0  → the gVisor netstack. No interface exists, nothing outside
	//              this process sees the tunnel; used by the desktop live test
	//              and by the "just prove it can connect" path.
	var tunDev tun.Device
	var stack *ipStack
	var counters tunCounter
	if tunFD > 0 {
		tunDev, counters, err = newFdTunDevice(tunFD, mtu)
	} else {
		tunDev, stack, err = newIPStack([]netip.Addr{
			netip.MustParseAddr(warpAddress),
			netip.MustParseAddr(warpAddressV6),
		}, mtu)
	}
	if err != nil {
		return nil, err
	}
	// Not conn.NewDefaultBind(): its BatchSize is 128 on Linux, so wireguard-go
	// holds a batch of MaxMessageSize buffers per receive routine per tunnel -
	// measured as 96% of the live heap, and the whole reason the memory limit
	// costs CPU. A scan pushes a trickle of packets, so the batch buys nothing.
	// 默认直连主机：socket 绑到系统接口（SO_BINDTODEVICE + protect）。内层
	// 隧道（outer != nil）则把 UDP 包送进外层隧道的 netstack，而不是主机栈。
	var bind conn.Bind = conn.Bind(newDeviceBind(scanInterface))
	if outer != nil {
		bind = newTunnelBind(outer)
	}
	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, ""))

	if err := dev.IpcSet(base); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &wgTunnel{ipStack: stack, dev: dev, byteCounter: counters}, nil
}

func (t *wgTunnel) Close()          { t.dev.Close() }
func (t *wgTunnel) ports() []int    { return warpPorts }
func (t *wgTunnel) attempts() int   { return 1 }
func (t *wgTunnel) stack() *ipStack { return t.ipStack }

func (t *wgTunnel) counters() (uint64, uint64) {
	if t.byteCounter == nil {
		return 0, 0
	}
	return t.byteCounter.Counters()
}

func (t *wgTunnel) handshake(ctx context.Context, endpoint string, timeout time.Duration) bool {
	peer, err := peerUAPI(endpoint)
	if err != nil {
		return false
	}
	if err := t.dev.IpcSet(peer); err != nil {
		return false
	}
	return waitHandshake(ctx, t.dev, timeout)
}

type probeTarget struct {
	ip   netip.Addr
	port int // 0 means "try the tunnel's whole port list"
}

func probeTargets(run protoRun, perPort bool, ips []netip.Addr, ports []int) []probeTarget {
	if !run.isMASQUE() && !perPort {
		targets := make([]probeTarget, len(ips))
		for i, ip := range ips {
			targets[i] = probeTarget{ip: ip}
		}
		return targets
	}
	targets := make([]probeTarget, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, port := range ports {
			targets = append(targets, probeTarget{ip: ip, port: port})
		}
	}
	return targets
}

func tunnelProbe(ctx context.Context, t tunnel, target probeTarget, timeout time.Duration, pings int, wantMeta bool) (tr metaResult, endpoint string, ok bool, rtt time.Duration, loss float32, torn bool) {
	ports := t.ports()
	if target.port != 0 {
		ports = []int{target.port}
	}
	for _, port := range ports {
		endpoint = net.JoinHostPort(target.ip.String(), strconv.Itoa(port))
		for attempt := 0; attempt < max(t.attempts(), 1); attempt++ {
			if ctx.Err() != nil {
				return metaResult{}, endpoint, false, 0, 0, false
			}
			if tr, rtt, loss, torn, ok = probeEndpoint(ctx, t, endpoint, timeout, pings, wantMeta); ok {
				return tr, endpoint, true, rtt, loss, torn
			}
		}
	}
	return metaResult{}, endpoint, false, 0, 0, false
}

func tunnelConnect(ctx context.Context, t tunnel, ip netip.Addr, timeout time.Duration) bool {
	for _, port := range t.ports() {
		if t.handshake(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(port)), timeout) {
			return true
		}
	}
	return false
}

func probeEndpoint(ctx context.Context, t tunnel, endpoint string, timeout time.Duration, pings int, wantMeta bool) (tr metaResult, rtt time.Duration, loss float32, torn, ok bool) {
	if !t.handshake(ctx, endpoint, timeout) {
		return metaResult{}, 0, 0, false, false
	}
	st := t.stack()
	if st == nil {
		// fd 模式下没有 netstack，扫描路径的隧道内探测无从谈起。返回未通过，
		// 而不是解引用空指针 —— 连接路径自己有走真实系统网络的验证。
		return metaResult{}, 0, 0, false, false
	}

	// find-junk only asks whether the peer comes up, and the durability ping
	// already proves the tunnel passes data - the meta fetch adds nothing.
	if !wantMeta {
		if pings <= 0 {
			return metaResult{}, 0, 0, false, true
		}
		rtt, loss, torn = st.durability(pings, timeout)
		return metaResult{}, rtt, loss, torn, true
	}

	body, ok := st.fetch(ctx, timeout)
	if !ok {
		return metaResult{}, 0, 0, false, false
	}
	if pings <= 0 {
		return parseMeta(body), 0, 0, false, true
	}
	rtt, loss, torn = st.durability(pings, timeout)
	return parseMeta(body), rtt, loss, torn, true
}

// A real DPI teardown stays dead across both bursts; transient loss does not,
// so the second burst's numbers are the ones reported when the first was noise.
// Running right after the meta fetch lets the burst read the tunnel's state once a
// real request has already given DPI something to kill.
func (s *ipStack) durability(count int, timeout time.Duration) (time.Duration, float32, bool) {
	rtt, loss, torn := s.tunnelPing(count, timeout)
	if !torn {
		return rtt, loss, false
	}
	rtt2, loss2, torn2 := s.tunnelPing(count, timeout)
	if !torn2 {
		return rtt2, loss2, false
	}
	return rtt, loss, true
}

func (s *ipStack) fetch(ctx context.Context, timeout time.Duration) (string, bool) {
	body, _, ok := s.fetchReason(ctx, timeout)
	return body, ok
}

// fetchReason 与 fetch 相同，但把失败原因带出来。
//
// 没有原因时，「DNS 挂了」「出口拒了 /meta」「隧道真的没通」三种情况在日志里
// 一模一样（都写成「数据面不通」），而它们的处理方式完全不同 —— 前两种会
// 把能用的端点误判成死端点，真机已经踩过两次。
func (s *ipStack) fetchReason(ctx context.Context, timeout time.Duration) (string, string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if resolveMetaAddr(reqCtx, s.tnet) {
		s.client.Timeout = timeout
		if body, ok := fetchMeta(reqCtx, s.client, metaURL); ok {
			return body, "", true
		}
		if body, ok := fetchMeta(reqCtx, s.client, traceURL); ok {
			return body, "", true
		}
	}
	// DNS 不通或上面两档被出口拒绝：改用 IP 字面量，这一步不需要任何解析。
	if body, ok := s.fetchLiteral(reqCtx, timeout); ok {
		return body, "", true
	}
	if reqCtx.Err() != nil {
		return "", "隧道内请求超时", false
	}
	return "", "隧道内请求失败（DNS 或被出口拒绝）", false
}

// fetchLiteral 在隧道里直连 IP 字面量的 trace 端点，绕开 DNS。
func (s *ipStack) fetchLiteral(ctx context.Context, timeout time.Duration) (string, bool) {
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		DialContext: func(dctx context.Context, _, addr string) (net.Conn, error) {
			// addr 是 URL 里的 host:port；traceIPURLs 全是 IP 字面量，
			// 所以这里不会触发解析。
			return s.tnet.DialContext(dctx, "tcp", addr)
		},
	}}
	for _, u := range traceIPURLs {
		if body, ok := fetchMeta(ctx, client, u); ok {
			return body, true
		}
	}
	return "", false
}

func (s *ipStack) speedTest(ctx context.Context) (float64, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, speedTimeout)
	defer cancel()
	if !resolveMetaAddr(reqCtx, s.tnet) {
		return 0, false
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, speedURL, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("Referer", metaReferer)

	s.client.Timeout = speedTimeout
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	return sampleThroughput(resp.Body)
}

func sampleThroughput(body io.Reader) (float64, bool) {
	buf := make([]byte, 64<<10)
	var got int64
	var start time.Time
	for {
		n, err := body.Read(buf)
		got += int64(n)
		if start.IsZero() && got >= speedWarmupBytes {
			got, start = 0, time.Now()
		}
		if err != nil {
			break
		}
		if !start.IsZero() && time.Since(start) >= speedSample {
			break
		}
	}
	if start.IsZero() || got == 0 {
		return 0, false
	}
	return mbits(got, time.Since(start)), true
}

func mbits(bytes int64, d time.Duration) float64 {
	if d <= 0 || bytes <= 0 {
		return 0
	}
	return float64(bytes) * 8 / 1e6 / d.Seconds()
}

var metaAddr atomic.Pointer[string]

func metaDialAddr() string {
	if p := metaAddr.Load(); p != nil {
		return *p
	}
	return ""
}

// Resolved through the tunnel, not on the host: a host resolver can answer with
// an address that only routes outside the tunnel. The first worker to get
// through fills it in for the rest of the run. Deliberately not under a lock:
// on a network where the lookup fails, workers holding one would time out one
// after another instead of all at once.
func resolveMetaAddr(ctx context.Context, tnet *netstack.Net) bool {
	if metaAddr.Load() != nil {
		return true
	}
	ips, err := tnet.LookupContextHost(ctx, metaHost)
	if err != nil || len(ips) == 0 {
		return false
	}
	addr := net.JoinHostPort(preferV4(ips), "443")
	metaAddr.CompareAndSwap(nil, &addr)
	return true
}

// The tunnel carries both families, but the meta fetch stays on v4
func preferV4(ips []string) string {
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			return ip
		}
	}
	return ips[0]
}

// The netstack resolver is a separate knob from the ping destination: -ping-target
// moves what TUN PING measures to, not where the tunnel resolves names.
const tunnelDNS = "1.1.1.1"

// pingTarget is set from -ping-target (flags.go) before any tunnel runs and may be
// a hostname, which pingDst resolves inside the tunnel for the reason
// resolveMetaAddr resolves metaHost: a host resolver can answer with an address
// that only routes outside the tunnel.
var (
	pingTarget = tunnelDNS
	pingAddr   atomic.Pointer[netip.Addr]
)

func pingDst(tnet *netstack.Net, timeout time.Duration) (netip.Addr, bool) {
	if a := pingAddr.Load(); a != nil {
		return *a, true
	}
	if a, err := netip.ParseAddr(pingTarget); err == nil {
		pingAddr.CompareAndSwap(nil, &a)
		return a, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := tnet.LookupContextHost(ctx, pingTarget)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(preferV4(ips))
	if err != nil {
		return netip.Addr{}, false
	}
	pingAddr.CompareAndSwap(nil, &a)
	return a, true
}

// The name plus what it resolved to: only the address explains the number next to
// it, and an unresolved name explains a whole column of 100% loss.
func pingTargetLabel() string {
	if a := pingAddr.Load(); a != nil && a.String() != pingTarget {
		return fmt.Sprintf("%s (%s)", pingTarget, a)
	}
	if _, err := netip.ParseAddr(pingTarget); err != nil {
		return pingTarget + " (unresolved)"
	}
	return pingTarget
}

const (
	pingInterval    = 200 * time.Millisecond
	durabilityPings = 10
	// torn down = the tunnel passes data and is then cut mid-stream, never recovering,
	// i.e. a trailing run of dropped pings. Sporadic single drops are loss, not a teardown, so we
	// key off a run of consecutive tail failures rather than a loss percentage.
	tornTailFails = 3
	// A burst of tornTailFails echoes technically fits a tail run, but with no
	// margin at all for a single stray drop:
	// measured 13 of 70 dead wg peers reported as working at 3 echoes, none at 10.
	minDurabilityPings = 5
)

// Echoes are spread over time to give DPI traffic to react to, but replies are
// matched by sequence in a shared window: a reply merely delayed by a contended
// netstack (many userspace tunnels at once) still counts instead of scoring as
// a loss.
func (s *ipStack) tunnelPing(count int, timeout time.Duration) (time.Duration, float32, bool) {
	dst, ok := pingDst(s.tnet, timeout)
	if !ok {
		return 0, 1, false
	}
	pc, err := s.tnet.DialPingAddr(netip.Addr{}, dst)
	if err != nil {
		return 0, 1, false
	}
	defer pc.Close()

	sent := make([]time.Time, count)
	got := make([]bool, count)
	buf := make([]byte, 1500)
	n := 0
	var total time.Duration

	drain := func(deadline time.Time) {
		for n < count {
			pc.SetReadDeadline(deadline)
			m, err := pc.Read(buf)
			if err != nil {
				return
			}
			seq, ok := parseEchoSeq(buf[:m])
			if !ok || seq < 0 || seq >= count || got[seq] || sent[seq].IsZero() {
				continue
			}
			got[seq] = true
			total += time.Since(sent[seq])
			n++
		}
	}

	for seq := 0; seq < count; seq++ {
		if s.sendEcho(pc, seq) {
			sent[seq] = time.Now()
		}
		drain(time.Now().Add(pingInterval))
	}
	drain(time.Now().Add(timeout)) // final window for stragglers before scoring loss

	return pingSummary(total, n), lossFraction(n, count), teardown(got)
}

func (s *ipStack) sendEcho(pc *netstack.PingConn, seq int) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0xbeef, Seq: seq, Data: []byte("warpscout")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	_, err = pc.Write(wire)
	return err == nil
}

func parseEchoSeq(b []byte) (int, bool) {
	m, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), b)
	if err != nil {
		return 0, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok || m.Type != ipv4.ICMPTypeEchoReply {
		return 0, false
	}
	return echo.Seq, true
}

func pingSummary(total time.Duration, got int) time.Duration {
	if got == 0 {
		return 0
	}
	return total / time.Duration(got)
}

func lossFraction(got, count int) float32 {
	if count == 0 {
		return 0
	}
	return float32(count-got) / float32(count)
}

// A trailing run of at least tornTailFails unanswered echoes means the tunnel
// stopped passing traffic and did not come back.
func teardown(results []bool) bool {
	if len(results) < tornTailFails {
		return false
	}
	for _, ok := range results[len(results)-tornTailFails:] {
		if ok {
			return false
		}
	}
	return true
}

// A live endpoint answers in one RTT, so a flat 50ms poll spent most of its wait
// on an already-finished handshake. The poll starts short and backs off: an
// IpcGet is 2.9us (measured), so the extra early polls cost nothing, while a
// dead endpoint still ends up polling rarely until -timeout.
const (
	handshakePollStart = 2 * time.Millisecond
	handshakePollMax   = 50 * time.Millisecond
)

func waitHandshake(ctx context.Context, dev *device.Device, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	wait := handshakePollStart
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		conf, err := dev.IpcGet()
		if err == nil && handshakeDone(conf) {
			return true
		}
		time.Sleep(wait)
		if wait < handshakePollMax {
			wait *= 2
		}
	}
	return false
}

const handshakeKey = "last_handshake_time_sec="

func handshakeDone(conf string) bool {
	i := strings.Index(conf, handshakeKey)
	if i < 0 {
		return false
	}
	v := i + len(handshakeKey)
	return v < len(conf) && conf[v] != '0'
}
