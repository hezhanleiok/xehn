package warp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	netstack "github.com/xhwarp/android-engine/warp/netstackx"
)

// MASQUEX2：MASQUE(HTTP/3) 套 MASQUE(HTTP/3)。
//
// 结构和 WARP-in-WARP（nest.go）一样，只是把「内层 WireGuard 的 UDP」换成
// 「内层 MASQUE 的 QUIC/UDP」：
//
//	系统 tun fd ──▶ 内层 MASQUE(CONNECT-IP, H3) ──QUIC/UDP──▶ 外层 MASQUE(CONNECT-IP, H3) ──▶ CF 边缘
//	                                   ▲
//	                         socket 开在外层隧道的 netstack 里
//
// 两个关键点：
//
//  1. **外层必须是另一套设备**。Cloudflare 会丢掉「同一设备嵌套自己」的流量，
//     WARP-in-WARP 踩过这个坑（见 nest.go 的 outerAcct），这里同理：
//     masqueOuterCredsFile 存的是第二套 masque 设备的凭据。
//
//  2. **外层 MTU 必须比内层大**。QUIC 规定客户端 Initial 包至少 1200 字节，所以
//     内层写进外层隧道的 IP 包约 1228 字节；外层若也按 1200 的 tun MTU 封装，
//     转成 CONNECT-IP DATAGRAM 后必然超限被静默丢弃（那是「握手成功、什么都不能
//     访问」的典型现场）。所以外层单独用 masqueX2OuterMTU(1400)——代价是外层
//     只能走 v4 路径（v6 路径 MTU 1280 塞不下），见下面对 o.IPv6 的处理。
const (
	// 外层隧道的 MTU。
	//
	// 这个值必须同时满足两件事：
	//   1. 装得下内层写进来的 IP 包：内层 QUIC 的 Initial 包 1200 字节（QUIC 规定
	//      的最小值）+ UDP 8 + IP 20 ≈ 1228；
	//   2. 外层自己封装后不超路径 MTU：外层 CONNECT-IP datagram ≈ MTU+60，
	//      手机网络（v4）的路径 MTU 常在 1400 左右。
	// 1300 → wire ≈1360，两边都留了余量。Aether 的实现里对应值是 1350（quiche
	// 的 MAX_DATAGRAM_SIZE），同一量级。
	//
	// 2026-11-07 真机教训：之前取 1400，wire 1460 已经压到很多移动网络的
	// 1400 路径 MTU 之上，结果外层的 8 个候选全部「已建立 CONNECT-IP、数据面不通」。
	masqueX2OuterMTU = 1300
)

// masqueNestState 是「内层 QUIC 的 socket 应该开在哪里」。
//
// 用包级 atomic 指针而不是参数透传：真正的 socket 是在 masque.go 的
// dialConnectIP 里开的，那里已经有一堆参数（tls/quic/endpoint/h2），再塞一个
// 可选载体只会让单层路径也被污染。单层拨号时它是 nil，行为与以前完全一致。
type masqueNestState struct {
	tnet *netstack.Net
	v4   netip.Addr
	v6   netip.Addr
}

var masqueNest atomic.Pointer[masqueNestState]

// masqueOuterCredsFile 是外层 MASQUE 设备凭据的存放路径（由 Config 注入）。
var masqueOuterCredsFile string

// dialUDP 在外层隧道的 netstack 里开一个连到 remote 的 UDP socket，
// 并包装成 quic.Transport 需要的 net.PacketConn。
func (n *masqueNestState) dialUDP(remote *net.UDPAddr) (net.PacketConn, error) {
	if n == nil || n.tnet == nil {
		return nil, fmt.Errorf("MASQUEX2 外层隧道不可用")
	}
	ip, ok := netip.AddrFromSlice(remote.IP)
	if !ok {
		return nil, fmt.Errorf("MASQUEX2 端点地址无效: %v", remote.IP)
	}
	raddr := netip.AddrPortFrom(ip.Unmap(), uint16(remote.Port))

	// 外层设备同时有 v4/v6 地址：用与端点同族的那一个，否则 gVisor 选不出路由
	// （绑 0.0.0.0 时每一次发送都会报 "network is unreachable"）。
	local := n.v4
	if raddr.Addr().Is6() {
		local = n.v6
	}
	if !local.IsValid() || local.Is6() != raddr.Addr().Is6() {
		return nil, fmt.Errorf("MASQUEX2 外层设备缺少 %s 地址，无法承载内层端点 %s",
			famName(raddr.Addr().Is6()), raddr)
	}

	c, err := n.tnet.DialUDPAddrPort(netip.AddrPortFrom(local, 0), raddr)
	if err != nil {
		return nil, fmt.Errorf("在外层隧道里开 UDP socket: %w", err)
	}
	return &netstackPacketConn{c: c, remote: remote}, nil
}

// netstackPacketConn 把「已连接的 net.Conn」伪装成 net.PacketConn。
//
// quic.Transport 只会用 WriteTo/ReadFrom 收发（它要支持一个 socket 对多个对端），
// 而 gVisor 的 DialUDP 是已连接的 socket：地址部分直接忽略/回填即可。
type netstackPacketConn struct {
	c      net.Conn
	remote net.Addr
}

func (p *netstackPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.c.Read(b)
	return n, p.remote, err
}

func (p *netstackPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.c.Write(b)
}

func (p *netstackPacketConn) Close() error                       { return p.c.Close() }
func (p *netstackPacketConn) LocalAddr() net.Addr                { return p.c.LocalAddr() }
func (p *netstackPacketConn) SetDeadline(t time.Time) error      { return p.c.SetDeadline(t) }
func (p *netstackPacketConn) SetReadDeadline(t time.Time) error  { return p.c.SetReadDeadline(t) }
func (p *netstackPacketConn) SetWriteDeadline(t time.Time) error { return p.c.SetWriteDeadline(t) }

// dialMasqueX2 是 masque-x2 的拨号入口：先拨外层（netstack、另一套设备），
// 再把内层 MASQUE 的 QUIC socket 塞进外层隧道。
func dialMasqueX2(ctx context.Context, o Options) (*Session, error) {
	// 外层要装下内层 1200 字节的 QUIC 初始包，v6 路径 MTU 1280 不够。
	// 不直接失败：v4 端点照样能用，把限制说清楚即可。
	if o.IPv6 {
		o.report("提示：MASQUEX2 的外层走 v6 时路径 MTU 只有 1280，可能装不下内层的 QUIC 初始包；连不上就把 IPv6 关掉")
	}

	// ---- 1) 外层：第二套 MASQUE 设备 ----
	savedAcct := masqueAcct
	savedCreds := masqueCredsFile
	masqueAcct = nil
	if masqueOuterCredsFile != "" {
		masqueCredsFile = masqueOuterCredsFile
	} else {
		// 没有第二套设备的落盘位置就只能共用主设备。功能上能拨通，但
		// Cloudflare 对「同一设备嵌套自己」的流量有丢弃策略（WARP-in-WARP 的
		// outerAcct 注释里记过同一件事），所以必须说出来。
		o.report("提示：没有配置外层设备凭据路径，MASQUEX2 的内外层共用同一台设备（可能被服务端丢弃）")
	}

	outerOpts := o
	outerOpts.Proto = protoMASQUE // 外层固定 H3（h2 是 TCP，做不了 UDP 载体）
	outerOpts.MTU = masqueX2OuterMTU
	outerOpts.SocksListen = ""
	outerOpts.SocksRequired = false
	// 外层只当载体，不需要上行并行（它自己就是被内层用的那一条）。
	outerOpts.NoParallelUplink = true
	// 外层只走 v4：v6 路径 MTU 1280 装不下「内层 1228 的 IP 包 + 外层封装」。
	// 2026-11-07 真机日志：外层候选混进 v6 时 8 轮全部「已建立 CONNECT-IP、
	// 数据面不通」——握手能过，数据包全超 MTU 被丢。
	outerOpts.IPv6 = false
	// 外层只用一半预算，别把内层的预算吃光。
	if outerOpts.Budget > 0 {
		outerOpts.Budget = max(20*time.Second, outerOpts.Budget/2)
	}

	// 外层只跑在进程内 netstack 里：系统 tun fd 归内层 MASQUE 使用。
	savedFD := tunFD
	tunFD = 0
	o.report("MASQUEX2：先拨外层 MASQUE(HTTP/3)…")
	outer, err := dialMasque(ctx, outerOpts)
	tunFD = savedFD
	if err != nil {
		masqueCredsFile = savedCreds
		masqueAcct = savedAcct
		return nil, fmt.Errorf("MASQUEX2 外层失败: %w", err)
	}
	// 此刻 masqueAcct 是外层设备：把它的地址留下来给内层 socket 绑定用。
	outerAcc := masqueAcct

	// ---- 2) 内层：主设备 + 系统 tun ----
	masqueCredsFile = savedCreds
	masqueAcct = savedAcct

	if outer.tn == nil || outer.tn.stack() == nil {
		outer.Close()
		return nil, fmt.Errorf("MASQUEX2 外层没有 netstack（数据面必须是进程内）")
	}
	nestState := &masqueNestState{tnet: outer.tn.stack().tnet}
	if outerAcc != nil {
		if a, perr := netip.ParseAddr(outerAcc.IPv4); perr == nil {
			nestState.v4 = a.Unmap()
		}
		if a, perr := netip.ParseAddr(outerAcc.IPv6); perr == nil {
			nestState.v6 = a
		}
	}
	if !nestState.v4.IsValid() && !nestState.v6.IsValid() {
		outer.Close()
		return nil, fmt.Errorf("MASQUEX2 外层设备没有任何接口地址")
	}

	masqueNest.Store(nestState)
	// 内层拨完就摘掉：之后建立的单层会话不能把 socket 开进这条外层隧道。
	defer masqueNest.Store(nil)

	o.report(fmt.Sprintf("外层 MASQUE 已就绪（%s），在内层 MASQUE 上选点…", outer.Endpoint))
	inner := o
	inner.Proto = protoMASQUE
	inner.MTU = 0
	// 内层的所有会话都挤在外层那一条隧道里：多开只会三条 QUIC 抢外层一个拥塞窗口。
	inner.NoParallelUplink = true
	s, err := dialMasque(ctx, inner)
	if err != nil {
		outer.Close()
		return nil, fmt.Errorf("MASQUEX2 内层失败: %w", err)
	}

	// 外层隧道的生命周期跟着内层会话走（Session.Close 会一并回收）。
	local := nestState.v4
	if !local.IsValid() {
		local = nestState.v6
	}
	s.outer = &nest{
		tunnel:   outer.tn,
		net:      nestState.tnet,
		local:    local,
		endpoint: outer.Endpoint,
	}
	o.report(fmt.Sprintf("MASQUEX2 已建立：内层出口 %s (%s)，外层 %s",
		s.ExitIP, s.Country, outer.Endpoint))
	return s, nil
}
