package warp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// WARP-in-WARP（协议名 wwarp）：一条 WARP 隧道套在另一条 WARP 隧道里。
//
// 为什么不是简单的两个 WG 对撞：Cloudflare 会丢掉「同一个设备嵌套自己」的
// 流量，所以外层必须是一套独立的设备（outerAcct）；内层用主账号。数据面是
// 把内层 WireGuard 的 UDP socket 塞进外层隧道的 netstack（tunnelBind），于是
// 内层握手/数据都作为外层隧道里的普通 UDP 传输，外层连上 = 内层直连外网。

// outer 是当前会话的外层隧道。Dial 分派到 wwarp 后先在此进程里拨一条普通
// WG/AWG 隧道（只跑在 netstack 里，作为内层 UDP 的载体），再把指针挂到这里；
// newWGTunnel 一看到 outer 非 nil，就把内层隧道的 bind 从「主机 socket」换成
// 「跑在外层 netstack 里的 socket」。
var outer *nest

// outerAcct 是第二套 WARP 设备，由 ensureOuterAccount 登记/加载后挂到这里。
var outerAcct *account

// 外层账号凭据文件路径，由 Config 注入（和 WG 主账号、MASQUE 分开存）。
var outerCredsFile string

type nest struct {
	tunnel tunnel
	net    *netstack.Net
	// 外层设备自己的地址，不是主账号地址：tunnelBind 打开的 socket 跑在外层
	// 隧道里，必须绑到外层隧道真正持有的地址上。
	local    netip.Addr
	endpoint string
}

// 内层 WireGuard 包作为 UDP 走在外层隧道里，要给外层封装留 MTU：
// 20 IP + 8 UDP + 16 WireGuard 头 + 16 Poly1305 标签 = 60。
// 设太高会「握手成功、数据静默死亡」。
const nestedOverhead = 60

// withOuterKeys 把账号全局临时切成外层设备：baseUAPI / peerUAPI / newIPStack
// 都读这些包级变量，所以外层隧道的 key 与地址就用外层设备；fn 返回后立刻
// 恢复主账号，后续内层隧道仍跑在主账号上。
func withOuterKeys(fn func() error) error {
	if outerAcct == nil {
		return fmt.Errorf("没有外层账号（WARP-in-WARP 需要第二套设备）")
	}
	priv, pub, v4, v6 := warpPrivateKey, warpPublicKey, warpAddress, warpAddressV6
	warpPrivateKey, warpPublicKey = outerAcct.PrivateKey, outerAcct.PeerPublicKey
	if outerAcct.IPv4 != "" {
		warpAddress = outerAcct.IPv4
	}
	if outerAcct.IPv6 != "" {
		warpAddressV6 = outerAcct.IPv6
	}
	defer func() {
		warpPrivateKey, warpPublicKey, warpAddress, warpAddressV6 = priv, pub, v4, v6
	}()
	return fn()
}

// ensureOuterAccount 拿一套可用的外层设备：优先读缓存，否则现登记一个普通
// WARP 设备。跟 MASQUE 一样要走 regTransport（它的 Control 钩子挂了 protect），
// 否则系统 VPN 起来后这些请求会被自己的 tun 吞掉。
func ensureOuterAccount(ctx context.Context, o Options) (*account, error) {
	if outerCredsFile != "" {
		if a, err := loadAccount(outerCredsFile); err == nil && a.PrivateKey != "" && a.PeerPublicKey != "" {
			o.report("复用已登记的外层设备")
			return &a, nil
		}
	}
	o.report("登记外层设备（WARP-in-WARP 需要第二套账号）…")
	client := &http.Client{Timeout: registerTimeout, Transport: regTransport(nil)}
	a, err := registerWARP(ctx, client)
	if err != nil {
		return nil, err
	}
	if outerCredsFile != "" {
		_ = os.MkdirAll(filepath.Dir(outerCredsFile), 0o755)
		if serr := saveAccount(outerCredsFile, a); serr != nil {
			o.report(fmt.Sprintf("警告：外层设备保存失败（下次会重新登记）：%v", serr))
		}
	}
	return &a, nil
}

// dialOuter 拨外层隧道并返回一个挂好的 nest。外层只是载体，不进系统 tun：
// 这里临时把 tunFD 清成 0 强制走 netstack，建完再恢复，内层隧道仍按调用方
// 的 tunFD 决定数据面。
func dialOuter(ctx context.Context, o Options) (*nest, error) {
	acct, err := ensureOuterAccount(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("外层账号: %w", err)
	}
	outerAcct = acct

	outerProto := o.ThroughProto
	if outerProto == "" {
		outerProto = protoWG
	}
	run, err := parseProto(outerProto)
	if err != nil || run.isMASQUE() {
		if err == nil && run.isMASQUE() {
			err = fmt.Errorf("外层协议不能是 MASQUE")
		}
		outerAcct = nil
		return nil, err
	}

	savedFD := tunFD
	outer = nil // 建外层本身时，它不是「内层」，bind 必须用主机 socket
	tunFD = 0
	var tn tunnel
	err = withOuterKeys(func() error {
		t, err := newTunnel(run)
		tn = t
		return err
	})
	tunFD = savedFD
	if err != nil {
		outerAcct = nil
		return nil, fmt.Errorf("外层隧道初始化: %w", err)
	}

	// 外层端点：钉了 Through 就只试它，否则按 v4/v6 偏好从池子里选。
	outerOpts := o
	outerOpts.Endpoint = o.Through
	cands, err := candidates(outerOpts)
	if err != nil {
		tn.Close()
		outerAcct = nil
		return nil, err
	}
	for _, port := range tn.ports() {
		for _, ip := range cands {
			if ctx.Err() != nil {
				tn.Close()
				outerAcct = nil
				return nil, ctx.Err()
			}
			ep := net.JoinHostPort(ip.String(), strconv.Itoa(port))
			if !tn.handshake(ctx, ep, o.HandshakeTimeout) {
				continue
			}
			// 外层必须**真的能过数据**，否则内层的 UDP 全部丢进黑洞：表现是内层
			// 把候选试满、每个都卡到握手超时（实测就是这样，日志里外层「已上线」，
			// 内层 20 次尝试全超时）。「握手成功但数据面不通」的半死端点在受限网络
			// 里很常见，一定要在这里筛掉。
			//
			// 判据有两条，先强后弱：真实 HTTPS（最接近「用户能不能上网」），
			// 失败时再用隧道内 ICMP 复核 —— 某些出口会把 /meta 拒掉，那不是隧道
			// 的问题，只看第一条会把能用的外层误杀。
			outerOK := false
			if _, passed := egressProbe(ctx, tn, o.VerifyTimeout); passed {
				outerOK = true
			} else if st := tn.stack(); st != nil {
				if _, loss, _ := st.tunnelPing(4, o.VerifyTimeout); loss < 1 {
					outerOK = true
					o.report(fmt.Sprintf("外层 %s 的 /meta 被拒，但隧道内 ICMP 有回包，判为可用", ep))
				}
			}
			if !outerOK {
				o.report(fmt.Sprintf("外层 %s 握手成功但数据面不通，换下一个", ep))
				continue
			}
			localStr := acct.IPv4
			if o.IPv6 && acct.IPv6 != "" {
				localStr = acct.IPv6
			}
			local, perr := netip.ParseAddr(localStr)
			if perr != nil {
				tn.Close()
				outerAcct = nil
				return nil, fmt.Errorf("外层设备缺 %s 地址：%v", famName(o.IPv6), perr)
			}
			o.report(fmt.Sprintf("外层 %s 端点 %s 已上线", run.name, ep))
			return &nest{tunnel: tn, net: tn.stack().tnet, local: local, endpoint: ep}, nil
		}
	}
	tn.Close()
	outerAcct = nil
	return nil, fmt.Errorf("外层隧道没有可用端点")
}

// dialWWarp 是 wwarp 的拨号入口：先外层后内层。内层隧道复用 dialWGTunnel 的
// 完整「握手 + 数据面验证」流程；只有外层隧道的生命周期要跟着内层 Session 走，
// 所以在拨成功后把它挂到 Session 上，由 Session.Close 一并回收。
func dialWWarp(ctx context.Context, o Options) (*Session, error) {
	ost, err := dialOuter(ctx, o)
	if err != nil {
		return nil, err
	}
	outer = ost
	teardown := func() {
		outer = nil
		ost.tunnel.Close()
		outerAcct = nil
	}

	inner := o
	inner.Proto = o.InnerProto
	if inner.Proto == "" {
		inner.Proto = protoWG
	}
	run, err := protoRunFor(inner.Proto)
	if err != nil {
		teardown()
		return nil, err
	}
	o.report(fmt.Sprintf("外层已就绪（%s），在内层 %s 上选点…", ost.endpoint, inner.Proto))

	s, err := dialWGTunnel(ctx, inner, run)
	if err != nil {
		teardown()
		return nil, err
	}
	s.outer = ost
	return s, nil
}

// tunnelBind 是一个 conn.Bind：它的 socket 开在外层隧道的 netstack 里，而不是
// 主机上，这正是「把一条 WARP 套进另一条 WARP」的关键。形状和 deviceBind 一样，
// 区别是这里用的是 netstack 的 UDPconn（普通 net.PacketConn，没有 AddrPort 读写对）。
type tunnelBind struct {
	nest *nest
	conn net.PacketConn
}

func newTunnelBind(n *nest) *tunnelBind { return &tunnelBind{nest: n} }

func (b *tunnelBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	// 绑隧道地址而不是通配：gvisor 对绑在 0.0.0.0 的 socket 选不出路由，
	// 每一次发送都会报 "network is unreachable"。
	laddr := netip.AddrPortFrom(b.nest.local, 0)
	c, err := b.nest.net.ListenUDPAddrPort(laddr)
	if err != nil {
		return nil, 0, err
	}
	b.conn = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

func (b *tunnelBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	n, addr, err := b.conn.ReadFrom(bufs[0])
	if err != nil {
		// 与 deviceBind 同一契约：读错误结束设备接收 goroutine，唯一预期的是
		// socket 关闭（net.ErrClosed）。
		return 0, net.ErrClosed
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.ErrClosed
	}
	sizes[0] = n
	eps[0] = &sourceEndpoint{dst: ua.AddrPort()}
	return 1, nil
}

func (b *tunnelBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst := net.UDPAddrFromAddrPort(ep.(*sourceEndpoint).dst)
	for _, buf := range bufs {
		if _, err := b.conn.WriteTo(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *tunnelBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &sourceEndpoint{dst: addr}, nil
}

func (b *tunnelBind) Close() error {
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *tunnelBind) SetMark(uint32) error { return nil }

func (b *tunnelBind) BatchSize() int { return 1 }
