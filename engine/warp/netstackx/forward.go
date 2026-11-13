//go:build android

// gVisor 的 tcp/udp forwarder 依赖 pkg/errors/linuxerr，而它只在 unix 平台可编译
// （unix.Errno）。本项目只在 Android 上需要 tun2socks，其余平台走 stub。

package netstack

import (
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// CreateNetTUNForwarding 建一个「接受任意入站连接」的栈 —— 也就是 tun2socks。
//
// 为什么需要它（2026-11-13 真机日志）：mihomo 自带的 tun 在 Android 上会去读
// `/data/system/packages.xml` 生成 UID 分应用规则，非 root 必然
// `permission denied`，而 sing-tun 那里**返回 error 而不是降级** —— 于是
// `Start TUN listening error`，数据面整个不存在（表现为「已连接、0 B/s」）。
// 所以 tun 归我们自己读，mihomo 只当代理内核（mixed-port 入站）。
func CreateNetTUNForwarding(
	localAddresses, dnsServers []netip.Addr, mtu, maxBuffer int, h ForwardHandlers,
) (tun.Device, *Net, error) {
	dev, tnet, err := CreateNetTUNBuffered(localAddresses, dnsServers, mtu, maxBuffer)
	if err != nil {
		return nil, nil, err
	}
	nt, ok := dev.(*netTun)
	if !ok {
		return dev, tnet, nil
	}
	// **tun2socks 的命门（三件套，缺一个就是「连上了、0 流量」）**：
	//
	//  1. 默认路由表：wireguard 的 netstack 只给「本机地址」加了路由，注入的包
	//     目的地址是任意外网 IP，查不到路由 → IP 层直接丢，一个字节都到不了
	//     forwarder。sing-tun 的 `NewGVisorStackWithOptions` 第一件事就是
	//     SetRouteTable(0.0.0.0/0 + ::/0)，我们漏了这一步（2026-11-13 真机：
	//     mihomo 起来了、mixed-port 在听、日志里 [TCP] 一条都没有）。
	//  2. Spoofing：允许 endpoint 用非本机地址做源/目的。
	//  3. PromiscuousMode：NIC 不做地址过滤。
	nt.stack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	nt.stack.SetSpoofing(1, true)
	nt.stack.SetPromiscuousMode(1, true)
	if h.DialTCP != nil {
		tcpFwd := tcp.NewForwarder(nt.stack, 0, 2048, func(r *tcp.ForwarderRequest) {
			id := r.ID()
			dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
			go forwardTCP(r, dst, h.DialTCP)
		})
		nt.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	}
	if h.DialUDP != nil {
		udpFwd := udp.NewForwarder(nt.stack, func(r *udp.ForwarderRequest) bool {
			id := r.ID()
			dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
			go forwardUDP(r, dst, h.DialUDP)
			return true
		})
		nt.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	}
	return dev, tnet, nil
}

func forwardTCP(r *tcp.ForwarderRequest, dst string, dial func(string) (net.Conn, error)) {
	up, err := dial(dst)
	if err != nil {
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		_ = up.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)
	defer local.Close()
	defer up.Close()
	go func() { _, _ = io.Copy(up, local) }()
	_, _ = io.Copy(local, up)
}

func forwardUDP(r *udp.ForwarderRequest, dst string, dial func(string) (net.PacketConn, error)) {
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	local := gonet.NewUDPConn(&wq, ep)
	defer local.Close()
	up, err := dial(dst)
	if err != nil {
		return
	}
	defer up.Close()
	go pipeUDP(local, up)
	pipeUDP(up, local)
}

func pipeUDP(dst, src net.PacketConn) {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := src.ReadFrom(buf)
		if n > 0 {
			_, _ = dst.WriteTo(buf[:n], addr)
		}
		if err != nil {
			return
		}
	}
}


