package warp

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/conn"
)

// SO_BINDTODEVICE rather than a source-IP bind, which cannot route traffic into
// a tun.
type deviceBind struct {
	iface string
	conn  *net.UDPConn
}

type sourceEndpoint struct{ dst netip.AddrPort }

func newDeviceBind(iface string) *deviceBind { return &deviceBind{iface: iface} }

func (b *deviceBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	var lc net.ListenConfig
	// Two hooks on the same socket, and both have to run at creation time:
	// deviceControl pins it to an interface (desktop -I), protectControl keeps
	// the Android system VPN from swallowing the tunnel's own transport.
	lc.Control = func(network, address string, c syscall.RawConn) error {
		if b.iface != "" {
			if err := deviceControl(b.iface, 0)(network, address, c); err != nil {
				return err
			}
		}
		return protectControl(c)
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", net.JoinHostPort("", strconv.Itoa(int(port))))
	if err != nil {
		return nil, 0, err
	}
	c := pc.(*net.UDPConn)
	tuneUDPBuffers(c)
	b.conn = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

// tuneUDPBuffers 把隧道 UDP socket 的内核收发缓冲拉大。
//
// 这是 WG/AWG 下行吞吐最便宜的一处提升：Android 给 UDP socket 的默认 rmem 只有
// 200 KB 量级，而这条 socket 要同时装「下行的全部密文包」。手机基带突发下行
// （几百 Mbps 的瞬时 burst）几百毫秒就能把它填满，之后内核直接丢包 —— 丢了就是
// wireguard-go 看到的重传，走的是 TCP 拥塞退避，用户看到的是「速度上不去、还抖」。
// 缓冲设大以后同一段突发能先存住再慢慢处理。
//
// 拿不到更大值时不报错：非 root 最多只能到 net.core.rmem_max，按系统上限跑即可。
func tuneUDPBuffers(c *net.UDPConn) {
	const want = 8 << 20
	for _, sz := range []int{want, 4 << 20, 1 << 20} {
		if err := c.SetReadBuffer(sz); err == nil {
			break
		}
	}
	// 发送侧不需要那么大（上行突发小得多），但 4 MB 足够吸收积压。
	for _, sz := range []int{4 << 20, 1 << 20} {
		if err := c.SetWriteBuffer(sz); err == nil {
			break
		}
	}
}

func (b *deviceBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	n, addr, err := b.conn.ReadFromUDPAddrPort(bufs[0])
	if err != nil {
		// The only expected read error is the socket being closed; treat any as terminal
		// so the device's receive goroutine exits cleanly, as the Bind contract requires.
		return 0, net.ErrClosed
	}
	sizes[0] = n
	eps[0] = &sourceEndpoint{dst: addr}
	return 1, nil
}

func (b *deviceBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst := ep.(*sourceEndpoint).dst
	for _, buf := range bufs {
		if _, err := b.conn.WriteToUDPAddrPort(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *deviceBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &sourceEndpoint{dst: addr}, nil
}

func (b *deviceBind) Close() error {
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *deviceBind) SetMark(uint32) error { return nil }

func (b *deviceBind) BatchSize() int { return 1 }

func (e *sourceEndpoint) ClearSrc()           {}
func (e *sourceEndpoint) SrcToString() string { return "" }
func (e *sourceEndpoint) DstToString() string { return e.dst.String() }
func (e *sourceEndpoint) DstToBytes() []byte  { b, _ := e.dst.MarshalBinary(); return b }
func (e *sourceEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *sourceEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
