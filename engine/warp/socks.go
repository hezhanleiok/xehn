package warp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	netstack "github.com/xhwarp/android-engine/warp/netstackx"
)

const (
	defaultSocksListen = "127.0.0.1"
	defaultSocksPort   = 1080
	socksTestingNote   = "For testing purposes ONLY."
)

func fetchExit(ctx context.Context, tn tunnel, timeout time.Duration) (metaResult, bool) {
	body, ok := tn.stack().fetch(ctx, timeout)
	if !ok {
		return metaResult{}, false
	}
	return parseMeta(body), true
}

// The warning comes before the address on purpose: the address is what gets
// copied, so the reader has to pass the caveat to reach it.

const (
	socksVersion  = 5
	socksNoAuth   = 0
	socksConnect  = 1
	socksOK       = 0
	socksRefused  = 5
	socksBadCmd   = 7
	socksIPv4     = 1
	socksDomain   = 3
	socksIPv6     = 4
	socksPortSize = 2
	// Not -timeout: that one bounds a handshake on a direct path, while this covers
	// the in-tunnel DNS lookup plus a TCP connect, both of which are slow through a
	// nested tunnel.
	socksDialTimeout = 10 * time.Second
)

func serveSOCKS(ctx context.Context, c net.Conn, tnet *netstack.Net, rules *RuleSet) {
	defer c.Close()
	target, err := socksHandshake(c)
	if err != nil {
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, socksDialTimeout)
	defer cancel()

	// 分流：命中 direct 的连接**不进隧道**，用本机的网络栈直接拨。
	//
	// 这里是整个 App 里唯一能按域名分流的地方：SOCKS5 请求带的是域名，
	// 而 VPN 模式只看得到 IP（见 docs/connection-modes-and-rules.md）。
	host, _, _ := net.SplitHostPort(target)
	var ip netip.Addr
	if a, perr := netip.ParseAddr(host); perr == nil {
		ip = a
	}
	if rules.Decide(host, ip) == ActionDirect {
		if dialDirect(dialCtx, c, target) {
			return
		}
		return
	}

	target, err = resolveInTunnel(dialCtx, tnet, target)
	if err != nil {
		socksReply(c, socksRefused)
		return
	}
	remote, err := tnet.DialContext(dialCtx, "tcp", target)
	if err != nil {
		socksReply(c, socksRefused)
		return
	}
	defer remote.Close()
	if err := socksReply(c, socksOK); err != nil {
		return
	}
	pipeBoth(c, remote)
}

// pipeBoth 在两个连接之间双向转发。
//
// 不用裸 io.Copy：它是 32 KB 缓冲、而且完全不碰 TCP_NODELAY。Psiphon 的上游就是
// 走这个 SOCKS（一条 OSSH TCP 穿过去），32 KB 的小缓冲 + Nagle 会把高 RTT 链路上
// 的吞吐压得很低 —— 用户反馈「赛风能用但只有 2 Mbps」有这一份。
func pipeBoth(a, b net.Conn) {
	if ta, ok := a.(interface{ SetNoDelay(bool) error }); ok {
		_ = ta.SetNoDelay(true)
	}
	if tb, ok := b.(interface{ SetNoDelay(bool) error }); ok {
		_ = tb.SetNoDelay(true)
	}
	go copyStream(b, a)
	copyStream(a, b)
}

func copyStream(dst, src net.Conn) {
	buf := make([]byte, 128<<10)
	_, _ = io.CopyBuffer(dst, src, buf)
}

// dialDirect 用本机网络（不进隧道）连目标并把两条连接对接起来。
// 返回 true 表示已经处理完（调用方直接 return）；false 表示应该回 SOCKS 失败。
func dialDirect(ctx context.Context, c net.Conn, target string) bool {
	d := &net.Dialer{}
	remote, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		socksReply(c, socksRefused)
		return true
	}
	defer remote.Close()
	if err := socksReply(c, socksOK); err != nil {
		return true
	}
	pipeBoth(c, remote)
	return true
}

// Resolved inside the tunnel, never on the host: a host lookup would leak the
// query onto the very network this command exists to bypass, and it answers with
// addresses picked for the host's own region. The v4 answer is taken for the same
// reason the meta fetch takes it - and, nested, because netstack tries the
// addresses in order with a share of the deadline each, so an IPv6 answer that
// does not pass eats the budget the working v4 one needed.
func resolveInTunnel(ctx context.Context, tnet *netstack.Net, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return target, nil
	}
	ips, err := tnet.LookupContextHost(ctx, host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no address for %s", host)
	}
	return net.JoinHostPort(preferV4(ips), port), nil
}

// No authentication and CONNECT only: no consumer of this command uses BIND or
// UDP ASSOCIATE.
func socksHandshake(rw io.ReadWriter) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(rw, head); err != nil {
		return "", err
	}
	if head[0] != socksVersion {
		return "", fmt.Errorf("socks version %d", head[0])
	}
	if _, err := io.ReadFull(rw, make([]byte, head[1])); err != nil {
		return "", err
	}
	if _, err := rw.Write([]byte{socksVersion, socksNoAuth}); err != nil {
		return "", err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(rw, req); err != nil {
		return "", err
	}
	if req[0] != socksVersion {
		return "", fmt.Errorf("socks version %d", req[0])
	}
	if req[1] != socksConnect {
		socksReply(rw, socksBadCmd)
		return "", fmt.Errorf("socks command %d is not CONNECT", req[1])
	}

	host, err := socksAddr(rw, req[3])
	if err != nil {
		return "", err
	}
	port := make([]byte, socksPortSize)
	if _, err := io.ReadFull(rw, port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), nil
}

func socksAddr(r io.Reader, atyp byte) (string, error) {
	n := 0
	switch atyp {
	case socksIPv4:
		n = 4
	case socksIPv6:
		n = 16
	case socksDomain:
		size := make([]byte, 1)
		if _, err := io.ReadFull(r, size); err != nil {
			return "", err
		}
		n = int(size[0])
	default:
		return "", fmt.Errorf("socks address type %d", atyp)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	if atyp == socksDomain {
		return string(buf), nil
	}
	addr, ok := netip.AddrFromSlice(buf)
	if !ok {
		return "", fmt.Errorf("socks address of %d bytes", n)
	}
	return addr.String(), nil
}

// The bound address is what the client is told, and no client of a CONNECT-only
// proxy reads it, so the all-zero IPv4 placeholder stands in for it.
func socksReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socksVersion, rep, 0, socksIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
