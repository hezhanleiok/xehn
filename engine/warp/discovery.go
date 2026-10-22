package warp

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	metaHost = "speed.cloudflare.com"
	metaURL  = "https://" + metaHost + "/meta"
	// Without a Referer the endpoint answers 403.
	metaReferer      = "https://" + metaHost
	speedURL         = "https://" + metaHost + "/__down?bytes=104857600"
	speedWarmupBytes = 1 << 20
	speedSample      = 3 * time.Second
	speedTimeout     = 20 * time.Second
	speedDrain       = 250 * time.Millisecond
	// GOGC for the speedtest phase only, see measureSpeed.
	speedGCPercent = 20
)

func fetchMeta(ctx context.Context, client *http.Client, url string) (string, bool) {
	body, err := fetchMetaErr(ctx, client, url)
	if err != nil {
		return "", false
	}
	return body, true
}

// fetchMetaErr 与 fetchMeta 相同，但把失败原因带出来。
//
// 出口验证那种「连上了但没数据」的场景里，光知道 false 没有诊断价值 ——
// 是 DNS、是超时、还是 TLS 被中间人拦，日志里必须能看出区别。
func fetchMetaErr(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Referer", metaReferer)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

const portProbeSample = 12

func haveAddrFamily(v6 bool) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if v6 == (ipn.IP.To4() == nil) {
			return true
		}
	}
	return false
}

func famName(v6 bool) string {
	if v6 {
		return "IPv6"
	}
	return "IPv4"
}

func interfaceAddr(name string, v6 bool) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() {
			continue
		}
		if v6 == (ipn.IP.To4() == nil) {
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			return ip.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %s has no %s address", name, famName(v6))
}

// One address at a time per tunnel, so the answer stays one address's port list
// rather than a mix: the first address that answers wins and cancels the rest.
// Sequentially this cost 4+50 ports x -timeout per dead address, measured at 109s
// on an address that answers nothing, times the whole sample.

const (
	pingProbes = 3
	pingID     = 0xbeef
)

func pingHost(addr netip.Addr, timeout time.Duration) (time.Duration, bool) {
	conn, dst := listenPing(addr)
	if conn == nil {
		return 0, false
	}
	defer conn.Close()

	_, replyType := icmpEchoTypes(dst)
	sent := make([]time.Time, pingProbes)
	got := make([]bool, pingProbes)
	for seq := range sent {
		if sendHostEcho(conn, dst, seq) {
			sent[seq] = time.Now()
		}
	}

	var total time.Duration
	n := 0
	buf := make([]byte, 1500)
	deadline := time.Now().Add(timeout)
	for n < pingProbes {
		conn.SetReadDeadline(deadline)
		m, peer, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if !sameHost(peer, dst) {
			continue
		}
		reply, err := icmp.ParseMessage(replyType.Protocol(), buf[:m])
		if err != nil || reply.Type != replyType {
			continue
		}
		echo, ok := reply.Body.(*icmp.Echo)
		if !ok || echo.Seq < 0 || echo.Seq >= pingProbes || got[echo.Seq] || sent[echo.Seq].IsZero() {
			continue
		}
		got[echo.Seq] = true
		total += time.Since(sent[echo.Seq])
		n++
	}
	if n == 0 {
		return 0, false
	}
	return total / time.Duration(n), true
}

func listenPing(addr netip.Addr) (*icmp.PacketConn, net.Addr) {
	udpNet, rawNet, wildcard := "udp4", "ip4:icmp", "0.0.0.0"
	if addr.Is6() {
		udpNet, rawNet, wildcard = "udp6", "ip6:ipv6-icmp", "::"
	}
	// Bind the host ping to the scan interface's address so latency is measured from
	// the same egress; fall back to the wildcard if that bind is unavailable.
	binds := []string{wildcard}
	if scanSourceIP.IsValid() && scanSourceIP.Is6() == addr.Is6() {
		binds = []string{scanSourceIP.String(), wildcard}
	}
	for _, bind := range binds {
		if conn, err := icmp.ListenPacket(udpNet, bind); err == nil {
			return conn, &net.UDPAddr{IP: addr.AsSlice()}
		}
		if conn, err := icmp.ListenPacket(rawNet, bind); err == nil {
			return conn, &net.IPAddr{IP: addr.AsSlice()}
		}
	}
	return nil, nil
}

func sendHostEcho(conn *icmp.PacketConn, dst net.Addr, seq int) bool {
	echoType, _ := icmpEchoTypes(dst)
	wire, err := (&icmp.Message{
		Type: echoType,
		Body: &icmp.Echo{ID: pingID, Seq: seq, Data: []byte("warpscout")},
	}).Marshal(nil)
	if err != nil {
		return false
	}
	_, err = conn.WriteTo(wire, dst)
	return err == nil
}

func icmpEchoTypes(dst net.Addr) (echo, reply icmp.Type) {
	if isV6Addr(dst) {
		return ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	return ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
}

func isV6Addr(dst net.Addr) bool {
	switch a := dst.(type) {
	case *net.UDPAddr:
		return a.IP.To4() == nil
	case *net.IPAddr:
		return a.IP.To4() == nil
	}
	return false
}

func sameHost(a, b net.Addr) bool {
	ipa, ipb := addrIP(a), addrIP(b)
	return ipa != nil && ipa.Equal(ipb)
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

func sampleAddrs(ips []netip.Addr, n int) []netip.Addr {
	if n <= 0 || n >= len(ips) {
		return ips
	}
	out := make([]netip.Addr, n)
	for i, j := range rand.Perm(len(ips))[:n] {
		out[i] = ips[j]
	}
	return out
}
