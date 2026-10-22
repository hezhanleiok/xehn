package warp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// traceURL is Cloudflare's plain-text echo. It is the second opinion when
// speed.cloudflare.com/meta refuses this egress, which it does for some CN
// colos - and a refused probe is not a failed tunnel, so the exit card must not
// go blank because one URL said 403.
const traceURL = "https://www.cloudflare.com/cdn-cgi/trace"

// egressProbe answers one question: does this tunnel actually carry traffic, and
// where does it come out?
//
// It is deliberately split by data plane, because "carries traffic" means two
// different things:
//
//	netstack mode - the request is dialled *inside* the tunnel by gVisor.
//	fd mode       - the request is made by the ordinary OS network stack,
//	                which routes it into our tun because VpnService said so.
//
// The fd branch is the stronger claim of the two: it fails unless the system VPN
// is really up, really routing, and really protected, which is exactly what the
// user sees on the phone.
func egressProbe(ctx context.Context, tn tunnel, timeout time.Duration) (string, bool) {
	if st := tn.stack(); st != nil {
		return st.fetch(ctx, timeout)
	}
	return fetchViaSystem(ctx, timeout)
}

// fetchViaSystem fetches the exit metadata over the normal network stack.
//
// 先强制 IPv4，拿不到再退回双栈。原因：手机是双栈时 Go 的拨号会先选 IPv6，
// Cloudflare 于是把 240e:… 那一长串回给我们，界面「本机 IP」就变成了 v6 ——
// 而用户（与运营商账单）认的是那个 IPv4。纯 v6 网络里第一步必然失败，这时
// 仍要能出数，所以保留双栈兜底，而不是把 v6 网络直接判死。
func fetchViaSystem(ctx context.Context, timeout time.Duration) (string, bool) {
	if body, ok := fetchMetaVia(ctx, timeout, "tcp4"); ok {
		return body, true
	}
	return fetchMetaVia(ctx, timeout, "")
}

// fetchMetaVia 用指定 network（"tcp4" 或空=双栈）取一次出口元数据。
func fetchMetaVia(ctx context.Context, timeout time.Duration, network string) (string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Timeout: timeout}
	if network != "" {
		dialer := &net.Dialer{Timeout: timeout}
		client.Transport = &http.Transport{
			DialContext: func(dctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(dctx, network, addr)
			},
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: timeout,
		}
	}
	if body, ok := fetchMeta(reqCtx, client, metaURL); ok {
		return body, true
	}
	return fetchMeta(reqCtx, client, traceURL)
}

// traceValue pulls one "key=value" line out of a /cdn-cgi/trace body.
func traceValue(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// latencyTarget is a Cloudflare anycast address: it is one hop from any WARP
// egress, so what the measurement mostly contains is our own tunnel, not the
// far side of the internet.
const latencyTarget = "1.1.1.1:443"

// ProbeLatency measures one TCP round trip to Cloudflare.
//
// In fd mode this really does travel through the tunnel (the OS routes it into
// our tun), so the number on the home screen is the latency of the connection
// the user is actually using. In netstack mode it would measure the phone's own
// uplink instead, which is why the sampler only runs while a session is up.
func ProbeLatency(ctx context.Context, timeout time.Duration) (int64, bool) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(reqCtx, "tcp", latencyTarget)
	if err != nil {
		return 0, false
	}
	conn.Close()
	return time.Since(start).Milliseconds(), true
}

// Counters reports cumulative (tx, rx) bytes of the data plane since the session
// was created. Zeros when the tunnel has no OS device to count.
func (s *Session) Counters() (tx, rx uint64) {
	if s == nil {
		return 0, 0
	}
	// OpenVPN 出口时 tn 是外层 netstack，它数的是加密后的包（含封装），跟用户在
	// 界面上看到的「上下行流量」不是一回事；直接数 tun 与节点之间的 IP 包更准。
	if s.ovpn != nil {
		return s.ovpn.counters()
	}
	if s.tn == nil {
		return 0, 0
	}
	return s.tn.counters()
}

// ProbeNetwork reports the address the internet sees for this phone right now.
//
// With the tunnel up that is the exit; with it down it is the carrier or Wi-Fi
// address, which is what the home screen shows as "your IP" before connecting.
// One function for both keeps the two numbers comparable: they come from the
// same probe, so "connected" cannot show a value measured some other way.
func ProbeNetwork(ctx context.Context, timeout time.Duration) (ip, country string, ok bool) {
	body, ok := fetchViaSystem(ctx, timeout)
	if !ok {
		return "", "", false
	}
	var m struct {
		ClientIP string `json:"clientIp"`
		IP       string `json:"ip"`
		Country  string `json:"country"`
	}
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		ip, country = m.ClientIP, m.Country
		if ip == "" {
			ip = m.IP
		}
	}
	if ip == "" {
		ip = traceValue(body, "ip")
	}
	if country == "" {
		country = traceValue(body, "loc")
	}
	if ip == "" {
		return "", "", false
	}
	return ip, country, true
}
