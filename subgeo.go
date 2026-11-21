package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Node country detection.
//
// A subscription name carries a country only when the provider bothered to put
// one there ("🇺🇸 US-443-WS", "香港节点"). Most CN-provider nodes are named after
// the ISP and a CDN hostname, so the name says nothing about where the traffic
// actually exits — and that is the flag a user compares against Mihomo Party.
//
// The only honest source is the exit itself. mihomo lets one inbound be pinned
// to one outbound (`listeners: - proxy: <name>`), so a throwaway core can bind
// one SOCKS port per node and ask every node, in parallel, what country the
// internet sees it as. Cloudflare's own trace endpoint answers that in one
// round trip and needs no API key or quota.

const (
	subGeoWorkers = 16
	subGeoHost    = "www.cloudflare.com:443"
	subGeoTimeout = 8 * time.Second
	// Some exits carry ordinary HTTP but stall the TLS handshake to
	// Cloudflare, so the fallback source gets its own shorter ceiling.
	subGeoFallbackTimeout = 6 * time.Second
)

// reservePorts grabs n free TCP ports at once (they are all bound before any is
// released, so they cannot collide with each other) and hands them back ready
// to use. A tiny race against another process is unavoidable without keeping
// the sockets open, and the core binds them within milliseconds.
func reservePorts(n int) ([]int, error) {
	if n <= 0 {
		return nil, nil
	}
	ls := make([]net.Listener, 0, n)
	ports := make([]int, 0, n)
	defer func() {
		for _, l := range ls {
			_ = l.Close()
		}
	}()
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

// countryTrace fetches Cloudflare's trace through one node and returns the
// ISO code it reports. loc= is the country Cloudflare sees the request coming
// from, which is exactly the flag the client should paint.
func countryTrace(ctx context.Context, socksPort int) (string, error) {
	conn, err := socks5Dial(ctx, socksPort, subGeoHost, subGeoTimeout)
	if err != nil {
		return "", err
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "www.cloudflare.com"})
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(subGeoTimeout))
	req := "GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: xehn/1.0\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("trace status %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "loc="); ok {
			v = strings.ToUpper(strings.TrimSpace(v))
			if len(v) == 2 && v != "XX" && v != "T1" {
				return v, nil
			}
			return "", fmt.Errorf("trace loc %q", v)
		}
	}
	return "", fmt.Errorf("trace without loc")
}

// countryTraceIPAPI is the plain-HTTP fallback: some exits carry ordinary
// HTTP but stall the TLS handshake to Cloudflare, and ip-api answers the
// country in one small JSON body without a TLS round trip.
func countryTraceIPAPI(ctx context.Context, socksPort int) (string, error) {
	conn, err := socks5Dial(ctx, socksPort, "ip-api.com:80", subGeoFallbackTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(subGeoFallbackTimeout))
	req := "GET /json/?fields=status,countryCode HTTP/1.1\r\nHost: ip-api.com\r\nUser-Agent: xehn/1.0\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ip-api status %d", resp.StatusCode)
	}
	var r struct {
		Status      string `json:"status"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&r); err != nil {
		return "", err
	}
	if r.Status != "success" || len(r.CountryCode) != 2 {
		return "", fmt.Errorf("ip-api status %q", r.Status)
	}
	return strings.ToUpper(r.CountryCode), nil
}

// probeNodeCountry tries the Cloudflare trace first and falls back to ip-api
// when the exit stalls it, so one blocked TLS path does not leave a live node
// without a flag.
func probeNodeCountry(ctx context.Context, socksPort int) (string, error) {
	cc, err := countryTrace(ctx, socksPort)
	if err == nil {
		return cc, nil
	}
	return countryTraceIPAPI(ctx, socksPort)
}

// probeProxyCountries resolves the exit country for every proxy in ports.
// A node that cannot answer simply gets no flag; the caller keeps whatever the
// name already advertised.
func probeProxyCountries(ctx context.Context, ports map[string]int, logf func(string)) map[string]string {
	out := make(map[string]string, len(ports))
	var mu sync.Mutex
	sem := make(chan struct{}, subGeoWorkers)
	var wg sync.WaitGroup
	done, total := 0, len(ports)
	for name, port := range ports {
		wg.Add(1)
		go func(name string, port int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			cc, err := probeNodeCountry(ctx, port)
			mu.Lock()
			if err == nil {
				out[name] = cc
			}
			done++
			if logf != nil && done%20 == 0 {
				logf(fmt.Sprintf("识别节点地区 %d/%d…", done, total))
			}
			mu.Unlock()
		}(name, port)
	}
	wg.Wait()
	return out
}

// geoListenerYAML renders the `listeners:` block that pins one SOCKS port to
// one outbound. Names are quoted: subscription names carry spaces, emoji and
// non-ASCII characters.
func geoListenerYAML(ports map[string]int) string {
	if len(ports) == 0 {
		return ""
	}
	names := make([]string, 0, len(ports))
	for n := range ports {
		names = append(names, n)
	}
	// Deterministic order keeps the config diffable when debugging.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	var b strings.Builder
	b.WriteString("listeners:\n")
	for i, n := range names {
		b.WriteString("  - name: \"geo-" + strconv.Itoa(i) + "\"\n")
		b.WriteString("    type: socks\n")
		b.WriteString("    port: " + strconv.Itoa(ports[n]) + "\n")
		b.WriteString("    listen: 127.0.0.1\n")
		b.WriteString("    proxy: " + fmt.Sprintf("%q", n) + "\n")
	}
	return b.String()
}
