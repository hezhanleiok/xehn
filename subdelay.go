package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xhwarp/warp-client/internal/core"
)

// Subscription latency test. mihomo exposes GET /proxies/{name}/delay, which
// dials a test URL through exactly that outbound. Nothing has to route through
// the proxy for this to work, so a throwaway core on private ports can measure
// every imported node without touching the live session, the system proxy or
// the user's config.yaml.

const (
	// gstatic's generate_204 is what every Clash client tests against, so the
	// number here is comparable with the one Mihomo Party shows.
	subDelayTestURL  = "https://www.gstatic.com/generate_204"
	subDelayWorkers  = 16
	subDelayCoreWait = 20 * time.Second
	// subDelayTimeoutMS is the per-proxy ceiling the core applies. Clash
	// clients use 5000ms; keeping the same value is what makes the numbers
	// comparable with them.
	subDelayTimeoutMS = 5000
	// probeGroupName is the select group the throwaway core exposes; the group
	// delay API tests every proxy in it in one call.
	probeGroupName = "PROBE"
)

func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// probeSubscriptionConfig is deliberately minimal: proxies plus one select
// group, no geo rules, no tun, no DNS. mihomo only needs the outbound
// definitions to answer the delay API.
func probeSubscriptionConfig(proxies []ProxySpec, mixedPort, apiPort int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "mixed-port: %d\n", mixedPort)
	// Loopback-only binds keep Windows Firewall from prompting for the core.
	b.WriteString("allow-lan: false\nbind-address: 127.0.0.1\n")
	fmt.Fprintf(&b, "external-controller: 127.0.0.1:%d\n", apiPort)
	b.WriteString("mode: direct\nlog-level: error\nipv6: false\n")
	// unified-delay reports the connection-setup time instead of the whole HTTP
	// round trip, which is exactly how Mihomo Party measures. Without it every
	// node here read ~300 ms higher than the same node in Party (DNS + TCP +
	// TLS handshake folded into the number), and a 92 ms node showed as 399 ms.
	b.WriteString("unified-delay: true\ntcp-concurrent: true\n")
	// A resolver block is not optional here. Without it mihomo resolves every
	// proxy-server hostname with the *system* resolver, which on this network
	// fails or crawls for a good half of the CDN front domains — those nodes then
	// time out before the handshake even starts, and the list looks far worse
	// than the same subscription in Clash Party (which always ships a resolver).
	// 1.1.1.1 first, domestic as fallback. A CDN front domain is routed by SNI:
	// the domestic resolvers answer with a Fastly edge (146.75.113.x) that accepts
	// the TCP connection but fails the TLS handshake for this hostname, so every
	// node on the subscription times out before its handshake even starts.
	// Verified against the user's subscription: 119.29.29.29 -> 146.75.113.242
	// (dead end), 1.1.1.1 -> 151.101.x.x (works, 1349ms / 1657ms measured).
	b.WriteString("dns:\n  enable: true\n  ipv6: false\n  use-hosts: false\n")
	// Same order as a live session (8.8.8.8 first): the probe must resolve the
	// node exactly the way the connect will, otherwise a node can measure fine
	// here and still fail to dial.
	b.WriteString("  nameserver:\n    - 8.8.8.8\n    - 1.1.1.1\n")
	// No domestic fallback on purpose. 119.29.29.29 answers a CDN front domain
	// with a Fastly edge that completes TCP and then fails TLS for that hostname,
	// so keeping it as a "safety net" reintroduces the exact timeout whenever the
	// overseas resolvers are slow enough to be skipped.
	b.WriteString("  proxy-server-nameserver:\n    - 8.8.8.8\n    - 1.1.1.1\n")
	b.WriteString("proxies:\n")
	for _, p := range proxies {
		fmt.Fprintf(&b, "  - name: %q\n    type: %q\n", p.Name, p.Type)
		keys := make([]string, 0, len(p.Fields))
		for k := range p.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "    %s: %s\n", k, subYAMLValue(p.Fields[k]))
		}
	}
	b.WriteString("proxy-groups:\n  - name: PROBE\n    type: select\n    proxies:\n")
	for _, p := range proxies {
		fmt.Fprintf(&b, "      - %q\n", p.Name)
	}
	b.WriteString("rules:\n  - MATCH,DIRECT\n")
	return []byte(b.String())
}

// measureProxyDelays hits the delay API for every name in parallel. A name
// present in failed did answer the API but not the test URL (timeout, refused,
// blocked), which the list paints as a red 超时 instead of an empty dash.
func measureProxyDelays(ctx context.Context, apiPort int, proxies []ProxySpec, logf func(string)) (map[string]int, map[string]bool) {
	// One group call first: mihomo schedules the probes itself, which is the
	// same path Clash clients use. Firing 16 concurrent /proxies/{name}/delay
	// requests from outside instead made far more nodes time out than the
	// reference client reported for the identical subscription.
	if logf != nil {
		logf(fmt.Sprintf("延迟测试：%d 个节点（核心内置并发）…", len(proxies)))
	}
	if ms, err := core.ProxyGroupDelay(apiPort, probeGroupName, subDelayTestURL, subDelayTimeoutMS); err == nil && len(ms) > 0 {
		log.Printf("probe group ok: %d/%d answered", len(ms), len(proxies))
		results := make(map[string]int, len(ms))
		failed := make(map[string]bool, len(proxies))
		for _, p := range proxies {
			if v, ok := ms[p.Name]; ok {
				results[p.Name] = int(v)
			} else {
				failed[p.Name] = true
			}
		}
		if logf != nil {
			logf(fmt.Sprintf("延迟测试完成：%d/%d 个有响应", len(results), len(proxies)))
		}
		// The group call only reports the survivors, so a "0/N" run says nothing
		// about WHY. For small lists (the common case: a handful of nodes) the
		// extra probe per failure is cheap and the reason is worth showing;
		// XEHN_PROBE_VERBOSE forces it on for large lists too.
		if logf != nil && (len(proxies) <= 10 || os.Getenv("XEHN_PROBE_VERBOSE") != "") {
			for _, p := range proxies {
				if !failed[p.Name] {
					continue
				}
				d, derr := core.ProxyDelay(apiPort, p.Name, subDelayTestURL)
				if derr == nil && d > 0 {
					results[p.Name] = int(d)
					delete(failed, p.Name)
					logf(fmt.Sprintf("  %s 重测成功: %dms", p.Name, d))
					continue
				}
				msg := "无响应"
				if derr != nil {
					msg = derr.Error()
				}
				logf(fmt.Sprintf("  %s 失败原因: %s", p.Name, msg))
			}
		}
		return results, failed
	}
	// Group call did not answer (missing PROBE group / 404 / core error): record
	// why before falling back, otherwise a 0/N run has no trail at all.
	if ms, gerr := core.ProxyGroupDelay(apiPort, probeGroupName, subDelayTestURL, subDelayTimeoutMS); gerr != nil {
		log.Printf("probe group call failed: %v", gerr)
	} else {
		log.Printf("probe group call returned %d entries", len(ms))
	}
	results := make(map[string]int, len(proxies))
	failed := make(map[string]bool, len(proxies))
	var mu sync.Mutex
	sem := make(chan struct{}, subDelayWorkers)
	var wg sync.WaitGroup
	done := 0
	for _, p := range proxies {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			d, err := core.ProxyDelay(apiPort, name, subDelayTestURL)
			mu.Lock()
			if err == nil && d > 0 {
				results[name] = int(d)
			} else {
				failed[name] = true
			}
			// log.Printf goes to xehn.log (the GUI redirects stderr there), so a
			// 0/N report leaves evidence on disk instead of only in the panel.
			if err != nil {
				log.Printf("probe delay %q failed: %v", name, err)
			} else if d <= 0 {
				log.Printf("probe delay %q returned %d", name, d)
			}
			done++
			if logf != nil && done%20 == 0 {
				logf(fmt.Sprintf("延迟测试 %d/%d…", done, len(proxies)))
			}
			mu.Unlock()
		}(p.Name)
	}
	wg.Wait()
	return results, failed
}

// subDelayReport is everything one latency run learns about the node list:
// the measured delay, which nodes were tested and did not answer, and the exit
// country resolved for the ones the name did not already advertise.
type subDelayReport struct {
	MS     map[string]int
	Failed map[string]bool
	CC     map[string]string
}

// withTempCore renders a throwaway core on private ports, starts it, and runs fn
// with the ports it actually bound. The temp work dir is removed on return, so a
// running session's config.yaml is never touched.
func withTempCore(ctx context.Context, tag string, build func(mixedPort, apiPort int) []byte, fn func(mixedPort, apiPort int) error) error {
	cDir, err := coreDir()
	if err != nil {
		return fmt.Errorf("%s: 数据目录不可用: %w", tag, err)
	}
	// The portable package ships core/mihomo.exe next to the exe, while the
	// writable app dir only gets a copy once a connect has run. Do exactly what
	// the connect path does, then point EnsureBinary at the bundled file, so a
	// probe on a fresh install never downloads a 60 MB release.
	syncBundledResources(cDir)
	bundled := os.Getenv("XEHN_PROBE_CORE") // diagnostic/test override
	if bundled == "" {
		if exe, eerr := os.Executable(); eerr == nil {
			p := filepath.Join(filepath.Dir(exe), coreDirName, core.ExeName())
			if fi, serr := os.Stat(p); serr == nil && fi.Size() > 0 {
				bundled = p
			}
		}
	}
	bin, err := core.EnsureBinary(cDir, bundled)
	if err != nil {
		return fmt.Errorf("%s: 找不到 mihomo 核心: %w", tag, err)
	}
	mixedPort, err := freeTCPPort()
	if err != nil {
		return err
	}
	apiPort, err := freeTCPPort()
	if err != nil {
		return err
	}
	workDir, err := os.MkdirTemp("", "xehn-probe-")
	if err != nil {
		return err
	}
	// XEHN_KEEP_PROBE_DIR keeps the throwaway core's directory (config + log) for
	// diagnosis: a probe that reports 0/N without any visible reason needs its
	// generated YAML and core log inspected after the fact.
	if os.Getenv("XEHN_KEEP_PROBE_DIR") == "" {
		defer os.RemoveAll(workDir)
	} else {
		fmt.Fprintf(os.Stderr, "probe dir kept: %s\n", workDir)
	}

	c, err := core.New(core.Config{
		BinaryPath: bin,
		WorkDir:    workDir,
		MixedPort:  mixedPort,
		APIPort:    apiPort,
	})
	if err != nil {
		return err
	}
	if err := c.WriteConfig(build(mixedPort, apiPort)); err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return fmt.Errorf("%s核心启动失败: %w", tag, err)
	}
	defer c.Stop()
	readyCtx, cancel := context.WithTimeout(ctx, subDelayCoreWait)
	defer cancel()
	if err := c.WaitReady(readyCtx); err != nil {
		return fmt.Errorf("%s核心未就绪: %w", tag, err)
	}
	// WaitReady only proves the REST API answers. The mixed listener binds on its
	// own schedule, and probing it too early returns "connection refused" — which
	// the caller reads as "this base endpoint cannot forward data", walks the
	// whole candidate list, and looks like an endless reconnect loop.
	if err := waitListening(ctx, mixedPort, 3*time.Second); err != nil {
		return fmt.Errorf("%s: 代理端口 %d 未就绪: %w", tag, mixedPort, err)
	}
	return fn(mixedPort, apiPort)
}

// waitListening blocks until something accepts TCP on the loopback port.
func waitListening(ctx context.Context, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for {
		if c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond); err == nil {
			_ = c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("端口 %d 在 %s 内未开始监听", port, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// startProbeCore renders a throwaway core on private ports and runs fn against
// its API port.
func startProbeCore(ctx context.Context, proxies []ProxySpec, extraYAML string, fn func(apiPort int) error) error {
	return withTempCore(ctx, "延迟测试", func(mixedPort, apiPort int) []byte {
		return append(probeSubscriptionConfig(proxies, mixedPort, apiPort), []byte(extraYAML)...)
	}, func(_, apiPort int) error {
		return fn(apiPort)
	})
}

// runSubscriptionDelayTest measures every proxy and, for the ones that answered
// without a country in their name, asks each node what country it exits from.
func runSubscriptionDelayTest(ctx context.Context, proxies []ProxySpec, logf func(string)) (subDelayReport, error) {
	var rep subDelayReport
	err := startProbeCore(ctx, proxies, "", func(apiPort int) error {
		rep.MS, rep.Failed = measureProxyDelays(ctx, apiPort, proxies, logf)
		return nil
	})
	if err != nil {
		return rep, err
	}
	rep.CC = geoPass(ctx, proxies, rep.MS, logf)
	return rep, nil
}

// geoPass resolves exit countries for nodes that answered the latency test but
// carry no country in their name. One listener per node pins each SOCKS port to
// exactly that outbound, so the probes run in parallel without fighting over a
// shared select group.
func geoPass(ctx context.Context, proxies []ProxySpec, ms map[string]int, logf func(string)) map[string]string {
	need := make([]ProxySpec, 0, len(proxies))
	for _, p := range proxies {
		if p.CC == "" && ms[p.Name] > 0 {
			need = append(need, p)
		}
	}
	if len(need) == 0 {
		return nil
	}
	ports := make(map[string]int, len(need))
	free, err := reservePorts(len(need))
	if err != nil {
		return nil
	}
	for i, p := range need {
		ports[p.Name] = free[i]
	}
	var cc map[string]string
	err = startProbeCore(ctx, proxies, geoListenerYAML(ports), func(int) error {
		cc = probeProxyCountries(ctx, ports, logf)
		return nil
	})
	if err != nil {
		return nil
	}
	return cc
}

// bestMeasuredProxy returns the name with the lowest measured delay, or ""
// when nothing has been tested yet.
func bestMeasuredProxy(proxies []ProxySpec) string {
	best, bestMS := "", 0
	for _, p := range proxies {
		if p.DelayMS <= 0 {
			continue
		}
		if best == "" || p.DelayMS < bestMS {
			best, bestMS = p.Name, p.DelayMS
		}
	}
	return best
}
