package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xhwarp/warp-client/internal/core"
)

// Mode B (Clash subscription) connect pipeline.
//
// It deliberately shares nothing with the WARP lifecycle: no account, no
// endpoint scan, no Cloudflare edge. The imported node is the first hop and
// stays the first hop whether the session exits directly, through Psiphon or
// through a VPN Gate relay. Before this existed, a subscription connect still
// registered a WARP account and swept the endpoint space (the log showed
// "[AWG] 扫描 WARP 端点…" and a 1-2 minute wait) only to throw the endpoint
// away when the config rendered — work that was pure latency and, worse, made
// "订阅模式不使用 WARP" false.
//
// The data-plane half (verifyTunnel, throughput probe, system proxy, state) is
// startAndVerify's, unchanged: it renders through renderClientConfig, which
// branches into renderSubscriptionConfig for this mode.

// runConnectSubscription brings a subscription session up. Three shapes share
// the pipeline: bare node, node + Psiphon exit, node + VPN Gate exit.
func runConnectSubscription(ctx context.Context, opts options) error {
	if opts.mixedPort == 0 {
		opts.mixedPort = core.DefaultMixedPort
	}
	if opts.apiPort == 0 {
		opts.apiPort = core.DefaultAPIPort
	}
	if len(opts.customProxies) == 0 {
		return fmt.Errorf("订阅模式没有可用节点：请先在「节点」页导入订阅链接或配置文件")
	}
	if opts.tunMode && !core.IsElevated() {
		return fmt.Errorf("TUN 模式需要管理员权限：请以管理员身份重新运行本程序")
	}
	// The user picked a node; the endpoint speed gate exists to rotate WARP
	// edges and would only turn a slow-but-working subscription node into a
	// failed connect.
	opts.speedGate = false
	// A stale chain from an earlier mode A run must not leak into the render.
	outer = nil
	chainUserProto = ""

	// Auto-select resolves here, not only in the settings snapshot: a repair
	// rebuilds options from state.json + settings.json and must reach the same
	// node.
	if opts.activeProxy == "" {
		if best := bestMeasuredProxy(opts.customProxies); best != "" {
			opts.activeProxy = best
		}
	}
	if opts.activeProxy == "" {
		opts.activeProxy = opts.customProxies[0].Name
	}

	cDir, err := coreDir()
	if err != nil {
		return err
	}
	syncBundledResources(cDir)
	bin, err := core.EnsureBinary(cDir, opts.corePath)
	if err != nil {
		return err
	}

	label := "订阅"
	if opts.psiphonMode {
		label = "订阅+Psiphon"
	}
	if opts.openvpnMode {
		label = "订阅+VPN Gate"
	}
	stageMsg(fmt.Sprintf("[%s] 前置节点 %s", label, opts.activeProxy))
	stageMsg(fmt.Sprintf("[%s] 开始连接（不使用 WARP）…", label))

	// A previous session's core and Psiphon sidecar hold the ports this one
	// needs; reap them before the new render picks its ports.
	reapStaleSession(cDir, opts)

	ce := cachedEndpoint{Endpoint: opts.activeProxy}
	run := protoRun{name: "订阅"}

	switch {
	case opts.psiphonMode:
		exe, err := resolvePsiphonExe(opts, cDir)
		if err != nil {
			return err
		}
		baseConfig, err := resolvePsiphonClientConfig(cDir)
		if err != nil {
			return err
		}
		psPort, err := pickFreePort()
		if err != nil {
			return err
		}
		// Psiphon's own dials go to the subscription node: the config emits a
		// dedicated SOCKS inbound (underlaySocksPort) whose traffic is routed
		// to SUB-BASE, so Psiphon never dials the relay directly.
		launch := psiphonLaunch{
			ExePath:        exe,
			DataDir:        filepath.Join(cDir, "psiphon-data"),
			BaseConfigPath: baseConfig,
			Upstream:       fmt.Sprintf("socks5://127.0.0.1:%d", underlaySocksPort(opts.mixedPort)),
			SocksPort:      psPort,
			EgressRegion:   opts.psiphonRegion,
		}
		opts.psiphonSocksPort = psPort
		// One transient underlay hiccup must not end the session: the front
		// node can refuse a dial right after a reconnect (cold WS handshake,
		// rate limit), while the same node worked seconds earlier. The OpenVPN
		// branch survives this by rotating relays; a single-node Psiphon
		// session needs explicit retries instead.
		var state clientState
		var lastErr error
		for attempt := 1; attempt <= 3; attempt++ {
			state, lastErr = connectPsiphonOn(ctx, opts, ce, run, bin, cDir, label, launch)
			if lastErr == nil {
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(lastErr, errPsiphonPolicyBlocked) || localCoreError(lastErr) {
				return lastErr
			}
			if attempt == 3 {
				break
			}
			wait := time.Duration(attempt) * 3 * time.Second
			stageMsg(fmt.Sprintf("[%s] 第 %d 次尝试失败：%v；%d 秒后重试…", label, attempt, lastErr, int(wait/time.Second)))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		if lastErr != nil {
			return lastErr
		}
		state.SubMode = true
		if err := saveState(state); err != nil {
			fmt.Fprintln(os.Stderr, errPal.warn("state not persisted: "+err.Error()))
		}
		stageMsg(fmt.Sprintf("[%s] 连接成功（前置 = 订阅节点，出口 = Psiphon）", label))
		if !opts.noGuard {
			ensureSessionGuard(state)
		}
		return nil
	case opts.openvpnMode:
		// Subscription mode has no WARP pipeline to pick a relay for us: the
		// caller only sets the switch, so the pool has to be consulted here.
		// Without this the connect died with "VPN Gate 出口缺少节点" no matter
		// how many relays the picker had just measured.
		relays, rerr := subscriptionRelayCandidates(opts)
		if rerr != nil {
			return rerr
		}
		stageMsg(fmt.Sprintf("[%s] 出口候选：%d 个 VPN Gate 节点（按实测速度优先）", label, len(relays)))
		var lastErr error
		for i := range relays {
			if err := ctx.Err(); err != nil {
				return err
			}
			node := relays[i]
			opts.openvpnNode = &node
			stageMsg(fmt.Sprintf("[%s] 前置 %s + 出口节点 %s（%s，%d/%d）…",
				label, opts.activeProxy, node.id(), node.CountryShort, i+1, len(relays)))
			state, serr := startAndVerify(ctx, opts, ce, run, bin, cDir, label, nil)
			if serr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if localCoreError(serr) {
					return fmt.Errorf("本地内核无法启动：%v（请关闭占用同一端口的其它代理客户端后重试）", serr)
				}
				var auth *authRejectError
				if errors.As(serr, &auth) {
					stageMsg(fmt.Sprintf("[%s] 中继 %s 拒绝认证（AUTH_FAILED），换下一个中继…", label, node.id()))
				}
				lastErr = serr
				fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("出口节点 %s: %v", node.id(), serr)))
				markVPNGateFailed(node.id())
				continue
			}
			clearVPNGateFailure(node.id())
			rememberLastGoodVPNGate(node)
			state.SubMode = true
			if err := saveState(state); err != nil {
				fmt.Fprintln(os.Stderr, errPal.warn("state not persisted: "+err.Error()))
			}
			stageMsg(fmt.Sprintf("[%s] 连接成功（前置 = 订阅节点，出口 = VPN Gate %s）", label, node.CountryShort))
			if opts.openvpnNodePin != "" && node.id() != opts.openvpnNodePin {
				stageMsg(fmt.Sprintf("[%s] 注意：固定节点 %s 本次未能连接，实际出口 = %s（你的固定选择仍保留）",
					label, opts.openvpnNodePin, node.id()))
			}
			if !opts.noGuard {
				ensureSessionGuard(state)
			}
			return nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("没有可用的 VPN Gate 节点")
		}
		return fmt.Errorf("订阅模式的 VPN Gate 出口全部失败: %w", lastErr)
	}

	state, err := startAndVerify(ctx, opts, ce, run, bin, cDir, label, nil)
	if err != nil {
		return err
	}
	state.SubMode = true
	if err := saveState(state); err != nil {
		fmt.Fprintln(os.Stderr, errPal.warn("state not persisted: "+err.Error()))
	}
	stageMsg(fmt.Sprintf("[%s] 连接成功（出口 = %s）", label, opts.activeProxy))
	if !opts.noGuard {
		ensureSessionGuard(state)
	}
	return nil
}

// reapStaleSession kills the core / Psiphon left by an earlier session and
// restores the system proxy it had set. Both hold the ports the new session
// needs, and an un-restored proxy snapshot would be orphaned.
func reapStaleSession(cDir string, opts options) {
	st, err := loadState()
	if err != nil {
		return
	}
	if st.Connected && !st.TUN && len(st.ProxySnap) > 0 {
		var snap core.ProxySnapshot
		if json.Unmarshal(st.ProxySnap, &snap) == nil {
			_ = core.UnsetSystemProxy(&snap)
		}
	}
	if st.CorePID > 0 {
		if kerr := core.KillByPID(st.CorePID, core.CoreInDir(cDir)); kerr == nil {
			fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("killed stale core (pid %d)", st.CorePID)))
		}
	}
	if st.PsiphonPID > 0 {
		if exe, eerr := resolvePsiphonExe(opts, cDir); eerr == nil {
			if kerr := core.KillByPID(st.PsiphonPID, exe); kerr == nil {
				fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("killed stale psiphon (pid %d)", st.PsiphonPID)))
			}
		}
	}
}

// repairSubscriptionOnce is the health guard's mode B repair: bring the same
// subscription session back, on the same front node, without ever scanning a
// WARP endpoint.
func repairSubscriptionOnce(ctx context.Context, opts options, logf func(string)) (clientState, bool) {
	if err := runConnectSubscription(ctx, opts); err != nil {
		if errors.Is(err, context.Canceled) {
			logf("会话已断开，中止修复")
		} else {
			logf("修复失败：" + err.Error())
		}
		return clientState{}, false
	}
	st, err := loadState()
	if err != nil {
		logf("修复后无法读取状态：" + err.Error())
		return clientState{}, false
	}
	return st, true
}

// subscriptionRelayCandidates picks the VPN Gate relays a subscription-mode
// session may exit through, ordered by this client's own measurements.
func subscriptionRelayCandidates(opts options) ([]vpnGateNode, error) {
	nodes, at := loadVPNGateCache()
	if len(nodes) == 0 || time.Since(at) > vpnGateCacheTTL {
		// A stale/empty pool is still worth trying: the picker may have just
		// measured it, and failing here would strand a working session.
		if len(nodes) == 0 {
			return nil, fmt.Errorf("VPN Gate 节点列表为空：请先在出口地区里刷新节点")
		}
	}
	if opts.openvpnNodePin != "" {
		// A pinned relay is the user's choice, but it must not be the ONLY
		// candidate: a single attempt meant one unlucky handshake ended the
		// session with "出口全部失败". Put the pin first, then the fastest
		// measured fallbacks from the same pool (which is the pool the WARP-mode
		// 延迟测试 filled, so both modes share one measurement table).
		var pinned *vpnGateNode
		rest := make([]vpnGateNode, 0, len(nodes))
		for i := range nodes {
			n := nodes[i]
			if n.IP == "" || n.Port <= 0 || n.Profile == "" {
				continue
			}
			if n.id() == opts.openvpnNodePin && pinned == nil {
				pn := n
				pinned = &pn
				continue
			}
			rest = append(rest, n)
		}
		if pinned != nil {
			// Prefer the pinned relay's own country, then anything measured
			// fast; the head of this list is what the session tries first.
			sortVPNGateNodesByLatency(rest)
			out := []vpnGateNode{*pinned}
			for _, n := range rest {
				if len(out) >= 6 {
					break
				}
				if strings.EqualFold(n.CountryShort, pinned.CountryShort) {
					out = append(out, n)
				}
			}
			for _, n := range rest {
				if len(out) >= 6 {
					break
				}
				dup := false
				for _, o := range out {
					if o.id() == n.id() {
						dup = true
						break
					}
				}
				if !dup {
					out = append(out, n)
				}
			}
			return out, nil
		}
	}
	relays := vpnGateCandidates(context.Background(), nodes, opts.openvpnRegion, opts.openvpnNodePin, vpnGateConnectNodes)
	if len(relays) == 0 {
		if opts.openvpnRegion != "" {
			return nil, fmt.Errorf("VPN Gate 当前没有 %s 地区的可用节点，请换一个出口地区", opts.openvpnRegion)
		}
		return nil, fmt.Errorf("VPN Gate 节点列表为空，请稍后重试")
	}
	relays = preferLastGoodVPNGate(relays, opts.openvpnNodePin, opts.openvpnRegion)
	// Six relays is plenty: the pool's head is already speed-ordered, and a
	// subscription session costs one core start per attempt.
	if len(relays) > 6 {
		relays = relays[:6]
	}
	return relays, nil
}

// subscriptionFronts orders the nodes worth carrying a list fetch: the active
// one first, then the fastest measured ones. A single dead front must not cost
// the whole refresh — one 12-second timeout would otherwise read as "订阅模式
// 拉不到节点" even though 50 other nodes were fine.
func subscriptionFronts(s clientSettings) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(name string) {
		if name == "" || seen[name] || len(out) >= 3 {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	add(s.ActiveProxy)
	type cand struct {
		name string
		ms   int
	}
	var best []cand
	for _, p := range s.CustomProxies {
		if p.Name == "" || p.DelayErr || p.DelayMS <= 0 {
			continue
		}
		best = append(best, cand{p.Name, p.DelayMS})
	}
	for i := 0; i < len(best) && len(out) < 3; i++ {
		min := i
		for j := i + 1; j < len(best); j++ {
			if best[j].ms < best[min].ms {
				min = j
			}
		}
		best[i], best[min] = best[min], best[i]
		add(best[i].name)
	}
	if len(out) == 0 {
		for _, p := range s.CustomProxies {
			add(p.Name)
		}
	}
	return out
}
