package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xhwarp/warp-client/internal/cache"
	"github.com/xhwarp/warp-client/internal/core"
)

// connectStage, when set by the native GUI, receives human-readable progress
// lines at each step of the connect pipeline. The CLI path never sets it, so
// its behaviour is unchanged.
var connectStage func(string)

func stageMsg(s string) {
	if connectStage != nil {
		connectStage(s)
	}
}

const (
	// connectMaxAttempts caps how many cached endpoints one connect tries in
	// best-first order before falling back to a fresh scan. Five, because on
	// DPI-torn networks the vanilla-WG pool loses endpoints to mid-stream
	// teardown faster than the scan retires them.
	connectMaxAttempts = 5
	// connectEarlyStop is how many durable endpoints the connect-path scan
	// verifies before it stops: enough for the ranking to pick a good one,
	// without paying a full handshake for every candidate the user is not
	// waiting on.
	connectEarlyStop = 4
	// psiphonTunnelWait bounds how long a Psiphon sidecar gets to reach a
	// server through a given underlay. A healthy underlay establishes in tens
	// of seconds; waiting minutes per candidate turns one dead underlay into a
	// multi-minute connect.
	psiphonTunnelWait = 75 * time.Second
	// verifyRetryDelay spaces the two tunnel probes: the first request races
	// the WG handshake (whose trigger packet is dropped), so one retry absorbs
	// a healthy-but-slow endpoint.
	verifyRetryDelay = 2 * time.Second
	// openvpnMaxAttempts caps base-endpoint × relay combinations in one connect.
	// A VPN Gate relay that cannot handshake is common; the candidates arrive
	// already ordered (residential block first, then the datacenter fleet), so six
	// attempts give the failover chain room without turning one connect into a
	// multi-minute walk through dead nodes.
	openvpnMaxAttempts = 6
	// openvpnWarmupWindow is how long one relay gets to complete its OpenVPN
	// handshake. mihomo detaches the handshake from the inbound dial (see
	// openvpnHandshakeTimeout), so the first client request necessarily fails;
	// repeated requests keep the outbound dialling until the tunnel is up. The
	// outbound itself gives up after openvpnHandshakeTimeout seconds, so waiting
	// longer than that only delays the next candidate.
	openvpnWarmupWindow = time.Duration(openvpnHandshakeTimeout+2) * time.Second
	// openvpnWarmupReqTimeout bounds one warm-up request. Short on purpose: the
	// request is a handshake trigger, not a transfer, and a dead combination
	// must fail fast enough for the next candidate to get a turn.
	openvpnWarmupReqTimeout = 4 * time.Second
	// openvpnSpeedProbeBytes / openvpnSpeedProbeTimeout are the verification
	// transfer for an OpenVPN exit. Larger than the generic 128 KiB gate
	// because the same transfer also feeds the speed ranking: 128 KiB is
	// dominated by TCP slow start and cannot separate a fast relay from one
	// that merely avoided stalling.
	openvpnSpeedProbeBytes   = 512 * 1024
	openvpnSpeedProbeTimeout = 12 * time.Second
	// openvpnMinBps is the usable-speed floor. Relays below it make every page
	// crawl; the connect loop rotates past up to openvpnSpeedRetries of them,
	// then keeps the next working relay anyway because slow beats nothing.
	// The floor sits far above the generic gate's ~11 KB/s, which this relay
	// class was passing while delivering ~14 KB/s.
	openvpnMinBps       = 150 * 1024
	openvpnSpeedRetries = 2
)

// slowRelayError marks a relay that passed every data-plane check but measured
// below the usable-speed floor. The connect loop rotates past it without
// blacklisting it (the relay works, so a later connect may still use it when
// nothing faster is left), and the speed memory keeps it out of the front.
type slowRelayError struct{ bps int64 }

func (e *slowRelayError) Error() string {
	return fmt.Sprintf("出口实测速度过慢（≈%d KB/s，低于 %d KB/s）", e.bps/1024, openvpnMinBps/1024)
}

// proxyHelperAllowed gates the UAC elevation fallback: only the windowsgui
// build (double-clicked GUI) may relaunch itself elevated — a console binary
// would flash a terminal window — and only a process that is not elevated
// already (an elevated one never sees the block).
func proxyHelperAllowed() bool {
	return windowsGUIBuild == "1" && !core.IsElevated()
}

// connect: register (if needed) → scan (cached) → pick best → render config →
// start mihomo core → verify the tunnel really passes traffic → set system
// proxy → report the exit IP/latency/country. A dark tunnel (dead or
// rate-silenced endpoint) is rotated out, never reported as success: it is
// exactly the state where the proxy is "connected" but every page times out.
// The system proxy is only touched AFTER the data plane is verified, so the
// host is never pointed at a tunnel that does not pass traffic.
func runConnectCmd(ctx context.Context, opts options) error {
	err := runConnectInner(ctx, opts)
	// The steps below report their own errors, and a step that dies because the
	// context was cancelled usually wraps that into "registration failed: ...".
	// The caller has to tell "the user cancelled" from "this failed", so the
	// cancellation wins whenever it is the real reason.
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func runConnectInner(ctx context.Context, opts options) error {
	if opts.mixedPort == 0 {
		opts.mixedPort = core.DefaultMixedPort
	}
	if opts.apiPort == 0 {
		opts.apiPort = core.DefaultAPIPort
	}
	// TUN needs an elevated process to create the adapter and edit routes. Fail
	// here, before any account/scan work, so the user sees the real reason
	// instead of a core that dies at startup with a driver error.
	if opts.tunMode && !core.IsElevated() {
		return fmt.Errorf("TUN 模式需要管理员权限：请以管理员身份重新运行本程序")
	}
	// V2 OpenVPN exit: same two-axis shape as Psiphon (base protocol carries the
	// exit's dials), but the exit is mihomo's native openvpn outbound instead of
	// an external SOCKS sidecar, so it has its own node pool and verification.
	if opts.openvpnMode {
		return runConnectOpenVPN(ctx, opts)
	}
	// V1 Psiphon exit: Psiphon is an independent localhost SOCKS5 egress, not a
	// WARP transport. It has its own connect pipeline (no account, no scan, no
	// endpoint manager) and does not touch the WARP lifecycle below.
	if opts.psiphonMode {
		return runConnectPsiphon(ctx, opts)
	}
	// outer is a package global the nested scan sets; a long-lived GUI process
	// must not inherit a stale chain from an earlier run.
	if opts.through == "" {
		outer = nil
	}

	// The account globals (warpPrivateKey, masqueAcct, outerAcct) feed every
	// config render below. The warm-cache path never enters doScan, so the
	// account must be loaded-and-applied here: without it a cached connect
	// silently renders the hardcoded default device instead of the registered
	// one (and MASQUE/chain connects fail their account checks outright).
	if err := ensureAccount(ctx, opts); err != nil {
		return fmt.Errorf("account: %w", err)
	}

	// The user-facing protocol name every stage log below is stamped with.
	userProto := opts.proto
	// Chained connects render as their carrier (wwarp → wg/awg, masque-mm →
	// masque), so the state file must be told which name to record; otherwise a
	// MASQUE-in-MASQUE session would be saved as plain MASQUE H3 and come back
	// as one tunnel instead of two.
	chainUserProto = userProto
	label := protoLabel(userProto)
	stageMsg(fmt.Sprintf("[%s] 开始连接…", label))
	// The user is waiting on this connect and needs one endpoint, so stop the
	// scan once a few are verified (the ranking still has room to pick a good
	// one). A plain `scan` leaves this at 0 and measures everything.
	if opts.earlyStop == 0 {
		opts.earlyStop = connectEarlyStop
	}

	// MASQUE in MASQUE (H3 in H3) is the masque twin of WARP-in-WARP: the inner
	// CONNECT-IP tunnel is dialled from inside the outer one, so Cloudflare
	// sees the outer edge and the inner tunnel is handed a second exit. Like
	// wwarp it is normalised into the engine's chain form — opts.proto becomes
	// the inner run (masque), opts.through the outer endpoint — and the render
	// emits two masque outbounds with dialer-proxy.
	if opts.proto == protoMASQUEMASQUE {
		opts.outerProto = protoMASQUE
		opts.innerProto = protoMASQUE
		if opts.through == "" {
			stageMsg(fmt.Sprintf("[%s] 选择外层端点…", label))
			endpoint, err := pickOuterEndpoint(ctx, opts)
			if err != nil {
				return err
			}
			opts.through = endpoint
			opts.outerAutoPicked = true
			stageMsg(fmt.Sprintf("[%s] 外层端点 %s", label, endpoint))
		}
		// One outer netstack, one worker: parallel inner dials would all share
		// the single outer QUIC connection.
		if opts.tunnelParallel == defaultTunnelJobs {
			opts.tunnelParallel = nestedTunnelJobs
		}
		opts.proto = protoMASQUE
	}

	// WARP-in-WARP is one of the five first-class protocols but not a wire
	// protocol: normalise it into the engine's chain form — proto = outer
	// carrier, innerProto = inner tunnel, through = outer endpoint — before
	// anything below looks at opts.
	if opts.proto == protoWWarp {
		if opts.outerProto == "" {
			opts.outerProto = protoWG
		}
		for _, p := range []string{opts.outerProto, opts.innerProto} {
			if p != protoWG && p != protoAWG {
				return fmt.Errorf("WARP-in-WARP 的外层/内层协议必须是 wg 或 awg，不是 %q", p)
			}
		}
		if opts.through == "" {
			stageMsg(fmt.Sprintf("[%s] 选择外层端点…", label))
			if _, ok := cachedScanFor(opts.outerProto, opts.ipv6); !ok {
				stageMsg(fmt.Sprintf("[%s] 外层端点无缓存，先扫描外层（约 1-2 分钟）…", label))
			}
			endpoint, err := pickOuterEndpoint(ctx, opts)
			if err != nil {
				return err
			}
			opts.through = endpoint
			opts.outerAutoPicked = true
			stageMsg(fmt.Sprintf("[%s] 外层端点 %s", label, endpoint))
		}
		// One outer netstack, one worker: parallel inner tunnels tear it down
		// (the same nestedTunnelJobs applyNestedJobs enforces for -through).
		// Lowered only after the outer endpoint is picked, so the outer's own
		// scan above still runs at full parallelism.
		if opts.tunnelParallel == defaultTunnelJobs {
			opts.tunnelParallel = nestedTunnelJobs
		}
		opts.proto = opts.outerProto
	}

	// A cold cache means the scan step registers a WARP account and sweeps
	// the whole endpoint space — minutes, not seconds. Tell the user before
	// the silence so the click does not look dead.
	if opts.scanNow {
		stageMsg(fmt.Sprintf("[%s] 重新扫描端点，约 1-2 分钟，请稍候…", label))
	} else if _, ok := cachedScanFor(scanKeyFor(opts), opts.ipv6); !ok {
		stageMsg(fmt.Sprintf("[%s] 首次使用：注册账号并扫描端点，约 1-2 分钟，请稍候…", label))
	}
	stageMsg(fmt.Sprintf("[%s] 扫描 WARP 端点…", label))
	results, run, err := runCachedScan(ctx, opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// A chained scan dials the outer tunnel in-process; a warm cache does
	// not, and the mihomo render still needs the outer's identity (endpoint,
	// protocol, account keys — never its netstack). Rebuild the lightweight
	// half so a cached chain connect renders the same two-proxy config a
	// fresh one does.
	if opts.through != "" && outer == nil {
		endpoint, err := parseEndpointSpec("-through", opts.through)
		if err != nil {
			return err
		}
		outerRun, err := parseProto(opts.proto)
		if err != nil {
			return err
		}
		// A masque outer is authenticated by the same enrolled device as the
		// inner hop, so the WireGuard outer account is not needed for it.
		if outerAcct == nil && !outerRun.isMASQUE() {
			return fmt.Errorf("account holds no outer device: run \"register\" again")
		}
		outer = &nest{
			run:      outerRun,
			endpoint: endpoint,
			label:    fmt.Sprintf("%s (%s)", endpoint, outerRun.name),
		}
	}

	// -pick pins one endpoint; otherwise the working set is tried in cached
	// (best-first) order until one passes live tunnel verification.
	var cands []cachedEndpoint
	if opts.pick != "" {
		best, ok := pickForced(results, opts.pick)
		if !ok {
			return fmt.Errorf("endpoint %q not in the cached scan (is -proto correct? try --scan-now)", opts.pick)
		}
		cands = []cachedEndpoint{best}
	} else {
		for _, ce := range results {
			if ce.Working && ce.Endpoint != "" {
				cands = append(cands, ce)
			}
		}
		if len(cands) > connectMaxAttempts {
			cands = cands[:connectMaxAttempts]
		}
		if len(cands) == 0 {
			// A cache that is "fresh" but holds no working endpoint is useless to
			// this connect: the earlier scan may simply have run while this
			// protocol had nothing (AWG / MASQUE-H2 caches go empty that way, and
			// then never get refreshed). Rescan once instead of failing instantly
			// — an immediate failure is exactly what "clicking connect does
			// nothing, no 连接中" was.
			if !opts.scanNow {
				stageMsg(fmt.Sprintf("[%s] 缓存中无可用端点，重新扫描…", label))
				opts.scanNow = true
				return runConnectCmd(ctx, opts)
			}
			return fmt.Errorf("no working endpoint found")
		}
	}
	stageMsg(fmt.Sprintf("[%s] 可用端点 %d 个，首选 %s (%s %s)",
		label, len(cands), cands[0].Endpoint, cands[0].Country, cands[0].Colo))
	fmt.Fprintln(os.Stderr, errPal.ok(fmt.Sprintf("best endpoint: %s (%s) → %s %s",
		cands[0].Endpoint, label, cands[0].Country, cands[0].Colo)))

	// Two hops need two edges. If the outer hop landed on the same endpoint the
	// inner one is about to use, the "second exit" would be one tunnel talking
	// to itself, so move the outer to the next working endpoint.
	if outer != nil && outer.run.isMASQUE() && strings.EqualFold(outer.endpoint, cands[0].Endpoint) {
		for _, ce := range results {
			if ce.Working && ce.Endpoint != "" && !strings.EqualFold(ce.Endpoint, cands[0].Endpoint) {
				stageMsg(fmt.Sprintf("[%s] 外层换一个边缘：%s", label, ce.Endpoint))
				outer.endpoint = ce.Endpoint
				break
			}
		}
	}
	if outer != nil && outer.run.isMASQUE() {
		stageMsg(fmt.Sprintf("[%s] 外层 %s → 内层 %s", label, outer.endpoint, cands[0].Endpoint))
	}

	cDir, err := coreDir()
	if err != nil {
		return err
	}
	stageMsg(fmt.Sprintf("[%s] 准备 Clash 核心…", label))
	bin, err := core.EnsureBinary(cDir, opts.corePath)
	if err != nil {
		return fmt.Errorf("Clash 核心不可用（应位于 %s）：%w；请放入 mihomo.exe 或用底栏「核心」按钮下载", core.CoreInDir(cDir), err)
	}
	// Capability gate: never render a protocol the running core cannot parse.
	// Each probe feeds the real binary a minimal config of exactly the shape
	// connect renders and asks `mihomo -t`; anything less than a clean pass
	// means "upgrade the core" — the honest answer up front instead of an
	// unknown-field error after the config is written.
	gates := []string{userProto}
	if opts.through != "" {
		gates = append(gates, opts.innerProto)
	}
	if userProto == protoWWarp {
		gates = append(gates, opts.outerProto)
	}
	for _, p := range gates {
		if !protoSupportedBy(bin, cDir, p) {
			return fmt.Errorf("当前 Core 不支持 %s 协议配置，请升级 Core（Mihomo 官方最新版）", protoLabel(p))
		}
	}
	stageMsg(fmt.Sprintf("[%s] Clash 核心就绪，协议配置校验通过", label))
	// A client that died without disconnecting (crash, Task Manager, security
	// software) leaves its core running; that core holds the mixed and API
	// ports, and every endpoint of this connect then fails with "port still in
	// use" no matter how good it is. state.json remembers one PID and is not
	// even written when the crash comes first, so sweep by binary path.
	if n := core.KillStaleCores(bin); n > 0 {
		stageMsg(fmt.Sprintf("[%s] 清理了 %d 个残留内核进程", label, n))
	}
	// A previous core can outlive its client (crash, kill -9 of the GUI): it
	// keeps the mixed/api ports bound and the new core fails to serve. Reap
	// any recorded PID before spawning our own — KillByPID verifies the image
	// path, so a recycled PID never takes out an unrelated process.
	if st, err := loadState(); err == nil && st.CorePID > 0 {
		// A live prior connect also left the system proxy pointing at itself.
		// Restore the pre-connect baseline now, so the snapshot this connect
		// takes captures the user's real proxy state instead of our leftovers.
		if st.Connected && !st.TUN && len(st.ProxySnap) > 0 {
			var snap core.ProxySnapshot
			if json.Unmarshal(st.ProxySnap, &snap) == nil {
				_ = core.UnsetSystemProxy(&snap)
			}
		}
		if kerr := core.KillByPID(st.CorePID, bin); kerr == nil {
			fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("killed stale core (pid %d)", st.CorePID)))
		}
	}

	var lastErr error
	for i, ce := range cands {
		if i > 0 {
			stageMsg(fmt.Sprintf("[%s] 端点 %s 隧道不通，换下一个…", label, cands[i-1].Endpoint))
		}
		stageMsg(fmt.Sprintf("[%s] 连接 %s（第 %d/%d 个）…", label, ce.Endpoint, i+1, len(cands)))
		state, serr := startAndVerify(ctx, opts, ce, run, bin, cDir, label, nil)
		if serr == nil {
			if err := saveState(state); err != nil {
				fmt.Fprintln(os.Stderr, errPal.warn("state not persisted: "+err.Error()))
			}
			stageMsg(fmt.Sprintf("[%s] 连接成功", label))
			fmt.Fprintln(os.Stderr, errPal.ok(state.statusLine()))
			if state.ProxyWarn != "" {
				fmt.Fprintln(os.Stderr, errPal.warn("系统代理设置被拦截: "+state.ProxyWarn))
				fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("请手动把系统/浏览器代理指向 127.0.0.1:%d，或将本程序加入安全软件白名单后重连", opts.mixedPort)))
			}
			if opts.tunMode {
				fmt.Fprintln(os.Stderr, errPal.warn("TUN mode requires running with administrator rights"))
			}
			// A CLI connect returns while its core keeps serving, so no process
			// of ours is left to notice the moment the endpoint stops passing
			// traffic - the "connected, nothing loads" state this whole file
			// exists to prevent. Whichever frontend started it, the session
			// gets one watcher; ensureSessionGuard is idempotent, and the GUI
			// takes ownership of its own sessions from its status loop.
			// The settings page's "auto repair" switch is the one way out: with
			// it off the session simply is not watched.
			if !opts.noGuard {
				ensureSessionGuard(state)
			}
			return nil
		}
		lastErr = serr
		// A cancelled attempt stops here: marking the endpoint dead or trying
		// the next one would keep a session the user already abandoned alive,
		// and the retry loop could still end up reporting success.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("endpoint %s: %v", ce.Endpoint, serr)))
		markEndpointDead(opts, ce)
		stageMsg(fmt.Sprintf("[%s] 端点 %s 已标记为 failed", label, ce.Endpoint))
	}

	// Every cached candidate failed: the cache is stale as a whole, not just
	// one endpoint. A fresh scan heals it for this connect and every later one.
	if opts.pick == "" && !opts.scanNow {
		stageMsg(fmt.Sprintf("[%s] 缓存端点全部失活，重新扫描端点，约 1-2 分钟…", label))
		opts.scanNow = true
		// A chain pins its outer endpoint once, so when every inner candidate
		// died the outer itself is the suspect. Drop an auto-picked outer so
		// the retry rescans and re-picks it; a -through the user asked for
		// stays pinned, exactly like -pick does for the inner.
		if opts.outerAutoPicked {
			opts.through = ""
			opts.outerAutoPicked = false
			stageMsg(fmt.Sprintf("[%s] 外层端点一并重选…", label))
		}
		return runConnectCmd(ctx, opts)
	}

	// Reflect reality in state.json: the stale core was reaped at the top, so
	// an untouched connected:true would leave the GUI showing a tunnel that
	// is not there.
	if st, err := loadState(); err == nil && st.Connected {
		st.Connected = false
		_ = saveState(st)
	}
	return fmt.Errorf("connect failed: tunnel verification failed on %d endpoint(s): %w", len(cands), lastErr)
}

// runConnectPsiphon wires the V1 Psiphon exit as a two-axis session: the base
// protocol (WG/AWG/MASQUE) comes up first and its own outbound carries Psiphon's
// server dials, then Psiphon exposes a localhost SOCKS5 that becomes the client's
// final egress. The host's public exit is Psiphon's, not the base protocol's.
//
// Direct Psiphon — a bare socks5 exit with no base protocol (the "wrong plan 2")
// — is deliberately gone: on the networks V1 targets Psiphon cannot dial its own
// servers directly, so a session without an underlay never establishes a tunnel.
func runConnectPsiphon(ctx context.Context, opts options) error {
	if opts.mixedPort == 0 {
		opts.mixedPort = core.DefaultMixedPort
	}
	if opts.apiPort == 0 {
		opts.apiPort = core.DefaultAPIPort
	}
	// V1 supports Psiphon only on a plain WG/AWG/MASQUE underlay, never on a
	// chain — a WARP-in-WARP is two WARP devices and Psiphon's SOCKS has no
	// place in it. Refuse rather than render something undefined.
	if opts.proto == protoWWarp || opts.proto == protoMASQUEMASQUE || opts.through != "" {
		return fmt.Errorf("Psiphon 暂不支持与嵌套协议（GOOL / MASQUE in MASQUE）组合：请用 wg / awg / masque 作为基础协议")
	}
	// outer is a package global a nested scan sets; a long-lived GUI process must
	// not inherit a stale chain, or the config would name an outbound that is not
	// in the two-axis render (Psiphon never chains).
	outer = nil
	cDir, err := coreDir()
	if err != nil {
		return err
	}
	exe, err := resolvePsiphonExe(opts, cDir)
	if err != nil {
		return err
	}
	baseConfig, err := resolvePsiphonClientConfig(cDir)
	if err != nil {
		return err
	}

	label := protoLabel(opts.proto) + "+Psiphon"
	stageMsg(fmt.Sprintf("[%s] 开始连接：先起基础协议，Psiphon 骑在其上…", label))

	if err := ensureAccount(ctx, opts); err != nil {
		return fmt.Errorf("account: %w", err)
	}
	results, run, err := runCachedScan(ctx, opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	var cands []cachedEndpoint
	if opts.pick != "" {
		best, ok := pickForced(results, opts.pick)
		if !ok {
			return fmt.Errorf("endpoint %q not in the cached scan (is -proto correct? try --scan-now)", opts.pick)
		}
		cands = []cachedEndpoint{best}
	} else {
		for _, ce := range results {
			if ce.Working && ce.Endpoint != "" {
				cands = append(cands, ce)
			}
		}
		if len(cands) > connectMaxAttempts {
			cands = cands[:connectMaxAttempts]
		}
		if len(cands) == 0 {
			// Nothing usable in the cache/scan: rescan rather than give up.
			if !opts.scanNow {
				stageMsg(fmt.Sprintf("[%s] 无可用基础端点，重新扫描…", label))
				opts.scanNow = true
				return runConnectPsiphon(ctx, opts)
			}
			return fmt.Errorf("no working endpoint found")
		}
	}

	bin, err := core.EnsureBinary(cDir, opts.corePath)
	if err != nil {
		return err
	}
	if !protoSupportedBy(bin, cDir, opts.proto) {
		return fmt.Errorf("当前 Core 不支持 %s 协议配置，请升级 Core（Mihomo 官方最新版）", protoLabel(opts.proto))
	}
	// Reap anything a previous session left behind: the core and the Psiphon
	// sidecar both outlive the CLI, and both hold ports the new session needs.
	if st, lerr := loadState(); lerr == nil {
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
			if kerr := core.KillByPID(st.PsiphonPID, exe); kerr == nil {
				fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("killed stale psiphon (pid %d)", st.PsiphonPID)))
			}
		}
	}

	// A fixed local SOCKS port lets mihomo's config name the Psiphon exit before
	// Psiphon exists — Psiphon needs mihomo (its upstream) and mihomo's rules
	// need Psiphon's port, so a dynamic port would deadlock the two.
	psPort, err := pickFreePort()
	if err != nil {
		return err
	}
	launch := psiphonLaunch{
		ExePath:        exe,
		DataDir:        filepath.Join(cDir, "psiphon-data"),
		BaseConfigPath: baseConfig,
		Upstream:       fmt.Sprintf("socks5://127.0.0.1:%d", underlaySocksPort(opts.mixedPort)),
		SocksPort:      psPort,
		EgressRegion:   opts.psiphonRegion,
	}
	opts.psiphonMode = true
	opts.psiphonSocksPort = psPort

	var lastErr error
	for i, ce := range cands {
		if i > 0 {
			stageMsg(fmt.Sprintf("[%s] 基础端点 %s 不通，换下一个…", label, cands[i-1].Endpoint))
		}
		stageMsg(fmt.Sprintf("[%s] 连接基础端点 %s（第 %d/%d 个）…", label, ce.Endpoint, i+1, len(cands)))
		state, serr := connectPsiphonOn(ctx, opts, ce, run, bin, cDir, label, launch)
		if serr == nil {
			if err := saveState(state); err != nil {
				fmt.Fprintln(os.Stderr, errPal.warn("state not persisted: "+err.Error()))
			}
			stageMsg(fmt.Sprintf("[%s] 连接成功（出口 = Psiphon）", label))
			fmt.Fprintln(os.Stderr, errPal.ok(state.statusLine()))
			if opts.tunMode {
				fmt.Fprintln(os.Stderr, errPal.warn("TUN mode requires running with administrator rights"))
			}
			// A CLI connect returns while both cores keep serving, so the session
			// outlives this process and needs exactly one watcher. The guard is
			// Psiphon-aware: it repairs a Psiphon session by restarting Psiphon,
			// never by rotating the underlay (see psiphon_health.go).
			if !opts.noGuard {
				ensureSessionGuard(state)
			}
			return nil
		}
		lastErr = serr
		fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("基础端点 %s: %v", ce.Endpoint, serr)))
		// Deliberately NOT markEndpointDead: a Psiphon tunnel failure does not
		// prove the underlay endpoint is dead (Psiphon owns its own servers),
		// and evicting a healthy WARP endpoint here would poison the cache.
	}
	// Every candidate failed: the scan snapshot is stale as a whole. Rescan
	// once (as runConnectCmd does) instead of reporting a dead network — a
	// fresh sweep is what finds endpoints the last one missed.
	if opts.pick == "" && !opts.scanNow {
		stageMsg(fmt.Sprintf("[%s] 基础端点全部不通，重新扫描端点…", label))
		opts.scanNow = true
		return runConnectPsiphon(ctx, opts)
	}
	return fmt.Errorf("connect failed: Psiphon 隧道验证失败于 %d 个基础端点: %w", len(cands), lastErr)
}

// runConnectOpenVPN wires the V2 OpenVPN exit into the same two-axis shape as
// Psiphon: the base protocol (WG/AWG/MASQUE) comes up first and carries the
// exit's dials, then mihomo's native openvpn outbound — pointed at one VPN Gate
// relay — becomes the client's final egress. No external OpenVPN binary and no
// sidecar SOCKS port: dialer-proxy chains the outbounds inside one core.
func runConnectOpenVPN(ctx context.Context, opts options) error {
	if opts.mixedPort == 0 {
		opts.mixedPort = core.DefaultMixedPort
	}
	if opts.apiPort == 0 {
		opts.apiPort = core.DefaultAPIPort
	}
	// The relay rides the base protocol, so a nested base would need a third
	// outbound for no benefit. Refuse it here, exactly like Psiphon does.
	if protoChained(opts.proto) || opts.through != "" {
		return fmt.Errorf("OpenVPN 出口暂不支持与嵌套协议（GOOL / MASQUE in MASQUE）组合：请用 wg / awg / masque 作为基础协议")
	}
	// VPN Gate relays are IPv4-only, and mihomo's openvpn outbound cannot carry
	// an IPv6 tunnel. Forcing v4 here also keys the scan cache correctly and
	// keeps verifyTunnel from demanding an IPv6 round-trip the exit cannot do.
	opts.family = famV4
	opts.ipv6 = false
	outer = nil
	// An interactive connect shops for a usable exit; the health repair builds
	// its own options and deliberately leaves this off.
	opts.openvpnSpeedGate = true

	label := protoLabel(opts.proto) + "+OpenVPN"
	stageMsg(fmt.Sprintf("[%s] 开始连接：先起基础协议，再经 VPN Gate 节点出站…", label))

	if err := ensureAccount(ctx, opts); err != nil {
		return fmt.Errorf("account: %w", err)
	}
	stageMsg(fmt.Sprintf("[%s] 账号就绪，读取/扫描基础端点…", label))
	results, run, err := runCachedScan(ctx, opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	var cands []cachedEndpoint
	if opts.pick != "" {
		best, ok := pickForced(results, opts.pick)
		if !ok {
			return fmt.Errorf("endpoint %q not in the cached scan (is -proto correct? try --scan-now)", opts.pick)
		}
		cands = []cachedEndpoint{best}
	} else {
		for _, ce := range results {
			if ce.Working && ce.Endpoint != "" {
				cands = append(cands, ce)
			}
		}
		if len(cands) > connectMaxAttempts {
			cands = cands[:connectMaxAttempts]
		}
		if len(cands) == 0 {
			if !opts.scanNow {
				stageMsg(fmt.Sprintf("[%s] 无可用基础端点，重新扫描…", label))
				opts.scanNow = true
				return runConnectOpenVPN(ctx, opts)
			}
			return fmt.Errorf("no working endpoint found")
		}
	}
	stageMsg(fmt.Sprintf("[%s] 基础端点 %d 个可用", label, len(cands)))

	cDir, err := coreDir()
	if err != nil {
		return err
	}
	stageMsg(fmt.Sprintf("[%s] 准备 Clash 核心…", label))
	bin, err := core.EnsureBinary(cDir, opts.corePath)
	if err != nil {
		return fmt.Errorf("Clash 核心不可用（应位于 %s）：%w；请放入 mihomo.exe 或用底栏「核心」按钮下载", core.CoreInDir(cDir), err)
	}
	if !protoSupportedBy(bin, cDir, opts.proto) {
		return fmt.Errorf("当前 Core 不支持 %s 协议配置，请升级 Core（Mihomo 官方最新版）", protoLabel(opts.proto))
	}
	if !protoSupportedBy(bin, cDir, probeOpenVPNProto) {
		return fmt.Errorf("当前 Core 不支持 OpenVPN 出站配置，请升级 Core（Mihomo 官方最新版）")
	}
	stageMsg(fmt.Sprintf("[%s] Clash 核心就绪，协议配置校验通过", label))
	// Reap anything a previous session left behind: the core outlives the CLI,
	// and its pid would otherwise keep the mixed port and the state file busy.
	if st, lerr := loadState(); lerr == nil {
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
	}

	// The relay pool: cached list first, live fetch otherwise. VPN Gate is often
	// blocked from this network directly, so the fetch can ride the base scan's
	// netstack (fetchVPNGateViaWARP) before any session exists.
	nodes, err := vpnGateNodesFor(ctx, results, run, opts.scanNow)
	if err != nil {
		return fmt.Errorf("获取 VPN Gate 节点失败: %w", err)
	}
	relays := vpnGateCandidates(ctx, nodes, opts.openvpnRegion, opts.openvpnNodePin, vpnGateConnectNodes)
	// Reconnects should reuse the relay that last carried traffic instead of
	// walking the class/latency ladder again. A manual pin always wins, and a
	// region that still has relays of its own is not overridden.
	relays = preferLastGoodVPNGate(relays, opts.openvpnNodePin, opts.openvpnRegion)
	if len(relays) == 0 {
		if opts.openvpnRegion != "" {
			return fmt.Errorf("VPN Gate 当前没有 %s 地区的可用节点，请换一个出口地区", opts.openvpnRegion)
		}
		return fmt.Errorf("VPN Gate 节点列表为空，请稍后重试")
	}
	measured := 0
	for _, n := range relays {
		if n.MeasuredBps > 0 {
			measured++
		}
	}
	if measured > 0 {
		stageMsg(fmt.Sprintf("[%s] 中继速度记忆：%d 个有实测记录，排序已按实测速度优先", label, measured))
	}
	stageMsg(fmt.Sprintf("[%s] 出口候选：%d 个基础端点 × %d 个 VPN Gate 节点（最多尝试 %d 组）",
		label, len(cands), len(relays), min(openvpnMaxAttempts, len(cands)*len(relays))))

	var lastErr error
	tried := 0
	slowRejects := 0
	for _, ce := range cands {
		for i := range relays {
			if tried >= openvpnMaxAttempts {
				break
			}
			// A cancelled attempt must stop the retry loop here: without this
			// the loop kept going, started core after core, and finally
			// reported success for an attempt the user had already abandoned.
			if err := ctx.Err(); err != nil {
				return err
			}
			tried++
			node := relays[i]
			opts.openvpnNode = &node
			stageMsg(fmt.Sprintf("[%s] 基础端点 %s + 出口节点 %s（%s，组合 %d/%d）…",
				label, ce.Endpoint, node.id(), node.CountryShort, tried, min(openvpnMaxAttempts, len(cands)*len(relays))))
			state, serr := startAndVerify(ctx, opts, ce, run, bin, cDir, label, nil)
			if serr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				var slow *slowRelayError
				if errors.As(serr, &slow) {
					// The relay works; only its throughput is unusable. Keep it
					// out of the failure memory — the speed memory already ranks
					// it behind everything else — and spend the next attempt on a
					// different relay.
					lastErr = serr
					slowRejects++
					stageMsg(fmt.Sprintf("[%s] 出口速度过慢（≈%d KB/s），换下一个中继…", label, slow.bps/1024))
					if slowRejects >= openvpnSpeedRetries {
						opts.openvpnAcceptSlow = true
						stageMsg(fmt.Sprintf("[%s] 已连续 %d 个中继偏慢，后续优先保持连接、不再因速度换节点", label, slowRejects))
					}
					continue
				}
			}
			if serr == nil {
				clearVPNGateFailure(node.id())
				rememberLastGoodVPNGate(node)
				if err := saveState(state); err != nil {
					fmt.Fprintln(os.Stderr, errPal.warn("state not persisted: "+err.Error()))
				}
				stageMsg(fmt.Sprintf("[%s] 连接成功（出口 = VPN Gate %s）", label, node.CountryShort))
				// Say it out loud when the session landed somewhere else: the
				// region is a preference, so a fallback is legitimate — but a
				// silent one looks like the selector is broken.
				if opts.openvpnRegion != "" && !strings.EqualFold(node.CountryShort, opts.openvpnRegion) {
					stageMsg(fmt.Sprintf("[%s] 注意：所选地区 %s 的节点都没连上，本次已改用 %s",
						label, opts.openvpnRegion, node.CountryShort))
				}
				fmt.Fprintln(os.Stderr, errPal.ok(state.statusLine()))
				if opts.tunMode {
					fmt.Fprintln(os.Stderr, errPal.warn("TUN mode requires running with administrator rights"))
				}
				if !opts.noGuard {
					ensureSessionGuard(state)
				}
				return nil
			}
			lastErr = serr
			fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf("组合 %s + %s: %v", ce.Endpoint, node.id(), serr)))
			// Deliberately NOT markEndpointDead: a relay failure says nothing
			// about the WARP underlay, and evicting a healthy endpoint here would
			// poison the scan cache for every later session.
			if serr != nil && strings.Contains(serr.Error(), "base endpoint") {
				// A dead underlay fails every relay; move on to the next base
				// instead of burning the remaining combinations on it.
				break
			}
			// The relay itself failed; the phone client's 10-minute memory keeps
			// the next attempt (or the automatic retry scan) off this node.
			markVPNGateFailed(node.id())
		}
		if tried >= openvpnMaxAttempts {
			break
		}
	}
	// Every combination failed: the snapshot may be stale on both axes. One
	// fresh scan and a forced VPN Gate refetch, then report honestly.
	if opts.pick == "" && !opts.scanNow {
		stageMsg(fmt.Sprintf("[%s] 全部组合失败，重新扫描基础端点并刷新 VPN Gate 节点…", label))
		opts.scanNow = true
		return runConnectOpenVPN(ctx, opts)
	}
	return fmt.Errorf("connect failed: OpenVPN 出口在 %d 个组合上均未通过验证: %w", tried, lastErr)
}

// warmupOpenVPN keeps triggering the chained openvpn outbound until it really
// carries a request. mihomo's inbound gives up on a dial after 5s while the
// outbound keeps its handshake alive for handshake-timeout seconds, so the
// first requests through a fresh session are expected to fail; verifyTunnel
// would otherwise see a dead-looking tunnel on a perfectly healthy relay.
func warmupOpenVPN(ctx context.Context, mixedPort int, label string) error {
	proxyURL := mustParseURL("http://127.0.0.1:" + strconv.Itoa(mixedPort))
	client := &http.Client{
		Timeout: openvpnWarmupReqTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	// Plain HTTP on purpose: the exit only has to prove it forwards bytes, and
	// a TLS handshake through a 1s-RTT relay adds time to every attempt.
	target := "http://www.gstatic.com/generate_204"
	deadline := time.Now().Add(openvpnWarmupWindow)
	started := time.Now()
	attempts := 0
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempts++
		resp, err := client.Get(target)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent || (resp.StatusCode >= 200 && resp.StatusCode < 400) {
				stageMsg(fmt.Sprintf("[%s] OpenVPN 中继握手完成（第 %d 次探测，%ds）", label, attempts, int(time.Since(started).Seconds())))
				return nil
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		lastErr = err
		if attempts%3 == 0 {
			stageMsg(fmt.Sprintf("[%s] OpenVPN 中继握手中…（%ds）", label, int(time.Since(started).Seconds())))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有请求完成")
	}
	return fmt.Errorf("OpenVPN 中继握手超时（%s 内未建链）: %w", openvpnWarmupWindow, lastErr)
}

// watchOpenVPNLogs follows mihomo's log stream and reports a terminal relay
// failure. The warm-up's HTTP requests only see an opaque 502 when the
// outbound refuses the credentials, so the reason has to come from the core's
// own log. The stream disappearing (old core, no API) is harmless: warm-up
// then falls back to its time window.
func watchOpenVPNLogs(ctx context.Context, apiPort int) (<-chan string, func()) {
	fatal := make(chan string, 1)
	streamCtx, cancel := context.WithCancel(ctx)
	go func() {
		url := "http://127.0.0.1:" + strconv.Itoa(apiPort) + "/logs?level=info"
		req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, url, nil)
		if err != nil {
			return
		}
		client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return
		}
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 4096), 1<<20)
		for sc.Scan() {
			if reason := vpnAuthFailure(sc.Text()); reason != "" {
				select {
				case fatal <- reason:
				default:
				}
				return
			}
		}
	}()
	return fatal, cancel
}

// vpnAuthFailure recognises a definitive OpenVPN credential rejection. This
// must stay narrow: a handshake timeout may still succeed on a retry, an
// AUTH_FAILED never does.
func vpnAuthFailure(line string) string {
	low := strings.ToLower(line)
	if strings.Contains(low, "auth_failed") || strings.Contains(low, "openvpn authentication failed") {
		return "AUTH_FAILED"
	}
	return ""
}

// connectPsiphonOn runs one two-axis attempt: render the base-protocol + Psiphon
// config, start mihomo, let startAndVerify's hook bring Psiphon up behind it and
// wait for a real tunnel, then verify traffic through the mixed port (which now
// exits via Psiphon). The base protocol is never verified on its own — the only
// thing that matters is that the final exit passes real traffic.
func connectPsiphonOn(ctx context.Context, opts options, ce cachedEndpoint, run protoRun, bin, cDir, label string, l psiphonLaunch) (clientState, error) {
	ps := &Psiphon{}
	state, err := startAndVerify(ctx, opts, ce, run, bin, cDir, label, func() error {
		// Fail fast. The scan verifies an endpoint inside its own netstack, which
		// says nothing about whether mihomo's outbound can actually forward
		// through it — and a dead underlay must cost seconds, not the whole
		// Psiphon tunnel wait. Probe the underlay inbound once before Psiphon.
		under := underlaySocksPort(opts.mixedPort)
		if err := probeUnderlaySocks(ctx, under, 8*time.Second); err != nil {
			return fmt.Errorf("underlay 数据面不可用 (socks 127.0.0.1:%d): %w", under, err)
		}
		stageMsg(fmt.Sprintf("[%s] underlay 数据面可用，启动 Psiphon（上游 %s）…", label, l.Upstream))
		if err := ps.Start(ctx, l); err != nil {
			return fmt.Errorf("psiphon start: %w", err)
		}
		if err := ps.WaitForSocks(ctx, 60*time.Second); err != nil {
			return fmt.Errorf("psiphon socks not ready: %w", err)
		}
		stageMsg(fmt.Sprintf("[%s] Psiphon SOCKS 127.0.0.1:%d 就绪，等待隧道…", label, ps.Port()))
		if err := ps.WaitForTunnel(ctx, psiphonTunnelWait); err != nil {
			return err
		}
		stageMsg(fmt.Sprintf("[%s] Psiphon 隧道已建立", label))
		return nil
	})
	if err != nil {
		_ = ps.Stop()
		return clientState{}, err
	}
	// Give Psiphon another draw when it landed on an unusably slow server: the
	// exit alone decides its throughput (measured spread ~150–700 KB/s behind the
	// same underlay). A restart reuses the SAME SOCKS port, so mihomo's rendered
	// config keeps pointing at it. Slow-but-working is accepted, never failed.
	for attempt := 0; ; attempt++ {
		bps := measureDownBps(opts.mixedPort, psiphonSpeedProbeBytes, psiphonSpeedProbeTimeout)
		if bps <= 0 {
			break
		}
		stageMsg(fmt.Sprintf("[%s] Psiphon 出口速度 ≈ %d KB/s", label, bps/1024))
		if bps >= psiphonMinBps || attempt >= psiphonSpeedRetries {
			break
		}
		stageMsg(fmt.Sprintf("[%s] 出口过慢（<%d KB/s），重启 Psiphon 换服务器…", label, psiphonMinBps/1024))
		if serr := ps.Stop(); serr != nil {
			break
		}
		if serr := ps.Start(ctx, l); serr != nil {
			break
		}
		if serr := ps.WaitForSocks(ctx, 60*time.Second); serr != nil {
			break
		}
		if serr := ps.WaitForTunnel(ctx, psiphonTunnelWait); serr != nil {
			break
		}
	}
	// startAndVerify already proved a real request completed through the mixed
	// port (which exits via Psiphon) — record that as the terminal lifecycle
	// state, distinct from "SOCKS up" and "tunnel established".
	ps.MarkRealTrafficReady()
	// Proto stays the base protocol (A1): the exit switch lives in PsiphonMode,
	// so a "WG" session with Psiphon on is Proto=wg + PsiphonMode=true, never a
	// fabricated "Psiphon" protocol that health/repair would mis-route.
	state.PsiphonMode = true
	state.PsiphonPID = ps.PID()
	state.PsiphonSocksPort = ps.Port()
	state.PsiphonRegion = opts.psiphonRegion
	return state, nil
}

// underlayProbeHost is a tiny, reliable HTTP endpoint: gstatic's generate_204
// answers 204 with an empty body, so the status line alone is a full round-trip.
const underlayProbeHost = "www.gstatic.com:80"

// probeUnderlaySocks proves the underlay actually carries data end to end: it
// opens a SOCKS5 connection through the base protocol's dedicated localhost SOCKS
// and requires a real HTTP response. A bare SOCKS CONNECT is NOT enough — for a
// WireGuard-family outbound mihomo dials on the gVisor stack and can answer the
// CONNECT before any packet has crossed the tunnel, so "connect succeeded" is a
// false positive on exactly the dead underlay this check exists to catch.
func probeUnderlaySocks(ctx context.Context, port int, timeout time.Duration) error {
	if port <= 0 {
		return fmt.Errorf("underlay socks 端口未知")
	}
	conn, err := socks5Dial(ctx, port, underlayProbeHost, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(conn, "GET /generate_204 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", underlayProbeHost); err != nil {
		return fmt.Errorf("underlay 写入失败: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("underlay 无响应（基础协议 outbound 未承载流量）: %w", err)
	}
	if !strings.HasPrefix(line, "HTTP/") {
		return fmt.Errorf("underlay 响应异常: %q", strings.TrimSpace(line))
	}
	return nil
}

// socks5Dial opens a no-auth SOCKS5 connection through the localhost SOCKS at
// socksPort to addr ("host:port"), sending the host as a domain name so the exit
// resolves it (SOCKS5h) — the probe then never depends on the host's resolver.
func socks5Dial(ctx context.Context, socksPort int, addr string, timeout time.Duration) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("probe addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("probe addr %q: %w", addr, err)
	}
	if host == "" || len(host) > 255 {
		return nil, fmt.Errorf("probe host %q invalid", host)
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)))
	if err != nil {
		return nil, fmt.Errorf("连接 underlay SOCKS 失败: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// Greeting: VER=5, NMETHODS=1, METHODS=[0x00] (no auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("underlay SOCKS 无响应: %w", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("underlay SOCKS 未接受无认证 (% x)", greeting[:])
	}
	// CONNECT host:port with ATYP=0x03 (domain name).
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("underlay CONNECT 无响应: %w", err)
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("underlay 拒绝 CONNECT (SOCKS code %d)", head[1])
	}
	// Drain the bound address that follows the reply head.
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(l[0]) + 2
	default:
		conn.Close()
		return nil, fmt.Errorf("underlay 响应地址类型未知 (%d)", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// startAndVerify renders the config for one endpoint, starts the core, and
// proves the tunnel passes traffic through the local mixed port — all BEFORE
// the system proxy is touched, so the host is never pointed at a tunnel that
// does not pass traffic. Only after the data plane is verified is the proxy
// set (and a blocked proxy edit degrades to a warning, never a teardown of a
// working tunnel). On verification failure the core is stopped and nothing
// host-side was mutated, so the candidate loop retries on a clean machine.
// The optional afterReady hook runs once the core is listening but before the
// data plane is verified: the Psiphon exit uses it to bring its sidecar up (and
// wait for a real tunnel) so the verification below already exercises the final
// egress. Every non-Psiphon caller passes nil and the flow is unchanged.
func startAndVerify(ctx context.Context, opts options, ce cachedEndpoint, run protoRun, bin, cDir, label string, afterReady func() error) (clientState, error) {
	configYAML, err := renderClientConfig(opts, ce, run)
	if err != nil {
		return clientState{}, err
	}
	c, err := core.New(core.Config{
		BinaryPath: bin,
		WorkDir:    cDir,
		MixedPort:  opts.mixedPort,
		APIPort:    opts.apiPort,
		TUN:        opts.tunMode,
		// A coreLog is attached only by the GUI (its log panel tee): that is
		// exactly the session type whose core must die with the client. The
		// CLI connect returns and leaves the core serving on purpose.
		TieCoreToClient: opts.coreLog != nil,
		LogWriter:       opts.coreLog,
	})
	if err != nil {
		return clientState{}, err
	}
	if c.Running() {
		return clientState{}, fmt.Errorf("core already running - disconnect first")
	}
	stageMsg(fmt.Sprintf("[%s] 生成并写入 Clash 配置…", label))
	if err := c.WriteConfig(configYAML); err != nil {
		return clientState{}, err
	}
	stageMsg(fmt.Sprintf("[%s] 启动 Clash 核心…", label))
	if err := c.Start(); err != nil {
		return clientState{}, err
	}
	stageMsg(fmt.Sprintf("[%s] Core 已启动 (PID=%d)，等待隧道就绪…", label, c.PID()))
	waitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := c.WaitReady(waitCtx); err != nil {
		_ = c.Stop()
		// A crash carries an actionable cause; say it here rather than leaving
		// the user with "not ready" five times in a row.
		var crash *core.CrashError
		if errors.As(err, &crash) {
			stageMsg(fmt.Sprintf("[%s] %s", label, crash.Hint()))
		}
		return clientState{}, err
	}
	stageMsg(fmt.Sprintf("[%s] 隧道就绪，开始数据面验证…", label))
	if afterReady != nil {
		if err := afterReady(); err != nil {
			_ = c.Stop()
			return clientState{}, err
		}
	}
	// The chained openvpn outbound handshakes lazily on its first dial and
	// outlives the inbound's 5s dial timeout, so the tunnel is warmed up with
	// repeated requests before verifyTunnel judges it. A relay that cannot link
	// within the window is a dead candidate, not a slow one.
	if opts.openvpnMode {
		stageMsg(fmt.Sprintf("[%s] 预热 OpenVPN 中继（握手窗口 %s）…", label, openvpnWarmupWindow))
		warmCtx, cancelWarm := context.WithCancel(ctx)
		fatalCh, stopWatch := watchOpenVPNLogs(warmCtx, opts.apiPort)
		warmDone := make(chan error, 1)
		go func() { warmDone <- warmupOpenVPN(warmCtx, opts.mixedPort, label) }()
		select {
		case werr := <-warmDone:
			stopWatch()
			if werr != nil {
				_ = c.Stop()
				return clientState{}, werr
			}
		case reason := <-fatalCh:
			// AUTH_FAILED is terminal for this relay: retrying the same node
			// only spends the rest of the window before rotating anyway.
			cancelWarm()
			stopWatch()
			_ = c.Stop()
			return clientState{}, fmt.Errorf("OpenVPN 出口认证被拒绝（%s），立即换节点", reason)
		}
	}

	// mihomo listening says nothing about the tunnel: with a dead endpoint the
	// proxy accepts CONNECT, the dial through the dark tunnel times out, and
	// every page fails. Only completed round-trips through the mixed port
	// (HTTPS, DNS via the hostname, optional IPv6, exit IP) prove it. The
	// system proxy is still untouched here — a failed candidate leaves no
	// host mutation to undo.
	probe, perr := verifyTunnel(opts, func(msg string) { stageMsg(fmt.Sprintf("[%s] %s", label, msg)) })
	if perr != nil {
		_ = c.Stop()
		return clientState{}, fmt.Errorf("数据面验证失败: %w", perr)
	}

	// A relay that passed every data-plane check can still be unusable: the
	// verification transfer also measured its throughput, and a VPN Gate relay
	// under the floor makes every page crawl. Remember the measurement for the
	// picker's ranking, then rotate — bounded by the loop, so a network where
	// every relay is slow still ends connected instead of failing.
	if opts.openvpnMode && opts.openvpnNode != nil && probe.MeasuredBps > 0 {
		bps := probe.MeasuredBps
		rememberVPNGateSpeed(opts.openvpnNode.id(), bps)
		stageMsg(fmt.Sprintf("[%s] 出口实测速度 ≈ %d KB/s", label, bps/1024))
		// A pinned relay is the user's choice: report its speed, never rotate
		// away from it on speed alone.
		if opts.openvpnSpeedGate && opts.openvpnNodePin == "" && bps < openvpnMinBps {
			if !opts.openvpnAcceptSlow {
				_ = c.Stop()
				return clientState{}, &slowRelayError{bps: bps}
			}
			stageMsg(fmt.Sprintf("[%s] 出口偏慢（低于 %d KB/s），但已无更快的候选，保留当前连接", label, openvpnMinBps/1024))
		}
	}

	// The user-facing protocol: a dialer-proxy chain is WARP-in-WARP or MASQUE
	// in MASQUE, not the carrier it happens to be rendered as.
	protoName := run.name
	if chainUserProto != "" {
		protoName = chainUserProto
	} else if opts.through != "" {
		protoName = protoWWarp
	}
	state := clientState{
		Proto:     protoName,
		Endpoint:  ce.Endpoint,
		Country:   ce.Country,
		Colo:      ce.Colo,
		NodeCity:  ce.NodeCity,
		LatencyMS: ce.EpPingMS,
		TunLatMS:  ce.TunPingMS,
		Connected: true,
		MixedPort: opts.mixedPort,
		APIPort:   opts.apiPort,
		CorePID:   c.PID(),
		TUN:       opts.tunMode,
		AllowLan:  opts.allowLan,
		Family:    opts.ipFamily(),
		NoProxy:   opts.noProxy,
		StartedAt: time.Now().Format(time.RFC3339),
		// Recorded so a health repair rebuilds the same session, not a default
		// one: see clientState.ProxyMode.
		ProxyMode:    opts.proxyMode,
		DNS:          opts.dns,
		DNSLeak:      opts.dnsLeak,
		DomainDirect: strings.Join(opts.domainDirect, ","),
		DomainProxy:  strings.Join(opts.domainProxy, ","),
	}
	state.MeasuredBps = probe.MeasuredBps
	// The exit descriptor travels in state: health repair rebuilds the session
	// from state.json alone, and without the relay it would silently drop the
	// OpenVPN exit and reconnect to the bare underlay.
	//
	// It also carries the exit's own geo, because ce.Country/ce.Colo describe
	// the WARP *carrier*. When the probe below only reaches an IP echo (VPN
	// Gate exits occasionally cannot reach Cloudflare), leaving the carrier's
	// country in place painted the underlay's flag on the home page while the
	// exit was Thai.
	if opts.openvpnMode && opts.openvpnNode != nil {
		node := *opts.openvpnNode
		state.OpenVPNMode = true
		state.OpenVPNRegion = opts.openvpnRegion
		state.OpenVPNNode = &node
		if cc := strings.ToUpper(node.CountryShort); cc != "" {
			state.Country = cc
		}
		state.Colo = ""
		state.NodeCity = ""
	}
	// The exit IP may legitimately stay empty when every probe URL refuses
	// this egress (CN nodes 403 speed.cloudflare.com): the round-trip itself
	// proved the tunnel. The status loop keeps filling the fields in live.
	state.ExitIP = probe.ExitIP
	if probe.Country != "" {
		state.Country = probe.Country
	}
	if probe.Colo != "" {
		state.Colo = probe.Colo
	}
	if probe.NodeCity != "" {
		state.NodeCity = probe.NodeCity
	}

	// Data plane proven — now, and only now, point the host at the tunnel.
	// TUN mode leaves the proxy untouched (the tun device routes everything),
	// and -no-proxy skips the WinINET edit entirely (manual/headless setups
	// point apps at the mixed port themselves).
	// Last checkpoint: the tunnel is up and verified, but if the user cancelled
	// while that was happening, pointing the host at it would be a session
	// nobody asked for. Returning here leaves the core to the caller's cleanup.
	if err := ctx.Err(); err != nil {
		return clientState{}, err
	}
	if !opts.tunMode && !opts.noProxy {
		stageMsg(fmt.Sprintf("[%s] 数据面验证通过，设置系统代理…", label))
		snap, err := core.SetSystemProxy(opts.mixedPort)
		if err != nil && proxyHelperAllowed() {
			// Security software on some hosts blocks every non-elevated
			// write path (registry, wininet API, even reg.exe). The elevated
			// daemon takes over: one UAC prompt now, and every later proxy
			// edit this session (switch, disconnect, exit) is silent.
			stageMsg(fmt.Sprintf("[%s] 代理写入被拦截，启动后台授权服务（仅本次需要 UAC 确认）…", label))
			if herr := core.SetSystemProxyElevated(opts.mixedPort); herr == nil {
				err = nil
			} else {
				stageMsg(fmt.Sprintf("[%s] 后台授权失败: %v", label, herr))
			}
		}
		if err != nil {
			// The core is up and the mixed port serves verified traffic; a
			// blocked host-side proxy edit (antivirus proxy-hijack heuristic,
			// locked-down machine) must not tear down a working tunnel. Stay
			// connected and surface a warning with the manual fallback.
			state.ProxyWarn = err.Error()
			stageMsg(fmt.Sprintf("[%s] 系统代理设置被拦截：请手动把系统/浏览器代理指向 127.0.0.1:%d", label, opts.mixedPort))
		} else if raw, err := json.Marshal(snap); err == nil {
			state.ProxySnap = raw
		}
	}
	return state, nil
}

// markEndpointDead persists a tunnel-verification failure in the scan cache so
// later connects skip straight past the endpoint instead of timing out on it
// again. Endpoints CF has silenced for this network only recover on a fresh
// scan, which is also the only thing that un-does the mark.
func markEndpointDead(opts options, ce cachedEndpoint) {
	store, err := cache.Open(cache.Options{TTL: scanTTL})
	if err != nil {
		return
	}
	// scanKeyFor, not opts.proto: a chained connect must mark the endpoint
	// dead in the chain's own cache (wwarp), not in the outer carrier's plain
	// cache where it never gets looked up again.
	key := scanCacheKey(scanKeyFor(opts), opts.ipv6)
	raw, ok := store.Get(key)
	if !ok {
		return
	}
	var cs cachedScan
	if json.Unmarshal(raw, &cs) != nil {
		return
	}
	changed := false
	for i := range cs.Results {
		if cs.Results[i].Endpoint == ce.Endpoint && cs.Results[i].Working {
			cs.Results[i].Working = false
			changed = true
		}
	}
	if !changed {
		return
	}
	if raw, err := json.Marshal(cs); err == nil {
		_ = store.Put(key, raw)
	}
}

// pickOuterEndpoint resolves the outer carrier endpoint for a WARP-in-WARP
// connect: it runs (or loads) the ordinary cached scan for the outer protocol
// and returns its best working endpoint. The outer half of a chain is just a
// plain tunnel, so its scan is the plain one — never the chained scan, which
// is what the inner half uses.
func pickOuterEndpoint(ctx context.Context, opts options) (string, error) {
	outerOpts := opts
	outerOpts.proto = opts.outerProto
	outerOpts.through = ""
	// Inherit scanNow: a fresh-scan retry (every inner candidate died on this
	// outer) must rescan the outer pool too, or the same dead endpoint wins
	// the re-pick straight from the stale cache.
	outerOpts.scanNow = opts.scanNow
	outerOpts.pick = ""
	results, _, err := runCachedScan(ctx, outerOpts)
	if err != nil {
		return "", fmt.Errorf("outer endpoint scan failed: %w", err)
	}
	best, ok := pickBest(results)
	if !ok {
		return "", fmt.Errorf("no working outer endpoint for %s: run a scan first", opts.outerProto)
	}
	return best.Endpoint, nil
}

// restoreHostProxy puts WinINET back the way it was before the session, and
// falls back to simply switching it off when no snapshot was persisted: a
// connect that died before saving one still left the proxy pointing at a port
// that is about to stop listening, and "no internet after quitting" is exactly
// that leftover.
func restoreHostProxy(state clientState) {
	if state.TUN || state.NoProxy {
		return
	}
	var snap core.ProxySnapshot
	if len(state.ProxySnap) > 0 && json.Unmarshal(state.ProxySnap, &snap) == nil {
		err := core.UnsetSystemProxy(&snap)
		if err == nil {
			return
		}
		if proxyHelperAllowed() && core.RestoreSystemProxyElevated(&snap) == nil {
			return
		}
		fmt.Fprintln(os.Stderr, errPal.warn("restore system proxy: "+err.Error()))
	} else if core.SystemProxyEnabledAt(state.MixedPort) {
		// No snapshot: the proxy is ours, so switch it off rather than leave the
		// host pointed at a dead port.
		off := &core.ProxySnapshot{}
		if err := core.UnsetSystemProxy(off); err != nil {
			if proxyHelperAllowed() {
				_ = core.RestoreSystemProxyElevated(off)
			}
			fmt.Fprintln(os.Stderr, errPal.warn("clear system proxy: "+err.Error()))
		}
	}
	if core.SystemProxyEnabledAt(state.MixedPort) {
		fmt.Fprintln(os.Stderr, errPal.warn(fmt.Sprintf(
			"系统代理仍指向 127.0.0.1:%d，请手动关闭系统代理，或以管理员身份运行本程序后断开", state.MixedPort)))
	}
}

// disconnect stops the core and restores the system proxy.
func runDisconnectCmd(ctx context.Context, opts options) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	cDir, err := coreDir()
	if err != nil {
		return err
	}
	bin := core.CoreInDir(cDir)
	if opts.corePath != "" {
		bin = opts.corePath
	}
	c, err := core.New(core.Config{
		BinaryPath: bin,
		WorkDir:    cDir,
		MixedPort:  state.MixedPort,
		APIPort:    state.APIPort,
		TUN:        state.TUN,
	})
	if err != nil {
		return err
	}
	// The host proxy goes first. It is a local registry write, and leaving it
	// pointing at a mixed port whose core is about to die is the failure users
	// actually feel — every page times out until they find the Windows proxy
	// settings. Restoring before the process kills means a wedged kill (or the
	// caller's timeout) cannot strand it.
	restoreHostProxy(state)

	if state.CorePID > 0 {
		// The core was started by an earlier connect (CLI: a different process,
		// GUI: a different Core instance), so only the recorded pid can reach
		// it. The image path is verified before the kill: a reused pid must
		// never take an unrelated process down with it.
		if err := core.KillByPID(state.CorePID, bin); err != nil {
			fmt.Fprintln(os.Stderr, errPal.warn(err.Error()))
		}
	} else if err := c.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, errPal.warn("stop core: "+err.Error()))
	}
	// Stop the external Psiphon process before restoring the host proxy, so no
	// traffic is left pointing at a dead localhost SOCKS listener.
	if state.PsiphonMode && state.PsiphonPID > 0 {
		if pexe, perr := resolvePsiphonExe(opts, cDir); perr == nil {
			if kerr := core.KillByPID(state.PsiphonPID, pexe); kerr != nil {
				fmt.Fprintln(os.Stderr, errPal.warn("stop psiphon: "+kerr.Error()))
			}
		} else {
			fmt.Fprintln(os.Stderr, errPal.warn("psiphon exe not found: "+perr.Error()))
		}
	}
	state.Connected = false
	// The recorded core is gone now; zero the pid so a later connect does not
	// "kill" it again (KillByPID treats an already-dead pid as success, which
	// printed a misleading "killed stale core" line on every connect).
	state.CorePID = 0
	state.PsiphonMode = false
	state.PsiphonPID = 0
	state.PsiphonSocksPort = 0
	// The OpenVPN exit is part of the same session: clearing it here is what
	// keeps a later health repair or reconnect from resurrecting a relay the
	// user already disconnected.
	state.OpenVPNMode = false
	state.OpenVPNRegion = ""
	state.OpenVPNNode = nil
	_ = saveState(state)
	fmt.Fprintln(os.Stderr, errPal.ok("disconnected"))
	return nil
}

// runStatusCmd reports the recorded connection plus whether it is actually
// carrying traffic right now. A recorded state alone is not evidence of
// anything: an endpoint torn down after connect leaves connected:true in the
// file while every page the user opens times out, which is exactly the report
// this command must never give.
func runStatusCmd(ctx context.Context, opts options) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	// A live run can report the current exit even if state was lost.
	if state.Connected && state.MixedPort > 0 {
		// A connected session must never be left unattended, and status is the
		// one command run against a session that may have gone wrong: if the
		// guard is gone (killed, crashed, its claim stale), a successor starts
		// here. No-op when the session already has an owner.
		ensureSessionGuard(state)
		if probe, perr := fetchExitProbe(state.MixedPort); perr == nil {
			state.ExitIP = probe.ExitIP
			if probe.Country != "" {
				state.Country = probe.Country
			}
			if probe.Colo != "" {
				state.Colo = probe.Colo
			}
		} else {
			// The file says connected and the data plane says nothing - say
			// both, and say it in the status line, not only afterwards.
			fmt.Fprintln(os.Stdout, "connected (tunnel up, INTERNET UNAVAILABLE)")
			fmt.Fprintf(os.Stdout, "  %-18s %v\n", "data-plane", perr)
			fmt.Fprintf(os.Stdout, "  %-18s %s\n", "hint", "端点可能已失效，运行 disconnect 后重新 connect 会自动换端点")
			rows := [][2]string{
				{"session", state.sessionLabel()},
				{"protocol", state.Proto},
				{"endpoint", state.Endpoint},
				{"relay", relayRow(state)},
				{"mixed port", strconv.Itoa(state.MixedPort)},
			}
			for _, r := range rows {
				if r[1] == "" || r[1] == "?" {
					continue
				}
				fmt.Fprintf(os.Stdout, "  %-18s %s\n", r[0], r[1])
			}
			return nil
		}
	}
	fmt.Fprintln(os.Stdout, state.statusLine())
	if state.Connected {
		rows := [][2]string{
			{"session", state.sessionLabel()},
			{"protocol", state.Proto},
			{"endpoint", state.Endpoint},
			{"relay", relayRow(state)},
			{"exit IP", state.ExitIP},
			{"country", state.Country},
			{"colo", state.Colo},
			{"node city", state.NodeCity},
			{"endpoint latency", latencyStr(time.Duration(state.LatencyMS) * time.Millisecond)},
			{"in-tunnel latency", latencyStr(time.Duration(state.TunLatMS) * time.Millisecond)},
			{"mixed port", strconv.Itoa(state.MixedPort)},
			{"tun", strconv.FormatBool(state.TUN)},
			{"started", state.StartedAt},
		}
		for _, r := range rows {
			if r[1] == "" || r[1] == "?" {
				continue
			}
			fmt.Fprintf(os.Stdout, "  %-18s %s\n", r[0], r[1])
		}
	}
	return nil
}

// runListCmd prints the cached scan results for the selected protocol.
func runListCmd(ctx context.Context, opts options) error {
	store, err := cache.Open(cache.Options{TTL: scanTTL})
	if err != nil {
		return err
	}
	key := scanCacheKey(opts.proto, opts.ipv6)
	raw, ok := store.Get(key)
	if !ok {
		fmt.Fprintf(os.Stdout, "no cached scan for proto=%s ipv6=%t\n", opts.proto, opts.ipv6)
		return nil
	}
	var cs cachedScan
	if err := json.Unmarshal(raw, &cs); err != nil {
		return fmt.Errorf("cache corrupt: %w", err)
	}
	fmt.Fprintf(os.Stdout, "cached scan: proto=%s ipv6=%t at=%s (%d endpoints)\n", cs.Proto, cs.IPv6, cs.At.Format(time.RFC3339), len(cs.Results))
	fmt.Fprintf(os.Stdout, "%-24s %-10s %-12s %-6s %-8s %-8s %-8s\n", "ENDPOINT", "COUNTRY", "COLO", "NODE", "EP-PING", "TUN-PING", "LOSS")
	for _, ce := range cs.Results {
		fmt.Fprintf(os.Stdout, "%-24s %-10s %-12s %-6s %-8s %-8s %.0f%%\n",
			ce.Endpoint, ce.Country, ce.Colo, ce.NodeCity,
			latencyStr(time.Duration(ce.EpPingMS)*time.Millisecond),
			latencyStr(time.Duration(ce.TunPingMS)*time.Millisecond),
			ce.Loss,
		)
	}
	return nil
}
