package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xhwarp/warp-client/internal/core"
)

// ---------------------------------------------------------------------------
// Data-plane health and repair.
//
// The client's whole contract with the user is "click connect and browse", so
// the only honest definition of connected is "a real request through the proxy
// completed just now". Everything nearer the tunnel - a WG handshake, a
// listening mixed port, mihomo answering /version - is a precondition, never
// proof: an endpoint torn down after connect keeps every sign of life while
// dropping payloads, and that used to be reported as "connected" against a
// browser that could load nothing.
//
// This file owns the check and what happens once it stops passing: repair by
// rotating to another endpoint, and only when every option is exhausted stop
// pretending and hand the host back to its own network.
// ---------------------------------------------------------------------------

const (
	// healthInterval spaces the checks: shorter than a page load, long enough
	// that an idle session costs nothing measurable.
	healthInterval = 10 * time.Second
	// healthFailLimit consecutive failures before the endpoint counts as dead.
	// One failure can be a busy core or a transient timeout; several spread
	// over half a minute cannot.
	healthFailLimit = 3
	// healthOwnerFile holds the pid of whoever currently owns this session's
	// health check and repair. Exactly one owner at a time, enforced by O_EXCL
	// and confirmed by whether that pid still runs - see claimHealthOwner.
	healthOwnerFile = "health-owner"
)

// ---------------------------------------------------------------------------
// Session ownership.
//
// Two parts of this client can look after a session: the detached guard a CLI
// connect spawns, and the GUI's own status loop. Both are fine alone; both at
// once is not - two independent schedulers would discover the same dead
// endpoint and each start rotating it, so two processes would kill each other's
// cores, write conflicting state.json describing different endpoints, and race
// to point the host at whichever core won the mixed port. The repairwould still
// usually succeed, for the same reason a coin lands heads eventually, and every
// failure would look unreproducible.
//
// So exactly one process owns repair, and the claim is how it is decided: an
// exclusive file holding the owner's pid. Presence alone proves nothing - a
// guard killed outright never returns from its deferral - so takeover rests on
// whether the recorded pid still runs.
// ---------------------------------------------------------------------------

func ownerClaimPath() (string, error) {
	home, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, healthOwnerFile), nil
}

// currentHealthOwner is the pid that owns health right now, and whether it is
// still alive. A missing claim means nobody owns it; a claim naming a dead pid
// means nobody owns it either, only messily.
func currentHealthOwner() (pid int, alive bool) {
	p, err := ownerClaimPath()
	if err != nil {
		return 0, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return 0, false
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	if !processAlive(pid) {
		return pid, false
	}
	return pid, true
}

// claimHealthOwner takes ownership of health for pid, when nobody living holds
// it. Idempotent for the same pid: a GUI ticking every two seconds renews the
// same claim rather than fighting itself for it.
func claimHealthOwner(pid int) bool {
	p, err := ownerClaimPath()
	if err != nil {
		return false
	}
	for attempt := 0; attempt < 2; attempt++ {
		f, ferr := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if ferr == nil {
			_, _ = fmt.Fprintf(f, "%d\n", pid)
			_ = f.Close()
			return true
		}
		if !os.IsExist(ferr) {
			return false
		}
		if owner, ok := currentHealthOwner(); ok {
			return owner == pid
		}
		// Stale claim: its owner is gone. Only a clean overwrite could lose a
		// race here, and the loser's next tick re-reads the claim instead of
		// assuming the repair it never started is still wanted.
		_ = os.Remove(p)
	}
	return false
}

// releaseHealthOwner gives the claim back, but only if it is ours - never pull
// a claim another process is mid-repair under.
func releaseHealthOwner(pid int) {
	p, err := ownerClaimPath()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	owner, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || owner != pid {
		return
	}
	_ = os.Remove(p)
}

// lostHealthOwner is true when the claim now names another living process: the
// GUI opened and took over, and a second watcher is one too many.
func lostHealthOwner(pid int) bool {
	owner, alive := currentHealthOwner()
	return alive && owner != pid
}

// healthResult is one check's outcome.
type healthResult struct {
	OK     bool
	ExitIP string
	Err    error
}

// healthVerdict is what one data-plane check means for the session: how many
// consecutive failures to carry forward, whether enough have stacked up to
// rotate endpoints, and whether a working answer just ended a bad streak.
//
// The three-way decision is kept out of the loop because it is the whole reason
// a transient hiccup costs nothing and a torn-down endpoint costs one rotation:
// one answer clears every failure before it, and nothing short of the limit
// moves the session. Getting either wrong is invisible in a log review and
// obvious in front of a browser.
type healthVerdict struct {
	fails     int
	repair    bool
	recovered bool
}

func judgeHealth(fails int, ok bool) healthVerdict {
	if ok {
		// One completed request through the proxy clears the lot: DNS hiccups,
		// a single EOF and one slow answer are all failures too, and none of
		// them means the endpoint went anywhere.
		return healthVerdict{fails: 0, recovered: fails > 0}
	}
	fails++
	if fails < healthFailLimit {
		return healthVerdict{fails: fails}
	}
	// Enough missed checks to call it dead - and start counting from zero, so
	// the successor endpoint is judged on what it does, not its predecessor.
	return healthVerdict{fails: 0, repair: true}
}

// checkDataPlane asks the question status used to assume the answer to: does a
// real HTTPS request through the local mixed port complete right now? A v6-only
// session is probed against a v6 literal, because its public sources are v4
// hostnames that the tunnel intentionally cannot reach.
func checkDataPlane(mixedPort int, family string) healthResult {
	if mixedPort <= 0 {
		return healthResult{Err: fmt.Errorf("no mixed port in state")}
	}
	if family == famV6 {
		ip, err := fetchV6Probe(mixedPort)
		if err != nil {
			return healthResult{Err: err}
		}
		return healthResult{OK: true, ExitIP: ip}
	}
	probe, err := fetchSessionProbe(mixedPort, family)
	if err != nil {
		return healthResult{Err: err}
	}
	if family == famBoth {
		if _, err := fetchV6Probe(mixedPort); err != nil {
			return healthResult{Err: fmt.Errorf("IPv6: %w", err)}
		}
	}
	return healthResult{OK: true, ExitIP: probe.ExitIP}
}

// optionsFromState rebuilds connect options from a persisted session, so a
// repair can re-render and re-verify the same kind of tunnel. Ports, protocol
// and mode come from the state; the endpoint deliberately does not - rotating
// away from the dead one is the whole point.
//
// A Psiphon session IS represented here, but only for its underlay half: the
// base protocol is a WARP layer, so rotating it is a legitimate repair, while
// the exit sidecar is not something options express. repairOnce recognises
// opts.psiphonMode and brings Psiphon back up on whatever endpoint it picks.
func optionsFromState(st clientState) options {
	proto := st.Proto
	if proto == "" {
		proto = protoAWG
	}
	// The persisted protocol for a chain is the user-facing "wwarp"; repairing
	// it needs its outer endpoint, which the state does not carry, so a chain
	// is repaired by a fresh pick rather than reproduced here.
	opts := defaultConnectOptions(proto, st.TUN, false)
	opts.mixedPort = st.MixedPort
	opts.apiPort = st.APIPort
	if opts.mixedPort == 0 {
		opts.mixedPort = core.DefaultMixedPort
	}
	if opts.apiPort == 0 {
		opts.apiPort = core.DefaultAPIPort
	}
	// Address family is a property of the session's endpoint, not something to
	// default away: markEndpointDead and runCachedScan both key the endpoint
	// cache on it, so guessing v4 here silently no-ops the eviction of a v6
	// endpoint and repairs onto it forever.
	opts.ipv6 = endpointIsV6(st.Endpoint)
	opts.family = st.Family
	switch opts.family {
	case famV4, famV6, famBoth:
	default:
		opts.family = famV4
		if opts.ipv6 {
			opts.family = famV6
		}
	}
	opts.allowLan = st.AllowLan
	// The preset and the DNS settings are part of what the user asked for, not
	// per-process defaults: a repair that forgets them turns 绕过大陆 into
	// "proxy everything" and switches DNS leak protection off.
	if st.ProxyMode != "" {
		opts.proxyMode = st.ProxyMode
	}
	opts.dns = st.DNS
	opts.dnsLeak = st.DNSLeak
	opts.domainDirect = splitStoredList(st.DomainDirect)
	opts.domainProxy = splitStoredList(st.DomainProxy)
	// A Psiphon session re-launches its exit with the same region it was
	// started with, so a repair never swaps the user's chosen country.
	opts.psiphonRegion = st.PsiphonRegion
	// An OpenVPN session must come back as the SAME kind of session: without the
	// exit descriptor a repair would rebuild the bare underlay and silently
	// drop the relay the user picked.
	if st.OpenVPNMode {
		opts.openvpnMode = true
		opts.openvpnRegion = st.OpenVPNRegion
		opts.openvpnNode = st.OpenVPNNode
		// The relay is IPv4-only; a v6 endpoint family would fail verification
		// on a chain that can never carry it.
		opts.ipv6 = false
		opts.family = famV4
	}
	return opts
}

// splitStoredList turns a comma-separated list stored in state back into its
// entries. It is deliberately not splitList: that one upper-cases and exits the
// process on an empty value, which is right for a command-line flag and wrong
// for a domain list read back from disk.
func splitStoredList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// endpointIsV6 says whether an "host:port" pair is IPv6 - the same question the
// scan asked of every candidate, answered the same way.
func endpointIsV6(endpoint string) bool {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Is6()
}

// stopRecordedCore kills the core the state names, if any. Called before a
// repair hands the ports to a fresh one: two mihomo instances cannot share a
// mixed port, and the dying one would answer the readiness check of the new.
func stopRecordedCore(st clientState) error {
	if st.CorePID <= 0 {
		return nil
	}
	cDir, err := coreDir()
	if err != nil {
		return err
	}
	bin := core.CoreInDir(cDir)
	if err := core.KillByPID(st.CorePID, bin); err != nil {
		return err
	}
	// A killed core does not release its sockets the instant TerminateProcess
	// returns, and the replacement core binding too early is what leaves this
	// exact failure class behind: a core that failed its bind yet keeps
	// running and being probed. core.Start waits for the ports itself, so this
	// only has to not race it.
	return nil
}

// stopRecordedPsiphon kills the external Psiphon sidecar the state names, if
// any. The mirror of stopRecordedCore for the exit sidecar: without it a
// giveUp (or a rollback) leaves a Psiphon process listening on localhost with
// nobody pointing at it — a stray that holds its SOCKS port and keeps dialing
// through an underlay that is being torn down.
func stopRecordedPsiphon(st clientState) error {
	if st.PsiphonPID <= 0 {
		return nil
	}
	cDir, err := coreDir()
	if err != nil {
		return err
	}
	exe, err := resolvePsiphonExe(options{}, cDir)
	if err != nil {
		// The state still records the PID; not knowing the image path (e.g. the
		// exe was moved) must not abort the rest of the teardown.
		return err
	}
	return core.KillByPID(st.PsiphonPID, exe)
}

// nextCandidates is the working-and-not-yet-tried set a repair may attempt,
// best-first and capped like an ordinary connect.
func nextCandidates(results []cachedEndpoint, tried map[string]bool, max int) []cachedEndpoint {
	var cands []cachedEndpoint
	for _, ce := range results {
		if !ce.Working || ce.Endpoint == "" || tried[ce.Endpoint] {
			continue
		}
		cands = append(cands, ce)
		if len(cands) >= max {
			break
		}
	}
	return cands
}

// repairOnce stops the current core and brings the tunnel up on another cached
// endpoint, keeping the host pointing at the mixed port it already uses. The
// dead endpoint is marked as such in the scan cache first, so the next connect
// never has to time out on it again - without that, a repair is only ever a
// reprieve: the cache keeps handing the dead endpoint back.
//
// It returns the new state and true when a candidate carried traffic.
//
// For a Psiphon session (opts.psiphonMode) this rotates the UNDERLAY and brings
// Psiphon back up on the new base endpoint: the base protocol is a WARP layer, so
// rotating it is the right remedy when it dies. The EXIT stays Psiphon — the
// sidecar is restarted on a fresh socks port that the same render names — and a
// bare WARP tunnel is never what comes back.
func repairOnce(ctx context.Context, opts options, dead string, tried map[string]bool, logf func(string)) (clientState, bool) {
	if dead != "" {
		tried[dead] = true
	}
	cDir, err := coreDir()
	if err != nil {
		logf(fmt.Sprintf("修复失败：无法定位核心目录：%v", err))
		return clientState{}, false
	}
	bin, err := core.EnsureBinary(cDir, opts.corePath)
	if err != nil {
		logf(fmt.Sprintf("修复失败：核心不可用：%v", err))
		return clientState{}, false
	}
	results, run, err := runCachedScan(ctx, opts)
	if err != nil {
		logf(fmt.Sprintf("修复失败：无法获取端点列表：%v", err))
		return clientState{}, false
	}
	label := protoLabel(opts.proto)
	if opts.psiphonMode {
		label += "+Psiphon"
	}

	if dead != "" {
		// Exactly what a failed verifyTunnel does - but only when the core was
		// still running and therefore cannot be the explanation. A core that
		// has died takes the data plane with it no matter how good the
		// endpoint was, and evicting a healthy endpoint for that is how a
		// crash turns into a round of pointless rotation (and eventually into
		// "no candidates left" on a network that still had plenty). Leave it
		// unmarked and let the same endpoint be retried first.
		prev, perr := loadState()
		coreWasAlive := perr == nil && prev.CorePID > 0 && processAlive(prev.CorePID)
		if coreWasAlive {
			for _, ce := range results {
				if ce.Endpoint == dead {
					markEndpointDead(opts, ce)
					break
				}
			}
		} else {
			tried[dead] = false
			logf("核心进程已消失（非端点问题），不淘汰 " + dead)
		}
	}

	cands := nextCandidates(results, tried, connectMaxAttempts)
	if len(cands) == 0 {
		logf("无可用备用端点")
		return clientState{}, false
	}
	for i, ce := range cands {
		// A disconnect has to win a repair it started losing. Each candidate
		// costs tens of seconds to verify, which is plenty of time for the
		// user to click away; without this check the repair would bring a core
		// back up afterwards and point the host at a proxy the user just
		// switched off.
		if prev, serr := loadState(); serr == nil && !prev.Connected {
			logf("会话已断开，中止修复")
			return clientState{}, false
		}
		logf(fmt.Sprintf("切换端点 %s（第 %d/%d 个）…", ce.Endpoint, i+1, len(cands)))
		if prev, serr := loadState(); serr == nil {
			if kerr := stopRecordedCore(prev); kerr != nil {
				logf(fmt.Sprintf("停止旧核心失败: %v", kerr))
			}
			// The old Psiphon sidecar was dialing through the old core; it dies
			// with the underlay it rode on.
			if perr := stopRecordedPsiphon(prev); perr != nil {
				logf(fmt.Sprintf("停止旧 Psiphon 失败: %v", perr))
			}
		}
		// Psiphon-aware repair: bring the sidecar up on the new base endpoint as
		// part of the same verify, so the state we return describes a session
		// that exits through Psiphon — never a bare WARP tunnel.
		var (
			ps         *Psiphon
			psPort     int
			afterReady func() error
		)
		if opts.psiphonMode {
			psPort, err = pickFreePort()
			if err != nil {
				logf(fmt.Sprintf("修复失败：无法选 Psiphon 端口：%v", err))
				return clientState{}, false
			}
			exe, xerr := resolvePsiphonExe(opts, cDir)
			if xerr != nil {
				logf(fmt.Sprintf("修复失败：%v", xerr))
				return clientState{}, false
			}
			baseConfig, cerr := resolvePsiphonClientConfig(cDir)
			if cerr != nil {
				logf(fmt.Sprintf("修复失败：%v", cerr))
				return clientState{}, false
			}
			opts.psiphonSocksPort = psPort
			launch := psiphonLaunch{
				ExePath:        exe,
				DataDir:        filepath.Join(cDir, "psiphon-data"),
				BaseConfigPath: baseConfig,
				Upstream:       fmt.Sprintf("socks5://127.0.0.1:%d", underlaySocksPort(opts.mixedPort)),
				SocksPort:      psPort,
				EgressRegion:   opts.psiphonRegion,
			}
			ps = &Psiphon{}
			afterReady = func() error {
				under := underlaySocksPort(opts.mixedPort)
				if uerr := probeUnderlaySocks(ctx, under, 8*time.Second); uerr != nil {
					return fmt.Errorf("underlay 数据面不可用: %w", uerr)
				}
				if serr := ps.Start(ctx, launch); serr != nil {
					return fmt.Errorf("psiphon start: %w", serr)
				}
				if werr := ps.WaitForSocks(ctx, 60*time.Second); werr != nil {
					return fmt.Errorf("psiphon socks 未就绪: %w", werr)
				}
				if werr := ps.WaitForTunnel(ctx, psiphonTunnelWait); werr != nil {
					return werr
				}
				return nil
			}
		}
		state, serr := startAndVerify(ctx, opts, ce, run, bin, cDir, label, afterReady)
		if serr != nil && ps != nil {
			_ = ps.Stop()
		}
		if serr == nil {
			if cur, cerr := loadState(); cerr == nil && !cur.Connected {
				// Too late: the disconnect landed while this candidate was
				// verifying. Undo what startAndVerify did with the host rather
				// than leaving it pointed at a session nobody asked for.
				logf("会话已断开，回滚刚启动的核心")
				if ps != nil {
					_ = ps.Stop()
				}
				rollbackRepair(state, logf)
				return clientState{}, false
			}
			if ps != nil {
				ps.MarkRealTrafficReady()
				state.PsiphonMode = true
				state.PsiphonPID = ps.PID()
				state.PsiphonSocksPort = psPort
			}
			if saveState(state) != nil {
				logf("状态保存失败")
			}
			logf("已切换到 " + ce.Endpoint)
			return state, true
		}
		tried[ce.Endpoint] = true
		markEndpointDead(opts, ce)
		logf(fmt.Sprintf("端点 %s 修复失败: %v", ce.Endpoint, serr))
	}
	return clientState{}, false
}

// repairOpenVPNOnce rebuilds a session whose final egress is a VPN Gate relay.
// The relay is the likely fault — public nodes churn within hours, while a
// scan-verified WARP endpoint usually stays up — so it is rotated first; the
// underlay endpoint is only rotated when every relay fails on it.
//
// Base endpoints are never marked dead here: a relay that cannot handshake says
// nothing about the tunnel underneath it, and evicting healthy WARP endpoints
// on a VPN Gate outage would poison the scan cache.
func repairOpenVPNOnce(ctx context.Context, st clientState, logf func(string)) (clientState, bool) {
	cDir, err := coreDir()
	if err != nil {
		logf(fmt.Sprintf("修复失败：无法定位核心目录：%v", err))
		return clientState{}, false
	}
	opts := optionsFromState(st)
	opts.openvpnNode = nil
	bin, err := core.EnsureBinary(cDir, opts.corePath)
	if err != nil {
		logf(fmt.Sprintf("修复失败：核心不可用：%v", err))
		return clientState{}, false
	}
	results, run, err := runCachedScan(ctx, opts)
	if err != nil {
		logf(fmt.Sprintf("修复失败：无法获取端点列表：%v", err))
		return clientState{}, false
	}
	// Forced refresh: the relay pool is the thing being repaired, and re-picking
	// from the same cached list would walk straight back into the dead nodes.
	nodes, err := vpnGateNodesFor(ctx, results, run, true)
	if err != nil {
		logf(fmt.Sprintf("修复失败：无法获取 VPN Gate 节点：%v", err))
		return clientState{}, false
	}
	// Respect the user's pin: a residential pick rotates through the other
	// residential relays first, exactly like the picker promised; the phone
	// client's class order is what fills the rest of the list.
	pin := loadSettings().OpenVPNNode
	relays := vpnGateCandidates(ctx, nodes, opts.openvpnRegion, pin, vpnGateConnectNodes)
	if len(relays) == 0 {
		logf("修复失败：VPN Gate 没有可用节点")
		return clientState{}, false
	}
	// Anything but the relay already in use comes first; the old one is kept as
	// the last resort so a transient failure does not lose a working session.
	if st.OpenVPNNode != nil {
		cur := st.OpenVPNNode.id()
		var ordered []vpnGateNode
		for _, n := range relays {
			if n.id() != cur {
				ordered = append(ordered, n)
			}
		}
		ordered = append(ordered, *st.OpenVPNNode)
		relays = ordered
	}

	// The current base endpoint gets the first turn (the relay is the suspect),
	// then the cached alternatives.
	var bases []cachedEndpoint
	for _, ce := range results {
		if ce.Endpoint == st.Endpoint && ce.Working {
			bases = append(bases, ce)
			break
		}
	}
	if len(bases) == 0 && st.Endpoint != "" {
		bases = append(bases, cachedEndpoint{Endpoint: st.Endpoint})
	}
	bases = append(bases, nextCandidates(results, map[string]bool{st.Endpoint: true}, connectMaxAttempts)...)
	if len(bases) == 0 {
		logf("修复失败：无可用基础端点")
		return clientState{}, false
	}

	const maxAttempts = 4
	attempts := 0
	for _, ce := range bases {
		for i := range relays {
			if attempts >= maxAttempts || ctx.Err() != nil {
				return clientState{}, false
			}
			if cur, cerr := loadState(); cerr == nil && !cur.Connected {
				logf("会话已断开，中止修复")
				return clientState{}, false
			}
			attempts++
			node := relays[i]
			opts.openvpnNode = &node
			logf(fmt.Sprintf("切换出口 %s（%s），基础端点 %s（第 %d/%d 次）…",
				node.id(), node.CountryShort, ce.Endpoint, attempts, maxAttempts))
			if prev, serr := loadState(); serr == nil {
				if kerr := stopRecordedCore(prev); kerr != nil {
					logf(fmt.Sprintf("停止旧核心失败: %v", kerr))
				}
			}
			state, serr := startAndVerify(ctx, opts, ce, run, bin, cDir, "OpenVPN", nil)
			if serr != nil {
				if !strings.Contains(serr.Error(), "base endpoint") {
					markVPNGateFailed(node.id())
				}
				logf(fmt.Sprintf("出口 %s 修复失败: %v", node.id(), serr))
				continue
			}
			clearVPNGateFailure(node.id())
			rememberLastGoodVPNGate(node)
			if cur, cerr := loadState(); cerr == nil && !cur.Connected {
				logf("会话已断开，回滚刚启动的核心")
				rollbackRepair(state, logf)
				return clientState{}, false
			}
			if saveState(state) != nil {
				logf("状态保存失败")
			}
			logf("已切换到 VPN Gate " + node.id())
			return state, true
		}
	}
	return clientState{}, false
}

// rollbackRepair undoes a repair that finished after the session it was
// repairing had been disconnected: stop the core it started and give the host
// its own proxy back. Everything else startAndVerify did (a written config, a
// dead endpoint's cache entry) is either local or desirable.
func rollbackRepair(state clientState, logf func(string)) {
	if state.CorePID > 0 {
		if kerr := stopRecordedCore(state); kerr != nil {
			logf(fmt.Sprintf("回滚：停止核心失败: %v", kerr))
		}
	}
	if state.PsiphonPID > 0 {
		if perr := stopRecordedPsiphon(state); perr != nil {
			logf(fmt.Sprintf("回滚：停止 Psiphon 失败: %v", perr))
		}
	}
	if !state.TUN && len(state.ProxySnap) > 0 {
		var snap core.ProxySnapshot
		if json.Unmarshal(state.ProxySnap, &snap) == nil {
			if err := core.UnsetSystemProxy(&snap); err != nil {
				logf(fmt.Sprintf("回滚：恢复系统代理失败: %v", err))
			}
		}
	}
}

// giveUp is the honest end of a session nothing can revive: restore the host's
// own proxy state, stop the core, and record that nothing is connected. Leaving
// a lit Connected over a dead port is worse than no connection at all - the
// machine has no internet either way, but one of them also lies about why.
func giveUp(logf func(string)) {
	logf("所有备用端点均无法恢复：正在恢复系统代理并停止核心")
	if prev, err := loadState(); err == nil {
		if prev.CorePID > 0 {
			_ = stopRecordedCore(prev)
		}
		// The Psiphon sidecar must die with the session, exactly as the core
		// does: a giveUp that stopped only the core would leave Psiphon holding
		// its SOCKS port and dialing a tunnel nobody uses.
		if prev.PsiphonPID > 0 {
			if perr := stopRecordedPsiphon(prev); perr != nil {
				logf(fmt.Sprintf("停止 Psiphon 失败: %v", perr))
			}
		}
		if !prev.TUN && len(prev.ProxySnap) > 0 {
			var snap core.ProxySnapshot
			if json.Unmarshal(prev.ProxySnap, &snap) == nil {
				if err := core.UnsetSystemProxy(&snap); err != nil {
					logf(fmt.Sprintf("恢复系统代理失败: %v", err))
				}
			}
		}
		prev.Connected = false
		prev.CorePID = 0
		prev.PsiphonMode = false
		prev.PsiphonPID = 0
		prev.PsiphonSocksPort = 0
		prev.OpenVPNMode = false
		prev.OpenVPNRegion = ""
		prev.OpenVPNNode = nil
		_ = saveState(prev)
	}
	logf("已断开：请重新点击连接（会重新扫描端点）")
}

// runHealthGuardCmd is the hidden "guard" subcommand connect spawns when it
// leaves a core behind for other processes to use (the CLI case): something has
// to keep asking whether the tunnel still carries traffic, because the session
// outlives every process that set it up.
//
// It exits on its own as soon as the session is gone - disconnected by another
// process, or the host's proxy pointed somewhere else by hand - so a guard is
// never a stray process with its own ideas about the machine.
func runHealthGuardCmd(ctx context.Context, opts options) error {
	if opts.mixedPort <= 0 {
		opts.mixedPort = core.DefaultMixedPort
	}
	pid := os.Getpid()
	if !claimHealthOwner(pid) {
		// Somebody is already looking after this session - the GUI opened, or
		// a guard from an earlier connect is still alive. Two watchers would
		// eventually discover the same dead endpoint at once and rotate it in
		// opposite directions.
		logf := func(s string) {
			fmt.Fprintln(os.Stderr, time.Now().Format("15:04:05")+" [guard] "+s)
		}
		logf("已有进程负责本会话的健康检查，退出")
		return nil
	}
	defer releaseHealthOwner(pid)

	logf := func(s string) {
		fmt.Fprintln(os.Stderr, time.Now().Format("15:04:05")+" [guard] "+s)
	}
	logf(fmt.Sprintf("数据面守护已启动 (port=%d)", opts.mixedPort))

	var fails int
	// psiphonRestarts / psiphonUnderlayFails count consecutive Psiphon-side
	// repairs for a Psiphon session; both reset the moment the data plane
	// answers (see psiphon_health.go).
	var (
		psiphonRestarts      int
		psiphonUnderlayFails int
	)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(healthInterval):
		}
		// Step aside if another process has taken the claim, whoever it is:
		// one session, one repairer. Ownership itself is decided by
		// claimHealthOwner; this only notices when the answer changed.
		if lostHealthOwner(pid) {
			logf("健康检查归属已转交给其他进程，退出守护")
			return nil
		}
		st, err := loadState()
		if err != nil || !st.Connected || st.CorePID <= 0 {
			logf("会话已结束，退出守护")
			return nil
		}
		// TUN mode routes without the WinINET proxy, a -no-proxy session never
		// had us set it, and a blocked proxy write left it as-is: in all three
		// the host proxy is not our signal, so only read it when we did set it.
		if !st.TUN && !st.NoProxy && st.ProxyWarn == "" && !core.SystemProxyEnabledAt(st.MixedPort) {
			logf("系统代理已不再指向本端口，退出守护")
			return nil
		}
		res := checkDataPlane(st.MixedPort, st.Family)
		if verdict := judgeHealth(fails, res.OK); !verdict.repair {
			fails = verdict.fails
			if res.OK {
				psiphonRestarts = 0
				psiphonUnderlayFails = 0
				if verdict.recovered {
					logf("数据面已恢复")
				}
				continue
			}
			logf(fmt.Sprintf("数据面探测失败 (%d/%d): %v", fails, healthFailLimit, res.Err))
			continue
		}
		logf(fmt.Sprintf("数据面探测失败 (%d/%d): %v", healthFailLimit, healthFailLimit, res.Err))
		// An OpenVPN session is repaired by rotating the VPN Gate relay, not by
		// rotating the underlay: the relay is the part that churns, and a bare
		// WARP re-connect would silently drop the exit the user chose.
		if st.OpenVPNMode {
			if fe := ctx.Err(); fe != nil {
				return nil
			}
			logf("OpenVPN 出口失效：更换 VPN Gate 节点并重建会话…")
			if _, ok := repairOpenVPNOnce(ctx, st, logf); ok {
				fails = 0
				continue
			}
			if done, derr := loadState(); derr == nil && !done.Connected {
				logf("会话已由用户断开，退出守护")
				return nil
			}
			logf("没有可用的 VPN Gate 节点，结束会话")
			giveUp(logf)
			return nil
		}
		// A Psiphon session is repaired by RESTARTING Psiphon, never by rotating
		// the WARP underlay: the latter would silently swap the final exit back
		// to WARP, which is exactly the mis-route this branch exists to avoid.
		// Give up only after several consecutive failed restarts.
		if st.PsiphonMode {
			if fe := ctx.Err(); fe != nil {
				return nil
			}
			// Which layer failed? Two remedies, one per layer:
			//  - underlay dead: the base protocol is a WARP layer, so rotating
			//    it is the right fix — re-establish it on another endpoint and
			//    bring Psiphon back up on top of it. The exit stays Psiphon.
			//  - underlay alive: the Psiphon sidecar itself is at fault, so
			//    restart it on the SAME port (mihomo's config names it).
			under := underlaySocksPort(st.MixedPort)
			if uerr := probeUnderlaySocks(ctx, under, 8*time.Second); uerr != nil {
				logf(fmt.Sprintf("基础协议 underlay 不可用 (%v)：重建基础协议并在其上恢复 Psiphon", uerr))
				psiphonUnderlayFails++
				if psiphonUnderlayFails > psiphonUnderlayLimit {
					logf(fmt.Sprintf("基础协议连续 %d 次重建失败，结束会话", psiphonUnderlayFails))
					giveUp(logf)
					return nil
				}
				repairOpts := optionsFromState(st)
				repairOpts.mixedPort = st.MixedPort
				repairOpts.apiPort = st.APIPort
				repairOpts.psiphonMode = true
				tried := map[string]bool{}
				if _, ok := repairOnce(ctx, repairOpts, st.Endpoint, tried, logf); ok {
					logf("已在新的基础端点上恢复 Psiphon 会话")
					psiphonUnderlayFails = 0
					fails = 0
					continue
				}
				// Every cached candidate failed: the cache is stale as a whole.
				logf("缓存端点全部失活，重新扫描…")
				repairOpts.scanNow = true
				if _, ok := repairOnce(ctx, repairOpts, st.Endpoint, tried, logf); ok {
					logf("已在新的基础端点上恢复 Psiphon 会话")
					psiphonUnderlayFails = 0
					fails = 0
					continue
				}
				if done, derr := loadState(); derr == nil && !done.Connected {
					logf("会话已由用户断开，退出守护")
					return nil
				}
				logf("无法重建基础协议，结束会话")
				giveUp(logf)
				return nil
			}
			if psiphonRestarts >= psiphonRestartLimit {
				logf(fmt.Sprintf("Psiphon 连续重启 %d 次仍不通，放弃", psiphonRestarts))
				giveUp(logf)
				return nil
			}
			psiphonRestarts++
			logf(fmt.Sprintf("underlay 正常，重启 Psiphon 出口（第 %d/%d 次）…", psiphonRestarts, psiphonRestartLimit))
			if perr := restartPsiphon(ctx, st, logf); perr != nil {
				logf("重启 Psiphon 失败: " + perr.Error())
			} else if r := checkDataPlane(st.MixedPort, st.Family); r.OK {
				logf("Psiphon 重启后数据面已恢复")
				psiphonRestarts = 0
			} else {
				logf("Psiphon 重启后数据面仍不通")
			}
			fails = 0
			continue
		}
		repairOpts := optionsFromState(st)
		repairOpts.mixedPort = st.MixedPort
		repairOpts.apiPort = st.APIPort
		tried := map[string]bool{}
		if fe := ctx.Err(); fe != nil {
			return nil
		}
		if _, ok := repairOnce(ctx, repairOpts, st.Endpoint, tried, logf); ok {
			continue
		}
		// Every cached candidate failed: the cache is stale as a whole. One
		// fresh scan is what a failing connect does too, and it is the only
		// thing that can offer endpoints this host has not lost yet.
		logf("缓存端点全部失活，重新扫描…")
		repairOpts.scanNow = true
		if _, ok := repairOnce(ctx, repairOpts, st.Endpoint, tried, logf); ok {
			continue
		}
		// Not every exhausted repair means the network gave up on us - the
		// user may have disconnected while it worked. Say which it was: a
		// "nothing can be revived" line over a session somebody closed is how
		// a correct shutdown gets reported as an outage.
		if done, derr := loadState(); derr == nil && !done.Connected {
			logf("会话已由用户断开，退出守护")
			return nil
		}
		giveUp(logf)
		return nil
	}
}

// runHealthGuard is the guard's entry point when spawned detached: it parses
// the two ports connect handed it and blocks watching the data plane until the
// session ends. Context lifetime belongs to the process, so nothing here can
// outlive a session that another command already ended.
func runHealthGuard(args []string) int {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	mixedPort := fs.Int("mixed-port", core.DefaultMixedPort, "local proxy port to probe")
	apiPort := fs.Int("api-port", core.DefaultAPIPort, "core controller port")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// The guard runs detached with no console of its own, so its findings would
	// evaporate if they went to stderr. Everything it says lands in the same
	// log every other headless part of the client uses - the whole point of
	// watching the data plane is being able to read afterwards what it saw.
	if home, herr := appDir(); herr == nil {
		if f, ferr := os.OpenFile(filepath.Join(home, "xehn.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); ferr == nil {
			os.Stderr = f
			log.SetOutput(f)
			log.SetFlags(log.LstdFlags)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := options{mixedPort: *mixedPort, apiPort: *apiPort}
	if err := runHealthGuardCmd(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, "guard: "+err.Error())
		return 1
	}
	return 0
}

// ensureSessionGuard makes sure a connected session has exactly one watcher.
// It is safe to call from anywhere that observes a session - a connect, a
// status run, a GUI poll - because ownership is decided once, by the claim:
//
//	already owned by a living process  -> do nothing
//	nobody owns it                     -> spawn a guard, which claims it
//	claimed by a process since dead    -> the claim is stale, so spawn
//
// That last case is why a killed guard is not the end of monitoring: the next
// process to look at the session replaces it. Nothing polls the guard from
// outside, and nothing needs to.
func ensureSessionGuard(st clientState) {
	// A Psiphon session is watched too, but by a Psiphon-aware guard: the guard
	// reads the state every cycle and repairs a Psiphon session by restarting
	// Psiphon, never by rotating the WARP underlay (see psiphon_health.go).
	if _, alive := currentHealthOwner(); alive {
		return
	}
	spawnHealthGuard(st)
}

// spawnHealthGuard starts a detached guard for a session this process is about
// to leave behind (a CLI connect returns while the core keeps serving). It is
// launched hidden and never waited on: its lifetime belongs to the session, not
// to this process. Whether its work is wanted is settled by the claim, decided
// by the guard itself on startup.
func spawnHealthGuard(st clientState) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	port := st.MixedPort
	if port <= 0 {
		port = core.DefaultMixedPort
	}
	cmd := exec.Command(exe, "guard",
		"--mixed-port", strconv.Itoa(port),
		"--api-port", strconv.Itoa(st.APIPort))
	hideGuard(cmd)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, errPal.warn("health guard not started: "+err.Error()))
		return
	}
	_ = cmd.Process.Release()
	fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("health guard: pid %d watches the data plane on port %d", cmd.Process.Pid, port)))
}
