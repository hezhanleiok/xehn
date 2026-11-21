package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/xhwarp/warp-client/internal/core"
)

// portListening reports whether something accepts connections on loopback:port.
// A refused dial is the definitive "no listener" answer on loopback, so this is
// enough to tell "the port is taken" from "the port is free".
func portListening(port int) bool {
	if port <= 0 {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// waitPortReleased waits up to timeout for a port to stop accepting.
func waitPortReleased(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !portListening(port) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(120 * time.Millisecond)
	}
}

// ensureCorePort returns a port the core can bind. When the preferred port is
// already taken it first reaps our own leftovers (an earlier core that outlived
// its client), and only then moves to a free port.
//
// Why this exists: mihomo fails to bind 7890 when any other Clash-family client
// is running (the user's Clash Party keeps 7890 as its mixed port). The old code
// waited 5 s per candidate and then reported "port 7890 still in use", so a
// whole 99-node list looked like 99 dead relays and neither WARP+OpenVPN nor
// subscription+OpenVPN could connect at all. Ports are an implementation detail
// of our own core; a foreign listener is not a reason to fail a connect.
func ensureCorePort(preferred int, bin, what string) int {
	if preferred <= 0 || !portListening(preferred) {
		return preferred
	}
	// Our own stale core first: killing it keeps the familiar 7890 and keeps
	// state.json/health checks on the port the user already knows.
	if n := core.KillStaleCores(bin); n > 0 {
		stageMsg(fmt.Sprintf("清理了 %d 个残留内核进程（占用 %s端口 %d）", n, what, preferred))
	}
	// A core left by an EARLIER XEHN folder (the usual update flow extracts a
	// new one) has a different image path, so the exact-path sweep above cannot
	// see it. Only runs when a port is actually taken, so a healthy
	// single-instance start never touches another copy's core.
	if n := core.KillStalePortableCores(); n > 0 {
		stageMsg(fmt.Sprintf("清理了 %d 个旧版本残留内核进程", n))
	}
	if st, err := loadState(); err == nil && st.CorePID > 0 {
		_ = core.KillByPID(st.CorePID, bin)
	}
	if waitPortReleased(preferred, 1500*time.Millisecond) {
		return preferred
	}
	// Prefer a predictable neighbour (7891, 7892 …) over a random ephemeral
	// port: the mixed port is what users type into other apps, and a port that
	// changes on every connect is unusable for that. Fall back to an ephemeral
	// one only when the whole block is taken.
	for i := 1; i <= 9; i++ {
		if p := preferred + i; p <= 65535 && !portListening(p) {
			stageMsg(fmt.Sprintf("%s端口 %d 已被其它程序占用（可能是另一个 Clash 客户端），本次改用 %d", what, preferred, p))
			return p
		}
	}
	free, err := freeTCPPort()
	if err != nil || free <= 0 {
		// Nothing better to offer; let Start report the bind failure.
		return preferred
	}
	stageMsg(fmt.Sprintf("%s端口 %d 已被其它程序占用（可能是另一个 Clash 客户端），本次改用 %d", what, preferred, free))
	return free
}

// resolveCorePorts guarantees the core can bind before any candidate is tried.
// It runs once per connect, so every attempt of a multi-endpoint loop reuses the
// same ports — the system proxy, the verification probes and state.json all read
// opts.mixedPort afterwards.
func resolveCorePorts(opts *options) {
	cDir, err := coreDir()
	if err != nil {
		return
	}
	bin := core.CoreInDir(cDir)
	if opts.corePath != "" {
		bin = opts.corePath
	}
	opts.mixedPort = ensureCorePort(opts.mixedPort, bin, "混合")
	opts.apiPort = ensureCorePort(opts.apiPort, bin, "控制")
	if opts.apiPort == opts.mixedPort {
		// A collision here would make the core bind its API over its own proxy
		// port; give the API a fresh one instead of silently breaking the panel.
		if p, perr := freeTCPPort(); perr == nil && p > 0 {
			opts.apiPort = p
		}
	}
}

// localCoreError reports whether a connect failure came from this machine — a
// port another process holds, a core that never bound, a config write that
// failed — rather than from the relay or the tunnel. Two consequences:
// retrying another candidate cannot fix it (fail fast with the real reason
// instead of burning eight 5-second attempts), and it must never enter the
// relay failure memory (a poisoned pool then skips healthy relays for ten
// minutes, which is exactly how the subscription pool shrank to one node).
func localCoreError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"still in use",
		"already running",
		"core: workdir",
		"core: start",
		"core: mixed port",
		"core: api port",
		"core: config",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
