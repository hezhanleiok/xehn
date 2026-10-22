package warp

import (
	"sync"
	"syscall"
)

// protectControlFn 适配 net.ListenConfig.Control 的签名，让每个新 socket
// 在创建那一刻就被排除出系统 VPN（安卓）。
func protectControlFn(_, _ string, c syscall.RawConn) error {
	return protectControl(c)
}

// socketProtector keeps one socket out of the VPN.
//
// It is the single most important Android-specific hook in this package: with
// the system VPN up, every packet the phone sends is routed into our own tun,
// including the encrypted UDP the tunnel uses to reach Cloudflare. Without
// exclude-the-tunnel-socket (VpnService.protect) the tunnel swallows its own
// transport and nothing can ever pass - the phone shows the VPN key, the app
// shows "connected", and no page loads.
//
// The engine injects the Android implementation; on desktop it stays nil and
// every call is a no-op.
type socketProtector interface {
	Protect(fd int) bool
}

var (
	protectMu sync.RWMutex
	protector socketProtector
)

// SetProtector installs (or with nil clears) the platform hook.
//
// Exported for the engine package, which adapts its gomobile-bound Protector
// interface to this one. The parameter type stays unexported on purpose: nothing
// outside this package should be able to name it, and Go lets a caller pass any
// value that satisfies it without naming it.
func SetProtector(p socketProtector) {
	protectMu.Lock()
	protector = p
	protectMu.Unlock()
}

func currentProtector() socketProtector {
	protectMu.RLock()
	defer protectMu.RUnlock()
	return protector
}
