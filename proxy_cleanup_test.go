//go:build windows

package main

import (
	"testing"

	"github.com/xhwarp/warp-client/internal/core"
)

// TestClearProxyIfOursRemovesDeadProxy pins the exit-path guarantee: a host
// proxy still pointing at a port whose core is gone must be switched off, even
// when there is no snapshot to restore. This is the "closed the app and now
// nothing loads" report, and it has to work without any state file.
//
// The test writes the real WinINET proxy and restores whatever was there before,
// so it is safe to run on a normal desktop.
func TestClearProxyIfOursRemovesDeadProxy(t *testing.T) {
	const port = 17999
	before, err := core.SetSystemProxy(port)
	if err != nil {
		t.Skipf("cannot write the system proxy on this machine: %v", err)
	}
	defer func() { _ = core.UnsetSystemProxy(before) }()

	if !core.SystemProxyEnabledAt(port) {
		t.Skip("proxy write did not take effect (blocked by security software)")
	}

	clearProxyIfOurs(port)

	if core.SystemProxyEnabledAt(port) {
		t.Fatal("proxy still points at the dead port after clearProxyIfOurs")
	}
}

// TestClearProxyIfOursLeavesForeignProxyAlone is the other half: a proxy the
// user set themselves (another client, or a corporate PAC) must not be touched
// just because our cleanup ran.
func TestClearProxyIfOursLeavesForeignProxyAlone(t *testing.T) {
	const foreign = 18080
	before, err := core.SetSystemProxy(foreign)
	if err != nil {
		t.Skipf("cannot write the system proxy on this machine: %v", err)
	}
	defer func() { _ = core.UnsetSystemProxy(before) }()

	if !core.SystemProxyEnabledAt(foreign) {
		t.Skip("proxy write did not take effect (blocked by security software)")
	}

	// Our ports are different, so nothing should change.
	clearProxyIfOurs(17998, 17997)

	if !core.SystemProxyEnabledAt(foreign) {
		t.Fatal("cleanup removed a proxy that belongs to someone else")
	}
}
