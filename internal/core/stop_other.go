//go:build !windows

package core

import (
	"errors"
	"os/exec"
)

func hideConsole(*exec.Cmd) {}

func spawnWatchdog(corePID int) {}

// WaitClientOrCore is only implemented on Windows: nowhere else is a
// watchdog ever spawned (spawnWatchdog is a no-op), so the answer never
// matters.
func WaitClientOrCore(clientPID, corePID int) (bool, error) {
	return false, errors.New("core: watchdog is not supported on this platform")
}

// KillByPID is only implemented on Windows (the only platform the client
// manages a system proxy and a long-lived core on).
func KillByPID(pid int, expectExe string) error {
	return errors.New("core: kill by pid is not supported on this platform")
}

// KillStaleCores is Windows-only; elsewhere the core is tied to the client's
// own lifetime by the shell, so there is nothing to reap.
func KillStaleCores(exe string) int { return 0 }

// KillStalePortableCores is Windows-only; elsewhere no portable core outlives
// its client.
func KillStalePortableCores() int { return 0 }
