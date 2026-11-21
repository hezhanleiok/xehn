package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/xhwarp/warp-client/internal/core"
)

// Psiphon exit health repair (V1).
//
// A Psiphon session's remedy is to RESTART the Psiphon sidecar — never to rotate
// the WARP underlay. The two failures look identical from the outside (the data
// plane stops answering), but they are different layers: rotating WARP endpoints
// on a Psiphon fault would silently swap the user's final exit back to WARP,
// which is exactly the mis-route the guard is kept away from. So the guard
// branches: a plain session repairs by endpoint rotation, a Psiphon session
// repairs by restarting Psiphon.
//
// The restart reuses the port the session already recorded, because that port is
// baked into mihomo's rendered config (the `Psiphon` socks5 outbound). A new port
// would leave mihomo dialing a dead listener; without a recorded port we cannot
// restart safely at all and say so instead of guessing.

// psiphonRestartLimit bounds consecutive Psiphon restarts before the guard gives
// up. Three, because a transient bootstrap failure usually clears within one or
// two attempts, and a fault that survives three is not a hiccup.
const psiphonRestartLimit = 3

// psiphonUnderlayLimit bounds consecutive base-protocol rebuilds in a Psiphon
// session. Rebuilding the underlay (rotating a WARP endpoint, re-rendering the
// config, restarting both cores) is far heavier than restarting Psiphon, so the
// budget is smaller: two rebuilds, then the guard gives up honestly.
const psiphonUnderlayLimit = 2

// psiphonLaunchFromState rebuilds the parameters a restart needs from the
// persisted session. Every field is derivable from state except the base config,
// which is still on disk in the core dir.
func psiphonLaunchFromState(st clientState) (psiphonLaunch, error) {
	cDir, err := coreDir()
	if err != nil {
		return psiphonLaunch{}, err
	}
	exe, err := resolvePsiphonExe(options{}, cDir)
	if err != nil {
		return psiphonLaunch{}, err
	}
	baseConfig, err := resolvePsiphonClientConfig(cDir)
	if err != nil {
		return psiphonLaunch{}, err
	}
	// The port must match the one mihomo's config names; a new port would be
	// unreachable and a missing one cannot be guessed.
	if st.PsiphonSocksPort <= 0 {
		return psiphonLaunch{}, fmt.Errorf("state 未记录 Psiphon SOCKS 端口，无法在不改写 mihomo 配置的前提下重启")
	}
	mixed := st.MixedPort
	if mixed <= 0 {
		mixed = core.DefaultMixedPort
	}
	return psiphonLaunch{
		ExePath:        exe,
		DataDir:        filepath.Join(cDir, "psiphon-data"),
		BaseConfigPath: baseConfig,
		Upstream:       fmt.Sprintf("socks5://127.0.0.1:%d", underlaySocksPort(mixed)),
		SocksPort:      st.PsiphonSocksPort,
		EgressRegion:   st.PsiphonRegion,
	}, nil
}

// restartPsiphon stops the recorded Psiphon sidecar (if any) and starts a fresh
// one on the same port, waiting for a real tunnel before declaring success. The
// new pid is written back so disconnect / giveUp can still reach it.
func restartPsiphon(ctx context.Context, st clientState, logf func(string)) error {
	if prev, err := loadState(); err == nil && prev.PsiphonPID > 0 {
		if kerr := stopRecordedPsiphon(prev); kerr != nil {
			logf(fmt.Sprintf("停止旧 Psiphon 失败: %v", kerr))
		}
	}
	l, err := psiphonLaunchFromState(st)
	if err != nil {
		return err
	}
	ps := &Psiphon{}
	if err := ps.Start(ctx, l); err != nil {
		return fmt.Errorf("启动 Psiphon: %w", err)
	}
	// Record the new pid at once: the process exists now, and a giveUp or a
	// disconnect landing during the (possibly long) tunnel wait must be able to
	// reach it — otherwise the restarted sidecar is orphaned.
	if cur, cerr := loadState(); cerr == nil {
		cur.PsiphonMode = true
		cur.PsiphonPID = ps.PID()
		cur.PsiphonSocksPort = l.SocksPort
		_ = saveState(cur)
	}
	if err := ps.WaitForSocks(ctx, psiphonSocksWait); err != nil {
		_ = ps.Stop()
		return fmt.Errorf("等待 SOCKS: %w", err)
	}
	if err := ps.WaitForTunnel(ctx, psiphonTunnelWait); err != nil {
		_ = ps.Stop()
		return fmt.Errorf("等待隧道: %w", err)
	}
	logf(fmt.Sprintf("Psiphon 已重启 (pid %d, socks 127.0.0.1:%d)", ps.PID(), l.SocksPort))
	return nil
}
