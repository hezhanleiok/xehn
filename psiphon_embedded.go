//go:build ignore

// DRAFT — excluded from the build (`//go:build ignore`).
//
// Goal: run psiphon-tunnel-core inside this process so Windows Smart App
// Control has no unsigned sidecar to block.
//
// Status: blocked by an irreconcilable dependency conflict, not by this code.
// psiphon's quic-go fork (Psiphon-Labs/quic-go v0.0.0-20261103172121) is written
// against qpack v0.4.0 (qpack.NewDecoder(callback) / Decoder.DecodeFull), while
// this client's own MASQUE stack needs quic-go v0.60.0 which requires
// qpack v0.6.0 (different API). A Go module graph can only carry ONE qpack
// version, so enabling this file breaks the psiphon http3 package:
//
//	quic-go/http3/conn.go:78: too many arguments in call to qpack.NewDecoder
//	quic-go/http3/conn.go:140: c.decoder.DecodeFull undefined
//
// Resolving it requires one of: (a) downgrading this client's quic-go, which
// breaks MASQUE; (b) forking psiphon to drop its QUIC support, losing one of its
// anti-censorship protocols; or (c) psiphon shipping a qpack-v0.6-compatible
// fork. Revisit when (c) happens.
//
// Everything else was verified working: psiphon-tunnel-core master builds its
// dependency graph through a local `replace` (fetched via the V2RayN proxy), and
// only the qpack API mismatch stops the build.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary/clientlib"
)

// embeddedPsiphon runs psiphon-tunnel-core INSIDE this process instead of
// forking core/psiphon.exe.
//
// Why: the sidecar is an unsigned third-party binary. On Windows 11 with Smart
// App Control enforced, CreateProcess is refused by the code-integrity policy
// ("An Application Control policy has blocked this file", WinError 4551), and
// neither "run as administrator" nor launching through cmd.exe bypasses it —
// the image itself has no publisher reputation. Keeping the tunnel core in our
// own process removes the child image entirely, so there is nothing for the
// policy to block.
type embeddedPsiphon struct {
	tunnel *clientlib.PsiphonTunnel
}

// startEmbedded renders the same official config the sidecar used (credentials,
// server-list URLs, upstream, egress region) and hands it to the library. It
// returns as soon as the worker is running; readiness is tracked through
// p.state exactly like the sidecar path, so WaitForSocks/WaitForTunnel need no
// special case.
func (p *Psiphon) startEmbedded(ctx context.Context, l psiphonLaunch) error {
	cfg, err := buildPsiphonConfig(l)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("psiphon: config marshal: %w", err)
	}
	if err := os.MkdirAll(l.DataDir, 0o755); err != nil {
		return fmt.Errorf("psiphon: data dir: %w", err)
	}
	// Keep the rendered config on disk for diagnostics/diffing; the library is
	// given the bytes directly.
	_ = os.WriteFile(filepath.Join(l.DataDir, "psiphon-config.json"), raw, 0o600)

	p.mu.Lock()
	if p.cmd != nil || p.embedded != nil {
		p.mu.Unlock()
		return fmt.Errorf("psiphon: already running")
	}
	p.state = psiphonStarting
	p.dataDir = l.DataDir
	p.exePath = "embedded"
	p.upstream = l.Upstream
	p.socksPort = l.SocksPort
	p.pid = 0
	done := make(chan struct{})
	p.done = done
	tctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.mu.Unlock()

	// NetworkID is mandatory for tunnel-core; the value only tags statistics.
	networkID := "XEHN"
	platform := "Windows"
	establishTimeout := 60
	params := clientlib.Parameters{
		DataRootDirectory:             &l.DataDir,
		NetworkID:                     &networkID,
		ClientPlatform:                &platform,
		EstablishTunnelTimeoutSeconds: &establishTimeout,
	}

	go func() {
		tunnel, serr := clientlib.StartTunnel(tctx, raw, "", params, nil, nil)
		p.mu.Lock()
		if serr != nil {
			p.embeddedErr = serr
			p.embedded = nil
			p.state = psiphonFailed
		} else {
			p.embedded = &embeddedPsiphon{tunnel: tunnel}
			if tunnel.SOCKSProxyPort > 0 {
				p.socksPort = tunnel.SOCKSProxyPort
			}
			p.state = psiphonTunnelReady
		}
		p.mu.Unlock()
		// Closed last: readers treat "done closed" as "the launch is over" and
		// must see the final state, never a half-written one.
		close(done)
	}()
	return nil
}

// stopEmbedded shuts the in-process tunnel down. Safe to call with nil.
func (p *Psiphon) stopEmbedded(e *embeddedPsiphon) {
	if e == nil || e.tunnel == nil {
		return
	}
	e.tunnel.Stop()
}
