package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/xhwarp/warp-client/internal/core"
)

// defaultConnectOptions builds the options struct a `connect` CLI invocation
// would produce, so the GUI and the CLI share the exact same code path.
func defaultConnectOptions(proto string, tun, scanNow bool) options {
	o := options{
		proto:          proto,
		tunMode:        tun,
		scanNow:        scanNow,
		mixedPort:      core.DefaultMixedPort,
		apiPort:        core.DefaultAPIPort,
		timeoutSec:     2,
		tunnelParallel: defaultTunnelJobs,
		perSubnet:      1,
		confType:       confTypeMihomo,
		wantMeta:       true,
	}
	if proto == "" {
		o.proto = protoAWG
	}
	return o
}

// The log file is opened for append and inherited by every child process (the
// mihomo core logs into it too), so it grows with the core's per-connection
// chatter. Left alone a long-lived install accumulates hundreds of megabytes.
// At startup, a file past the cap is rewritten to keep only its tail: the
// recent lines are what a bug report needs, and a smaller file keeps the
// guard's 2-second incremental read cheap.
const (
	logTrimAbove = 8 << 20 // rewrite when the file is larger than this
	logTrimKeep  = 2 << 20 // bytes of tail to keep
)

// trimLogFile shrinks an oversized log to its last logTrimKeep bytes.
func trimLogFile(path string) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() <= logTrimAbove {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	off := fi.Size() - logTrimKeep
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return
	}
	tail, err := io.ReadAll(io.LimitReader(f, logTrimKeep))
	if err != nil || len(tail) == 0 {
		return
	}
	// Start on a line boundary so the first kept line is not a fragment.
	if i := bytes.IndexByte(tail, '\n'); i >= 0 && i+1 < len(tail) {
		tail = tail[i+1:]
	}
	if err := os.WriteFile(path, tail, 0o644); err != nil {
		return
	}
}

// redirectLogs sends stdout+stderr to a log file next to the binary when the
// process has no console (windowsgui build). In a terminal it is a no-op.
func redirectLogs() {
	// If stderr is a real console, keep printing there.
	if fi, err := os.Stderr.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		return
	}
	home, err := appDir()
	if err != nil {
		return
	}
	logPath := filepath.Join(home, "xehn.log")
	trimLogFile(logPath)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	// Replace the (dead) standard handles wholesale so every child process —
	// the mihomo core included — inherits the log file instead of a console
	// handle that does not exist in the windowsgui subsystem.
	os.Stdout = f
	os.Stderr = f
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags)
}

// ensurePortableHome anchors WARP_CLIENT_HOME to the executable's folder when
// it is not set, so an extracted ZIP keeps account, cache, core binary and
// config.yaml next to the exe — the v2rayN portable layout. It also creates
// a marker so `go test` runs (whose exe lives in a temp dir) can still override
// it via the environment first.
func ensurePortableHome() {
	if os.Getenv("WARP_CLIENT_HOME") != "" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	// Only adopt the exe's folder when it is writable: a Program Files install
	// must fall back to %APPDATA% instead of failing every write.
	probe := filepath.Join(dir, ".warp-portable")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		_ = os.Remove(probe)
		return
	}
	_ = os.Remove(probe)
	os.Setenv("WARP_CLIENT_HOME", dir)
}

// dirWritable reports whether a probe file can be created in dir. A read-only
// install (Program Files, a controlled folder) makes ensurePortableHome fall
// back to %APPDATA%, which is the single most common reason a perfectly good
// bundled core is not found on first launch.
func dirWritable(dir string) bool {
	p := filepath.Join(dir, ".xehn-write-probe")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		return false
	}
	_ = os.Remove(p)
	return true
}

// logStartupDiagnostics writes one structured block per launch, before any
// connection is attempted. Missing core folder, a quarantined binary, a
// read-only install that fell back to %APPDATA%, and a core that Windows
// refuses to execute all used to surface as the same "Clash 核心不可用"
// message. One log block makes them distinguishable without asking the user
// to reproduce anything.
// syncBundledResources fixes the read-only-install case: ensurePortableHome
// falls back to %APPDATA%\xehn when the exe's folder cannot be written, which
// used to hide the perfectly good core/ and geodata shipped next to the exe.
// Instead of forcing every write into a protected folder, copy the read-only
// resources into the writable data dir once. Only missing/empty files are
// copied, so a user-updated mihomo.exe in the data dir is never overwritten.
func syncBundledResources(workDir string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	src := filepath.Join(filepath.Dir(exe), coreDirName)
	absSrc, absWork := filepath.Clean(src), filepath.Clean(workDir)
	if strings.EqualFold(absSrc, absWork) {
		return
	}
	for _, name := range []string{core.ExeName(), "geosite.dat", "geoip.metadb"} {
		dst := filepath.Join(workDir, name)
		if fi, statErr := os.Stat(dst); statErr == nil && fi.Size() > 0 {
			continue
		}
		if cerr := copyFileAtomic(filepath.Join(src, name), dst); cerr != nil {
			log.Printf("bundled resource %s unavailable: %v", name, cerr)
		} else {
			log.Printf("restored bundled %s into %s", name, workDir)
		}
	}
}

func copyFileAtomic(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	tmp := to + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	out.Close()
	return os.Rename(tmp, to)
}

func logStartupDiagnostics() {
	home, herr := appDir()
	cDir, cerr := coreDir()
	exe, eerr := os.Executable()
	lines := []string{
		"=== startup diagnostics ===",
		fmt.Sprintf("version=%s build=%s", resolveVersion(), buildStamp),
		fmt.Sprintf("WARP_CLIENT_HOME=%q", os.Getenv("WARP_CLIENT_HOME")),
		fmt.Sprintf("appDir=%q err=%v", home, herr),
		fmt.Sprintf("coreDir=%q err=%v", cDir, cerr),
	}
	if eerr == nil {
		lines = append(lines, fmt.Sprintf("exe=%q exeDirWritable=%v", exe, dirWritable(filepath.Dir(exe))))
	} else {
		lines = append(lines, fmt.Sprintf("exe stat ERR %v", eerr))
	}
	if cerr == nil {
		bin := core.CoreInDir(cDir)
		if fi, err := os.Stat(bin); err != nil {
			lines = append(lines, fmt.Sprintf("core=%q stat=ERR %v", bin, err))
		} else {
			lines = append(lines, fmt.Sprintf("core=%q size=%d", bin, fi.Size()))
			if v, verr := core.BinaryVersion(bin); verr != nil {
				lines = append(lines, fmt.Sprintf("coreVersion=ERR %v", verr))
			} else {
				lines = append(lines, "coreVersion="+v)
			}
		}
		lines = append(lines, fmt.Sprintf("geodataReady=%v", core.GeoDataReady(cDir)))
		for _, n := range core.GeoDataNames() {
			p := filepath.Join(cDir, n)
			if fi, err := os.Stat(p); err != nil {
				lines = append(lines, fmt.Sprintf("geo %s: ERR %v", n, err))
			} else {
				lines = append(lines, fmt.Sprintf("geo %s: %d bytes", n, fi.Size()))
			}
		}
	}
	lines = append(lines, "=== end diagnostics ===")
	for _, l := range lines {
		log.Print(l)
	}
}
