package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var versionRe = regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)

// BinaryVersion runs `mihomo -v` and returns the bare semantic version
// ("1.19.32"). It works for both official releases ("Mihomo Meta v1.19.32 …")
// and older/forked builds that print no "v" prefix.
func BinaryVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-v")
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("core: %s -v timed out (blocked by security software?): %w", filepath.Base(bin), ctx.Err())
		}
		return "", fmt.Errorf("core: %s -v: %w", filepath.Base(bin), err)
	}
	if m := versionRe.FindSubmatch(out); m != nil {
		return string(m[1]), nil
	}
	return "", fmt.Errorf("core: cannot parse version from %q", strings.TrimSpace(string(out)))
}

// TestConfig asks the core to validate configYAML via `mihomo -t` and returns
// an error carrying the core's own complaint when it rejects the file. This is
// the ground truth for capability probing: instead of guessing from a version
// number whether an outbound type exists, the actual binary parses a minimal
// per-protocol config and answers.
func TestConfig(bin, workDir string, configYAML []byte) error {
	ok, _, err := TestConfigDetail(bin, workDir, configYAML)
	if !ok {
		return err
	}
	return nil
}

// TestConfigDetail is TestConfig with the two failure modes separated:
//
//	ok  — the core accepted the config
//	ran — the probe actually reached the core
//
// A probe that could not run at all (the temp file could not be created, the
// binary could not be executed, a scanner locked it) must not be reported as
// "this core does not support the protocol": that answer sends the user off to
// re-download a core that is perfectly fine, and blocks the connect. Only
// ran && !ok is a real rejection.
//
// The YAML is written to the system temp directory rather than workDir: the
// core directory can be read-only (Program Files), can be watched by security
// software, and is not ours to litter with probe files.
func TestConfigDetail(bin, workDir string, configYAML []byte) (ok, ran bool, err error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return false, false, err
	}
	dir, terr := os.MkdirTemp("", "warp-probe")
	if terr != nil {
		return false, false, terr
	}
	defer os.RemoveAll(dir)
	probe := filepath.Join(dir, "probe.yaml")
	if werr := os.WriteFile(probe, configYAML, 0o600); werr != nil {
		return false, false, werr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-t", "-d", workDir, "-f", probe)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return false, false, fmt.Errorf("core: %s -t timed out (blocked by security software?)", filepath.Base(bin))
	}
	if err != nil {
		// A Windows exception code means the process died before it could say
		// anything. That is an environment problem, not a rejected config, and
		// the caller has to be able to tell the two apart.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if code := uint32(ee.ExitCode()); code >= 0xC0000000 {
				return false, true, &CrashError{Code: code}
			}
		}
		msg := strings.TrimSpace(string(out))
		if i := strings.LastIndex(msg, "\n"); i >= 0 {
			msg = msg[i+1:]
		}
		if msg == "" {
			msg = err.Error()
		}
		// No output at all means the child never ran (missing binary, exec
		// failure): that is infrastructure, not a rejected config.
		if strings.TrimSpace(string(out)) == "" {
			return false, false, fmt.Errorf("%s", msg)
		}
		return false, true, fmt.Errorf("%s", msg)
	}
	return true, true, nil
}
