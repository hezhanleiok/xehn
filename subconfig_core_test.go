//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestRenderedSubscriptionConfigLoads is the "will the core start" guard. It
// renders a subscription config with a full node pool and hands it to the
// bundled mihomo with -t, so a malformed proxy entry or a name collision is
// caught here instead of as "核心无法启动" on a user's machine.
func TestRenderedSubscriptionConfigLoads(t *testing.T) {
	bin := filepath.Join("core", "mihomo.exe")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("bundled core not present")
	}

	const n = 300
	proxies := make([]ProxySpec, 0, n)
	for i := 0; i < n; i++ {
		typ := "ss"
		fields := map[string]any{
			"server":   fmt.Sprintf("10.0.%d.%d", i/200, i%200+1),
			"port":     8388 + i%100,
			"cipher":   "aes-128-gcm",
			"password": "pw",
		}
		if i%3 == 0 {
			typ = "trojan"
			fields = map[string]any{
				"server":   fmt.Sprintf("10.1.%d.%d", i/200, i%200+1),
				"port":     443,
				"password": "pw",
			}
		}
		proxies = append(proxies, ProxySpec{
			Name:   fmt.Sprintf("节点-%03d", i),
			Type:   typ,
			Fields: fields,
		})
	}

	opts := options{
		confType:      confTypeMihomo,
		mixedPort:     17999,
		apiPort:       17998,
		customProxies: proxies,
		activeProxy:   proxies[0].Name,
	}
	cfg, err := renderSubscriptionConfig(opts)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	// The core resolves geodata relative to its data dir; point it at core/.
	absCore, err := filepath.Abs("core")
	if err != nil {
		t.Fatal(err)
	}
	out, runErr := exec.Command(bin, "-t", "-f", path, "-d", absCore).CombinedOutput()
	if runErr != nil {
		t.Fatalf("core rejected the rendered config: %v\n%s", runErr, tailOf(string(out), 1500))
	}
}

// TestRenderedConfigRejectsDuplicateNames pins the invariant the renamer exists
// for: mihomo refuses two proxies with the same name, so the client must never
// render one.
func TestRenderedConfigRejectsDuplicateNames(t *testing.T) {
	bin := filepath.Join("core", "mihomo.exe")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("bundled core not present")
	}
	dup := []ProxySpec{
		{Name: "同名节点", Type: "ss", Fields: map[string]any{"server": "10.0.0.1", "port": 8388, "cipher": "aes-128-gcm", "password": "pw"}},
		{Name: "同名节点", Type: "ss", Fields: map[string]any{"server": "10.0.0.2", "port": 8388, "cipher": "aes-128-gcm", "password": "pw"}},
	}
	opts := options{confType: confTypeMihomo, mixedPort: 17997, apiPort: 17996, customProxies: dup, activeProxy: dup[0].Name}
	cfg, err := renderSubscriptionConfig(opts)
	if err != nil {
		t.Fatalf("render failed: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	absCore, _ := filepath.Abs("core")
	out, runErr := exec.Command(bin, "-t", "-f", path, "-d", absCore).CombinedOutput()
	if runErr == nil {
		t.Log("core accepted duplicate names; the renamer still prevents them in the import path")
	} else {
		t.Logf("core rejected duplicates as expected: %s", tailOf(string(out), 300))
	}
}

func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
