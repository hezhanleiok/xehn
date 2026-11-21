//go:build windows

package core

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	internetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	proxyServerKey       = "ProxyServer"
	proxyEnableKey       = "ProxyEnable"
	proxyOverrideKey     = "ProxyOverride"
	proxyAutoConfigKey   = "AutoConfigURL"
	proxyAutoDetectKey   = "AutoDetect"

	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
	// INTERNET_OPTION_PER_CONN_OPTION: set the whole per-connection option
	// list (flags + server + bypass + auto-config URL + auto-discover flags)
	// in one WinINet call — the same call the Internet Options dialog makes.
	internetOptionPerConnOption = 75

	internetPerConnFlags         = 1
	internetPerConnProxyServer   = 2
	internetPerConnProxyBypass   = 3
	internetPerConnAutoConfigURL = 4
	internetPerConnAutoDiscovery = 5

	proxyTypeDirect       = 1
	proxyTypeProxy        = 2
	proxyTypeAutoProxyURL = 4
	proxyTypeAutoDetect   = 8
)

// openInternetSettings opens the WinINET key. The open can transiently fail
// with "Access is denied" while wininet's own refresh storm (or antivirus)
// holds the key. Spaced, growing retries ride out the race instead of failing
// the whole connect over a millisecond window.
func openInternetSettings(access uint32) (registry.Key, error) {
	var lastErr error
	for try := 0; try < 5; try++ {
		k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, access)
		if err == nil {
			return k, nil
		}
		lastErr = err
		time.Sleep(time.Duration(400+try*300) * time.Millisecond)
	}
	return 0, fmt.Errorf("core: open internet settings: %w", lastErr)
}

// ProxySnapshot holds the pre-change values so Unset can restore them exactly.
// The auto-config URL and auto-detect flag are captured on top of the classic
// three values: a host that runs a PAC-mode proxy client alongside this one
// keeps that PAC inside the per-connection settings, and a faithful restore
// must be able to put it back on disconnect.
type ProxySnapshot struct {
	Server        string `json:"server"`
	Override      string `json:"override"`
	Enable        uint32 `json:"enable"`
	AutoConfigURL string `json:"auto_config_url,omitempty"`
	AutoDetect    uint32 `json:"auto_detect,omitempty"`
}

// readProxySnapshot captures the current WinINET values through a read-only
// open. Guarding software blocks the write, not the read, so even on a
// locked-down machine the connect still gets its restore baseline; a failed
// read just degrades to a clean no-proxy baseline.
func readProxySnapshot() *ProxySnapshot {
	snap := &ProxySnapshot{}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE)
	if err != nil {
		return snap
	}
	defer k.Close()
	if s, _, err := k.GetStringValue(proxyServerKey); err == nil {
		snap.Server = s
	}
	if s, _, err := k.GetStringValue(proxyOverrideKey); err == nil {
		snap.Override = s
	}
	if v, _, err := k.GetIntegerValue(proxyEnableKey); err == nil {
		snap.Enable = uint32(v)
	}
	if s, _, err := k.GetStringValue(proxyAutoConfigKey); err == nil {
		snap.AutoConfigURL = s
	}
	if v, _, err := k.GetIntegerValue(proxyAutoDetectKey); err == nil {
		snap.AutoDetect = uint32(v)
	}
	return snap
}

// SetSystemProxy points Windows' WinINET proxy at the local mixed port and
// notifies the running shell. It returns a snapshot to hand back to
// UnsetSystemProxy. The write itself goes through applyProxyValues, which
// degrades from a direct registry edit to the WinINet per-connection API to a
// reg.exe subprocess so proxy-hijack protection on the host cannot silently
// strand a verified tunnel.
func SetSystemProxy(port int) (*ProxySnapshot, error) {
	snap := readProxySnapshot()

	server := fmt.Sprintf("127.0.0.1:%d", port)
	// If the proxy already points at our mixed port, the captured "current"
	// values are a previous xehn connect's leftovers (crash mid-connect,
	// or connect while connected), not the user's baseline. Restoring them on
	// disconnect would leave the proxy enabled against a dead port; snapshot a
	// clean no-proxy baseline instead.
	if snap.Server == server {
		snap.Server = ""
		snap.Enable = 0
		snap.Override = strings.TrimPrefix(strings.TrimPrefix(snap.Override, "<local>;"), "<local>")
	}
	// Leave the bypass list intact: localhost must still bypass so the core's
	// controller and the tunnel itself are not sent back through the proxy.
	bypass := "<local>"
	if snap.Override != "" && !strings.Contains(snap.Override, "<local>") {
		bypass = "<local>;" + snap.Override
	}
	// Manual proxy, no PAC, no auto-detect: everything except the bypass list
	// resolves through the mixed port.
	if err := applyProxyValues(proxyValues{Server: server, Override: bypass, Enable: 1}); err != nil {
		return snap, err
	}
	return snap, nil
}

// UnsetSystemProxy restores the values captured by SetSystemProxy — including
// any auto-config URL and auto-detect flag the host had before connect. It
// walks the same degrade chain: a disconnect whose restore write is blocked
// must not leave the host pointed at a dead port.
func UnsetSystemProxy(snap *ProxySnapshot) error {
	if snap == nil {
		return nil
	}
	return applyProxyValues(proxyValues{
		Server:        snap.Server,
		Override:      snap.Override,
		Enable:        snap.Enable,
		AutoConfigURL: snap.AutoConfigURL,
		AutoDetect:    snap.AutoDetect,
	})
}

// SystemProxyEnabledAt reports whether the machine proxy is currently
// enabled and pointing at the given local port — the watchdog's "is the
// leftover proxy still ours" test after a killed client's cleanup.
func SystemProxyEnabledAt(port int) bool {
	snap := readProxySnapshot()
	return snap.Enable == 1 && strings.EqualFold(snap.Server, fmt.Sprintf("127.0.0.1:%d", port))
}

// SystemProxyPointsElsewhere distinguishes "another program took the host proxy"
// from "the user turned the proxy off". The first invalidates the session and
// deserves a teardown; the second may well be deliberate (the user switched to
// TUN, or is debugging), and killing their tunnel over it would be rude.
func SystemProxyPointsElsewhere(port int) bool {
	snap := readProxySnapshot()
	if snap.Enable != 1 {
		return false
	}
	server := strings.TrimSpace(snap.Server)
	return server != "" && !strings.EqualFold(server, fmt.Sprintf("127.0.0.1:%d", port))
}

// ClearSystemProxy disables the machine proxy outright: the watchdog's last
// resort when the client died between pointing the proxy at the tunnel and
// persisting the snapshot that would restore the user's own settings. With
// ProxyEnable=0 the leftover ProxyServer value is inert.
func ClearSystemProxy() error {
	return applyProxyValues(proxyValues{})
}

// applyProxyValues commits one proxy state (wininet per-conn first) through
// every write path until one lands and survives read-back:
//
//  1. direct registry edit — works on any unguarded machine;
//  2. the WinINet PER_CONN_OPTION API — the same InternetSetOption call the
//     Internet Options dialog makes; proxy-hijack heuristics that block a
//     foreign process writing the key usually let the OS's own DLL through;
//  3. reg.exe — a Microsoft-signed binary; the last thing a whitelist-style
//     guard still blocks, and when even that fails the user needs a trust
//     entry for the client, not another code path.
//
// Every "success" is verified by reading the values back: security software
// that swallows or rolls back the edit must surface as a failure here, never
// as a connected state with an unproxied browser.
// proxyValues is one complete machine-proxy target state. The auto-config
// (PAC) URL and auto-detect flags ride along with the classic three values
// because a host that previously ran a PAC-mode client keeps that PAC inside
// the per-connection settings; writing only ProxyServer/ProxyEnable leaves the
// PAC in place, and Chromium/WinINET keep resolving through it - the classic
// "connected but every page times out".
type proxyValues struct {
	Server        string
	Override      string
	Enable        uint32
	AutoConfigURL string
	AutoDetect    uint32
}

func applyProxyValues(v proxyValues) error {
	errWininet := setProxyViaWininet(v)
	if errWininet == nil && verifyProxyReadback(v) == nil {
		return nil
	}
	errRegistry := writeProxyRegistry(v)
	if errRegistry == nil && verifyProxyReadback(v) == nil {
		return nil
	}
	errRegExe := setProxyViaRegExe(v)
	if errRegExe == nil && verifyProxyReadback(v) == nil {
		return nil
	}
	return fmt.Errorf("注册表(%v) · WinInet API(%v) · reg.exe(%v)", errRegistry, errWininet, errRegExe)
}

// writeProxyRegistry is the plain path: open, write, notify. The auto-config
// URL and auto-detect flag are written too so the top-level keys and the
// per-connection settings never disagree.
func writeProxyRegistry(v proxyValues) error {
	k, err := openInternetSettings(registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue(proxyServerKey, v.Server); err != nil {
		return err
	}
	if err := k.SetStringValue(proxyOverrideKey, v.Override); err != nil {
		return err
	}
	if err := k.SetStringValue(proxyAutoConfigKey, v.AutoConfigURL); err != nil {
		return err
	}
	if err := k.SetDWordValue(proxyAutoDetectKey, v.AutoDetect); err != nil {
		return err
	}
	// Enable last: the proxy is never switched on before its address is in
	// place, so a mid-write observer never sees a half-configured proxy.
	if err := k.SetDWordValue(proxyEnableKey, v.Enable); err != nil {
		return err
	}
	notifyProxyChange()
	return nil
}

// perConnOption mirrors INTERNET_PER_CONN_OPTION_W: dwOption selects the
// option; the union value is either a DWORD (flags) or a wide-string pointer
// (server / bypass) packed into one pointer-sized slot.
type perConnOption struct {
	option uint32
	value  uintptr
}

// perConnOptionList mirrors INTERNET_PER_CONN_OPTION_LIST_W with a NULL
// connection name, i.e. the default (LAN) connection. dwSize must be the first
// member or the API reads the whole list misaligned and fails.
type perConnOptionList struct {
	size        uint32
	connection  uintptr
	count       uint32
	optionError uint32
	options     *perConnOption
}

// setProxyViaWininet sets flags + server + bypass in one
// InternetSetOptionW(INTERNET_OPTION_PER_CONN_OPTION) call — the write happens
// inside wininet.dll, the component that owns the settings.
func setProxyViaWininet(v proxyValues) error {
	pServer, err := syscall.UTF16PtrFromString(v.Server)
	if err != nil {
		return err
	}
	pBypass, err := syscall.UTF16PtrFromString(v.Override)
	if err != nil {
		return err
	}
	pAutoConfig, err := syscall.UTF16PtrFromString(v.AutoConfigURL)
	if err != nil {
		return err
	}
	opts := []perConnOption{
		{option: internetPerConnFlags, value: uintptr(perConnFlags(v))},
		{option: internetPerConnProxyServer, value: uintptr(unsafe.Pointer(pServer))},
		{option: internetPerConnProxyBypass, value: uintptr(unsafe.Pointer(pBypass))},
		{option: internetPerConnAutoConfigURL, value: uintptr(unsafe.Pointer(pAutoConfig))},
		{option: internetPerConnAutoDiscovery, value: uintptr(v.AutoDetect)},
	}
	list := perConnOptionList{
		size:    uint32(unsafe.Sizeof(perConnOptionList{})),
		count:   uint32(len(opts)),
		options: &opts[0],
	}
	r1, _, callErr := internetSetOptionW.Call(
		0,
		internetOptionPerConnOption,
		uintptr(unsafe.Pointer(&list)),
		unsafe.Sizeof(list),
	)
	if r1 == 0 {
		return fmt.Errorf("InternetSetOption: %w", callErr)
	}
	notifyProxyChange()
	return nil
}

// perConnFlags computes the INTERNET_PER_CONN_FLAGS bitmask that matches a
// target state: a manual proxy when enabled, an auto-config URL when a PAC is
// the target, auto-detect when enabled, and DIRECT when all three are off.
func perConnFlags(v proxyValues) uint32 {
	flags := uint32(proxyTypeDirect)
	switch {
	case v.Enable != 0:
		flags = proxyTypeProxy
	case v.AutoConfigURL != "":
		flags = proxyTypeAutoProxyURL
	}
	if v.AutoDetect != 0 {
		flags |= proxyTypeAutoDetect
	}
	return flags
}

// setProxyViaRegExe writes the values with reg.exe, a Microsoft-signed
// binary: a guard that already blocked our process and wininet's caller still
// has to decide whether to block the OS's own registry tool. The subprocess
// is fully hidden (CREATE_NO_WINDOW) — no console may ever flash.
func setProxyViaRegExe(v proxyValues) error {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	reg := filepath.Join(root, "system32", "reg.exe")
	if _, err := os.Stat(reg); err != nil {
		return fmt.Errorf("reg.exe not found: %w", err)
	}
	values := []struct{ name, typ, data string }{
		{proxyServerKey, "REG_SZ", v.Server},
		{proxyOverrideKey, "REG_SZ", v.Override},
		{proxyAutoConfigKey, "REG_SZ", v.AutoConfigURL},
		{proxyAutoDetectKey, "REG_DWORD", fmt.Sprintf("%d", v.AutoDetect)},
		{proxyEnableKey, "REG_DWORD", fmt.Sprintf("%d", v.Enable)},
	}
	for _, v := range values {
		cmd := exec.Command(reg, "add", `HKCU\`+internetSettingsPath,
			"/v", v.name, "/t", v.typ, "/d", v.data, "/f")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("reg add %s: %w: %s", v.name, err, strings.TrimSpace(string(out)))
		}
	}
	notifyProxyChange()
	return nil
}

// verifyProxyReadback re-opens the WinINET key read-only and confirms the
// values a write path claimed it set actually landed.
func verifyProxyReadback(v proxyValues) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsPath, registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("verify open: %w", err)
	}
	defer k.Close()
	got, _, err := k.GetIntegerValue(proxyEnableKey)
	if err != nil || uint32(got) != v.Enable {
		return fmt.Errorf("ProxyEnable 未生效")
	}
	if v.Enable != 0 {
		gotServer, _, err := k.GetStringValue(proxyServerKey)
		if err != nil || gotServer != v.Server {
			return fmt.Errorf("ProxyServer 未生效")
		}
	}
	// A stale auto-config URL silently overrides the manual proxy in Chromium:
	// confirm it matches the target so a PAC the client meant to clear cannot
	// leave the browser resolving somewhere else.
	gotAutoConfig, _, _ := k.GetStringValue(proxyAutoConfigKey)
	if gotAutoConfig != v.AutoConfigURL {
		return fmt.Errorf("AutoConfigURL 未生效")
	}
	return nil
}

// blockerSignatures maps the processes of the security suites whose
// proxy-hijack protection is the usual reason a WinINET edit comes back
// "Access is denied" to a friendly name for the warning banner.
var blockerSignatures = []struct{ proc, name string }{
	{"360tray.exe", "360安全卫士"},
	{"360safe.exe", "360安全卫士"},
	{"zhudongfangyu.exe", "360安全卫士"},
	{"360sd.exe", "360杀毒"},
	{"360rp.exe", "360杀毒"},
	{"usysdiag.exe", "火绒安全"},
	{"wsctrl.exe", "火绒安全"},
	{"hipstray.exe", "火绒安全"},
	{"hipsdaemon.exe", "火绒安全"},
	{"hipsmain.exe", "火绒安全"},
	{"qqpcrtp.exe", "腾讯电脑管家"},
	{"qqpcmgr.exe", "腾讯电脑管家"},
	{"kxetray.exe", "金山毒霸"},
	{"kwsprotect64.exe", "金山毒霸"},
	{"ksafe.exe", "金山毒霸"},
}

// DetectProxyBlocker returns the friendly name of any known security suite
// running on the host, or "". It only feeds a hint into the proxy-blocked
// warning: no match does not mean nothing guards the registry.
func DetectProxyBlocker() string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return ""
	}
	for {
		name := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		for _, sig := range blockerSignatures {
			if name == sig.proc {
				return sig.name
			}
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			return ""
		}
	}
}

var (
	wininetDLL         = syscall.NewLazyDLL("wininet.dll")
	internetSetOptionW = wininetDLL.NewProc("InternetSetOptionW")

	shell32DLL      = syscall.NewLazyDLL("shell32.dll")
	shellExecuteExW = shell32DLL.NewProc("ShellExecuteExW")
)

// notifyProxyChange pushes the registry edit out to live applications the way
// the Control Panel does. It is best-effort: a failure here only means some
// apps pick the proxy up on restart.
func notifyProxyChange() {
	internetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	internetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
}

// ---------------------------------------------------------------------------
// Elevated helper — the last resort when security software blocks every
// non-elevated write path (observed on real hosts: registry "Access is
// denied", wininet #12010, and even reg.exe "拒绝访问", all from a
// medium-integrity process, all fine once elevated). The GUI binary relaunches
// itself with "runas": one UAC prompt, the helper does the same verified
// write, exits. Only the -H windowsgui build may do this — relaunching a
// console binary elevated would flash a terminal window.
// ---------------------------------------------------------------------------

const (
	seeMaskNocloseProcess = 0x40
	swHide                = 0
)

// IsElevated reports whether the current process runs with an elevated token.
func IsElevated() bool {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer tok.Close()
	return tok.IsElevated()
}

// shellExecuteInfoW mirrors SHELLEXECUTEINFOW.
type shellExecuteInfoW struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     uintptr
}

// runSelfElevated relaunches the current executable with the given parameters
// under "runas" (the UAC consent prompt). A user declining the prompt surfaces
// as ERROR_CANCELLED. When wait is true it blocks until the child exits.
func runSelfElevated(parameters string, wait bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	pVerb, _ := syscall.UTF16PtrFromString("runas")
	pFile, _ := syscall.UTF16PtrFromString(exe)
	pParams, _ := syscall.UTF16PtrFromString(parameters)
	sei := shellExecuteInfoW{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfoW{})),
		fMask:        seeMaskNocloseProcess,
		lpVerb:       pVerb,
		lpFile:       pFile,
		lpParameters: pParams,
		nShow:        swHide,
	}
	r1, _, callErr := shellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r1 == 0 {
		return fmt.Errorf("runas: %w", callErr)
	}
	if wait && sei.hProcess != 0 {
		defer windows.CloseHandle(windows.Handle(sei.hProcess))
		_, _ = windows.WaitForSingleObject(windows.Handle(sei.hProcess), 120*1000)
	} else if sei.hProcess != 0 {
		windows.CloseHandle(windows.Handle(sei.hProcess))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Elevated daemon — one UAC prompt per GUI run, then silent proxy edits. The
// GUI relaunches itself elevated as "proxy-helper daemon <port> <token>
// <parent-pid>": the daemon listens on 127.0.0.1 only, authenticates every
// command with the random token handed over at start, and exits by itself
// within seconds of the parent GUI dying. First proxy edit of a session pays
// the UAC prompt; disconnect / protocol switch / exit are silent.
// ---------------------------------------------------------------------------

type helperDaemon struct {
	port  int
	token string
}

var (
	helperDaemonMu  sync.Mutex
	helperDaemonRef *helperDaemon
)

// helperCommand delivers one set/restore command to the elevated daemon,
// starting (and consenting to) a fresh daemon if none is reachable.
func helperCommand(req map[string]any) error {
	helperDaemonMu.Lock()
	defer helperDaemonMu.Unlock()
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if helperDaemonRef == nil {
			d, err := startHelperDaemon()
			if err != nil {
				return err
			}
			helperDaemonRef = d
		}
		if err := helperDaemonCall(helperDaemonRef, req); err == nil {
			return nil
		} else {
			lastErr = err
			helperDaemonRef = nil // daemon died: one retry with a fresh one
		}
	}
	return fmt.Errorf("proxy helper daemon: %w", lastErr)
}

// startHelperDaemon asks the user for one elevation and brings the daemon up.
func startHelperDaemon() (*helperDaemon, error) {
	// Pick a free port by binding and releasing it; the tiny race is covered
	// by the retry in helperCommand.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	buf := make([]byte, 16)
	if _, err := cryptorand.Read(buf); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(buf)
	if err := runSelfElevated(fmt.Sprintf("proxy-helper daemon %d %s %d", port, token, os.Getpid()), false); err != nil {
		return nil, err // includes the user declining the UAC prompt
	}
	// The daemon comes up right after consent; poll for it briefly.
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			conn.Close()
			return &helperDaemon{port: port, token: token}, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("daemon did not start")
}

func helperDaemonCall(d *helperDaemon, req map[string]any) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", d.port), 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	req["token"] = d.token
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var resp struct {
		OK  bool   `json:"ok"`
		Err string `json:"err,omitempty"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Err)
	}
	return nil
}

// SetSystemProxyElevated finishes a blocked proxy edit through the elevated
// daemon. Returns nil only when the read-back confirms the proxy landed.
func SetSystemProxyElevated(port int) error {
	if err := helperCommand(map[string]any{"cmd": "set", "port": port}); err != nil {
		return err
	}
	return verifyProxyReadback(proxyValues{Server: fmt.Sprintf("127.0.0.1:%d", port), Enable: 1})
}

// hiddenCmd builds a console-less command. netsh is a console program: started
// from a windowsgui process without CREATE_NO_WINDOW it allocates its own
// console, which is the black box that flashes on every LAN-share toggle.
func hiddenCmd(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	return c
}

// lanRuleName is the firewall rule this client owns, one pair per port so a
// changed mixed port does not leave a stale opening behind. The v2 marker lets a
// rule built with the old private,domain-only profile be replaced rather than
// mistaken for the current one.
func lanRuleName(port int, proto string) string {
	return fmt.Sprintf("XEHN-LAN-v2-%d-%s", port, proto)
}

// coreRuleName is the program-level rule pair for the bundled core. Windows
// asks "allow this program?" per executable, and that prompt is not satisfied by
// a port rule: the prompt is what appears on the first connect after sharing is
// turned on. Allowing the binary by path ends it for good, and unlike opening a
// port it grants nothing to any other program.
const (
	coreRuleIn  = "XEHN-CORE-IN"
	coreRuleOut = "XEHN-CORE-OUT"
)

// currentProfileIsPublic reports whether Windows classifies the active network
// as 公用. Plenty of home networks are, and a private,domain-only rule silently
// does nothing there.
func currentProfileIsPublic() bool {
	out, err := hiddenCmd("netsh", "advfirewall", "show", "currentprofile").CombinedOutput()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "公用") || strings.Contains(strings.ToLower(s), "public")
}

// addLanFirewallRule opens the mixed port for inbound LAN clients and allows the
// core binary itself. Windows prompts "allow this app to communicate on these
// networks" for any non-loopback listener; a user who dismisses it — or picks
// 取消 — leaves allow-lan looking enabled while nothing on the LAN can reach the
// port. An explicit rule also stops the prompt from appearing at all, which is
// the "mihomo asks for network permission on every connect" report.
//
// All three profiles on purpose: Windows classifies plenty of home networks as
// 公用 (public), and a private,domain-only rule silently does nothing there —
// the second half of "sharing is on but the phone cannot connect". The user has
// already turned sharing on, so opening the port is what they asked for.
func addLanFirewallRule(port int, corePath string) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	for _, proto := range []string{"TCP", "UDP"} {
		name := lanRuleName(port, proto)
		// Delete first: netsh appends a duplicate rule otherwise, and repeats
		// of this call must stay idempotent. The v1 name from an earlier build
		// is cleared too, so the port ends up with exactly one rule pair.
		_ = hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
		_ = hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+fmt.Sprintf("XEHN-LAN-%d-%s", port, proto)).Run()
		out, err := hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+name,
			"dir=in",
			"action=allow",
			"protocol="+proto,
			"localport="+strconv.Itoa(port),
			"profile=private,domain,public",
			"enable=yes",
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh add %s: %w (%s)", proto, err, strings.TrimSpace(string(out)))
		}
	}
	// Program-level pair, for the prompt the port rule cannot suppress.
	if corePath != "" {
		for _, dir := range []string{"in", "out"} {
			name := coreRuleIn
			if dir == "out" {
				name = coreRuleOut
			}
			_ = hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
			out, err := hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule",
				"name="+name,
				"dir="+dir,
				"action=allow",
				// Quoted: netsh splits on spaces, and an install under
				// "C:\Program Files\..." would otherwise be parsed as two
				// arguments and the rule silently fails to match any binary.
				"program=\""+corePath+"\"",
				"profile=any",
				"enable=yes",
			).CombinedOutput()
			if err != nil {
				return fmt.Errorf("netsh add core %s: %w (%s)", dir, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// ruleExists is the unprivileged probe: netsh show runs as a normal user, so
// the connect path can skip the elevation prompt when the rule is already there.
func ruleExists(name string) bool {
	out, err := hiddenCmd("netsh", "advfirewall", "firewall", "show", "rule", "name="+name).CombinedOutput()
	return err == nil && strings.Contains(string(out), name)
}

// coreRuleExists reports the program-level pair that suppresses the
// "allow this app?" prompt.
func coreRuleExists() bool { return ruleExists(coreRuleIn) && ruleExists(coreRuleOut) }

// lanRuleExistsV2 reports the current (all-profiles) port rule.
func lanRuleExistsV2(port int) bool { return ruleExists(lanRuleName(port, "TCP")) }

// lanPortRuleExists also accepts the v1 name a previous build wrote, so an
// upgrade on a private network does not ask for elevation again.
func lanPortRuleExists(port int) bool {
	return lanRuleExistsV2(port) || ruleExists(fmt.Sprintf("XEHN-LAN-%d-TCP", port))
}

// EnsureLanFirewall makes the mixed port reachable from the LAN and stops the
// core's per-program firewall prompt, adding what is missing through the
// elevated helper. Safe to call on every connect: the common case is a couple of
// unprivileged netsh queries.
//
// A v1-only rule is accepted when the active network is private/domain — it does
// the job there, and re-prompting for elevation on every upgrade is exactly what
// users complain about. On a public-classified network it is useless, so the
// rule is rebuilt.
func EnsureLanFirewall(port int, corePath string) error {
	if coreRuleExists() && lanRuleExistsV2(port) {
		return nil
	}
	if coreRuleExists() && lanPortRuleExists(port) && !currentProfileIsPublic() {
		return nil
	}
	return helperCommand(map[string]any{"cmd": "firewall", "port": port, "core": corePath})
}

// LanFirewallReady reports whether the inbound rule is already in place, for the
// settings page to tell the user what the switch will do.
func LanFirewallReady(port int) bool {
	return lanPortRuleExists(port)
}

// RemoveLanFirewall drops the rules this client added, so uninstalling or moving
// to a different port does not leave the port open.
func RemoveLanFirewall(port int) {
	for _, proto := range []string{"TCP", "UDP"} {
		_ = hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+lanRuleName(port, proto)).Run()
	}
}

// RestoreSystemProxyElevated restores a snapshot through the elevated daemon.
func RestoreSystemProxyElevated(snap *ProxySnapshot) error {
	if snap == nil {
		return nil
	}
	if err := helperCommand(map[string]any{"cmd": "restore", "snap": snap}); err != nil {
		return err
	}
	return verifyProxyReadback(proxyValues{
		Server:        snap.Server,
		Override:      snap.Override,
		Enable:        snap.Enable,
		AutoConfigURL: snap.AutoConfigURL,
		AutoDetect:    snap.AutoDetect,
	})
}

// RunProxyHelper is the elevated helper entry point:
//
//	proxy-helper daemon <port> <token> <parent-pid>   serve proxy edits until the parent dies
//	proxy-helper set <port>                           one-shot: point WinINET at 127.0.0.1:<port>
//	proxy-helper restore <snap-file>                  one-shot: restore a snapshot file
//
// The daemon never touches the state file — the parent process stays the
// single writer.
func RunProxyHelper(args []string) int {
	if len(args) < 2 {
		return 2
	}
	switch args[0] {
	case "daemon":
		if len(args) < 4 {
			return 2
		}
		port, err1 := strconv.Atoi(args[1])
		parentPID, err2 := strconv.Atoi(args[3])
		if err1 != nil || err2 != nil {
			return 2
		}
		return runHelperDaemon(port, args[2], parentPID)
	case "set":
		port, err := strconv.Atoi(args[1])
		if err != nil || port <= 0 || port > 65535 {
			return 2
		}
		if _, err := SetSystemProxy(port); err != nil {
			fmt.Fprintln(os.Stderr, "proxy-helper set:", err)
			return 1
		}
		return 0
	case "restore":
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return 1
		}
		var snap ProxySnapshot
		if json.Unmarshal(raw, &snap) != nil {
			return 1
		}
		if err := UnsetSystemProxy(&snap); err != nil {
			return 1
		}
		return 0
	case "firewall":
		port, err := strconv.Atoi(args[1])
		if err != nil || port <= 0 || port > 65535 {
			return 2
		}
		corePath := ""
		if len(args) > 2 {
			corePath = args[2]
		}
		if err := addLanFirewallRule(port, corePath); err != nil {
			fmt.Fprintln(os.Stderr, "proxy-helper firewall:", err)
			return 1
		}
		return 0
	}
	return 2
}

// runHelperDaemon serves authenticated proxy edits on 127.0.0.1 and exits by
// itself once the parent GUI is gone — an elevated listener that outlives the
// client is exactly the kind of leftover this project must never leave.
func runHelperDaemon(port int, token string, parentPID int) int {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return 1
	}
	go func() {
		for {
			time.Sleep(2 * time.Second)
			if !processAlive(parentPID) {
				os.Exit(0)
			}
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return 1
		}
		go handleHelperConn(conn, token)
	}
}

func handleHelperConn(conn net.Conn, token string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	var req struct {
		Token string         `json:"token"`
		Cmd   string         `json:"cmd"`
		Port  int            `json:"port"`
		Core  string         `json:"core"`
		Snap  *ProxySnapshot `json:"snap"`
	}
	if json.NewDecoder(conn).Decode(&req) != nil || req.Token != token {
		_ = json.NewEncoder(conn).Encode(map[string]any{"ok": false, "err": "unauthorized"})
		return
	}
	var err error
	switch req.Cmd {
	case "set":
		_, err = SetSystemProxy(req.Port)
	case "restore":
		err = UnsetSystemProxy(req.Snap)
	case "firewall":
		err = addLanFirewallRule(req.Port, req.Core)
	default:
		err = fmt.Errorf("unknown cmd %q", req.Cmd)
	}
	resp := map[string]any{"ok": err == nil}
	if err != nil {
		resp["err"] = err.Error()
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

// processAlive reports whether the pid still runs. Good enough for the
// daemon's liveness poll; a recycled pid at worst keeps an idle listener
// around a little longer.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}
