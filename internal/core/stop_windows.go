//go:build windows

package core

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hideConsole keeps the child core out of sight: a console-subprocess child of
// a windowsgui process would otherwise pop up its own black console window.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}

// spawnWatchdog launches a hidden watchdog subprocess that ties the core to
// this process's lifetime: a client killed without disconnecting (crash,
// task manager, a test harness) must never leave a stray mihomo holding the
// mixed port with the system proxy still pointing at it. When the client
// dies, the watchdog runs the disconnect cleanup — stop the core, restore
// the proxy, clear the state — and reaps any core its state cannot reach.
//
// This replaces the job-object guard: on hosts where every process already
// lives in a job (VDI/silo images) AssignProcessToJobObject is denied
// outright and the guard silently did nothing, while a watchdog works
// everywhere and also restores host state a job never could.
//
// The watchdog retires the moment ITS core exits: candidate rotation stops
// the failed core and starts a fresh one (with a fresh watchdog), and a
// guard whose core is gone must neither linger nor clean up a live session.
func spawnWatchdog(corePID int) {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("core: watchdog: resolve executable: %v", err)
		return
	}
	cmd := exec.Command(exe, "watchdog",
		"--client-pid", strconv.Itoa(os.Getpid()),
		"--core-pid", strconv.Itoa(corePID))
	hideConsole(cmd)
	if err := cmd.Start(); err != nil {
		log.Printf("core: watchdog: spawn: %v", err)
		return
	}
	wdPID := cmd.Process.Pid
	// Deliberately never waited on, and the handle released at once: the
	// watchdog is meant to outlive this process.
	_ = cmd.Process.Release()
	log.Printf("core: watchdog active: pid %d guards core pid %d until client pid %d dies",
		wdPID, corePID, os.Getpid())
}

// WaitClientOrCore blocks until either the client or the core process exits
// and reports which one died first. It is the watchdog's entire event loop:
// WaitForMultipleObjects performs the "either handle signals" select in one
// call — no polling, no CPU. A pid that cannot be opened is treated as
// already exited (Windows refuses OpenProcess on gone pids).
func WaitClientOrCore(clientPID, corePID int) (clientDied bool, err error) {
	if clientPID <= 0 || corePID <= 0 {
		return false, errors.New("core: watchdog: invalid pids")
	}
	ch, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(clientPID))
	if err != nil {
		return true, nil // the client is already gone — cleanup case
	}
	defer windows.CloseHandle(ch)
	kh, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(corePID))
	if err != nil {
		return false, nil // the core is already gone — retire
	}
	defer windows.CloseHandle(kh)
	handles := [2]windows.Handle{ch, kh}
	event, werr := windows.WaitForMultipleObjects(handles[:], false, windows.INFINITE)
	switch {
	case werr != nil:
		return false, fmt.Errorf("core: watchdog: wait: %w", werr)
	case event == windows.WAIT_OBJECT_0:
		return true, nil // the client died
	case event == windows.WAIT_OBJECT_0+1:
		return false, nil // the core died first: rotation or a clean disconnect
	default:
		return false, fmt.Errorf("core: watchdog: unexpected wait event %d", event)
	}
}

// KillByPID terminates the core process with the given id — the companion to
// Core.PID for the disconnect path, which runs in a different process (CLI) or
// at least in a different Core instance (GUI) than the one that started the
// core, so Core.Stop alone cannot reach it.
//
// The process's image path must match expectExe (when non-empty): a pid from a
// state file can be stale, and silently terminating an unrelated reused pid
// would be far worse than leaving the orphan alive.
//
// The call returns only once the process object is signalled (i.e. the
// process is really gone). TerminateProcess alone is asynchronous: a core
// spawned right after a kill that returned early races the dying process's
// socket cleanup, fails its mixed-port/controller bind (mihomo logs the error
// but keeps running as a zombie), and the connect's readiness and tunnel
// verification then get answered by the dying ghost — "connected" on screen,
// dead port seconds later.
// KillStaleCores terminates every process still running this exact core
// binary and returns how many were killed. This is the recovery path after a
// client dies without disconnecting (crash, Task Manager, AV termination): its
// core keeps the mixed and API ports bound, and the next connect fails every
// endpoint with "port still in use". state.json only remembers one PID and it
// is not even written when the crash happens before the save, so the binary
// path — which we know — is the reliable signature.
func KillStaleCores(exe string) int {
	want, err := filepath.Abs(exe)
	if err != nil {
		return 0
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	killed := 0
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		pid := int(entry.ProcessID)
		if pid <= 0 || pid == os.Getpid() {
			continue
		}
		// KillByPID re-checks the image path before touching the process, so a
		// recycled PID is never killed by mistake.
		if err := KillByPID(pid, want); err == nil {
			if strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), filepath.Base(want)) {
				killed++
			}
		}
	}
	return killed
}

func KillByPID(pid int, expectExe string) error {
	if pid <= 0 {
		return errors.New("core: kill: no pid")
	}
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
		false, uint32(pid))
	if err != nil {
		// Already gone: nothing to do, which is success for a "stop" call.
		return nil
	}
	defer windows.CloseHandle(h)

	// An exited-but-still-referenced process opens fine, yet refuses
	// TerminateProcess with access denied. A signalled handle means the pid
	// is dead already — report success instead of a scary non-error.
	if event, _ := windows.WaitForSingleObject(h, 0); event == windows.WAIT_OBJECT_0 {
		return nil
	}

	if expectExe != "" {
		var buf [windows.MAX_PATH]uint16
		size := uint32(len(buf))
		if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
			image := windows.UTF16ToString(buf[:])
			want, _ := filepath.Abs(expectExe)
			if !strings.EqualFold(image, want) {
				return fmt.Errorf("core: pid %d is %s, not the core %s - refusing to kill", pid, image, want)
			}
		}
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("core: kill pid %d: access denied (try running as administrator)", pid)
		}
		return fmt.Errorf("core: kill pid %d: %w", pid, err)
	}
	if event, werr := windows.WaitForSingleObject(h, 5000); werr != nil || event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("core: kill pid %d: process did not exit in time", pid)
	}
	return nil
}

// processImagePath returns the full image path of a live pid.
func processImagePath(pid int) (string, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", false
	}
	return windows.UTF16ToString(buf[:]), true
}

// KillStalePortableCores terminates cores belonging to ANY XEHN portable folder,
// not just the copy this build runs from.
//
// Updating by extracting a new folder (the normal flow for this app) leaves the
// previous version's core running: it holds memory, and when it managed to bind
// it holds the ports the new build needs. KillStaleCores cannot see it because
// the image path differs from the current build's.
//
// The match is deliberately narrow — the file must be the core executable AND
// its path must contain "xehn" — so a Clash Party / Verge sidecar
// ("...\resources\sidecar\mihomo.exe") is never touched.
func KillStalePortableCores() int {
	want := strings.ToLower(ExeName())
	if want == "" {
		return 0
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	killed := 0
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		pid := int(entry.ProcessID)
		if pid <= 0 || pid == os.Getpid() {
			continue
		}
		if !strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), ExeName()) {
			continue
		}
		image, ok := processImagePath(pid)
		if !ok {
			continue
		}
		lower := strings.ToLower(image)
		if !strings.Contains(lower, "xehn") {
			continue
		}
		if err := KillByPID(pid, image); err == nil {
			killed++
		}
	}
	return killed
}
