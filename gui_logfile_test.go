//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTrimLogFileShrinksOversizedLog pins the disk-side cap: xehn.log is opened
// for append and inherited by the core, so without this a long-lived install
// accumulates the core's chatter indefinitely.
func TestTrimLogFileShrinksOversizedLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xehn.log")

	// ~10MB of numbered lines, so the trim point lands mid-line.
	var b strings.Builder
	line := strings.Repeat("x", 99) + "\n"
	for b.Len() < logTrimAbove+2<<20 {
		b.WriteString(line)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	trimLogFile(path)

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > logTrimKeep+4096 {
		t.Fatalf("log still %d bytes after trim, want about %d", fi.Size(), logTrimKeep)
	}
	if fi.Size() < logTrimKeep/2 {
		t.Fatalf("log trimmed too aggressively: %d bytes", fi.Size())
	}
	// The kept tail must start on a line boundary, not mid-line.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), strings.Repeat("x", 99)) {
		t.Fatalf("kept tail starts mid-line: %q", string(data[:20]))
	}
}

// TestTrimLogFileLeavesSmallLogsAlone is the guard for the common case: a
// normal session must never be truncated.
func TestTrimLogFileLeavesSmallLogsAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xehn.log")
	body := "line one\nline two\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	trimLogFile(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != body {
		t.Fatalf("small log was modified: %q", string(data))
	}
}
