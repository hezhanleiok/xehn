//go:build windows

package main

import (
	"fmt"
	"strings"
	"testing"
)

// TestCoreChatterIsBounded pins the retention rule that keeps a long session
// from growing without limit: the core's per-connection chatter is capped while
// the client's own lines (the ones a failed connect is diagnosed from) survive.
func TestCoreChatterIsBounded(t *testing.T) {
	u := &natUI{m: newNatModel()}

	const clientLines = 400
	for i := 0; i < clientLines; i++ {
		u.addLog(fmt.Sprintf("client %d", i), false)
	}
	// A busy session emits far more core lines than this; the panel must not
	// keep them all.
	for i := 0; i < 40000; i++ {
		u.addLogFull(fmt.Sprintf("core %d", i), 0, true)
	}

	if got := len(u.m.logs); got > maxLogLines {
		t.Fatalf("retained lines = %d, want <= %d", got, maxLogLines)
	}

	text := u.logText()
	// Every client line survives the trim, oldest included.
	for _, want := range []string{"client 0\r\n", "client 399\r\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("log lost a client line %q after trimming", strings.TrimSpace(want))
		}
	}
	// The newest core line is kept; the very first one is long gone.
	if !strings.Contains(text, "core 39999") {
		t.Fatalf("log lost the newest core line")
	}
	if strings.Contains(text, "core 0\r\n") {
		t.Fatalf("oldest core line should have been trimmed")
	}

	// The panel is capped, and a trim keeps at most the core budget so the
	// client's own lines are what the copy function returns.
	core := 0
	for _, l := range u.m.logs {
		if l.core {
			core++
		}
	}
	if core > maxCoreLogLines*3 {
		t.Fatalf("retained core lines = %d, want well under the panel ceiling", core)
	}
}

// TestTrimKeepsClientLinesWhenCoreFloodsAlone covers the pathological case where
// the core floods with nothing else in the panel: the cap must still hold.
func TestTrimKeepsClientLinesWhenCoreFloodsAlone(t *testing.T) {
	u := &natUI{m: newNatModel()}
	for i := 0; i < 60000; i++ {
		u.addLogFull(fmt.Sprintf("core %d", i), 0, true)
	}
	if got := len(u.m.logs); got > maxLogLines {
		t.Fatalf("retained lines = %d, want <= %d", got, maxLogLines)
	}
}
