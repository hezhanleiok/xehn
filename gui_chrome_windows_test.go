//go:build windows

package main

import "testing"

func TestDefaultClientSize(t *testing.T) {
	cases := []struct {
		name                 string
		dpi                  float64
		workW, workH, fw, fh int32
		wantW, wantH         int32
	}{
		// Roomy 100% screen: the preferred 1280x860 logical window.
		{"96dpi", 96, 1920, 1040, 16, 16, 1280, 860},
		// 150%: width hits the preferred 1920, height is capped at 85%.
		{"144dpi", 144, 2560, 1504, 24, 24, 1920, 1258},
		// 200% on a big screen: both axes capped by the work area, independently.
		{"192dpi-capped", 192, 2560, 1504, 24, 24, 2029, 1258},
		// 200% on 1080p: the 80%/85% caps fall below the logical floor, so the
		// floor wins and the window opens at 880x560 logical.
		{"192dpi-1080p", 192, 1920, 1080, 24, 24, 1760, 1056},
		// Small laptop: width is lifted to the 880 logical floor.
		{"96dpi-small", 96, 1024, 768, 16, 16, 880, 639},
		// Tiny screen: the floor gives way to the physical work area.
		{"96dpi-tiny", 96, 800, 600, 16, 16, 784, 560},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, h := defaultClientSize(c.dpi, c.workW, c.workH, c.fw, c.fh)
			if w != c.wantW || h != c.wantH {
				t.Fatalf("client = %dx%d, want %dx%d", w, h, c.wantW, c.wantH)
			}
		})
	}
}

// The startup window must never spill off the screen, at any DPI or resolution,
// and on any screen big enough for the floor it must not open below it.
func TestDefaultClientSizeMatrix(t *testing.T) {
	works := [][2]int32{
		{1366, 768}, {1920, 1080}, {2560, 1440}, {3840, 2160}, {1024, 600},
	}
	for _, dpi := range []float64{96, 120, 144, 192} {
		for _, wa := range works {
			w, h := defaultClientSize(dpi, wa[0], wa[1], 16, 16)
			if w <= 0 || h <= 0 {
				t.Fatalf("dpi %.0f work %v: empty client %dx%d", dpi, wa, w, h)
			}
			if w+16 > wa[0] || h+16 > wa[1] {
				t.Fatalf("dpi %.0f work %v: client %dx%d overflows", dpi, wa, w, h)
			}
			k := dpi / 96
			if float64(wa[0]-16) >= minW*k && float64(w) < minW*k-0.5 {
				t.Fatalf("dpi %.0f work %v: width %d below floor %.0f", dpi, wa, w, minW*k)
			}
			if float64(wa[1]-16) >= minH*k && float64(h) < minH*k-0.5 {
				t.Fatalf("dpi %.0f work %v: height %d below floor %.0f", dpi, wa, h, minH*k)
			}
		}
	}
}