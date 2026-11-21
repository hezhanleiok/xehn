package main

import (
	"io"
	"testing"
	"time"
)

func TestMedianMbps(t *testing.T) {
	cases := []struct {
		name string
		in   []float64
		want float64
	}{
		{"empty", nil, 0},
		{"single", []float64{42}, 42},
		{"odd", []float64{30, 10, 20}, 20},
		{"even", []float64{10, 20, 30, 40}, 25},
		// One stalled segment must not drag the median the way a mean would.
		{"stall outlier", []float64{100, 102, 98, 101, 3}, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := medianMbps(tc.in); got != tc.want {
				t.Fatalf("medianMbps(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// pacedReader delivers a fixed chunk every delay, then EOF — a stand-in for a
// tunnel carrying a steady download.
type pacedReader struct {
	chunk     []byte
	delay     time.Duration
	remaining int
}

func (r *pacedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	time.Sleep(r.delay)
	r.remaining--
	n := copy(p, r.chunk)
	return n, nil
}

func TestCollectSegmentsSteady(t *testing.T) {
	// ~32KB every 2ms ≈ 128 Mbit/s. Warmup 30ms, 20ms segments, 120ms window.
	r := &pacedReader{chunk: make([]byte, 32<<10), delay: 2 * time.Millisecond, remaining: 200}
	segs := collectSegments(r, 30*time.Millisecond, 20*time.Millisecond, 120*time.Millisecond)
	if len(segs) < 2 {
		t.Fatalf("expected several steady segments, got %d", len(segs))
	}
	m := medianMbps(segs)
	if m < 60 || m > 220 {
		t.Fatalf("median %v Mbit/s outside the plausible band for a ~128 Mbit/s stream", m)
	}
}

func TestCollectSegmentsStalledYieldsNothing(t *testing.T) {
	// EOF arrives before warmup elapses: the tunnel never proved steady state,
	// so there must be no sample (unmeasured), not a fabricated zero-capacity one.
	r := &pacedReader{chunk: make([]byte, 1024), delay: time.Millisecond, remaining: 3}
	segs := collectSegments(r, time.Hour, 20*time.Millisecond, 120*time.Millisecond)
	if len(segs) != 0 {
		t.Fatalf("a stream that never warms up must yield no segments, got %v", segs)
	}
	if m := medianMbps(segs); m != 0 {
		t.Fatalf("median of no segments = %v, want 0", m)
	}
}

func TestCollectSegmentsDoesNotMutateInput(t *testing.T) {
	in := []float64{50, 10, 40, 20, 30}
	_ = medianMbps(in)
	for i, want := range []float64{50, 10, 40, 20, 30} {
		if in[i] != want {
			t.Fatalf("medianMbps reordered its input: %v", in)
		}
	}
}