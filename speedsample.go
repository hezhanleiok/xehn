package main

import (
	"io"
	"sort"
	"time"
)

// Unified throughput caliber (S0). A ranking number has to describe the steady
// state of a tunnel, not the luck of its first second: TCP slow-start, a QUIC
// window opening, or one retransmit can swing a single whole-transfer average
// by 2-3x while the tunnel's real capacity is unchanged. So every measurement
// here drops a warmup prefix, buckets the remainder into fixed segments, and
// reports the median segment — one stalled segment cannot drag the number down
// the way a mean would, and one burst cannot inflate it.
const (
	// rankStreams is how many concurrent downloads the ranking probe opens. A
	// single stream under-fills a fat tunnel (one loss halves its window); four
	// ride out loss the way a browser's parallel fetches do.
	rankStreams = 4
	// rankSeg is the segment width. 500ms is short enough to localise a stall
	// and long enough that timer jitter is noise.
	rankSeg = 500 * time.Millisecond
	// rankWarmup is the prefix discarded before sampling begins.
	rankWarmup = 1 * time.Second
	// rankWindow is how long steady-state sampling runs after warmup. Kept short
	// so ranking the top few endpoints costs seconds, not the standalone scan's
	// full speedtest budget.
	rankWindow = 2 * time.Second
)

// collectSegments reads body, discards everything received during warmup, then
// buckets the following bytes into seg-wide windows and returns each window's
// throughput in Mbit/s. Sampling stops once window has elapsed after warmup, or
// at EOF. The final partial window is included when it carries data so a short
// transfer still yields a sample. A reader that never warms up (stalled tunnel)
// returns no segments, which the caller reads as "unmeasured", never as zero
// capacity proven.
func collectSegments(body io.Reader, warmup, seg, window time.Duration) []float64 {
	buf := make([]byte, 64<<10)
	start := time.Now()
	var (
		segs     []float64
		segBytes int64
		segStart time.Time
		warmed   bool
	)
	flush := func(now time.Time) {
		if segBytes > 0 && !segStart.IsZero() {
			if d := now.Sub(segStart); d > 0 {
				segs = append(segs, mbits(segBytes, d))
			}
		}
		segBytes, segStart = 0, now
	}
	for {
		n, err := body.Read(buf)
		now := time.Now()
		if !warmed {
			if now.Sub(start) >= warmup {
				warmed = true
				segStart = now
			}
		} else {
			segBytes += int64(n)
			if now.Sub(segStart) >= seg {
				flush(now)
				if now.Sub(start) >= warmup+window {
					break
				}
			}
		}
		if err != nil {
			if warmed {
				flush(time.Now())
			}
			break
		}
	}
	return segs
}

// medianMbps returns the median of the segment samples, or 0 when there are
// none. The median, not the mean: a ranking must not be decided by a single
// stalled or bursty segment.
func medianMbps(segs []float64) float64 {
	if len(segs) == 0 {
		return 0
	}
	s := append([]float64(nil), segs...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}