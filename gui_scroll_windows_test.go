//go:build windows

package main

import "testing"

// The settings scrollbar is the only way to move that page besides the wheel,
// so its geometry and its mapping from pointer position to scroll offset have
// to hold at both ends of the track. The range is derived from the page's real
// content height (clampSetScroll recomputes it on every drag), so the test
// asserts against that range rather than a seeded constant — and it drags the
// handle by a fraction of its movable span instead of clicking mid-track, which
// lands inside the handle once the page is only a little taller than the body.
func TestScrollbarDrag(t *testing.T) {
	u := &natUI{m: newNatModel(), k: 1, dw: 1080}
	u.clampSetScroll()
	max := u.m.setScrollMax
	if max <= 0 {
		t.Fatal("the settings page must overflow the body for this test")
	}

	trackTop, trackH, thumbTop, thumbH := u.scrollbarGeom()
	if trackH <= 0 || thumbH <= 0 || thumbH >= trackH {
		t.Fatalf("bad geometry: trackH=%v thumbH=%v", trackH, thumbH)
	}
	if u.m.setScroll != 0 || thumbTop != trackTop {
		t.Fatalf("at offset 0 the thumb must sit at the track top: %v vs %v", thumbTop, trackTop)
	}

	// Grab the handle and drag it to the bottom of the track: the page must
	// reach its maximum, not stop short.
	u.beginScrollDrag(u.sy(thumbTop + 2))
	if !u.scrollDrag {
		t.Fatal("drag did not start")
	}
	u.dragScrollTo(u.sy(trackTop + trackH))
	if u.m.setScroll != max {
		t.Fatalf("drag to bottom = %d, want %d", u.m.setScroll, max)
	}

	// And back to the top.
	u.dragScrollTo(u.sy(trackTop - 100))
	if u.m.setScroll != 0 {
		t.Fatalf("drag past the top = %d, want 0", u.m.setScroll)
	}

	// Dragging the handle a quarter of its movable span scrolls a quarter of
	// the range, whatever the handle's size.
	span := trackH - thumbH
	u.beginScrollDrag(u.sy(thumbTop + 2))
	u.dragScrollTo(u.sy(thumbTop + 2 + span/4))
	if q := u.m.setScroll - max/4; q > 20 || q < -20 {
		t.Fatalf("quarter-span drag = %d, want about %d", u.m.setScroll, max/4)
	}

	// Clicking the track below the handle jumps it toward the click and clamps
	// at the end of the range (the press was outside the handle, so it centres
	// the handle on the pointer rather than keeping a grab offset).
	u.m.setScroll = 0
	u.clampSetScroll()
	u.beginScrollDrag(u.sy(trackTop + trackH - 5))
	if u.m.setScroll != max {
		t.Fatalf("track click below the handle = %d, want %d", u.m.setScroll, max)
	}

	// A page that fits has nothing to drag.
	u.scrollDrag = false
	u.m.setScrollMax = 0
	u.beginScrollDrag(u.sy(trackTop + 10))
	if u.scrollDrag {
		t.Fatal("drag must not start when the page fits")
	}
}