//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/lxn/walk"
)

// uiPalette is every colour the dashboard paints. One struct, two values: a new
// colour is added here and filled in twice, so light and dark cannot drift
// apart, and no paint site invents a colour of its own. (The CLI's own colour
// helper is a different type — see palette in ui.go.)
//
// The light palette is the reference mock's "frosted glass" look: a pale blue
// wash for the canvas, near-white surfaces, and text in a soft blue-grey. There
// is deliberately no dark text and no saturated accent fill — the window reads
// as one continuous light material, and colour is only used for state.
type uiPalette struct {
	// Surfaces, from the window down to the smallest control.
	window, sidebar, card, cardHover, line, input walk.Color
	// inset is the recessed surface (stat tiles, sidebar, badge wells); overlay
	// is the raised popup surface; line2 the subtler inner border.
	inset, overlay, line2 walk.Color
	// Text: primary, secondary, and the faintest (hints, disabled).
	text, dim, faint walk.Color
	// Accent and status.
	accent, accentText, accentSoft, accentLine walk.Color
	ok, okSoft, warn, warnSoft, bad, badSoft   walk.Color
	// The v4 data-viz accents: cyan secondary, bright-green download, blue
	// upload, and the pink/violet used by the traffic-share categories.
	accent2, ok2, up, mag, vio walk.Color
	// Controls. Logs deliberately share the same card language as the rest of
	// the client rather than looking like a separate terminal window.
	chip, chipText, toggleOff walk.Color
	// The connect disc's radial fill, highlight to shadow.
	connectFrom, connectTo walk.Color
	// The v5 hexagon key's idle/connecting gradient, top to bottom.
	hexFrom, hexTo walk.Color
}

// The palettes are the home-v4 design tokens. Dark is the primary look: a deep
// blue-black canvas, layered surfaces, and a small set of full-chroma data
// accents (green download, blue upload, cyan secondary). Light keeps the same
// hues but darkens the semantic text colours so values stay readable on white.
var paletteLight = uiPalette{
	window:     rx(235, 242, 252), // #EBF2FC pale periwinkle canvas
	sidebar:    rx(246, 250, 254), // #F6FAFE rail
	card:       rx(255, 255, 255), // surface
	cardHover:  rx(246, 250, 254),
	line:       rx(226, 234, 246), // #E2EAF6 border
	line2:      rx(233, 240, 249), // #E9F0F9 inner border
	input:      rx(246, 250, 254),
	inset:      rx(246, 250, 254), // recessed tiles
	overlay:    rx(255, 255, 255),
	text:       rx(30, 41, 59),    // #1E293B slate
	dim:        rx(100, 116, 139), // #64748B muted
	faint:      rx(148, 163, 184), // #94A3B8
	accent:     rx(37, 99, 235),   // #2563EB reference blue
	accentText: rx(255, 255, 255),
	accentSoft: rx(232, 240, 254),
	accentLine: rx(191, 219, 254),
	accent2:    rx(37, 99, 235), // active nav / icons share the reference blue
	ok:         rx(22, 163, 74),
	ok2:        rx(34, 197, 94), // #22C55E download line
	okSoft:     rx(230, 247, 237),
	warn:       rx(217, 119, 6),
	warnSoft:   rx(253, 245, 224),
	bad:        rx(220, 38, 38),
	badSoft:    rx(252, 235, 235),
	up:         rx(59, 130, 246),
	mag:        rx(219, 39, 119),
	vio:        rx(124, 58, 237),
	chip:       rx(246, 250, 254),
	chipText:   rx(100, 116, 139),
	toggleOff:  rx(214, 222, 233),
	connectFrom: rx(74, 222, 128), // ring highlight
	connectTo:   rx(22, 163, 74),  // ring shadow
	hexFrom:     rx(77, 163, 255), // #4DA3FF hexagon top
	hexTo:       rx(29, 111, 224), // #1D6FE0 hexagon foot
}

var paletteDark = uiPalette{
	window:     rx(11, 14, 20),   // #0B0E14 canvas
	sidebar:    rx(16, 21, 31),   // #10151F rail
	card:       rx(20, 26, 36),   // #141A24 surface
	cardHover:  rx(26, 34, 48),   // #1A2230 overlay
	line:       rx(35, 44, 58),   // #232C3A border
	line2:      rx(30, 39, 51),   // #1E2733 inner border
	input:      rx(16, 21, 31),
	inset:      rx(16, 21, 31),
	overlay:    rx(26, 34, 48),
	text:       rx(230, 237, 245), // #E6EDF5
	dim:        rx(138, 151, 168), // #8A97A8 muted
	faint:      rx(93, 107, 126),  // #5D6B7E
	accent:     rx(59, 130, 246),  // #3B82F6
	accentText: rx(255, 255, 255),
	accentSoft: rx(27, 42, 66),
	accentLine: rx(45, 72, 92),
	accent2:    rx(34, 211, 238), // #22D3EE
	ok:         rx(34, 197, 94),  // #22C55E
	ok2:        rx(74, 222, 128), // #4ADE80
	okSoft:     rx(24, 48, 44),
	warn:       rx(251, 191, 36), // #FBBF24
	warnSoft:   rx(52, 45, 26),
	bad:        rx(248, 113, 113), // #F87171
	badSoft:    rx(54, 34, 38),
	up:         rx(96, 165, 250), // #60A5FA
	mag:        rx(244, 114, 182), // #F472B6
	vio:        rx(167, 139, 250), // #A78BFA
	chip:       rx(16, 21, 31),
	chipText:   rx(138, 151, 168),
	toggleOff:  rx(45, 55, 70),
	connectFrom: rx(52, 211, 119), // #34D377 disc highlight
	connectTo:   rx(21, 128, 61),  // #15803D disc shadow
	hexFrom:     rx(76, 130, 247), // #4C82F7 hexagon top
	hexTo:       rx(42, 85, 208),  // #2A55D0 hexagon foot
}

func rx(r, g, b byte) walk.Color { return walk.RGB(r, g, b) }

// th is the active palette. The paint code reads it on every frame, so the
// theme is a global rather than a parameter; applyTheme is its only writer.
var th = paletteLight

// Shape constants. They live beside the palette because they are part of the
// same visual language: one radius per surface class, no paint site inventing a
// rounder corner than its neighbours.
const (
	cardRadius  = 16.0 // content cards and the large popups
	panelRadius = 20.0 // the protocol selector, popups
	ctrlRadius  = 10.0 // buttons, inputs, chips
)

// pillRad is the fully-round radius for a control of the given height: GDI+'s
// rounded rectangle takes a radius, not a "make it a pill" flag, and handing it
// half the height is how a pill is drawn without measuring twice.
func pillRad(h float64) float64 { return h / 2 }

// navRadius is the sidebar selection's corner radius: a soft pill, the way the
// mock highlights the active rail item.
const navRadius = 12.0

// darkNow reports whether the UI is currently dark. ThemeAuto defers to the
// system's app-theme preference; anything else is explicit.
func darkNow(set clientSettings) bool {
	switch set.Theme {
	case themeDark:
		return true
	case themeAuto:
		return systemDark()
	default:
		return false
	}
}

// systemDark reads Windows' "app mode" preference. A missing value (older
// builds, locked-down profile) means light, which is also the app default.
func systemDark() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return false
	}
	return v == 0
}

// applyTheme makes the palette match the settings and repaints. The dark title
// bar is set separately because it lives on the window, not on the canvas.
func (u *natUI) applyTheme() {
	if darkNow(u.m.set) {
		th = paletteDark
	} else {
		th = paletteLight
	}
	setDarkTitleBar(u.mw, darkNow(u.m.set))
	u.setFrameColor()
	u.invalidate()
}

// setDarkTitleBar switches the non-client area between the light and dark
// title bars. DWMWA_USE_IMMERSIVE_DARK_MODE is 20 on current builds and 19 on
// the first ones that shipped it; both are tried, and a failure is ignored
// (the window simply keeps the default bar).
func setDarkTitleBar(mw *walk.MainWindow, dark bool) {
	if mw == nil {
		return
	}
	dwm := windows.NewLazySystemDLL("dwmapi.dll")
	proc := dwm.NewProc("DwmSetWindowAttribute")
	if err := proc.Find(); err != nil {
		return
	}
	v := int32(0)
	if dark {
		v = 1
	}
	for _, attr := range []uintptr{20, 19} {
		r, _, _ := proc.Call(uintptr(mw.Handle()), attr, uintptr(unsafe.Pointer(&v)), 4)
		if r == 0 {
			return
		}
	}
}
