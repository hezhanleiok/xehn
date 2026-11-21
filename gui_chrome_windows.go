//go:build windows

package main

import (
	"math"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/lxn/walk"
)

const (
	designW = 1080.0
	designH = 700.0 + capH
)

// The window is adaptive: it opens near 1280x860 logical pixels, resizes freely
// on both axes, and the pages re-layout through breakpoints instead of keeping
// one fixed ratio. These are the preferred startup size and the smallest layout
// the pages support, all in 96-DPI logical pixels.
const (
	defaultW = 1280.0
	defaultH = 860.0
	minW     = 880.0
	minH     = 560.0
)

// The window has no OS caption: the reference draws only three round buttons in
// the top-right corner over the same background as the page, and no title text
// on the left. capH is that band, in design units; every page is offset below it
// (see natUI.sy), so nothing has to know the caption exists.
const capH = 34.0

// Caption button metrics: three 46x34 hit areas flush with the right edge.
const (
	capBtnW = 46.0
	capBtnH = capH
)

var user32 = windows.NewLazySystemDLL("user32.dll")

func proc(name string) *windows.LazyProc { return user32.NewProc(name) }

// windowDPI is the display scale the window is on. Design units are 96-DPI
// logical pixels, so this is what turns the 1080x734 grid into the device-pixel
// client size that keeps the same apparent size at any Windows scaling.
func windowDPI(hwnd uintptr) float64 {
	if p := proc("GetDpiForWindow"); p.Find() == nil {
		if dpi, _, _ := p.Call(hwnd); dpi >= 72 && dpi <= 480 {
			return float64(dpi)
		}
	}
	if p := proc("GetDpiForSystem"); p.Find() == nil {
		if dpi, _, _ := p.Call(); dpi >= 72 && dpi <= 480 {
			return float64(dpi)
		}
	}
	return 96
}

// stripCaptionBar removes WS_CAPTION from the window, which turns the native
// title bar into client area (the frame stays, so resizing and maximise keep
// working) and gives the page the whole top edge. Everything that used to be
// drawn by Windows — title, icon, buttons — is now ours.
func (u *natUI) stripCaptionBar() {
	if u.mw == nil {
		return
	}
	hwnd := uintptr(u.mw.Handle())
	const (
		gwlStyle      = ^uintptr(15) // -16
		wsCaption     = 0x00C00000
		swpFrameChang = 0x0020
		swpNoMove     = 0x0002
		swpNoSize     = 0x0001
		swpNoZOrder   = 0x0004
	)
	get := proc("GetWindowLongPtrW")
	set := proc("SetWindowLongPtrW")
	setPos := proc("SetWindowPos")

	st, _, _ := get.Call(hwnd, gwlStyle)
	style := uint32(st) &^ uint32(wsCaption)
	set.Call(hwnd, gwlStyle, uintptr(style))
	setPos.Call(hwnd, 0, 0, 0, 0, 0,
		uintptr(swpNoMove|swpNoSize|swpNoZOrder|swpFrameChang))

	// The client area just grew by the caption's height; the paint widget owns
	// the whole client area, so re-fit it here instead of waiting for a resize.
	if u.cw != nil {
		b := u.mw.ClientBoundsPixels()
		u.cw.SetBoundsPixels(walk.Rectangle{Width: b.Width, Height: b.Height})
	}

	// Match the frame to the palette where the OS lets us: rounded corners and
	// a border colour drawn from the canvas instead of the system accent.
	dwm := windows.NewLazySystemDLL("dwmapi.dll")
	attr := dwm.NewProc("DwmSetWindowAttribute")
	round := int32(2) // DWMWCP_ROUND
	attr.Call(hwnd, 33, uintptr(unsafe.Pointer(&round)), 4)
	border := uint32(th.window.B())<<16 | uint32(th.window.G())<<8 | uint32(th.window.R())
	attr.Call(hwnd, 34, uintptr(unsafe.Pointer(&border)), 4)
}

// Window-message types for the minimise/maximise clamp.
type winPoint struct{ x, y int32 }
type winRect struct{ left, top, right, bottom int32 }

type minMaxInfo struct {
	ptReserved, ptMaxSize, ptMaxPosition, ptMinTrackSize, ptMaxTrackSize winPoint
}

type monitorInfo struct {
	cbSize            uint32
	rcMonitor, rcWork winRect
	dwFlags           uint32
}

var (
	wndProcOld uintptr
	wndProcNew uintptr
)

// frameDeltas is how much larger the window is than its client area. With the
// OS caption stripped this is only the thin resize frame, and it is constant
// for the current DPI and style.
func frameDeltas(hwnd uintptr) (int32, int32) {
	var wr, cr winRect
	proc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&wr)))
	proc("GetClientRect").Call(hwnd, uintptr(unsafe.Pointer(&cr)))
	return (wr.right - wr.left) - (cr.right - cr.left),
		(wr.bottom - wr.top) - (cr.bottom - cr.top)
}

// defaultClientSize is the startup client area in physical pixels: the
// preferred 1280x860 logical window scaled by the display DPI, shrunk to fit
// the work area (80% wide, 85% tall) but never below the 880x560 logical floor
// unless the screen itself is smaller. Width and height shrink independently —
// the layout is adaptive, so the window carries no fixed aspect ratio.
func defaultClientSize(dpi float64, workW, workH, fw, fh int32) (int32, int32) {
	availW := math.Max(float64(workW-fw), 1)
	availH := math.Max(float64(workH-fh), 1)
	k := dpi / 96
	cw := math.Min(availW*0.8, defaultW*k)
	ch := math.Min(availH*0.85, defaultH*k)
	cw = math.Max(cw, math.Min(minW*k, availW))
	ch = math.Max(ch, math.Min(minH*k, availH))
	return int32(math.Round(cw)), int32(math.Round(ch))
}

// fitDesignWindow sizes the client for the current display and centres it. The
// preferred size is scaled by the display DPI before it is capped to the work
// area; without that a 200% screen shows the whole window at half its intended
// apparent size. The pages adapt to whatever size results.
func (u *natUI) fitDesignWindow() {
	if u.mw == nil {
		return
	}
	hwnd := uintptr(u.mw.Handle())

	mon, _, _ := proc("MonitorFromWindow").Call(hwnd, 2) // nearest
	var mi monitorInfo
	mi.cbSize = uint32(unsafe.Sizeof(mi))
	if ok, _, _ := proc("GetMonitorInfoW").Call(mon, uintptr(unsafe.Pointer(&mi))); ok == 0 {
		return
	}
	workW := mi.rcWork.right - mi.rcWork.left
	workH := mi.rcWork.bottom - mi.rcWork.top

	// Physical pixels: defaultClientSize already resolved the DPI, so using the
	// DIP API here would scale the result a second time.
	fw, fh := frameDeltas(hwnd)
	cw, ch := defaultClientSize(windowDPI(hwnd), workW, workH, fw, fh)
	_ = u.mw.SetClientSizePixels(walk.Size{Width: int(cw), Height: int(ch)})

	var wr winRect
	proc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&wr)))
	w, h := wr.right-wr.left, wr.bottom-wr.top
	x := mi.rcWork.left + (workW-w)/2
	y := mi.rcWork.top + (workH-h)/2
	if x < mi.rcWork.left {
		x = mi.rcWork.left
	}
	if y < mi.rcWork.top {
		y = mi.rcWork.top
	}
	const (
		swpNoSize     = 0x0001
		swpNoZOrder   = 0x0004
		swpNoActivate = 0x0010
	)
	proc("SetWindowPos").Call(hwnd, 0, uintptr(uint32(x)), uintptr(uint32(y)), 0, 0,
		swpNoSize|swpNoZOrder|swpNoActivate)

	if u.cw != nil {
		b := u.mw.ClientBoundsPixels()
		u.cw.SetBoundsPixels(walk.Rectangle{Width: b.Width, Height: b.Height})
		u.cw.Invalidate()
	}
}

// constrainWindowToWorkArea installs a minimum track size so the window cannot
// be dragged below the smallest layout the pages support. Maximise is left to
// the OS, which already keeps the window inside the work area; the pages are
// adaptive, so no aspect clamp is needed any more.
func (u *natUI) constrainWindowToWorkArea() {
	hwnd := uintptr(u.mw.Handle())
	callOld := proc("CallWindowProcW")
	setLong := proc("SetWindowLongPtrW")

	if wndProcNew == 0 {
		wndProcNew = windows.NewCallback(func(h, msg, wp, lp uintptr) uintptr {
			r, _, _ := callOld.Call(wndProcOld, h, msg, wp, lp)
			const wmGetMinMaxInfo = 0x0024
			if msg == wmGetMinMaxInfo && lp != 0 {
				fw, fh := frameDeltas(h)
				k := windowDPI(h) / 96
				mm := (*minMaxInfo)(unsafe.Pointer(lp))
				mm.ptMinTrackSize.x = int32(math.Round(minW*k)) + fw
				mm.ptMinTrackSize.y = int32(math.Round(minH*k)) + fh
			}
			return r
		})
	}
	// GWLP_WNDPROC = -4
	if old, _, _ := setLong.Call(hwnd, ^uintptr(3), wndProcNew); old != 0 && wndProcOld == 0 {
		wndProcOld = old
	}
}

// styleDialogChrome tints a modal's caption to the dialog surface where the OS
// supports it (Windows 11). Older builds ignore the attributes and keep the
// system caption, so the dialog still works there.
func styleDialogChrome(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	dwm := windows.NewLazySystemDLL("dwmapi.dll")
	attr := dwm.NewProc("DwmSetWindowAttribute")
	caption := uint32(0x00FCF9F8) // COLORREF of rgb(248, 249, 252)
	text := uint32(0x0028201C)    // COLORREF of rgb(28, 32, 40)
	attr.Call(hwnd, 35, uintptr(unsafe.Pointer(&caption)), 4)
	attr.Call(hwnd, 36, uintptr(unsafe.Pointer(&text)), 4)
	attr.Call(hwnd, 34, uintptr(unsafe.Pointer(&caption)), 4)
}

// setFrameColor re-applies the DWM border colour after a theme switch.
func (u *natUI) setFrameColor() {
	if u.mw == nil {
		return
	}
	dwm := windows.NewLazySystemDLL("dwmapi.dll")
	attr := dwm.NewProc("DwmSetWindowAttribute")
	col := uint32(th.window.B())<<16 | uint32(th.window.G())<<8 | uint32(th.window.R())
	attr.Call(uintptr(u.mw.Handle()), 34, uintptr(unsafe.Pointer(&col)), 4)
}

// paintCaption draws the three window buttons on the band the OS caption used
// to occupy. They are drawn as thin glyphs in the page's own text colour, so
// the strip keeps the same material as everything under it.
func (u *natUI) paintCaption(c *walk.Canvas, w float64) {
	ids := []string{"cap:min", "cap:max", "cap:close"}
	kinds := []string{"min", "max", "close"}
	for i := range ids {
		x := w - float64(len(ids)-i)*capBtnW
		r := u.capR(x, 0, capBtnW, capBtnH)
		if u.m.hover == ids[i] {
			bg := mix(th.window, th.card, 0.55)
			if ids[i] == "cap:close" {
				bg = th.bad
			}
			u.fillRound(c, bg, r, 8)
		}
		col := th.dim
		if u.m.hover == ids[i] && ids[i] == "cap:close" {
			col = rx(255, 255, 255)
		} else if u.m.hover == ids[i] {
			col = th.text
		}
		cx, cy := x+capBtnW/2, capBtnH/2
		switch kinds[i] {
		case "min":
			u.capLine(c, col, cx-5, cy, cx+5, cy, 1.3)
		case "max":
			u.thickRound(c, col, u.capR(cx-5, cy-5, 10, 10), 2, 1.3)
		default:
			u.capLine(c, col, cx-4.5, cy-4.5, cx+4.5, cy+4.5, 1.3)
			u.capLine(c, col, cx+4.5, cy-4.5, cx-4.5, cy+4.5, 1.3)
		}
		u.addSpot(ids[i], r, true)
	}
}

// capR is a rectangle inside the caption band: y is measured from the top of the
// window, not from the top of the content grid.
func (u *natUI) capR(x, y, w, h float64) walk.Rectangle {
	return walk.Rectangle{X: u.sx(x), Y: u.oy + u.s(y), Width: u.s(w), Height: u.s(h)}
}

// capPoint / capLine are the caption-band equivalents of u.p / u.thickLine.
// Using the page helpers here would push the glyphs down by the caption band,
// because sy() skips it for page content.
func (u *natUI) capPoint(x, y float64) walk.Point {
	return walk.Point{X: u.sx(x), Y: u.oy + u.s(y)}
}

func (u *natUI) capLine(c *walk.Canvas, col walk.Color, x1, y1, x2, y2, w float64) {
	p := u.penW(col, w)
	if p == nil {
		return
	}
	defer p.Dispose()
	_ = c.DrawLinePixels(p, u.capPoint(x1, y1), u.capPoint(x2, y2))
}

// startWindowDrag hands the drag to Windows: with the caption gone, the only
// way to move the window is to synthesise a caption-area button press.
func (u *natUI) startWindowDrag() {
	rel := proc("ReleaseCapture")
	send := proc("SendMessageW")
	rel.Call()
	const (
		wmNCLButtonDown = 0x00A1
		htCaption       = 2
	)
	send.Call(uintptr(u.mw.Handle()), wmNCLButtonDown, htCaption, 0)
}

// windowAction runs one of the caption buttons.
func (u *natUI) windowAction(id string) bool {
	hwnd := uintptr(u.mw.Handle())
	show := proc("ShowWindow")
	switch id {
	case "cap:min":
		show.Call(hwnd, 6) // SW_MINIMIZE
	case "cap:max":
		zoomed := proc("IsZoomed")
		if r, _, _ := zoomed.Call(hwnd); r != 0 {
			show.Call(hwnd, 9) // SW_RESTORE
		} else {
			show.Call(hwnd, 3) // SW_MAXIMIZE
		}
	case "cap:close":
		u.mw.Close()
	default:
		return false
	}
	return true
}

// inCaption reports whether a device point is inside the caption band. The
// buttons live there too, and they register their own spots first.
func (u *natUI) inCaption(x, y int) bool {
	return y >= u.oy && y < u.oy+u.s(capH)
}
