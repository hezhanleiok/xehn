//go:build windows

package main

import (
	"math"
	"time"

	"github.com/lxn/walk"
)

// The shell: a sidebar on the left and the active page on the right. The
// sidebar always shows icon + text labels — it never collapses to an icon-only
// rail, because a nav without labels is not usable. Its width steps down with
// the window (240 → 204), and the home page re-layouts through its own
// breakpoints. Every other page paints into the same content box and keeps its
// title bar.
const (
	shellPadX  = 26.0
	shellHeadH = 74.0

	shellBodyY = shellHeadH + 10
	shellBodyH = 700 - shellBodyY - 14
)

// sidebarW is the sidebar width for the current window. It reads winW (the
// DPI-only logical width) rather than dw, so a short non-home page that is
// scaled down to fit does not also push the sidebar into a wider breakpoint.
// It never drops below 204: the icon-only rail hid the nav labels, so the
// narrow breakpoint only trims padding, never the text.
func (u *natUI) sidebarW() float64 {
	switch {
	case u.winW <= 1280:
		return 204
	default:
		return 240
	}
}

func (u *natUI) contentX() float64 { return u.sidebarW() + shellPadX }

// contentW is the content column width in design units. It comes from the live
// window, so maximising widens the cards instead of leaving a blank strip.
func (u *natUI) contentW() float64 { return u.dw - u.contentX() - shellPadX }

type navItem struct {
	page, icon, label string
}

var navItems = []navItem{
	{pageHome, "home", "首页"},
	// The node page owns the subscription toolbar and the mode switch, so its
	// nav entry is labelled 模式 (mode), matching the approved mock.
	{pageNodes, "nodes", "模式"},
	{pageSettings, "settings", "设置"},
	{pageAbout, "info", "关于"},
	{pageLogs, "logs", "日志"},
}

func (u *natUI) paintShell(c *walk.Canvas) {
	u.paintSidebar(c)
	// Page-switch transition: the incoming page rises ~14 design px into place
	// over 240ms on an ease-out curve. Only the page (head + body) moves — the
	// sidebar, wallpaper, popups and caption stay pinned — and spinLoop keeps
	// the frames coming until the window closes.
	u.ay = 0
	if d := time.Since(u.pageAnimAt); d < 240*time.Millisecond {
		t := float64(d) / float64(240*time.Millisecond)
		e := 1 - (1-t)*(1-t)*(1-t)
		u.ay = int((1 - e) * 14 * u.k)
	}
	// The home page is the poster view: no title bar of its own, its top row is
	// the appearance pills on the right.
	if u.m.page != pageHome {
		u.paintPageHead(c)
	}
	switch u.m.page {
	case pageNodes:
		u.paintNodes(c)
	case pageSettings:
		u.paintSettings(c)
	case pageAbout:
		u.paintAbout(c, u.contentX(), shellBodyY, u.contentW())
	case pageLogs:
		u.paintLogs(c)
	default:
		u.paintHome(c)
	}
	u.ay = 0
	// Open dropdown overlays next, so they sit above the page (and hit-testing
	// scans spots back to front), and the window buttons above everything.
	u.paintDropdownPopups(c)
	u.paintCaption(c, u.dw)
}

// paintWallpaper is the layered background. Dark keeps the two soft aurora
// glows; light mirrors the reference mock: flowing blue wave bands behind the
// cards plus a faint green wash above the connect disc.
func (u *natUI) paintWallpaper(c *walk.Canvas, pxW, pxH int) {
	u.fillRect(c, th.window, pxRect(0, 0, pxW, pxH))
	w, h := u.dw, u.dh+capH
	if th.window.R() < 128 {
		for _, s := range u.darkWashes(w, h) {
			u.glowPx(c, th.window, s.cx, s.cy, s.ew, s.eh, s.col, s.strength)
		}
		return
	}
	for _, b := range u.waveBandSpecs(w, h) {
		u.waveBand(c, w, h, b.base, b.amp, b.freq, b.phase, b.col)
	}
	for _, s := range u.lightWashes(w, h) {
		u.glowPx(c, th.window, s.cx, s.cy, s.ew, s.eh, s.col, s.strength)
	}
}

type washSpec struct {
	cx, cy, ew, eh, strength float64
	col                      walk.Color
}

func (u *natUI) darkWashes(w, h float64) []washSpec {
	return []washSpec{
		{w * 0.55, -h * 0.10, w * 0.55, h * 0.42, 0.16, th.ok},
		{w * 0.92, h * 1.08, w * 0.45, h * 0.40, 0.14, th.accent},
	}
}

func (u *natUI) lightWashes(w, h float64) []washSpec {
	return []washSpec{
		{w * 0.55, -h * 0.06, w * 0.50, h * 0.34, 0.07, th.ok},
	}
}

type bandSpec struct {
	base, amp, freq, phase float64
	col                    walk.Color
}

func (u *natUI) waveBandSpecs(w, h float64) []bandSpec {
	return []bandSpec{
		{h * 0.14, h * 0.07, 1.20, 0.6, mix(th.window, th.accent, 0.06)},
		{h * 0.30, h * 0.10, 1.35, 0.0, mix(th.window, th.accent, 0.10)},
		{h * 0.46, h * 0.12, 1.10, 2.1, mix(th.window, th.accent, 0.16)},
		{h * 0.64, h * 0.10, 0.85, 4.2, mix(th.window, th.up, 0.10)},
	}
}

// wallpaperAt reproduces the painted background colour at a whole-window
// design point. The connect button blends its halo from this instead of
// th.window: over the dark aurora (or a light wave band) a window-based wash
// paints a visible disc darker than the surface around it.
func (u *natUI) wallpaperAt(x, y float64) walk.Color {
	w, h := u.dw, u.dh+capH
	col := th.window
	if th.window.R() < 128 {
		for _, s := range u.darkWashes(w, h) {
			col = mix(col, s.col, glowFall(s.strength, x, y, s.cx, s.cy, s.ew, s.eh))
		}
		return col
	}
	for _, b := range u.waveBandSpecs(w, h) {
		if y >= waveRidgeY(w, b.base, b.amp, b.freq, b.phase, x) {
			col = b.col
		}
	}
	for _, s := range u.lightWashes(w, h) {
		col = mix(col, s.col, glowFall(s.strength, x, y, s.cx, s.cy, s.ew, s.eh))
	}
	return col
}

// waveBand fills from a flowing sine ridge down to the window foot, one vertical
// strip per sample — the same primitive the traffic area chart uses.
func (u *natUI) waveBand(c *walk.Canvas, w, h, base, amp, freq, phase float64, col walk.Color) {
	const n = 72
	step := w / n
	for i := 0; i <= n; i++ {
		x := float64(i) / n * w
		y := waveRidgeY(w, base, amp, freq, phase, x)
		u.fillRect(c, col, u.r(x, y, step+0.6, h-y))
	}
}

func waveRidgeY(w, base, amp, freq, phase, x float64) float64 {
	t := x / w
	return base + amp*math.Sin(t*freq*2*math.Pi+phase) + amp*0.4*math.Sin(t*freq*4.7*math.Pi+phase*1.7)
}

// navRowBg paints the active/hover backing for one nav row. Active is a soft
// accent wash with a bright left bar; hover is the raised surface.
func (u *natUI) navRowBg(c *walk.Canvas, r walk.Rectangle, page string, x, y, w, h float64) {
	switch {
	case u.m.page == page:
		u.fillRound(c, th.accentSoft, r, 11)
		u.fillRound(c, th.accent2, u.r(x, y+9, 3, h-18), 1.5)
	case u.m.hover == "nav:"+page:
		u.fillRound(c, th.card, r, 11)
	}
}

func (u *natUI) paintSidebar(c *walk.Canvas) {
	h := u.mw.ClientBoundsPixels().Height
	if h < 10 {
		h = 700
	}
	sw := u.sidebarW()
	sep := u.sx(sw)

	// The sidebar runs the full height of the window — a pane, not a card — so
	// it is painted in device pixels and keeps its edge at any window size.
	u.fillRect(c, th.sidebar, pxRect(0, 0, sep, h))
	u.fillRect(c, th.line2, pxRect(sep-1, 0, 1, h))

	// Brand, centred on the rail: logo, wordmark, then the version pill on its
	// own line, then the connection state. The logo keeps its own aspect.
	const logoW = 64.0
	u.drawLogo(c, (sw-logoW)/2, 20, logoW)
	logoH := logoW * 321.0 / 512.0
	nameY := 20 + logoH + 12

	ver := shortVersion()
	nameW := float64(u.measure(c, "XEHN", u.f.f18b)) / u.k
	verW := float64(u.measure(c, ver, u.f.f8))/u.k + 16
	// Dev builds carry long version strings; the pill must never overflow the
	// rail, so ellipsize it into the width available on its own line.
	maxVerW := sw - 24
	if verW > maxVerW {
		rv := []rune(ver)
		for len(rv) > 0 && float64(u.measure(c, string(rv)+"…", u.f.f8))/u.k+16 > maxVerW {
			rv = rv[:len(rv)-1]
		}
		ver = string(rv) + "…"
		verW = float64(u.measure(c, ver, u.f.f8))/u.k + 16
	}
	u.txt(c, (sw-nameW)/2, nameY, nameW+2, 26, "XEHN", u.f.f18b, th.text)
	verY := nameY + 30
	vr := u.r((sw-verW)/2, verY, verW, 18)
	u.fillRound(c, mix(th.sidebar, th.accent2, 0.12), vr, 9)
	u.strokeRound(c, mix(th.sidebar, th.accent2, 0.35), vr, 9)
	u.textC(c, ver, u.f.f8, th.accent2, vr)

	// Connection state under the brand: status word only, no session clock —
	// the readable clock lives under the connect disc on Home.
	st, col := tr("未连接"), th.faint
	switch {
	case u.m.connecting:
		st, col = tr("连接中…"), th.warn
	case u.m.connected && u.m.proxyLost:
		// Same wording as the home disc: the tunnel is up but the host proxy is
		// gone, so traffic is leaving directly. Two different answers in one
		// window is how a user ends up trusting the wrong one.
		st, col = tr("直连中"), th.warn
	case u.m.connected:
		st, col = tr("已连接"), th.ok
	}
	stY := verY + 26
	stW := float64(u.measure(c, st, u.f.f9)) / u.k
	totalW := 7 + 7 + stW
	sx := (sw - totalW) / 2
	u.statusDot(c, sx+3.5, stY+9, 3.5, col)
	u.txt(c, sx+14, stY, stW+2, 18, st, u.f.f9, col)

	// Divider, then the navigation.
	divY := stY + 30
	u.hline(c, 14, divY, sw-28, th.line2)
	navY := divY + 16
	for i, n := range navItems {
		y := navY + float64(i)*52
		r := u.r(14, y, sw-28, 46)
		u.navRowBg(c, r, n.page, 14, y, sw-28, 46)
		iconCol, txtCol := th.faint, th.dim
		switch {
		case u.m.page == n.page:
			iconCol, txtCol = th.accent, th.accent
		case u.m.hover == "nav:"+n.page:
			iconCol, txtCol = th.dim, th.text
		}
		u.icon(c, n.icon, 28, y+13, 20, iconCol)
		u.txt(c, 60, y+12, sw-74, 22, tr(n.label), u.f.f15, txtCol)
		u.addSpot("nav:"+n.page, r, true)
	}

	// Foot: the running core version, pinned to the bottom of the rail.
	fullH := u.dh + capH
	footY := fullH - 40
	u.hline(c, 14, footY-12, sw-28, th.line2)
	core := "mihomo " + orEmpty(u.m.coreVersion, tr("未探测"))
	u.txt(c, 22, footY, sw-44, 18, core, u.f.f8, th.faint)
}

func (u *natUI) paintPageHead(c *walk.Canvas) {
	x := u.contentX()
	u.txt(c, x, 16, u.contentW()-40, 28, tr(u.pageTitle()), u.f.f15b, th.text)
	u.txt(c, x, 46, u.contentW()-40, 18, tr(u.pageSubtitle()), u.f.f8, th.faint)
	u.hline(c, x, shellHeadH-2, u.contentW(), th.line2)
}

// paintAppearancePills is the theme/language pair in Home's top-right corner.
func (u *natUI) paintAppearancePills(c *walk.Canvas, y float64) {
	themeIcon, themeLabel := "sun", tr("浅色")
	switch {
	case u.m.set.Theme == themeDark:
		themeIcon, themeLabel = "moon", tr("深色")
	case u.m.set.Theme == themeAuto:
		themeIcon, themeLabel = "monitor", tr("跟随系统")
	}
	lw := 68.0
	if u.m.set.Lang == langEN {
		lw = 96
	}
	langLabel := "中文"
	if u.m.set.Lang == langEN {
		langLabel = "English"
	}
	lx := u.dw - shellPadX - lw
	const themeW = 100.0
	tx := lx - 8 - themeW
	u.headPill(c, tx, y, themeW, themeIcon, themeLabel, "theme:cycle")
	u.headPill(c, lx, y, lw, "globe", langLabel, "lang:cycle")
}

// headPill is the bordered pill with an icon and a label used in the header.
func (u *natUI) headPill(c *walk.Canvas, x, y, w float64, icon, label, id string) {
	r := u.r(x, y, w, 28)
	bg := th.card
	if u.m.hover == id {
		bg = th.cardHover
	}
	u.fillRound(c, bg, r, pillRad(28))
	u.strokeRound(c, th.line, r, pillRad(28))
	u.icon(c, icon, x+10, y+7, 14, th.dim)
	u.txt(c, x+29, y+4, w-34, 20, label, u.f.f9, th.text)
	u.addSpot(id, r, true)
}

func (u *natUI) pageTitle() string {
	switch u.m.page {
	case pageNodes:
		return "模式"
	case pageSettings:
		return "设置"
	case pageAbout:
		return "关于"
	case pageLogs:
		return "日志"
	default:
		return "首页"
	}
}

func (u *natUI) pageSubtitle() string {
	switch u.m.page {
	case pageNodes:
		return "切换连接模式 · 管理节点与分组"
	case pageSettings:
		return "连接与接管 · 分流规则 · 出口与启动"
	case pageAbout:
		return "本程序 · 开源许可 · 客户端更新 · 内核"
	case pageLogs:
		return "运行日志 · 连接记录 · 调试信息"
	default:
		return "快速概览 · 连接状态 · 节点信息"
	}
}
