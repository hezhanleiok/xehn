//go:build windows

package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/lxn/walk"
)

// Home is the poster layout: a quiet canvas, the orbital connect key with its
// uptime underneath, the wide node/protocol selector, a passive hint band, the
// three circular-badge info cards (exit IP / country / latency), and the traffic
// panel filling whatever height is left.
//
// The vertical budget is spent TOP-DOWN: the hero (disc + uptime + selector +
// hints) and the info row take FIXED, comfortable heights, and the traffic panel
// only ever receives the remainder. That is the whole answer to "the traffic
// share must not crowd the connect button / exit-IP row" — those rows can never
// be squeezed, because the share lives inside the traffic remainder and hides
// itself (donut first, then the whole share band) when that remainder is small.
//
// Every coordinate is derived from the live logical window (u.dw/u.dh) through
// the breakpoint table, so the page re-layouts instead of letterboxing. Business
// logic (connect orchestration, node picking, protocol switching) is reused
// unchanged; only the painting and geometry live here.

// homeGeo is one frame's resolved home layout, in design units.
type homeGeo struct {
	cx, x, w float64 // content centre, card-box left and width

	discR   float64
	discCY  float64
	uptimeY float64
	uptimeH float64

	ddX, ddY, ddW, ddH float64

	hintY    float64
	hintH    float64
	showHint bool
	wwarp    bool

	infoY, infoH float64
	badge        float64
	stackInfos   bool

	trafficY, trafficH float64

	// Traffic internals.
	pad, headH     float64
	bodyY, bodyH   float64
	statsW         float64
	statsRow       bool
	showShare      bool
	showDonut      bool
	shareY, shareH float64
	compactH       bool
	compactW       bool
}

// homeLayout resolves the breakpoint table against the live design grid. Home
// shares the 700-tall fit factor with the other pages, so widths read u.dw
// (the grid the content actually lays out on); heights read dh + caption.
func (u *natUI) homeLayout() homeGeo {
	g := homeGeo{}
	fullH := u.dh + capH
	g.compactW = u.dw <= 1280
	g.compactH = fullH <= 680
	shortH := fullH <= 820
	g.wwarp = u.m.proto == protoWWarp

	g.x = u.contentX()
	g.w = u.contentW()
	g.cx = g.x + g.w/2
	// The labelled sidebar keeps the content column wide enough for three info
	// tiles at the supported minimum width; stacking is only a safety net.
	g.stackInfos = g.w < 620

	switch {
	case g.compactH:
		g.discR = 48
	case shortH:
		g.discR = 70
	case g.compactW:
		g.discR = 75
	default:
		g.discR = 86
	}
	switch {
	case g.compactH:
		g.badge, g.infoH = 34, 54
	case shortH:
		g.badge, g.infoH = 40, 66
	default:
		g.badge, g.infoH = 46, 80
	}
	if g.stackInfos {
		g.badge, g.infoH = 40, 64
	}

	heroTop := 50.0
	switch {
	case g.compactH:
		heroTop = 44
	case shortH:
		heroTop = 48
	}
	g.discCY = heroTop + g.discR
	discBottom := g.discCY + g.discR

	g.uptimeH = 26
	g.uptimeY = discBottom + 8
	if g.compactH {
		g.uptimeY = discBottom + 6
	}
	upBottom := g.uptimeY + g.uptimeH

	g.ddH = 44
	switch {
	case g.compactH:
		g.ddH = 38
	case shortH:
		g.ddH = 42
	}
	g.ddW = 400
	if g.stackInfos {
		g.ddW = g.w
	}
	if g.ddW > g.w-24 {
		g.ddW = g.w - 24
	}
	g.ddX = g.cx - g.ddW/2
	g.ddY = upBottom + 16
	if g.compactH {
		g.ddY = upBottom + 10
	}
	ddBottom := g.ddY + g.ddH

	// The hint band is passive on most layouts, but WARP-in-WARP keeps its
	// interactive outer/inner chips here, so that band must survive even the
	// compact heights — those chips are the only place the chain is chosen.
	g.hintH = 26
	g.showHint = g.wwarp || (!shortH && !g.compactH && !g.stackInfos)
	g.hintY = ddBottom + 14
	hintBottom := ddBottom
	if g.showHint {
		hintBottom = g.hintY + g.hintH
	}

	g.infoY = hintBottom + 18
	if g.compactH {
		g.infoY = hintBottom + 12
	}
	infoBottom := g.infoY + g.infoH
	if g.stackInfos {
		infoBottom = g.infoY + g.infoH*3 + 20
	}

	g.trafficY = infoBottom + 18
	if g.compactH {
		g.trafficY = infoBottom + 14
	}
	g.trafficH = u.dh - 14 - g.trafficY
	if g.trafficH < 120 {
		g.trafficH = 120
	}

	// Traffic internals: head, then the chart/stats body, then the share band.
	g.pad = 16
	if g.compactH {
		g.pad = 12
	}
	g.headH = 30
	const gapHB = 10.0
	g.statsW = 264
	if g.compactW {
		g.statsW = 230
	}
	g.statsRow = g.compactH || g.stackInfos

	availH := g.trafficH - 2*g.pad - g.headH - gapHB
	bodyMin, shareNoDonut, shareDonut := 150.0, 124.0, 150.0
	if g.compactH {
		bodyMin, shareNoDonut = 132, 96
	}
	const shareGap = 10.0
	// Real data only: the share band exists solely when a live session has
	// classified bytes. Otherwise the chart body keeps the whole remainder.
	g.showShare = u.m.connected && u.m.shareTotal > 0 &&
		availH >= bodyMin+shareGap+shareNoDonut && g.trafficH >= 210
	g.showDonut = g.showShare && !g.statsRow && availH >= bodyMin+shareGap+shareDonut
	g.shareH = 0
	if g.showShare {
		g.shareH = shareNoDonut
		if g.showDonut {
			g.shareH = shareDonut
		}
		g.bodyH = availH - shareGap - g.shareH
	} else {
		g.bodyH = availH
	}
	if g.bodyH < 70 {
		g.bodyH = 70
	}
	g.bodyY = g.trafficY + g.pad + g.headH + gapHB
	g.shareY = g.bodyY + g.bodyH + shareGap
	return g
}

func (u *natUI) paintHome(c *walk.Canvas) {
	g := u.homeLayout()
	u.paintConnectButton(c, g.cx, g.discCY, g.discR)
	u.paintHomeUptime(c, g)
	u.paintHomeDropdown(c, g.ddX, g.ddY, g.ddW, g.ddH)
	if g.showHint {
		u.paintHomeHints(c, g)
	}
	u.paintInfoCard(c, g.x, g.infoY, g.w, g.infoH, g)
	u.paintTrafficCard(c, g.x, g.trafficY, g.w, g.trafficH, g)
	// Home has no page head, so the appearance pills live in its top-right.
	u.paintAppearancePills(c, 18)
}

// paintHomeUptime is the large mono session clock on its own line below the
// key. Connected reads the session uptime; connecting reads the attempt's
// elapsed time (mm:ss under an hour) so the wait is measurable; idle keeps the
// slot empty so the vertical rhythm does not jump between states.
func (u *natUI) paintHomeUptime(c *walk.Canvas, g homeGeo) {
	var d time.Duration
	switch {
	case u.m.connected:
		d = sessionUptime(u.m.status)
	case (u.m.connecting || u.m.working) && !u.m.connectAt.IsZero():
		d = time.Since(u.m.connectAt)
	default:
		return
	}
	txt := clockText(d)
	if !u.m.connected && d < time.Hour {
		s := int64(d.Seconds())
		txt = fmt.Sprintf("%02d:%02d", s/60, s%60)
	}
	u.textC(c, txt, u.f.fmonoL, th.dim,
		u.r(g.cx-120, g.uptimeY, 240, g.uptimeH))
}

// ---------------------------------------------------------------------------
// Connect key (v5 tech hexagon)
// ---------------------------------------------------------------------------

// paintConnectButton is the focal control: a rounded pointy-top hexagon with a
// vertical state gradient, an outer trace ring with vertex nodes, side bracket
// handles, an inner trace and a top gloss. The state word sits inside under the
// white mark. Motion never rotates: connecting expands two hexagon pulse rings
// and sweeps a scan band top-to-bottom while the brackets breathe; connected
// pulses once per 3.4s and drifts the gloss sideways; idle only breathes halo.
func (u *natUI) paintConnectButton(c *walk.Canvas, cx, cy, r float64) {
	connecting := u.m.connecting || u.m.working
	connected := u.m.connected && !connecting
	winding := connecting && (!u.m.connecting || u.m.cancelling)
	light := th.window.R() >= 128
	t := float64(time.Now().UnixNano()) / 1e9
	// Halo and trace colours blend from the wallpaper actually painted under
	// the key, so no dark disc rims the glow on the aurora/band backgrounds.
	base := u.wallpaperAt(cx, cy+capH)

	from, to, ring := th.hexFrom, th.hexTo, th.accent
	switch {
	case connected:
		from, to, ring = th.connectFrom, th.connectTo, th.ok
	case winding:
		from, to, ring = mix(th.warn, rx(255, 255, 255), 0.28), th.warn, th.warn
	}
	clickable := (!u.m.working || u.m.connecting) && !u.m.cancelling
	R := r
	if u.m.hover == "connect" && clickable {
		R = r * 1.02
	}

	// Halo behind the key, breathing on a state-dependent period.
	glowStr, period, amp := 0.10, 3.6, 0.02
	switch {
	case connected:
		glowStr, amp = 0.16, 0.03
	case winding:
		glowStr, period, amp = 0.12, 2.2, 0.04
	case connecting:
		glowStr, period, amp = 0.14, 2.2, 0.05
	}
	if !light {
		glowStr += 0.06
	}
	glowStr += amp * (0.5 + 0.5*math.Sin(2*math.Pi*t/period))
	u.glowAlpha(c, cx, cy, R+30, R+30, ring, glowStr, 0)

	// Expanding hexagon pulses: two staggered while connecting, one slow once
	// the tunnel is up. Scale + fade only, no rotation anywhere.
	if connecting {
		for _, off := range []float64{0, 1.2} {
			ph := math.Mod(t+off, 2.4) / 2.4
			u.hexStroke(c, mix(base, ring, 0.42*(1-ph)),
				u.hexPoints(cx, cy, R*1.045*(1+0.17*ph), R*0.2), 2)
		}
	} else if connected {
		ph := math.Mod(t, 3.4) / 3.4
		u.hexStroke(c, mix(base, ring, 0.30*(1-ph)),
			u.hexPoints(cx, cy, R*1.045*(1+0.12*ph), R*0.2), 2)
	}

	// Soft hexagon glow hugging the body, then the outer trace ring + nodes.
	u.glowAlpha(c, cx, cy+3, R+12, R+12, to, 0.16, R/(R+12))
	u.hexStroke(c, mix(base, ring, 0.35), u.hexPoints(cx, cy, R*1.15, R*0.22), 1.6)
	nodeA := 0.45
	if connecting {
		nodeA = 0.3 + 0.55*(0.5+0.5*math.Sin(2*math.Pi*t/1.6))
	} else if connected {
		nodeA = 0.6
	}
	for _, v := range hexVerts(cx, cy, R*1.15) {
		u.circleFill(c, mix(base, ring, nodeA), v[0], v[1], 2.4)
	}
	// Side brackets breathe while connecting, steady otherwise.
	brkA := 0.35
	if connecting {
		brkA = 0.35 + 0.6*(0.5+0.5*math.Sin(2*math.Pi*t/1.6))
	} else if connected {
		brkA = 0.6
	}
	brkCol := mix(base, ring, brkA)
	u.hexBracket(c, brkCol, cx, cy, R, -1, 4.5)
	u.hexBracket(c, brkCol, cx, cy, R, 1, 4.5)

	// Body: exact-width gradient rows inside the rounded hexagon.
	main := hexDesign(cx, cy, R, R*0.2)
	u.hexFillGrad(c, main, from, to, cy, R)
	// Top gloss; drifts sideways once connected.
	gx := cx
	if connected {
		gx = cx + 5*math.Sin(2*math.Pi*t/4.5)
	}
	u.softEllipse(c, mix(from, to, 0.28), rx(255, 255, 255), gx, cy-R*0.435, R*0.565, R*0.24, 0.32)
	// Scan band sweeping down while connecting (translation, not rotation).
	if connecting {
		ph := math.Mod(t, 2.2) / 2.2
		e := ph * ph * (3 - 2*ph)
		u.hexScan(c, main, from, to, cy, R, cy-R-30+e*(2*R+60), 30)
	}
	// Rim light + inner trace.
	mid := mix(from, to, 0.5)
	rimA := 0.16
	if light {
		rimA = 0.30
	}
	u.hexStroke(c, mix(mid, rx(255, 255, 255), rimA), u.hexPoints(cx, cy, R, R*0.2), 1.2)
	u.hexStroke(c, mix(mid, rx(255, 255, 255), 0.16), u.hexPoints(cx, cy, R*0.826, R*0.16), 1.2)

	// Mark: white power glyph, white check once the tunnel is up.
	gy := cy - R*0.16
	g := R * 0.56
	if connected {
		u.polylineW(c, rx(255, 255, 255), []walk.Point{
			u.p(cx-0.34*g, gy+0.02*g),
			u.p(cx-0.08*g, gy+0.28*g),
			u.p(cx+0.38*g, gy-0.24*g),
		}, 0.14*g)
	} else {
		u.powerGlyph(c, cx, gy, g, rx(255, 255, 255))
	}

	// State word inside the hexagon, beneath the mark.
	labelY := cy + R*0.30
	labelH := math.Min(20, math.Max(13, R*0.28))
	lf := u.f.f12b
	if r < 60 {
		lf = u.f.f9
	}
	label := tr("连接")
	switch {
	case connected && u.m.proxyLost:
		// The tunnel is up but the host proxy was taken over by another client,
		// so traffic is leaving directly. "已连接" here would be a lie about
		// where the user's packets go.
		label = tr("直连中")
	case connected:
		label = tr("已连接")
	case winding:
		label = tr("断开中")
		if u.m.cancelling {
			label = tr("正在取消")
		}
	case connecting:
		label = tr("连接中")
	}
	u.textC(c, label, lf, rx(255, 255, 255), u.r(cx-R*0.86, labelY, R*1.72, labelH))
	// Hit area is the key's bounding circle plus a small margin. It stays
	// clickable while connecting: that click cancels the attempt.
	u.addSpot("connect", u.r(cx-r-8, cy-r-8, (r+8)*2, (r+8)*2), clickable)
}

// ---------------------------------------------------------------------------
// Protocol selector
// ---------------------------------------------------------------------------

// paintHomeDropdown is the wide selector under the disc. In subscription mode it
// is the front-node picker — flag (or the auto bolt) + name + measured latency,
// opening the latency-sorted node list; in WARP mode it is the protocol picker —
// shield + protocol name, opening the six-protocol list. One pill, two meanings,
// both wired to the same business actions the node page already uses.
func (u *natUI) paintHomeDropdown(c *walk.Canvas, x, y, w, h float64) {
	box := u.r(x, y, w, h)
	u.shadowRound(c, box, pillRad(h), shadowTint(), th.window)
	u.fillRound(c, th.card, box, pillRad(h))
	u.strokeRound(c, th.line, box, pillRad(h))
	enabled := !u.m.working && !u.m.connecting
	sub := u.m.set.ConnMode == "subscription"
	hoverID := "drop:proto"
	if sub {
		hoverID = "drop:homenode"
	}
	if u.m.hover == hoverID && enabled {
		u.strokeRound(c, th.accentLine, box, pillRad(h))
	}

	const padX = 16.0
	if sub {
		name, cc, ms, hasMS := u.homeActiveProxy()
		lx := x + padX
		switch {
		case u.m.set.SubAutoSelect:
			bs := h - 16
			u.fillRound(c, mix(th.accent2, th.card, 0.82), u.r(lx, y+8, bs, bs), 8)
			u.icon(c, "bolt", lx+bs*0.24, y+8+bs*0.24, bs*0.52, th.accent2)
			lx += bs + 10
		case cc != "":
			u.flagChip(c, lx, y+(h-16)/2, 24, 16, cc)
			lx += 24 + 10
		default:
			u.icon(c, "globe", lx, y+h/2-9, 18, th.accent)
			lx += 18 + 10
		}
		label := tr("自动选择")
		switch {
		case name != "" && u.m.set.SubAutoSelect:
			label = tr("自动 · ") + clipName(name)
		case name != "":
			label = clipName(name)
		case len(u.m.set.CustomProxies) == 0:
			label = tr("订阅节点 · 未导入")
		}
		latW := 0.0
		if hasMS {
			latW = u.textW(itoa(int64(ms))+"ms", 11) + 14
		}
		labelW := w - (lx - x) - latW - 34
		u.textL(c, label, u.f.f13b, th.text, u.r(lx, y, labelW, h))
		if hasMS {
			u.textR(c, itoa(int64(ms))+"ms", u.f.f10b, homeLatColor(ms), u.r(x+w-latW-30, y, latW, h))
		}
		u.icon(c, "chevron", x+w-28, y+h/2-6.5, 13, th.faint)
		u.addSpot("drop:homenode", box, enabled)
		return
	}
	u.icon(c, "shield", x+padX, y+h/2-11, 22, th.accent)
	u.textL(c, protoDisplayName(u.m.proto), u.f.f13b, th.text, u.r(x+padX+32, y, w-padX-66, h))
	u.icon(c, "chevron", x+w-28, y+h/2-6.5, 13, th.faint)
	u.addSpot("drop:proto", box, enabled)
}

// paintHomeHints is the band under the selector. WARP-in-WARP keeps its
// interactive outer/inner chain chips here — the only place the chain is chosen,
// so homeLayout forces this band to survive even the compact heights. Every other
// layout shows read-only state chips summarising the session at a glance.
func (u *natUI) paintHomeHints(c *walk.Canvas, g homeGeo) {
	if g.wwarp {
		u.paintWWarpChips(c, g.cx, g.hintY)
		return
	}
	mode := tr("WARP 模式")
	if u.m.set.ConnMode == "subscription" {
		mode = tr("订阅模式")
	}
	exit := tr("直连")
	if u.m.openvpn {
		exit = "VPN Gate"
	} else if u.m.psiphon {
		exit = "Psiphon"
	}
	route := tr("已启用")
	switch u.m.set.ProxyMode {
	case modeGlobal:
		route = tr("全局")
	case modeDirect:
		route = tr("直连")
	}
	capture := tr("系统代理")
	if u.m.set.CaptureMode == captureTun {
		capture = "TUN"
	}
	labels := []string{
		mode,
		tr("出口方式") + " " + exit,
		tr("规则分流") + " " + route,
		tr("接管") + " " + capture,
	}
	const gap = 8.0
	total := -gap
	for _, l := range labels {
		total += chipWidth(l) + gap
	}
	x := g.cx - total/2
	if x < g.x {
		x = g.x
	}
	for _, l := range labels {
		x += u.hintChip(c, l, x, g.hintY+1) + gap
	}
}

// hintChip is a passive (non-clickable) state pill: recessed surface, faint
// label, no hit spot. It reads as a caption, not a control.
func (u *natUI) hintChip(c *walk.Canvas, label string, x, y float64) float64 {
	w := chipWidth(label)
	r := u.r(x, y, w, 24)
	u.fillRound(c, th.inset, r, pillRad(24))
	u.strokeRound(c, th.line2, r, pillRad(24))
	u.textC(c, label, u.f.f8, th.dim, r)
	return w
}

// paintWWarpChips is the carrier/inner pair, shown only for WARP-in-WARP.
func (u *natUI) paintWWarpChips(c *walk.Canvas, cx, y float64) {
	total := 190.0 + 12 + 190.0
	x := cx - total/2
	u.txt(c, x, y+4, 34, 18, tr("外层"), u.f.f8, th.dim)
	u.chainChips(c, x+38, y, "outer:", u.m.outerProto)
	x2 := x + 190 + 12
	u.txt(c, x2, y+4, 34, 18, tr("内层"), u.f.f8, th.dim)
	u.chainChips(c, x2+38, y, "inner:", u.m.innerProto)
}

func (u *natUI) chainChips(c *walk.Canvas, x, y float64, prefix, cur string) {
	for i, p := range []string{protoWG, protoAWG} {
		u.chipAt(c, prefix+p, strings.ToUpper(p), x+float64(i)*54, y, cur == p, !u.m.working && !u.m.connecting)
	}
}

// ---------------------------------------------------------------------------
// Info card: IP / country / latency
// ---------------------------------------------------------------------------

// paintInfoCard is the reference's row of three separate tiles — exit IP,
// country, latency — each with a round tinted badge (or the flag) on the left and
// the label over the value to its right. The badge is centred on the text block,
// not pinned to the card's top edge, and the value sits on the label's left edge,
// which is what makes the row read as aligned rather than hand-placed. Badge size
// and tile height come from the breakpoint table (g), so the row stays
// proportionate to the connect disc above it instead of competing with it.
func (u *natUI) paintInfoCard(c *walk.Canvas, x, y, w, h float64, g homeGeo) {
	const gap = 16.0
	badge := g.badge
	padX := 18.0
	labelH, valueH := 16.0, 26.0
	valueFont := u.f.f17b
	if g.compactH {
		padX, labelH, valueH, valueFont = 14, 14, 22, u.f.f15b
	}
	blockH := labelH + 4 + valueH
	textX := padX + badge + 14

	type tile struct{ x, y, w, h float64 }
	tiles := make([]tile, 3)
	if g.stackInfos {
		for i := range tiles {
			tiles[i] = tile{x, y + float64(i)*(h+10), w, h}
		}
	} else {
		cw := (w - gap*2) / 3
		for i := range tiles {
			tiles[i] = tile{x + float64(i)*(cw+gap), y, cw, h}
		}
	}
	geom := func(t tile) (labelY, valueY, badgeY float64) {
		labelY = t.y + (t.h-blockH)/2
		valueY = labelY + labelH + 4
		badgeY = labelY + (blockH-badge)/2
		return
	}

	// Exit IP (本机IP while idle): a blue pin badge, the address, and a copy
	// affordance that follows the measured value width.
	t := tiles[0]
	u.cardPlain(c, t.x, t.y, t.w, t.h)
	labelY, valueY, badgeY := geom(t)
	u.homeBadge(c, t.x+padX, badgeY, badge, "pin", th.up)
	ipLabel := tr("本机IP")
	if u.m.connected {
		ipLabel = tr("出口IP")
	}
	u.txt(c, t.x+textX, labelY, t.w-textX-padX, labelH, ipLabel, u.f.f8, th.dim)
	ip := u.displayIP()
	if ip == "" {
		u.txt(c, t.x+textX, valueY, t.w-textX-padX, valueH, "—", valueFont, th.faint)
	} else {
		u.txt(c, t.x+textX, valueY, t.w-textX-padX-30, valueH, ip, valueFont, th.text)
		ipW := float64(u.measure(c, ip, valueFont)) / u.k
		cx := t.x + textX + ipW + 8
		if cx > t.x+t.w-30 {
			cx = t.x + t.w - 30
		}
		u.iconButton(c, cx, valueY+(valueH-22)/2, 22, "copyip", "copy", true)
	}

	// Country / region: the flag when known, a cyan globe before the first geo
	// answer. No osRegionCC() fallback — the Windows UI locale is not the
	// machine's location, and using it painted a foreign flag on every launch.
	t = tiles[1]
	u.cardPlain(c, t.x, t.y, t.w, t.h)
	labelY, valueY, badgeY = geom(t)
	cc, _ := u.displayGeo()
	if cc == "" {
		u.homeBadge(c, t.x+padX, badgeY, badge, "globe", th.accent2)
	} else {
		fh := badge * 0.675
		u.flagChip(c, t.x+padX, badgeY+(badge-fh)/2, badge, fh, cc)
	}
	u.txt(c, t.x+textX, labelY, t.w-textX-padX, labelH, tr("国家/地区"), u.f.f8, th.dim)
	if cc == "" {
		label := tr("—")
		if !u.m.connected {
			label = tr("本机")
		}
		u.txt(c, t.x+textX, valueY, t.w-textX-padX, valueH, label, valueFont, th.faint)
	} else {
		u.txt(c, t.x+textX, valueY, t.w-textX-padX, valueH, regionLabel(cc), valueFont, th.text)
	}

	// Latency: an amber clock badge, the number and its unit once connected, a
	// placeholder until the first sample, an honest dash while idle.
	t = tiles[2]
	u.cardPlain(c, t.x, t.y, t.w, t.h)
	labelY, valueY, badgeY = geom(t)
	u.homeBadge(c, t.x+padX, badgeY, badge, "clock", th.warn)
	u.txt(c, t.x+textX, labelY, t.w-textX-padX, labelH, tr("延迟"), u.f.f8, th.dim)
	ms := u.m.latency
	switch {
	case u.m.connected && ms > 0:
		num := itoa(ms)
		u.txt(c, t.x+textX, valueY, 110, valueH, num, valueFont, th.text)
		u.txt(c, t.x+textX+u.textW(num, 15)+6, valueY+valueH-19, 40, 18, "ms", u.f.f8, th.dim)
	case u.m.connected:
		u.txt(c, t.x+textX, valueY+2, t.w-textX-padX, valueH, tr("检测中…"), u.f.f13, th.faint)
	default:
		u.txt(c, t.x+textX, valueY, t.w-textX-padX, valueH, "—", valueFont, th.faint)
	}
}

// homeBadge is the round tinted icon at the head of an info tile: a soft disc of
// the tile's accent, a faint rim, and the glyph centred inside. size is the
// diameter, so the three tiles share one metric whatever the leading element is.
func (u *natUI) homeBadge(c *walk.Canvas, x, y, size float64, kind string, col walk.Color) {
	u.circleFill(c, mix(col, th.card, 0.86), x+size/2, y+size/2, size/2)
	u.circleStrokeW(c, mix(col, th.card, 0.60), x+size/2, y+size/2, size/2-0.5, 1)
	u.icon(c, kind, x+size*0.27, y+size*0.27, size*0.46, col)
}

// ---------------------------------------------------------------------------
// Traffic card: live chart + per-direction stats + application share
// ---------------------------------------------------------------------------

// paintTrafficCard fills the remainder below the info row. Its height is whatever
// the fixed hero/info budget leaves, so it can never push the connect disc or the
// exit-IP row upward. Inside, the head and the chart/stats body come first; the
// application-share band only appears when a live session has classified bytes
// AND the remainder is tall enough — otherwise the chart keeps the whole space.
func (u *natUI) paintTrafficCard(c *walk.Canvas, x, y, w, h float64, g homeGeo) {
	u.cardPlain(c, x, y, w, h)
	pad := g.pad
	u.paintTrafficHead(c, x+pad, y+pad, w-2*pad, g.headH, g)

	bodyX := x + pad
	bodyW := w - 2*pad
	if g.statsRow {
		// Short layout: chart on top, the three stat tiles in a row beneath it.
		statsH := 78.0
		chartH := g.bodyH - statsH - 10
		if chartH < 50 {
			chartH = 50
			statsH = g.bodyH - chartH - 10
			if statsH < 40 {
				statsH = 40
			}
		}
		u.paintTrafficChart(c, bodyX, g.bodyY, bodyW, chartH, g)
		u.paintTrafficStatsRow(c, bodyX, g.bodyY+chartH+10, bodyW, statsH, g)
	} else {
		chartW := bodyW - g.statsW - 18
		u.paintTrafficChart(c, bodyX, g.bodyY, chartW, g.bodyH, g)
		u.paintTrafficStatsColumn(c, bodyX+chartW+18, g.bodyY, g.statsW, g.bodyH, g)
	}
	if g.showShare {
		u.paintTrafficShare(c, bodyX, g.shareY, bodyW, g.shareH, g)
	}
}

// paintTrafficHead is the panel's title row: title, a pulsing "live" badge while
// connected, the down/up legend, and the time-window chip pinned to the right.
func (u *natUI) paintTrafficHead(c *walk.Canvas, x, y, w, h float64, g homeGeo) {
	title := tr("实时流量")
	u.txt(c, x, y, 150, h, title, u.f.f13b, th.text)
	tx := x + float64(u.measure(c, title, u.f.f13b))/u.k + 14

	wlabel := tr("最近 60 秒")
	ww := float64(u.measure(c, wlabel, u.f.f8))/u.k + 22
	wr := u.r(x+w-ww, y+(h-22)/2, ww, 22)

	if u.m.connected {
		lw := 54.0
		lr := u.r(tx, y+(h-22)/2, lw, 22)
		u.fillRound(c, mix(th.ok, th.card, 0.88), lr, pillRad(22))
		u.strokeRound(c, mix(th.ok, th.card, 0.62), lr, pillRad(22))
		u.statusDot(c, tx+13, y+h/2, 3, th.ok2)
		u.txt(c, tx+21, y+(h-18)/2, lw-26, 18, tr("实时"), u.f.f8, th.ok2)
		tx += lw + 16
	}
	// Legend, only while it fits clear of the window chip.
	for _, lg := range []struct {
		label string
		col   walk.Color
	}{{tr("下载"), th.ok2}, {tr("上传"), th.up}} {
		lw := 14 + float64(u.measure(c, lg.label, u.f.f8))/u.k + 16
		if tx+lw > x+w-ww-12 {
			break
		}
		u.fillRound(c, lg.col, u.r(tx, y+h/2-4.5, 9, 9), 3)
		u.txt(c, tx+14, y+(h-18)/2, lw, 18, lg.label, u.f.f8, th.dim)
		tx += lw
	}
	u.fillRound(c, th.inset, wr, pillRad(22))
	u.strokeRound(c, th.line2, wr, pillRad(22))
	u.textC(c, wlabel, u.f.f8, th.faint, wr)
}

// paintTrafficChart is the smoothed down/up area chart with a labelled gridline
// axis, mirroring the reference: green download beneath blue upload, a bright
// endpoint dot on each, and round-number MB/s / KB/s gridlines. The window is the
// last 30 samples (≈60s at the 2s poll cadence), so the "最近 60 秒" chip is honest.
func (u *natUI) paintTrafficChart(c *walk.Canvas, x, y, w, h float64, g homeGeo) {
	dS := lastN(u.m.downRates, 30)
	uS := lastN(u.m.upRates, 30)
	peak := nicePeak(maxSeries(dS, uS))
	padL, padR, padT, padB := 48.0, 8.0, 6.0, 4.0
	if g.compactH {
		padL = 40
	}
	// A fixed gutter clips wide axis labels; size it to the widest one.
	for _, f := range []float64{0, 0.5, 1} {
		if lw := float64(u.measure(c, axisRate(peak, f), u.f.fmono))/u.k + 12; lw > padL {
			padL = lw
		}
	}
	plotX := x + padL
	plotW := w - padL - padR
	plotY := y + padT
	plotH := h - padT - padB
	if plotW < 24 || plotH < 24 {
		return
	}

	// Gridlines at 0 / ½ / 1 of the peak, dashed, with a right-aligned axis label.
	for _, f := range []float64{0, 0.5, 1} {
		gy := plotY + plotH*(1-f)
		u.dashedHLine(c, plotX, gy, plotW, th.line2)
		u.textR(c, axisRate(peak, f), u.f.fmono, th.faint, u.r(x, gy-8, padL-8, 16))
	}

	base := plotY + plotH
	if len(dS) < 2 && len(uS) < 2 {
		u.textC(c, tr("等待数据"), u.f.f9, th.faint, u.r(plotX, plotY, plotW, plotH))
		return
	}
	// Download area + line (green), then upload (blue) on top.
	if len(dS) > 1 {
		pts := u.curveSamples(plotX, plotY, plotW, plotH, dS, peak, 4)
		u.curveFill(c, pts, base, mix(th.card, th.ok2, 0.20), plotW/float64(len(dS)*4)+0.8)
		u.polylineW(c, th.ok2, pts, 2.2)
		last := pts[len(pts)-1]
		ex, ey := u.ux(last.X), u.uy(last.Y)
		u.circleFill(c, mix(th.ok2, th.card, 0.70), ex, ey, 7)
		u.circleFill(c, th.ok2, ex, ey, 3.6)
	}
	if len(uS) > 1 {
		pts := u.curveSamples(plotX, plotY, plotW, plotH, uS, peak, 4)
		u.curveFill(c, pts, base, mix(th.card, th.up, 0.18), plotW/float64(len(uS)*4)+0.8)
		u.polylineW(c, th.up, pts, 2.0)
		last := pts[len(pts)-1]
		ex, ey := u.ux(last.X), u.uy(last.Y)
		u.circleFill(c, mix(th.up, th.card, 0.70), ex, ey, 6)
		u.circleFill(c, th.up, ex, ey, 3.2)
	}
}

// paintTrafficStatsColumn is the right-hand stack: a download tile, an upload
// tile, and the session-total card. Tile heights adapt to the body; the
// cumulative/peak second row only appears when a tile is tall enough for it.
func (u *natUI) paintTrafficStatsColumn(c *walk.Canvas, x, y, w, h float64, g homeGeo) {
	const gap = 8.0
	totalH := 48.0
	tileH := (h - totalH - gap*2) / 2
	if tileH < 46 {
		tileH = 46
	}
	u.paintRateTile(c, x, y, w, tileH, "down", tr("下载"), th.ok2, lastOf(u.m.downRates), u.m.sessionDown, u.m.peakDown)
	u.paintRateTile(c, x, y+tileH+gap, w, tileH, "up", tr("上传"), th.up, lastOf(u.m.upRates), u.m.sessionUp, u.m.peakUp)
	u.paintSessionTotal(c, x, y+2*(tileH+gap), w, totalH)
}

// paintTrafficStatsRow is the short-layout variant: the same three tiles side by
// side beneath the chart.
func (u *natUI) paintTrafficStatsRow(c *walk.Canvas, x, y, w, h float64, g homeGeo) {
	const gap = 8.0
	cw := (w - gap*2) / 3
	u.paintRateTile(c, x, y, cw, h, "down", tr("下载"), th.ok2, lastOf(u.m.downRates), u.m.sessionDown, u.m.peakDown)
	u.paintRateTile(c, x+cw+gap, y, cw, h, "up", tr("上传"), th.up, lastOf(u.m.upRates), u.m.sessionUp, u.m.peakUp)
	u.paintSessionTotal(c, x+2*(cw+gap), y, cw, h)
}

// paintRateTile is one direction's stat: an arrow badge, the label, the live rate
// in the direction's colour, and (when tall enough) the cumulative total and the
// session peak beneath it.
func (u *natUI) paintRateTile(c *walk.Canvas, x, y, w, h float64, kind, label string, col walk.Color, rate, total, peak int64) {
	box := u.r(x, y, w, h)
	u.fillRound(c, th.inset, box, 13)
	u.strokeRound(c, th.line2, box, 13)
	const pad = 13.0
	bs := 30.0
	showSecond := h >= 74
	blockH := 44.0
	if showSecond {
		blockH += 20
	}
	by := y + (h-blockH)/2
	badgeY := by + (44-bs)/2
	u.fillRound(c, mix(col, th.card, 0.84), u.r(x+pad, badgeY, bs, bs), 9)
	u.icon(c, kind, x+pad+bs*0.24, badgeY+bs*0.24, bs*0.52, col)
	lx := x + pad + bs + 10
	u.txt(c, lx, by, w-(lx-x)-pad, 16, label, u.f.f9, th.dim)
	num, unit := splitRate(speedText(rate))
	u.txt(c, lx, by+17, 130, 26, num, u.f.f16b, col)
	if unit != "" {
		u.txt(c, lx+float64(u.measure(c, num, u.f.f16b))/u.k+5, by+25, 72, 16, unit, u.f.f8, th.dim)
	}
	if showSecond {
		r2y := by + 48
		u.txt(c, x+pad, r2y, (w-2*pad)/2, 14, tr("累计")+" "+byteText(total), u.f.f8, th.faint)
		u.textR(c, tr("峰值")+" "+speedText(peak), u.f.f8, th.faint, u.r(x+w/2, r2y, w/2-pad, 14))
	}
}

// paintSessionTotal is the blue→cyan total card: the run's cumulative bytes from
// the core's /connections counters, labelled distinctly from the live share so
// the two real numbers are never confused.
func (u *natUI) paintSessionTotal(c *walk.Canvas, x, y, w, h float64) {
	box := u.r(x, y, w, h)
	u.fillRound(c, mix(th.accent, th.card, 0.88), box, 13)
	// Horizontal blend toward cyan, inset so the rounded rim stays clean.
	const steps = 20
	ix, iw := x+13, w-26
	if iw > 0 {
		bw := iw / steps
		for i := 0; i < steps; i++ {
			t := float64(i) / (steps - 1)
			u.fillRect(c, mix(mix(th.accent, th.card, 0.88), mix(th.accent2, th.card, 0.90), t),
				u.r(ix+float64(i)*bw, y+2, bw+0.6, h-4))
		}
	}
	u.strokeRound(c, mix(th.accent2, th.card, 0.62), box, 13)
	const pad = 14.0
	u.txt(c, x+pad, y+(h-18)/2, w*0.55, 18, tr("本次会话总流量"), u.f.f9, th.dim)
	num, unit := splitRate(byteText(u.m.sessionUp + u.m.sessionDown))
	numW := float64(u.measure(c, num, u.f.f15b)) / u.k
	unitW := float64(u.measure(c, unit, u.f.f8)) / u.k
	rx0 := x + w - pad - numW - unitW - 6
	u.txt(c, rx0, y+(h-22)/2, numW+4, 22, num, u.f.f15b, th.accent2)
	u.txt(c, rx0+numW+6, y+(h-16)/2, unitW+4, 16, unit, u.f.f8, th.faint)
}

// paintTrafficShare is the application-category band: a dashed separator, a
// section title, then the donut (when there is room) beside the per-category
// bars. Every byte here is classified from the core's live connection table —
// nothing is invented, and a zero total hides the whole band upstream.
func (u *natUI) paintTrafficShare(c *walk.Canvas, x, y, w, h float64, g homeGeo) {
	u.dashedHLine(c, x, y, w, th.line)
	titleY := y + 8
	u.txt(c, x, titleY, w, 16, tr("流量占比 · 按应用类别"), u.f.f9, th.dim)
	rowY := titleY + 22
	rowH := h - (rowY - y)
	if rowH < 40 {
		rowH = 40
	}
	if g.showDonut {
		donutW := 120.0
		u.paintDonut(c, x+donutW/2, rowY+rowH/2, 44)
		rx := x + donutW + 20
		u.paintShareRows(c, rx, rowY, w-donutW-20, rowH, g)
	} else {
		u.paintShareRows(c, x, rowY, w, rowH, g)
	}
}

// paintShareRows draws the five category bars: swatch, name, proportional bar,
// percent, and byte size. The size column drops out on the narrowest layouts.
func (u *natUI) paintShareRows(c *walk.Canvas, x, y, w, h float64, g homeGeo) {
	total := u.m.shareTotal
	if total <= 0 {
		return
	}
	cats := u.shareCats()
	rh := h / float64(len(cats))
	nw := 78.0
	if g.compactW {
		nw = 64
	}
	for i, cat := range cats {
		ry := y + float64(i)*rh
		cy := ry + rh/2
		pct := float64(cat.bytes) / float64(total) * 100
		u.fillRound(c, cat.col, u.r(x, cy-4.5, 9, 9), 3)
		u.txt(c, x+16, ry, nw, rh, cat.label, u.f.f8, th.dim)
		barX := x + 16 + nw + 8
		pcW, szW := 40.0, 70.0
		barW := w - (barX - x) - pcW - szW - 16
		if barW < 24 {
			barW = 24
			szW = 0
		}
		u.fillRound(c, th.inset, u.r(barX, cy-3, barW, 6), 3)
		if pct > 0 {
			fw := barW * pct / 100
			if fw < 3 {
				fw = 3
			}
			u.fillRound(c, cat.col, u.r(barX, cy-3, fw, 6), 3)
		}
		u.textR(c, fmt.Sprintf("%.0f%%", pct), u.f.f8, th.text, u.r(barX+barW+8, ry, pcW, rh))
		if szW > 0 {
			u.textR(c, byteText(cat.bytes), u.f.f8, th.faint, u.r(x+w-szW, ry, szW, rh))
		}
	}
}

// paintDonut is the category ring: a recessed track with one coloured arc per
// category (small gaps between segments) and the session's classified total in
// the centre. Segments start at 12 o'clock and sweep clockwise.
func (u *natUI) paintDonut(c *walk.Canvas, cx, cy, r float64) {
	total := u.m.shareTotal
	if total <= 0 {
		return
	}
	width := r * 0.30
	u.ring(c, th.inset, th.card, cx, cy, r, width)
	start := -90.0
	for _, cat := range u.shareCats() {
		if cat.bytes <= 0 {
			continue
		}
		sweep := float64(cat.bytes) / float64(total) * 360
		a1, a2 := start+1.5, start+sweep-1.5
		if a2 > a1 {
			u.arcW(c, cat.col, cx, cy, r-width/2, width, a1, a2)
		}
		start += sweep
	}
	u.textC(c, fmt.Sprintf("%.2f", float64(total)/(1<<30)), u.f.f13b, th.text, u.r(cx-r, cy-13, 2*r, 16))
	u.textC(c, tr("GB 总量"), u.f.f8, th.faint, u.r(cx-r, cy+3, 2*r, 12))
}

// shareCat is one application category's label, colour and classified bytes.
type shareCat struct {
	label string
	col   walk.Color
	bytes int64
}

// shareCats pairs the five category slots with their display label and colour.
// The order and hues match the reference legend so the donut, bars and chart
// read as one system.
func (u *natUI) shareCats() []shareCat {
	return []shareCat{
		{tr("流媒体视频"), th.ok2, u.m.shareBytes[shareStream]},
		{tr("网页浏览"), th.up, u.m.shareBytes[shareWeb]},
		{tr("文件传输"), th.accent2, u.m.shareBytes[shareFile]},
		{tr("游戏加速"), th.warn, u.m.shareBytes[shareGame]},
		{tr("其他"), th.mag, u.m.shareBytes[shareOther]},
	}
}

// dashedHLine is the reference's dashed separator (4 on, 5 off), drawn as short
// fills because GDI+ has no dash style on a cosmetic pen here.
func (u *natUI) dashedHLine(c *walk.Canvas, x, y, w float64, col walk.Color) {
	for dx := 0.0; dx < w; dx += 9 {
		seg := 4.0
		if dx+seg > w {
			seg = w - dx
		}
		u.fillRect(c, col, u.r(x+dx, y, seg, 1))
	}
}

// ---------------------------------------------------------------------------
// Open popups (painted above the pages by the shell)
// ---------------------------------------------------------------------------

func (u *natUI) paintDropdownPopups(c *walk.Canvas) {
	switch u.m.dropOpen {
	case "region":
		ax, ay, aw, ah := u.regionAnchor()
		u.paintRegionPopup(c, ax, ay, aw, ah)
	case "vpnregion":
		ax, ay, aw, ah := u.openvpnRegionAnchor()
		u.paintVPNRegionPopup(c, ax, ay, aw, ah)
	case "family":
		ax, ay, aw, ah := u.familyAnchor()
		u.paintFamilyPopup(c, ax, ay, aw, ah)
	case "preset":
		ax, ay, aw, ah := u.presetAnchor()
		u.paintPresetPopup(c, ax, ay, aw, ah)
	case "capture":
		ax, ay, aw, ah := u.captureAnchor()
		u.paintCapturePopup(c, ax, ay, aw, ah)
	case "proto":
		g := u.homeLayout()
		u.paintProtoPopup(c, g.ddX, g.ddY, g.ddW, g.ddH)
	case "homenode":
		g := u.homeLayout()
		u.paintHomeNodePopup(c, g.ddX, g.ddY, g.ddW, g.ddH)
	case "connmode":
		ax, ay, aw, ah := u.modeConnAnchor()
		u.paintConnModePopup(c, ax, ay, aw, ah)
	case "addmenu":
		ax, ay, aw, ah := u.modeAddAnchor()
		u.paintAddMenuPopup(c, ax, ay, aw, ah)
	case "submgr":
		ax, ay, aw, ah := u.modeSubAnchor(u.contentX(), u.contentW())
		u.paintSubMgrPopup(c, ax, ay, aw, ah)
	}
}

// paintHomeNodePopup is the subscription front-node picker opened from the home
// pill: a header, an auto-select row (lowest measured latency), the latency-sorted
// node list with flag + name + delay + tick, and a footer link to the mode page.
// It flips above the pill when below would clip, and the wheel scrolls the list.
func (u *natUI) paintHomeNodePopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	rows := u.homeNodeRows()
	visible := u.homeNodeVisible()
	const (
		headH = 30.0
		autoH = 44.0
		rowH  = 36.0
		footH = 32.0
		pad   = 8.0
	)
	listH := float64(visible) * rowH
	ph := pad*2 + headH + autoH + listH + footH
	pw := aw
	if pw < 320 {
		pw = 320
	}
	px := ax
	if px+pw > u.dw-8 {
		px = u.dw - 8 - pw
	}
	if px < 8 {
		px = 8
	}
	py := ay + ah + 8
	if py+ph > u.dh-8 {
		py = ay - 8 - ph
	}
	if py < 8 {
		py = 8
	}
	box := u.r(px, py, pw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.overlay, box, panelRadius)
	u.strokeRound(c, th.line, box, panelRadius)

	// Header.
	u.txt(c, px+16, py+pad, pw-140, headH, tr("选择节点 · 按延迟排序"), u.f.f9, th.faint)
	u.textR(c, trf("%d 个节点", len(rows)), u.f.f8, th.faint, u.r(px+pw-118, py+pad, 102, headH))

	// Auto-select row.
	autoY := py + pad + headH
	u.hline(c, px+12, autoY, pw-24, th.line2)
	autoR := u.r(px+8, autoY+4, pw-16, autoH-8)
	if u.m.hover == "subauto" {
		u.fillRound(c, th.cardHover, autoR, ctrlRadius)
	}
	bs := 30.0
	bx := px + 16
	by := autoY + (autoH-bs)/2
	u.fillRound(c, mix(th.accent2, th.card, 0.82), u.r(bx, by, bs, bs), 9)
	u.icon(c, "bolt", bx+bs*0.24, by+bs*0.24, bs*0.52, th.accent2)
	tx := bx + bs + 12
	u.txt(c, tx, autoY+6, pw-(tx-px)-50, 18, tr("自动选择"), u.f.f10b, th.text)
	sub := tr("当前最低延迟") + " · " + tr("未测")
	if best := bestMeasuredProxy(rows); best != "" {
		sub = tr("当前最低延迟") + " · " + clipName(best)
	}
	u.txt(c, tx, autoY+24, pw-(tx-px)-50, 14, sub, u.f.f8, th.dim)
	if u.m.set.SubAutoSelect {
		u.textC(c, "✓", u.f.f12b, th.accent2, u.r(px+pw-44, autoY, 32, autoH))
	}
	u.addSpot("subauto", autoR, true)

	// Node list (scrollable).
	listY := autoY + autoH
	maxScroll := len(rows) - visible
	if maxScroll < 0 {
		maxScroll = 0
	}
	if u.m.homeNodeScroll > maxScroll {
		u.m.homeNodeScroll = maxScroll
	}
	if u.m.homeNodeScroll < 0 {
		u.m.homeNodeScroll = 0
	}
	activeName, _, _, _ := u.homeActiveProxy()
	for i := 0; i < visible; i++ {
		idx := u.m.homeNodeScroll + i
		if idx >= len(rows) {
			break
		}
		p := rows[idx]
		ry := listY + float64(i)*rowH
		id := "subpick:" + p.Name
		rr := u.r(px+8, ry+2, pw-16, rowH-4)
		if p.Name == activeName {
			u.fillRound(c, mix(th.accent2, th.card, 0.90), rr, ctrlRadius)
		} else if u.m.hover == id {
			u.fillRound(c, th.cardHover, rr, ctrlRadius)
		}
		fx := px + 16
		if p.CC != "" {
			u.flagChip(c, fx, ry+(rowH-16)/2, 24, 16, p.CC)
		} else {
			u.icon(c, "globe", fx+2, ry+(rowH-16)/2, 16, th.faint)
		}
		nx := fx + 34
		msW := 64.0
		u.textL(c, clipName(p.Name), u.f.f10, th.text, u.r(nx, ry, pw-(nx-px)-msW-40, rowH))
		latTxt, latCol := tr("未测"), th.faint
		if p.DelayMS > 0 {
			latTxt = itoa(int64(p.DelayMS)) + "ms"
			latCol = homeLatColor(p.DelayMS)
		} else if p.DelayErr {
			latTxt, latCol = tr("超时"), th.bad
		}
		u.textR(c, latTxt, u.f.f9, latCol, u.r(px+pw-msW-30, ry, msW, rowH))
		if p.Name == activeName {
			u.textC(c, "✓", u.f.f10, th.accent2, u.r(px+pw-30, ry, 24, rowH))
		}
		u.addSpot(id, rr, true)
	}
	if maxScroll > 0 {
		thumbH := listH * float64(visible) / float64(len(rows))
		if thumbH < 20 {
			thumbH = 20
		}
		thumbY := listY + (listH-thumbH)*float64(u.m.homeNodeScroll)/float64(maxScroll)
		u.fillRound(c, th.line, u.r(px+pw-7, listY, 3, listH), 2)
		u.fillRound(c, th.faint, u.r(px+pw-7, thumbY, 3, thumbH), 2)
	}

	// Footer link to the mode page.
	footY := listY + listH
	u.hline(c, px+12, footY, pw-24, th.line2)
	u.txt(c, px+16, footY, pw-32, footH, tr("管理节点与分组 → 模式页"), u.f.f9, th.accent2)
	u.addSpot("subnodes", u.r(px+8, footY, pw-16, footH), true)
}

func (u *natUI) paintProtoPopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const (
		rowH = 40.0
		pad  = 6.0
	)
	protos := []string{protoWG, protoAWG, protoWWarp, protoMASQUE, protoMASQUEH2, protoMASQUEMASQUE}
	ph := pad*2 + float64(len(protos))*rowH
	px, py := ax, ay+ah+6
	box := u.r(px, py, aw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.card, box, panelRadius)
	u.strokeRound(c, mix(th.card, rx(255, 255, 255), 0.55), box, panelRadius)

	for i, p := range protos {
		ry := py + pad + float64(i)*rowH
		id := "proto:" + p
		r := u.r(px+6, ry, aw-12, rowH)
		if u.m.hover == id {
			u.fillRound(c, th.cardHover, r, ctrlRadius)
		}
		col := th.text
		if u.m.proto == p {
			col = th.accent
		}
		u.txt(c, px+16, ry+10, aw-120, 20, protoDisplayName(p), u.f.f10, col)
		// Core capability, so a protocol the installed mihomo cannot parse is
		// visibly marked before it is picked.
		state, stCol := tr("不可用"), th.bad
		if u.m.capab == nil {
			state, stCol = tr("未探测"), th.faint
		} else if u.protoOK(p) {
			state, stCol = tr("可用"), th.ok
		}
		u.statusDot(c, px+aw-74, ry+rowH/2, 3, stCol)
		u.txt(c, px+aw-64, ry+10, 50, 20, state, u.f.f8, th.dim)
		u.addSpot(id, r, !u.m.working && !u.m.connecting)
	}
}

// ---------------------------------------------------------------------------
// Region popup (settings proxy tab) and the region table
// ---------------------------------------------------------------------------

// settingsFieldAnchor is the right-hand field box on a settings card: every
// dropdown on that page is 228 wide and 30 tall, aligned to the card's right
// padding, so one helper keeps the popups over the control that opened them
// even while the single column is scrolled.
func (u *natUI) settingsFieldAnchor(cardY, rowOff float64) (x, y, w, h float64) {
	return u.contentX() + u.contentW() - 16 - 228, cardY + 40 + rowOff, 228, 30
}

// regionAnchor is the Psiphon egress dropdown in the exit/startup card.
func (u *natUI) regionAnchor() (x, y, w, h float64) {
	_, _, exit := u.settingsTops()
	return u.settingsFieldAnchor(exit, 50)
}

// openvpnRegionAnchor is the VPN Gate egress dropdown, one exit-toggle below
// the Psiphon one in the same card.
func (u *natUI) openvpnRegionAnchor() (x, y, w, h float64) {
	_, _, exit := u.settingsTops()
	return u.settingsFieldAnchor(exit, 154)
}

// familyAnchor is the address-family box in the connection card.
func (u *natUI) familyAnchor() (x, y, w, h float64) {
	conn, _, _ := u.settingsTops()
	return u.settingsFieldAnchor(conn, 162)
}

// presetAnchor is the routing-preset dropdown in the split-rules card.
func (u *natUI) presetAnchor() (x, y, w, h float64) {
	_, routing, _ := u.settingsTops()
	return u.settingsFieldAnchor(routing, 4)
}

// captureAnchor is the capture-mode dropdown at the top of the connection card.
func (u *natUI) captureAnchor() (x, y, w, h float64) {
	conn, _, _ := u.settingsTops()
	return u.settingsFieldAnchor(conn, 4)
}

// regionPopupRows is how many rows the Psiphon region popup shows at once; the
// wheel scrolls the rest (the live egress set can exceed 30 countries).
const regionPopupRows = 13

func (u *natUI) paintRegionPopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const (
		rowH = 34.0
		pad  = 6.0
		pw   = 300.0
	)
	regions := currentPsiphonRegions()
	items := 1 + len(regions) // automatic + countries
	visible := items
	if visible > regionPopupRows {
		visible = regionPopupRows
	}
	ph := pad*2 + float64(visible)*rowH
	px := ax + aw - pw
	if px < 8 {
		px = 8
	}
	py := ay + ah + pad
	if py+ph > 686 {
		py = ay - pad - ph // open upward when below would clip
	}
	if py < 4 {
		py = 4
	}
	box := u.r(px, py, pw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.card, box, panelRadius)
	u.strokeRound(c, mix(th.card, rx(255, 255, 255), 0.55), box, panelRadius)

	maxScroll := items - visible
	if u.m.regionScroll > maxScroll {
		u.m.regionScroll = maxScroll
	}
	if u.m.regionScroll < 0 {
		u.m.regionScroll = 0
	}
	cur := u.m.set.PsiphonRegion
	ry := py + pad
	for i := u.m.regionScroll; i < u.m.regionScroll+visible; i++ {
		cc := ""
		if i > 0 {
			cc = regions[i-1].cc
		}
		u.regionPopupRow(c, px, ry, pw, rowH, cc, cur == cc)
		ry += rowH
	}
}

// regionEnsureSelectedVisible scrolls the popup just enough to show the saved
// region when it opens (row 0 is automatic).
func (u *natUI) regionEnsureSelectedVisible() {
	cur := u.m.set.PsiphonRegion
	if cur == "" {
		return
	}
	for i, r := range currentPsiphonRegions() {
		if r.cc != cur {
			continue
		}
		idx := i + 1
		if idx < u.m.regionScroll {
			u.m.regionScroll = idx
		}
		if idx >= u.m.regionScroll+regionPopupRows {
			u.m.regionScroll = idx - regionPopupRows + 1
		}
		return
	}
}

func (u *natUI) regionPopupRow(c *walk.Canvas, x, y, w, h float64, cc string, cur bool) {
	id := "pickregion:" + cc
	r := u.r(x+6, y, w-12, h)
	if u.m.hover == id {
		u.fillRound(c, th.cardHover, r, ctrlRadius)
	}
	if cc == "" {
		u.icon(c, "globe", x+16, y+h/2-8, 16, th.dim)
	} else {
		u.flagChip(c, x+16, y+(h-18)/2, 26, 18, cc)
	}
	col := th.text
	if cur {
		col = th.accent
	}
	u.txt(c, x+54, y+(h-20)/2, w-190, 20, regionName(cc), u.f.f10, col)
	u.textR(c, regionSubName(cc), u.f.f8, th.faint, u.r(x+w-140, y+(h-18)/2, 124, 18))
	u.addSpot(id, r, true)
}

// paintRegionDropdownSmall is the settings-page region control: a compact
// edit-box-sized dropdown on one line.
func (u *natUI) paintRegionDropdownSmall(c *walk.Canvas, x, y, w, h float64, enabled bool) {
	box := u.r(x, y, w, h)
	u.fillRound(c, th.input, box, ctrlRadius)
	if u.m.hover == "drop:region" && enabled {
		u.strokeRound(c, th.accentLine, box, ctrlRadius)
	}
	cc := u.m.set.PsiphonRegion
	col := th.text
	if !enabled {
		col = th.faint
	}
	if cc == "" {
		u.icon(c, "globe", x+10, y+h/2-8, 16, col)
	} else {
		u.flagChip(c, x+10, y+(h-18)/2, 24, 18, cc)
	}
	u.textL(c, regionName(cc), u.f.f10, col, u.r(x+42, y, w-60, h))
	u.icon(c, "chevron", x+w-22, y+h/2-6, 12, th.faint)
	u.addSpot("drop:region", box, enabled)
}

// ---------------------------------------------------------------------------
// OpenVPN / VPN Gate region control
// ---------------------------------------------------------------------------

// vpnRegionPopupRows is how many rows the country popup shows at once; the
// wheel scrolls the rest (VPN Gate can expose 30+ countries).
const vpnRegionPopupRows = 9

func (u *natUI) paintOpenVPNRegionDropdownSmall(c *walk.Canvas, x, y, w, h float64, enabled bool) {
	box := u.r(x, y, w, h)
	u.fillRound(c, th.input, box, ctrlRadius)
	if u.m.hover == "drop:vpnregion" && enabled {
		u.strokeRound(c, th.accentLine, box, ctrlRadius)
	}
	cc := u.m.set.OpenVPNRegion
	col := th.text
	if !enabled {
		col = th.faint
	}
	if cc == "" {
		u.icon(c, "globe", x+10, y+h/2-8, 16, col)
	} else {
		u.flagChip(c, x+10, y+(h-18)/2, 24, 18, cc)
	}
	label := tr("自动选择（延迟最低）")
	if cc != "" {
		label = u.vpnCountryLabel(cc)
		if pin := u.m.set.OpenVPNNode; pin != "" {
			if n, ok := u.vpnNodeByID(pin); ok {
				label = u.vpnCountryLabel(n.CountryShort) + " · " + u.vpnNodeSlot(n)
			}
		}
	}
	u.textL(c, label, u.f.f10, col, u.r(x+42, y, w-60, h))
	u.icon(c, "chevron", x+w-22, y+h/2-6, 12, th.faint)
	u.addSpot("drop:vpnregion", box, enabled)
}

// VPN Gate picker rows. The popup is a small tree, not a flat list: a country
// collapses to one row, and expanding it adds an "auto" row plus every relay in
// that country with its measured latency — the same shape as the phone client's
// picker.
const (
	vpnRowAuto = iota
	vpnRowCountry
	vpnRowCountryAuto
	vpnRowNode
)

type vpnPopupRow struct {
	kind    int
	cc      string
	country vpnGateCountry
	node    vpnGateNode
}

func (u *natUI) vpnPopupRows() []vpnPopupRow {
	rows := make([]vpnPopupRow, 0, 1+len(u.m.vpnCountries))
	rows = append(rows, vpnPopupRow{kind: vpnRowAuto})
	for _, co := range u.m.vpnCountries {
		rows = append(rows, vpnPopupRow{kind: vpnRowCountry, cc: co.CC, country: co})
		if !strings.EqualFold(u.m.vpnExpanded, co.CC) {
			continue
		}
		rows = append(rows, vpnPopupRow{kind: vpnRowCountryAuto, cc: co.CC, country: co})
		for _, n := range u.vpnNodesIn(co.CC) {
			rows = append(rows, vpnPopupRow{kind: vpnRowNode, cc: co.CC, node: n})
		}
	}
	return rows
}

// vpnNodesIn is the per-country node list in the phone client's order: class
// (residential before datacenter), then measured latency, then the API's
// self-reported ping. The slice is a copy — the popup must not reorder the pool.
func (u *natUI) vpnNodesIn(cc string) []vpnGateNode {
	var out []vpnGateNode
	for _, n := range u.m.vpnNodes {
		if strings.EqualFold(n.CountryShort, cc) {
			out = append(out, u.withProbeResult(n))
		}
	}
	sortVPNGateNodesByLatency(out)
	return out
}

// withProbeResult overlays this session's measured state onto a pool node.
// A pool refresh rebuilds every vpnGateNode with empty probe fields, so the
// list would fall back to 未检测 while the results still existed — reading them
// from the id-keyed table keeps the rows truthful across rebuilds.
func (u *natUI) withProbeResult(n vpnGateNode) vpnGateNode {
	r, ok := u.m.probeResults[n.id()]
	if !ok {
		return n
	}
	n.ProbeState = r.State
	n.ProbeMS = r.MS
	n.MeasuredBps = r.Bps
	n.ProbeErr = r.Err
	if r.State == "ok" {
		n.LatencyMS = r.MS
	}
	return n
}

func (u *natUI) vpnNodeByID(id string) (vpnGateNode, bool) {
	for _, n := range u.m.vpnNodes {
		if n.id() == id {
			return n, true
		}
	}
	return vpnGateNode{}, false
}

// vpnEnsureRowVisible scrolls the popup just enough to keep idx on screen.
func (u *natUI) vpnEnsureRowVisible(idx int) {
	if idx < 0 {
		return
	}
	if idx < u.m.vpnScroll {
		u.m.vpnScroll = idx
	}
	if idx >= u.m.vpnScroll+vpnRegionPopupRows {
		u.m.vpnScroll = idx - vpnRegionPopupRows + 1
	}
	if u.m.vpnScroll < 0 {
		u.m.vpnScroll = 0
	}
}

// vpnNodeSlot numbers a relay inside its country and class, in the order the
// expanded list shows it: JP家宽01, JP家宽02, JP机房01… The phone client's
// reasoning applies verbatim: the class tag is part of the name because that is
// what the user picks between, and numbering each block separately keeps the
// number stable when a different class sorts above it.
func (u *natUI) vpnNodeSlot(n vpnGateNode) string {
	key := n.classKey()
	var same []vpnGateNode
	for _, x := range u.vpnNodesIn(n.CountryShort) {
		if x.classKey() == key {
			same = append(same, x)
		}
	}
	idx := -1
	for i := range same {
		if same[i].id() == n.id() {
			idx = i
			break
		}
	}
	label := strings.ToUpper(n.CountryShort) + n.classTag()
	if idx >= 0 {
		return fmt.Sprintf("%s%02d", label, idx+1)
	}
	return label
}

// vpnNodeLatencyLabel is the node row's right-hand label. A refresh only
// fetches the list, so rows start at 未检测. The MANUAL OpenVPN handshake test
// is the only thing that produces the three required values: 类型 / 延迟 / 速度
// (or 失败). Self-reported Ping/Score are deliberately never shown here —
// they are not measurements.
func vpnNodeLatencyLabel(n vpnGateNode) string {
	switch n.ProbeState {
	case "fail":
		// The user asked for one word here: 超时, in red. The stage detail
		// (端口不可达 / 握手超时 / 下载中断) stays in the log where it is
		// actionable, instead of widening a 96px column.
		return tr("超时")
	case "ok":
		return trf("%s·%dms·%s", n.classTag(), n.ProbeMS, vpnProbeSpeedText(n.MeasuredBps))
	default:
		return tr("未检测")
	}
}

func vpnProbeSpeedText(bps int64) string {
	switch {
	case bps >= 1<<20:
		return trf("%.1fMB/s", float64(bps)/(1<<20))
	case bps > 0:
		return trf("%dKB/s", bps/1024)
	default:
		return "0KB/s"
	}
}

// vpnCountrySub is the country row's right-hand line, matching the phone
// client: the pool size and how many of its relays answered the probe.
func vpnCountrySub(c vpnGateCountry) string {
	if c.Responded > 0 {
		return trf("%d 个 · %d 有响应", c.Count, c.Responded)
	}
	return trf("%d 个", c.Count)
}

func (u *natUI) paintVPNRegionPopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const (
		rowH      = 34.0
		pad       = 6.0
		pw        = 440.0 // 两枚头部按钮并排，较原来的 348 加宽，避免与标题文字重叠
		headerH   = 36.0
		progressH = 28.0 // 延迟测试按钮下方的进度行
	)
	empty := len(u.m.vpnCountries) == 0
	rows := u.vpnPopupRows()
	visible := len(rows)
	if visible > vpnRegionPopupRows {
		visible = vpnRegionPopupRows
	}
	bodyRows := visible
	if empty {
		// The empty state keeps a note row under the header: the refresh button
		// is the one control that must stay reachable when there is no list.
		bodyRows = 1
	}
	ph := pad*2 + headerH + progressH + float64(bodyRows)*rowH
	px := ax + aw - pw
	if px < 8 {
		px = 8
	}
	py := ay + ah + pad
	if py+ph > 686 {
		py = ay - pad - ph // open upward when below would clip
	}
	if py < 4 {
		py = 4
	}
	box := u.r(px, py, pw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.card, box, panelRadius)
	u.strokeRound(c, mix(th.card, rx(255, 255, 255), 0.55), box, panelRadius)

	u.vpnPickerHeader(c, px, py+pad, pw, headerH)
	u.vpnProbeProgressRow(c, px, py+pad+headerH, pw, progressH)
	if empty {
		note := u.m.vpnPoolNote
		if note == "" {
			note = tr("暂无 VPN Gate 节点，点右上角刷新获取")
		}
		col := th.faint
		if !u.m.vpnPoolBusy {
			col = th.accent
		}
		u.txt(c, px+16, py+pad+headerH+progressH+(rowH-20)/2, pw-32, 20, note, u.f.f9, col)
		return
	}

	maxScroll := len(rows) - visible
	if u.m.vpnScroll > maxScroll {
		u.m.vpnScroll = maxScroll
	}
	if u.m.vpnScroll < 0 {
		u.m.vpnScroll = 0
	}
	cur := u.m.set.OpenVPNRegion
	pin := u.m.set.OpenVPNNode
	top := py + pad + headerH + progressH
	for i := u.m.vpnScroll; i < u.m.vpnScroll+visible && i < len(rows); i++ {
		ry := top + float64(i-u.m.vpnScroll)*rowH
		row := rows[i]
		switch row.kind {
		case vpnRowAuto:
			u.vpnRegionPopupRow(c, px, ry, pw, rowH, "", tr("自动选择（按延迟/可用性）"), "", cur == "" && pin == "")
		case vpnRowCountry:
			u.vpnCountryPopupRow(c, px, ry, pw, rowH, row.country, cur == row.cc, strings.EqualFold(u.m.vpnExpanded, row.cc))
		case vpnRowCountryAuto:
			u.vpnRegionPopupRow(c, px, ry, pw, rowH, row.cc,
				// "自动选 X 里的节点" read as "automatic, all nodes" and made a
				// 46-of-99 run look like the scope was broken. Say what it filters.
				trf("只在 %s 国内自动选节点", vpnCountryName(row.country)),
				vpnCountrySub(row.country), cur == row.cc && pin == "")
		case vpnRowNode:
			u.vpnNodePopupRow(c, px, ry, pw, rowH, row.node, pin != "" && pin == row.node.id())
		}
	}
}

// vpnProbeProgressRow sits directly under the 延迟测试 button. It shows the
// scope (全部 / 指定国家 / 指定节点), the done/total counter, the node currently
// being tested and a thin progress bar. Nothing here runs automatically: the
// counters are only set by a manual button press.
func (u *natUI) vpnProbeProgressRow(c *walk.Canvas, x, y, w, h float64) {
	bar := u.r(x+16, y+2, w-32, h-6)
	u.fillRound(c, th.chip, bar, 6)
	text := ""
	switch {
	case u.m.vpnProbeBusy:
		text = trf("延迟测试 %d/%d · %s · %s", u.m.vpnProbeDone, u.m.vpnProbeTotal,
			u.m.vpnProbeNote, u.m.vpnProbeCurrent)
	case u.m.vpnProbeTotal > 0:
		text = trf("延迟测试完成 %d/%d · %s · 成功 %d / 失败 %d",
			u.m.vpnProbeDone, u.m.vpnProbeTotal, u.m.vpnProbeNote, u.m.vpnProbeOK, u.m.vpnProbeFail)
	default:
		text = tr("节点未检测 · 点「延迟测试」做真实 OpenVPN 握手与下载测速")
	}
	u.txt(c, x+24, y+2, w-48, h-10, text, u.f.f9, th.text)
	if u.m.vpnProbeTotal > 0 {
		ratio := float64(u.m.vpnProbeDone) / float64(u.m.vpnProbeTotal)
		if ratio > 1 {
			ratio = 1
		}
		if ratio < 0 {
			ratio = 0
		}
		u.fillRound(c, th.accent, u.r(x+16, y+h-7, (w-32)*ratio, 3), 2)
	}
}

// vpnPickerHeader 是出口地区弹窗的标题行：固定的「出口地区」标签，加两枚
// 常驻按钮——「延迟测试」(vpnprobe) 与「刷新」(vpnrefresh)。弹窗宽度已放大
// 到 440，两枚按钮并排各 76px、间隔 8px，与标题文字互不相交。
func (u *natUI) vpnPickerHeader(c *walk.Canvas, x, y, w, h float64) {
	const (
		bw  = 76.0
		bh  = 26.0
		gap = 8.0
	)
	// 标题给右侧两枚按钮让出空间：2*bw + gap + 左右各 16 padding。
	u.txt(c, x+16, y+(h-20)/2, w-32-2*bw-gap-8, 20, tr("出口地区"), u.f.f10b, th.text)
	by := y + (h-bh)/2
	probeR := u.r(x+w-16-2*bw-gap, by, bw, bh)
	refreshR := u.r(x+w-16-bw, by, bw, bh)

	// 延迟测试：busy 时置灰并显示「测试中…」，同时不再注册热区（禁用），
	// 与刷新按钮 busy 时的处理保持一致。
	plabel := tr("延迟测试")
	pcol := th.accent
	pbg := th.accentSoft
	if u.m.vpnProbeBusy {
		plabel = tr("测试中…")
		pcol = th.faint
		pbg = th.chip
	}
	u.fillRound(c, pbg, probeR, ctrlRadius)
	u.textC(c, plabel, u.f.f9, pcol, probeR)
	if !u.m.vpnProbeBusy {
		u.addSpot("vpnprobe", probeR, true)
	}

	// 刷新：保持原有样式与 busy 处理。
	label := tr("刷新")
	col := th.accent
	bg := th.accentSoft
	if u.m.vpnPoolBusy {
		label = tr("刷新中…")
		col = th.faint
		bg = th.chip
	}
	u.fillRound(c, bg, refreshR, ctrlRadius)
	u.textC(c, label, u.f.f9, col, refreshR)
	if !u.m.vpnPoolBusy {
		u.addSpot("vpnrefresh", refreshR, true)
	}
}

// vpnProbeCancelFn 保存当前在飞的测速取消函数。它只在 GUI 线程被读写
// （runVPNProbe 入口、经 u.sync 回投的完成回调、重复点击入口），无需加锁。
// 窗口退出时 u.cancel() 取消 u.ctx，由此派生的 ctx 会随之结束。
var vpnProbeCancelFn context.CancelFunc

// vpnProbeCandidates 决定这一轮测速测哪些节点：
//   - 指定节点 → 只测那一个；
//   - 选了国家（或弹窗里展开了某国）→ 该国全部节点；
//   - 都没选 → 整个池子的全部节点，不再截断。
//
// 数据源是 picker 现有的 u.m.vpnNodes（model 里并无名为 vpnPool 的字段）。
func (u *natUI) vpnProbeCandidates() ([]vpnGateNode, string) {
	// 1) A pinned node wins: test exactly that one.
	if id := u.m.set.OpenVPNNode; id != "" {
		for i := range u.m.vpnNodes {
			if u.m.vpnNodes[i].id() == id {
				return []vpnGateNode{u.m.vpnNodes[i]}, tr("指定节点")
			}
		}
	}
	// 2) A chosen country (or the country row currently expanded in the
	//    picker) restricts the test to that country only.
	cc := u.m.set.OpenVPNRegion
	if cc == "" {
		cc = u.m.vpnExpanded
	}
	var nodes []vpnGateNode
	if cc != "" {
		nodes = u.vpnNodesIn(cc) // 已按延迟/测速排序
	}
	if len(nodes) == 0 {
		nodes = append([]vpnGateNode(nil), u.m.vpnNodes...)
		sortVPNGateNodesByLatency(nodes)
	}
	// 3) Nothing selected = every node in the pool. Truncating here is what made
	//    「全部」 look broken: only the first N were probed, every other row kept
	//    未检测, and the user read that as "整批测试失败".
	if cc != "" {
		return nodes, trf("指定国家 %s · 共 %d 个", strings.ToUpper(cc), len(nodes))
	}
	return nodes, trf("全部节点 · 共 %d 个", len(nodes))
}

// probeCarrier is the WARP base an OpenVPN probe dials through: the same
// outbound a real session uses, resolved once per run.
type probeCarrier struct {
	opts options
	ce   cachedEndpoint
	run  protoRun
}

// prepareProbeCarrier resolves a WARP endpoint + account for the probe. It runs
// off the GUI thread (account registration / a scan can take seconds).
func (u *natUI) prepareProbeCarrier() (*probeCarrier, error) {
	proto := u.m.proto
	if protoChained(proto) {
		proto = protoAWG
	}
	switch proto {
	case protoWG, protoAWG, protoMASQUE, protoMASQUEH2:
	default:
		proto = protoAWG
	}
	o := defaultConnectOptions(proto, false, false)
	u.m.set.apply(&o)
	if err := ensureAccount(u.ctx, o); err != nil {
		return nil, err
	}
	var results []cachedEndpoint
	// The cache key is the *scan* family, not the tunnel's ip_family. Reading it
	// with o.ipv6 while every writer uses scanFamilyV6() meant a user who had
	// once selected "IPv6 only" never found the cached endpoints: the probe then
	// fell back to direct dials, where VPN Gate relays are unreachable, and a
	// 46-node run reported 1/46 or 0/46.
	if cs, ok := cachedScanFor(proto, scanFamilyV6()); ok {
		results = cs.Results
	}
	prefer := u.m.pin
	if st, err := loadState(); err == nil && st.Endpoint != "" && prefer == "" && st.Proto == proto {
		prefer = st.Endpoint
	}
	if prefer != "" {
		if ce, ok := pickForced(results, prefer); ok {
			return &probeCarrier{opts: o, ce: ce, run: mustParseProto(proto)}, nil
		}
	}
	best, ok := pickBest(results)
	if !ok {
		return nil, fmt.Errorf("缓存里没有可用的 WARP 端点")
	}
	return &probeCarrier{opts: o, ce: best, run: mustParseProto(proto)}, nil
}

// probeRenderConfig 是测速 Render 回调的占位实现：生成一个含 openvpn 出站与
// MATCH 规则的最小 mihomo YAML。端口取 DefaultProbeConfig 的独立端口，
// rewriteProbePorts 会在每个节点/并发槽上再覆盖成真正隔离的端口。
//
// 注意：这里只搭出配置骨架，openvpn 出站真正需要的证书、加密参数来自
// vpnGateNode.Profile，尚未接入——握手不会成功。需主代理后续接真实渲染：
// 用 nodeID 找回节点并展开 mihomo 的 openvpn 字段，替换本方法即可。
// probeRenderConfig renders a REAL OpenVPN outbound for one relay. The probe
// must prove an actual OpenVPN handshake and carry real download bytes, so a
// stub proxy with only an IP and port is not enough: the certificate/cipher
// material comes from the cached VPN Gate profile, exactly as a connect does.
// The probe runner overwrites mixed-port / external-controller with isolated
// ports, so the values written here only have to be syntactically valid.
// No GEOIP/GEOSITE rules: the isolated WorkDir has no geodata.
func (u *natUI) probeRenderConfig(nodeID string) ([]byte, error) {
	cfg := DefaultProbeConfig()
	var node *vpnGateNode
	for i := range u.m.vpnNodes {
		if u.m.vpnNodes[i].id() == nodeID {
			node = &u.m.vpnNodes[i]
			break
		}
	}
	if node == nil {
		return nil, fmt.Errorf("测速找不到节点 %s，请先刷新节点列表", nodeID)
	}
	// Subscription mode: the relay has to be dialled through the front node,
	// exactly like the real session does. Probing it directly measured a route
	// the session never takes — and on a network where vpngate.net is blocked,
	// every row failed while the session itself was fine.
	if u.m.set.ConnMode == "subscription" {
		o := options{}
		u.m.set.apply(&o)
		prof, perr := parseOVPNProfile(node.Profile)
		if perr != nil {
			return nil, fmt.Errorf("节点 %s 的 OpenVPN 配置无效: %w", nodeID, perr)
		}
		return probeSubscriptionExitConfig(o, prof, cfg.MixedPort, cfg.APIPort)
	}
	// WARP mode: probe through the same WARP base the session uses. A direct
	// dial says nothing about a relay that is only reachable through the tunnel.
	if c := u.probeCarrier; c != nil {
		prof, perr := parseOVPNProfile(node.Profile)
		if perr != nil {
			return nil, fmt.Errorf("节点 %s 的 OpenVPN 配置无效: %w", nodeID, perr)
		}
		return probeCarrierExitConfig(c.opts, c.ce, c.run, prof, cfg.MixedPort, cfg.APIPort)
	}
	profile, err := parseOVPNProfile(node.Profile)
	if err != nil {
		return nil, fmt.Errorf("节点 %s 的 OpenVPN 配置无效: %w", nodeID, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "mixed-port: %d\n", cfg.MixedPort)
	fmt.Fprintf(&b, "external-controller: 127.0.0.1:%d\n", cfg.APIPort)
	b.WriteString("mode: rule\nlog-level: info\nproxies:\n")
	writeYAML(&b, mihomoOpenVPNProxy(profile, 0), "  ", "- ")
	fmt.Fprintf(&b, "rules:\n  - MATCH,%s\n", mihomoOpenVPNName)
	return []byte(b.String()), nil
}

// runVPNProbe 对当前地区 Top 8 节点做真实 OpenVPN 测速。异步范式与
// refreshVPNGatePool 一致：置 busy → goroutine → u.sync 回投 → invalidate。
// ctx 由 u.ctx 派生，窗口退出自动取消；busy 时再次触发则取消上一次测速。
func (u *natUI) runVPNProbe() {
	if u.m.vpnProbeBusy {
		// 重复点击（或重绘前命中的旧热区）：取消上一次，不启动新的测速。
		if vpnProbeCancelFn != nil {
			vpnProbeCancelFn()
		}
		u.addLog(tr("延迟测试已取消"), false)
		u.invalidate()
		return
	}
	nodes, scope := u.vpnProbeCandidates()
	if len(nodes) == 0 {
		u.addLog(tr("暂无可测速节点，请先点「刷新」获取节点"), true)
		return
	}
	u.m.vpnProbeBusy = true
	u.m.vpnProbeDone = 0
	u.m.vpnProbeOK = 0
	u.m.vpnProbeFail = 0
	u.m.vpnProbeTotal = len(nodes)
	u.m.vpnProbeCurrent = tr("准备中")
	u.m.vpnProbeNote = scope
	u.addLog(trf("开始延迟测试：%s，共 %d 个节点（真实 OpenVPN 握手 + 下载）", scope, len(nodes)), false)
	u.invalidate()

	ctx, cancel := context.WithCancel(u.ctx)
	vpnProbeCancelFn = cancel

	cfg := DefaultProbeConfig() // Top 8 / 单节点 2MiB / 总 16MiB / 独立端口
	cfg.Render = u.probeRenderConfig
	cfg.Log = func(s string) {
		u.sync(func() { u.addLog(s, false) })
	}
	// Live progress for the row under the button; marshalled back to the GUI
	// thread because the probe workers run concurrently.
	cfg.Progress = func(done, total int, current string) {
		u.sync(func() {
			u.m.vpnProbeDone = done
			u.m.vpnProbeTotal = total
			u.m.vpnProbeCurrent = current
			u.invalidate()
		})
	}
	// 在 GUI 线程把候选快照成 []ProbeNode，goroutine 只读，避免并发触碰 model。
	pnodes := make([]ProbeNode, 0, len(nodes))
	for _, n := range nodes {
		pnodes = append(pnodes, ProbeNode{
			ID:     n.id(),
			Region: strings.ToUpper(n.CountryShort),
			// The relay's own endpoint, so the probe can drop a silent port in
			// three seconds instead of spending the whole node budget on it.
			Server: n.IP,
			Port:   n.Port,
			Proto:  n.Proto,
		})
	}
	// Snapshot the mode before leaving the GUI thread: settings can be edited
	// while the probe runs, and reading u.m.set from a worker is a data race.
	subMode := u.m.set.ConnMode == "subscription"
	go func() {
		// Probe through the same carrier the session will use. Dialling the
		// relay directly is what made a 94-node list look 90% dead: most of
		// these relays are only reachable through the tunnel.
		if subMode {
			cfg.SkipReachCheck = true
		} else if c, cerr := u.prepareProbeCarrier(); cerr == nil {
			u.probeCarrier = c
			cfg.SkipReachCheck = true
			u.sync(func() {
				u.addLog(trf("测速经 WARP 底座 %s（与真实连接同一条路径）", c.ce.Endpoint), false)
			})
		} else {
			u.sync(func() {
				u.addLog(tr("未找到可用 WARP 端点，本次按直连测速："+cerr.Error()), true)
			})
		}
		outcomes := RunOpenVPNProbe(ctx, cfg, pnodes)
		u.probeCarrier = nil
		u.sync(func() {
			cancel()
			vpnProbeCancelFn = nil
			u.m.vpnProbeBusy = false
			u.m.vpnProbeDone = len(outcomes)
			u.m.vpnProbeCurrent = ""
			okN, failN := 0, 0
			for _, o := range outcomes {
				// Publish 类型 / 延迟 / 速度 (or 失败) straight into the pool so
				// the picker rows update immediately, not on the next reload.
				class := ""
				for i := range u.m.vpnNodes {
					if u.m.vpnNodes[i].id() != o.NodeID {
						continue
					}
					class = u.m.vpnNodes[i].classTag()
					if u.m.probeResults == nil {
						u.m.probeResults = map[string]probeResult{}
					}
					if o.Err == nil && o.Bps > 0 {
						okN++
						rememberVPNGateSpeed(o.NodeID, o.Bps)
						u.m.probeResults[o.NodeID] = probeResult{State: "ok", MS: o.HandshakeMS, Bps: o.Bps}
						u.m.vpnNodes[i].ProbeState = "ok"
						u.m.vpnNodes[i].ProbeMS = o.HandshakeMS
						u.m.vpnNodes[i].LatencyMS = o.HandshakeMS
						u.m.vpnNodes[i].MeasuredBps = o.Bps
						u.m.vpnNodes[i].ProbeErr = ""
					} else {
						failN++
						u.m.probeResults[o.NodeID] = probeResult{State: "fail", Err: probeFailReason(o)}
						u.m.vpnNodes[i].ProbeState = "fail"
						u.m.vpnNodes[i].ProbeMS = 0
						u.m.vpnNodes[i].MeasuredBps = 0
						u.m.vpnNodes[i].ProbeErr = probeFailReason(o)
					}
					break
				}
				prefix := o.NodeID
				if class != "" {
					prefix += "[" + class + "]"
				}
				u.addLog(prefix+" "+o.Summary(), o.Err != nil)
			}
			u.m.vpnProbeOK = okN
			u.m.vpnProbeFail = failN
			u.m.vpnMeasured = true
			if ctx.Err() == nil {
				u.addLog(trf("延迟测试完成：成功 %d / 失败 %d（共 %d 个节点）", okN, failN, len(outcomes)), false)
			}
			u.invalidate()
		})
	}()
}

func (u *natUI) vpnCountryPopupRow(c *walk.Canvas, x, y, w, h float64, co vpnGateCountry, cur, expanded bool) {
	id := "vpncountry:" + co.CC
	r := u.r(x+6, y, w-12, h)
	if u.m.hover == id {
		u.fillRound(c, th.cardHover, r, ctrlRadius)
	}
	u.flagChip(c, x+16, y+(h-18)/2, 26, 18, co.CC)
	if expanded {
		u.icon(c, "chevron", x+48, y+h/2-6, 12, th.accent)
	} else {
		u.icon(c, "chevron", x+48, y+h/2-6, 12, th.faint)
	}
	col := th.text
	if cur {
		col = th.accent
	}
	u.txt(c, x+68, y+(h-20)/2, w-68-134, 20, vpnCountryName(co), u.f.f10, col)
	u.textR(c, vpnCountrySub(co), u.f.f8, th.faint, u.r(x+w-128, y+(h-18)/2, 112, 18))
	u.addSpot(id, r, true)
}

// vpnClassColor is the phone client's slot colour: residential green, the
// datacenter fleet gold. Dark mode lightens the two accents; the light values
// are the phone's own #1B7F3B / #8A6D3B.
func (u *natUI) vpnClassColor(class string) walk.Color {
	dark := darkNow(u.m.set)
	switch class {
	case "residential":
		if dark {
			return rx(110, 205, 150)
		}
		return rx(27, 127, 59)
	case "datacenter":
		if dark {
			return rx(205, 170, 105)
		}
		return rx(138, 109, 59)
	}
	return th.text
}

func (u *natUI) vpnNodePopupRow(c *walk.Canvas, x, y, w, h float64, n vpnGateNode, cur bool) {
	id := "pickvpnnode:" + n.id()
	r := u.r(x+6, y, w-12, h)
	if u.m.hover == id {
		u.fillRound(c, th.cardHover, r, ctrlRadius)
	}
	u.circleFill(c, th.faint, x+20, y+h/2, 3)
	// Slot only, coloured by class; the class word is inside the slot name.
	u.txt(c, x+34, y+(h-20)/2, w-34-124, 20, u.vpnNodeSlot(n), u.f.f10, u.vpnClassColor(n.classKey()))
	latCol := th.faint
	switch n.ProbeState {
	case "ok":
		latCol = th.ok
	case "fail":
		latCol = rx(214, 69, 69)
	}
	u.textR(c, vpnNodeLatencyLabel(n), u.f.f8, latCol, u.r(x+w-150, y+(h-18)/2, 96, 18))
	if cur {
		u.textC(c, "✓", u.f.f10, th.accent, u.r(x+w-46, y, 28, h))
	}
	u.addSpot(id, r, true)
}

func (u *natUI) vpnRegionPopupRow(c *walk.Canvas, x, y, w, h float64, cc, name, sub string, cur bool) {
	id := "pickvpnregion:" + cc
	r := u.r(x+6, y, w-12, h)
	if u.m.hover == id {
		u.fillRound(c, th.cardHover, r, ctrlRadius)
	}
	if cc == "" {
		u.icon(c, "globe", x+16, y+h/2-8, 16, th.dim)
	} else {
		u.icon(c, "globe", x+30, y+h/2-7, 14, th.dim)
	}
	col := th.text
	if cur {
		col = th.accent
	}
	if sub == "" {
		// Phone parity: the top auto row is one full-width label with only a
		// tick on the right, so it never gets truncated by a side note.
		u.txt(c, x+54, y+(h-20)/2, w-54-54, 20, name, u.f.f10, col)
		if cur {
			u.textC(c, "✓", u.f.f10, th.accent, u.r(x+w-46, y, 28, h))
		}
	} else {
		u.txt(c, x+54, y+(h-20)/2, w-54-134, 20, name, u.f.f10, col)
		u.textR(c, sub, u.f.f8, th.faint, u.r(x+w-128, y+(h-18)/2, 112, 18))
	}
	u.addSpot(id, r, true)
}

// vpnRegionNames covers the countries VPN Gate actually serves, in the same
// Chinese the rest of the UI uses. The pool's own CountryLong is the fallback:
// a country outside this table still gets a usable row instead of a bare code.
var vpnRegionNames = map[string]string{
	"JP": "日本", "KR": "韩国", "US": "美国", "GB": "英国", "DE": "德国",
	"FR": "法国", "CA": "加拿大", "NL": "荷兰", "RU": "俄罗斯", "SG": "新加坡",
	"HK": "中国香港", "TW": "中国台湾", "TH": "泰国", "VN": "越南", "IN": "印度",
	"AU": "澳大利亚", "BR": "巴西", "TR": "土耳其", "PL": "波兰", "SE": "瑞典",
	"CH": "瑞士", "IT": "意大利", "ES": "西班牙", "MY": "马来西亚", "ID": "印度尼西亚",
	"PH": "菲律宾", "UA": "乌克兰", "RO": "罗马尼亚", "CZ": "捷克", "AT": "奥地利",
	"BE": "比利时", "DK": "丹麦", "NO": "挪威", "FI": "芬兰", "IE": "爱尔兰",
	"PT": "葡萄牙", "MX": "墨西哥", "AR": "阿根廷", "CL": "智利", "ZA": "南非",
	"EG": "埃及", "AE": "阿联酋", "IL": "以色列", "SA": "沙特阿拉伯", "KZ": "哈萨克斯坦",
	"GE": "格鲁吉亚", "MD": "摩尔多瓦", "BG": "保加利亚", "HU": "匈牙利", "GR": "希腊",
	"RS": "塞尔维亚", "HR": "克罗地亚", "SK": "斯洛伐克", "SI": "斯洛文尼亚", "LT": "立陶宛",
	"LV": "拉脱维亚", "EE": "爱沙尼亚", "IS": "冰岛", "NZ": "新西兰", "CO": "哥伦比亚",
	"PE": "秘鲁", "IR": "伊朗", "IQ": "伊拉克", "JO": "约旦", "LB": "黎巴嫩",
	"CY": "塞浦路斯", "MT": "马耳他", "LU": "卢森堡", "MO": "中国澳门", "KH": "柬埔寨",
	"MM": "缅甸", "NP": "尼泊尔", "BD": "孟加拉国", "PK": "巴基斯坦", "LK": "斯里兰卡",
	"MN": "蒙古",
}

// vpnRegionName is the dropdown label for a VPN Gate country: the Chinese name
// when known, otherwise the pool's English country name, otherwise the code.
func vpnRegionName(cc string) string {
	cc = strings.ToUpper(cc)
	if zh, ok := vpnRegionNames[cc]; ok {
		return tr(zh)
	}
	return cc
}

// vpnCountryName names one pool entry, using its CountryLong when the Chinese
// table does not know the code.
func vpnCountryName(c vpnGateCountry) string {
	if zh, ok := vpnRegionNames[c.CC]; ok {
		return tr(zh)
	}
	if c.Name != "" {
		return c.Name
	}
	return c.CC
}

// vpnCountryLabel is vpnCountryName for a code whose pool entry may not be
// loaded right now (the dropdown redraws before the first pool refresh).
func (u *natUI) vpnCountryLabel(cc string) string {
	for _, c := range u.m.vpnCountries {
		if c.CC == cc {
			return vpnCountryName(c)
		}
	}
	return vpnRegionName(cc)
}

// regionOption is one Psiphon egress country. The Chinese name is the i18n
// key; the English name doubles as the popup's second line.
type regionOption struct{ cc, zh, en string }

// psiphonRegionsFallback is the built-in egress table shown before the first
// successful Psiphon run. Afterwards the dropdown uses the live list Psiphon
// itself reports (see currentPsiphonRegions).
var psiphonRegionsFallback = []regionOption{
	{"US", "美国", "United States"},
	{"GB", "英国", "United Kingdom"},
	{"DE", "德国", "Germany"},
	{"FR", "法国", "France"},
	{"NL", "荷兰", "Netherlands"},
	{"CA", "加拿大", "Canada"},
	{"JP", "日本", "Japan"},
	{"KR", "韩国", "South Korea"},
	{"SG", "新加坡", "Singapore"},
	{"HK", "中国香港", "Hong Kong"},
	{"IN", "印度", "India"},
	{"AU", "澳大利亚", "Australia"},
}

// regionEnglishNames is the popup's second line for every country the shared
// Chinese table knows; codes outside it fall back to the code itself.
var regionEnglishNames = map[string]string{
	"JP": "Japan", "KR": "South Korea", "US": "United States", "GB": "United Kingdom", "DE": "Germany",
	"FR": "France", "CA": "Canada", "NL": "Netherlands", "RU": "Russia", "SG": "Singapore",
	"HK": "Hong Kong", "TW": "Taiwan, China", "TH": "Thailand", "VN": "Vietnam", "IN": "India",
	"AU": "Australia", "BR": "Brazil", "TR": "Turkey", "PL": "Poland", "SE": "Sweden",
	"CH": "Switzerland", "IT": "Italy", "ES": "Spain", "MY": "Malaysia", "ID": "Indonesia",
	"PH": "Philippines", "UA": "Ukraine", "RO": "Romania", "CZ": "Czechia", "AT": "Austria",
	"BE": "Belgium", "DK": "Denmark", "NO": "Norway", "FI": "Finland", "IE": "Ireland",
	"PT": "Portugal", "MX": "Mexico", "AR": "Argentina", "CL": "Chile", "ZA": "South Africa",
	"EG": "Egypt", "AE": "United Arab Emirates", "IL": "Israel", "SA": "Saudi Arabia", "KZ": "Kazakhstan",
	"GE": "Georgia", "MD": "Moldova", "BG": "Bulgaria", "HU": "Hungary", "GR": "Greece",
	"RS": "Serbia", "HR": "Croatia", "SK": "Slovakia", "SI": "Slovenia", "LT": "Lithuania",
	"LV": "Latvia", "EE": "Estonia", "IS": "Iceland", "NZ": "New Zealand", "CO": "Colombia",
	"PE": "Peru", "IR": "Iran", "IQ": "Iraq", "JO": "Jordan", "LB": "Lebanon",
	"CY": "Cyprus", "MT": "Malta", "LU": "Luxembourg", "MO": "Macao, China", "KH": "Cambodia",
	"MM": "Myanmar", "NP": "Nepal", "BD": "Bangladesh", "PK": "Pakistan", "LK": "Sri Lanka",
	"MN": "Mongolia",
}

// psiphonRegionOption names one live region code: Chinese from the shared
// country table, English from the English table, otherwise the code itself.
func psiphonRegionOption(cc string) regionOption {
	zh, en := cc, cc
	if name, ok := vpnRegionNames[cc]; ok {
		zh = name
	}
	if name, ok := regionEnglishNames[cc]; ok {
		en = name
	}
	return regionOption{cc: cc, zh: zh, en: en}
}

// currentPsiphonRegions is the dropdown's live list: the latest egress set
// Psiphon reported (cached in psiphon-regions.json, refreshed on every run),
// falling back to the built-in table before the first successful run. Memoized
// by file mtime so repaints do not re-read the file; all callers run on the UI
// thread, so no lock is needed.
var (
	regionCacheMTime time.Time
	regionCacheList  []regionOption
	regionCacheInit  bool
)

func currentPsiphonRegions() []regionOption {
	var mt time.Time
	if p := psiphonRegionsPath(); p != "" {
		if fi, err := os.Stat(p); err == nil {
			mt = fi.ModTime()
		}
	}
	if regionCacheInit && mt.Equal(regionCacheMTime) {
		return regionCacheList
	}
	regionCacheInit = true
	regionCacheMTime = mt
	codes := loadPsiphonRegions()
	if len(codes) == 0 {
		regionCacheList = psiphonRegionsFallback
		return regionCacheList
	}
	list := make([]regionOption, 0, len(codes))
	for _, cc := range codes {
		list = append(list, psiphonRegionOption(cc))
	}
	regionCacheList = list
	return list
}

// displayRegions covers codes shown on the home geo tile that are not
// selectable Psiphon egress options (the exit table must not offer the local
// country, but the tile still has to name it).
var displayRegions = map[string]regionOption{
	"CN": {"CN", "中国", "China"},
}

func regionOptionByCC(cc string) (regionOption, bool) {
	for _, r := range currentPsiphonRegions() {
		if r.cc == cc {
			return r, true
		}
	}
	if r, ok := displayRegions[cc]; ok {
		return r, true
	}
	// A saved region Psiphon no longer offers still deserves a real name.
	if _, ok := vpnRegionNames[cc]; ok {
		return psiphonRegionOption(cc), true
	}
	return regionOption{}, false
}

// regionName is the main display name: automatic, the translated country
// name, or the raw code when it is not in the table.
func regionName(cc string) string {
	if cc == "" {
		return tr("自动选择")
	}
	if r, ok := regionOptionByCC(cc); ok {
		return tr(r.zh)
	}
	return cc
}

// regionLabel is the info card's country line: the Chinese name plus the ISO
// code, so the row identifies the country in either language ("中国 · CN").
func regionLabel(cc string) string {
	if cc == "" {
		return tr("自动选择")
	}
	return regionName(cc) + " · " + strings.ToUpper(cc)
}

// regionSubName is the popup's second line: the English name, always in
// English — it is a proper noun.
func regionSubName(cc string) string {
	if cc == "" {
		return "Automatic"
	}
	if r, ok := regionOptionByCC(cc); ok {
		return r.en
	}
	return ""
}

// protoDisplayName is the human protocol name used by the dropdown: the names
// the user asked for — WireGuard / AWG / GOOL / MASQUE H2 / MASQUE H3.
func protoDisplayName(p string) string {
	switch p {
	case protoWG:
		return "WireGuard"
	case protoAWG:
		return "AWG"
	case protoMASQUE:
		return "MASQUE H3"
	case protoMASQUEH2:
		return "MASQUE H2"
	case protoWWarp:
		return "GOOL"
	case protoMASQUEMASQUE:
		return "MASQUE in MASQUE"
	default:
		return strings.ToUpper(p)
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// textW estimates a string's rendered width in design units for a given font
// size in points. MeasureTextPixels answers in device pixels and a canvas is
// not always at hand at layout time, so the estimate is character-class based,
// same as chipWidth.
func (u *natUI) textW(s string, pt float64) float64 {
	w := 0.0
	for _, r := range s {
		switch {
		case r > 0x2E80: // CJK and fullwidth forms
			w += pt * 1.0
		case r >= 'A' && r <= 'Z':
			w += pt * 0.62
		case r >= '0' && r <= '9':
			w += pt * 0.58
		default:
			w += pt * 0.52
		}
	}
	return w
}

// sessionUptime is how long the recorded session has been up, from the state
// file's start stamp.
func sessionUptime(st clientState) time.Duration {
	if !st.Connected || st.StartedAt == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, st.StartedAt)
	if err != nil {
		return 0
	}
	return time.Since(t)
}

func clockText(d time.Duration) string {
	if d <= 0 {
		return "00:00:00"
	}
	s := int64(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", s/3600, (s/60)%60, s%60)
}

func lastOf(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	return v[len(v)-1]
}

// splitRate separates "12.4 KB/s" into the number and its unit, so the card can
// draw the number large and the unit a size smaller (the mock's treatment).
func splitRate(s string) (string, string) {
	if i := strings.LastIndexByte(s, ' '); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// probeFailReason turns a probe outcome into the three words a row can show.
// The stage is the most useful part: it tells the user whether the relay was
// dead on arrival (端口不可达), never linked (握手超时) or linked but could not
// carry bytes (下载中断) — the difference between "this node is dead" and
// "this node is slow", which a bare 失败 cannot express.
func probeFailReason(o ProbeOutcome) string {
	msg := ""
	if o.Err != nil {
		msg = o.Err.Error()
	}
	switch o.Stage {
	case "start":
		if strings.Contains(msg, "不可达") {
			return tr("端口不可达")
		}
		return tr("启动失败")
	case "handshake":
		if strings.Contains(msg, "deadline") || strings.Contains(msg, "超时") {
			return tr("握手超时")
		}
		return tr("握手失败")
	case "download":
		if strings.Contains(msg, "deadline") || strings.Contains(msg, "超时") {
			return tr("下载超时")
		}
		return tr("下载中断")
	}
	return tr("失败")
}
