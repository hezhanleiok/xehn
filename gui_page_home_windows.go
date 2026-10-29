//go:build windows

package main

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/lxn/walk"
)

// Home is the poster layout: a quiet grey canvas, the big round connect button,
// the wide protocol selector under it, then two cards — IP / country / latency,
// and the upload / download rates with their curves. The exit-region choice
// lives on the settings proxy tab, next to the Psiphon switch.
//
// All geometry is derived from the mock's proportions on the 1080x700 design
// grid (the mock's 1536x1024 canvas scaled by 0.703/0.684), and anchored to the
// shell's content box so the sidebar width stays in charge of the horizontal.
const (
	homeBtnCY   = 140.0 // compact vertical composition above the data cards
	homeBtnR    = 70.0  // disc radius
	homeProtoW  = 264.0 // compact selector aligned with the reference mock
	homeProtoH  = 40.0
	homeProtoY  = 244.0
	homeCardPad = 24.0 // mock's 34px margin → 24 design px
	homeInfoY   = 344.0
	homeInfoH   = 88.0
	homeRateY   = 448.0
	homeRateH   = 146.0
)

func (u *natUI) homeCardGeo() (x, w float64) {
	return shellContentX + homeCardPad, u.contentW() - homeCardPad*2
}

// homeCX is the horizontal centre of the content column. Every centred element
// on this page — button, selector, popup — derives from it, so a popup can
// never drift away from the control that opened it.
func (u *natUI) homeCX() float64 { return shellContentX + u.contentW()/2 }

func (u *natUI) paintHome(c *walk.Canvas) {
	cx := u.homeCX()

	u.paintConnectButton(c, cx, homeBtnCY)

	// Protocol selector, directly under the button.
	u.paintProtoDropdown(c, cx-homeProtoW/2, homeProtoY, homeProtoW, homeProtoH)
	if u.m.proto == protoWWarp {
		// The chips get their own 28px band between the selector and the cards.
		u.paintWWarpChips(c, cx, homeProtoY+homeProtoH+4)
	}

	x, w := u.homeCardGeo()
	u.paintInfoCard(c, x, homeInfoY, w, homeInfoH)
	u.paintRatesCard(c, x, homeRateY, w, homeRateH)

	// Appearance controls live here and only here: Home is the page that has no
	// header of its own, so they sit in its top-right corner instead of being
	// repeated over every other page's title.
	u.paintAppearancePills(c, 18)
}

// ---------------------------------------------------------------------------
// Connect button
// ---------------------------------------------------------------------------

// paintConnectButton is the focal control, exactly as the reference has it: a
// frosted near-white disc (not a blue one), two faint rings around it, and a
// soft blue-grey power glyph over the state word — no fill colour, no bold.
func (u *natUI) paintConnectButton(c *walk.Canvas, cx, cy float64) {
	// Shadow: a stack of discs that fade outward, so the edge of the shadow is
	// a gradient rather than the crescent a single offset disc leaves behind.
	const shadowRings = 14
	for i := shadowRings; i >= 1; i-- {
		r := homeBtnR - 6 + float64(i)*2.2
		f := 0.30 * math.Pow(float64(shadowRings-i)/float64(shadowRings-1), 2)
		u.circleFill(c, mix(th.window, shadowTint(), f), cx, cy+7, r)
	}
	// The disc carries the state: frosted near-white while idle, the success
	// colour once the tunnel is up, an accent wash while connecting. Same shape
	// either way, so the change reads as "now connected" and not as a different
	// control.
	connecting := u.m.connecting || u.m.working
	connected := u.m.connected && !connecting
	switch {
	case connected:
		u.radial(c, th.ok, mix(th.ok, rx(255, 255, 255), 0.34), cx, cy, homeBtnR)
		u.circleStrokeW(c, mix(th.ok, rx(255, 255, 255), 0.45), cx, cy, homeBtnR-0.5, 1.0)
	default:
		// Bright at the centre, a touch cooler at the rim: frosted glass.
		u.radial(c, th.connectTo, th.connectFrom, cx, cy, homeBtnR)
		u.circleStrokeW(c, mix(th.card, th.accentLine, 0.7), cx, cy, homeBtnR-0.5, 1.0)
	}

	switch {
	case connecting:
		// Three dots breathing in sequence, in the power glyph's slot. No ring,
		// no rotation: a rotating arc reads as a progress wheel that never
		// arrives, while three dots say "working" without implying a position.
		const dotGap = 13.0
		for i := 0; i < 3; i++ {
			// Each dot is a third of a cycle behind the previous one; the cosine
			// gives a soft in-and-out rather than a blink.
			phase := math.Mod(float64(u.m.spin)+float64(i)*8, 24) / 24
			t := 0.5 - 0.5*math.Cos(2*math.Pi*phase)
			col := mix(mix(th.accent, rx(255, 255, 255), 0.70), th.accent, t)
			u.circleFill(c, col, cx-dotGap+float64(i)*dotGap, cy-14, 3.4+1.4*t)
		}

		label := tr("连接中…")
		if u.m.connecting && !u.m.cancelling && !u.m.connectAt.IsZero() {
			label = trf("连接中… %ds", int(time.Since(u.m.connectAt).Seconds()))
		}
		if u.m.working && !u.m.connecting {
			label = tr("断开中…")
		}
		if u.m.cancelling {
			// Between the click and the pipeline noticing it: say so, otherwise
			// the seconds keep counting and the cancel looks ignored.
			label = tr("正在取消…")
		}
		u.textC(c, label, u.f.f13b, th.dim, u.r(cx-110, cy+16, 220, 24))
	case connected:
		// White on the success fill: the glyph and the word have to stay legible
		// against a colour instead of the frosted glass they were drawn for.
		fg := rx(255, 255, 255)
		u.powerGlyph(c, cx, cy-14, 42, fg)
		u.textC(c, tr("已连接"), u.f.f16b, fg, u.r(cx-110, cy+12, 220, 28))
		u.textC(c, clockText(sessionUptime(u.m.status)), u.f.f12,
			mix(fg, th.ok, 0.22), u.r(cx-110, cy+40, 220, 20))
	default:
		u.powerGlyph(c, cx, cy-14, 42, th.dim)
		u.textC(c, tr("连接"), u.f.f16b, th.dim, u.r(cx-110, cy+12, 220, 28))
	}
	// Hit area is the visible disc plus its rings, nothing else. It stays
	// clickable while connecting: that click cancels the attempt.
	u.addSpot("connect", u.r(cx-homeBtnR-10, cy-homeBtnR-10, (homeBtnR+10)*2, (homeBtnR+10)*2),
		(!u.m.working || u.m.connecting) && !u.m.cancelling)
}

// ---------------------------------------------------------------------------
// Protocol selector
// ---------------------------------------------------------------------------

func (u *natUI) paintProtoDropdown(c *walk.Canvas, x, y, w, h float64) {
	box := u.r(x, y, w, h)
	u.shadowRound(c, box, pillRad(h), shadowTint(), th.window)
	u.fillRound(c, mix(th.card, rx(255, 255, 255), 0.5), box, pillRad(h))
	u.strokeRound(c, mix(th.card, rx(255, 255, 255), 0.6), box, pillRad(h))
	u.icon(c, "shield", x+18, y+h/2-11, 22, th.accent)
	u.textL(c, protoDisplayName(u.m.proto), u.f.f13b, th.text, u.r(x+50, y, w-94, h))
	u.icon(c, "chevron", x+w-30, y+h/2-6.5, 13, th.faint)
	u.addSpot("drop:proto", box, !u.m.working && !u.m.connecting)
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

// paintInfoCard is the reference's row of three *separate* cards — IP, country,
// latency — each with a round icon badge (or the flag) on the left and the label
// over the value to its right.
//
// One grid for all three, and it is the badge that is centred on the text block,
// not pinned to the card's top edge: badge 40, then label 20 + 4 + value 34
// (a 58px block) centred in the card. The value sits on the label's left edge,
// which is what makes the row look aligned instead of hand-placed.
func (u *natUI) paintInfoCard(c *walk.Canvas, x, y, w, h float64) {
	const gap = 14.0
	cw := (w - gap*2) / 3
	x1, x2, x3 := x, x+cw+gap, x+2*(cw+gap)

	// Shared vertical grid. The stats are a glance, not a headline: a 30px
	// badge and a 26px value keep the row proportionate to the card, where the
	// old 40/34 pair made three tiles read louder than the connect button.
	const (
		badge  = 30.0
		badgeX = 14.0
		textX  = 54.0
		blockH = 46.0 // label 17 + gap 3 + value 26
		labelH = 17.0
		valueH = 26.0
	)
	labelY := y + (h-blockH)/2
	valueY := labelY + labelH + 3
	badgeY := labelY + (blockH-badge)/2

	// IP: 本机IP while idle (the machine's real LAN address), 出口IP once
	// connected — with a copy affordance beside the value.
	u.cardPlain(c, x1, y, cw, h)
	u.statBadgeAt(c, x1+badgeX, badgeY, badge, "pin")
	ipLabel := tr("本机IP")
	if u.m.connected {
		ipLabel = tr("出口IP")
	}
	u.txt(c, x1+textX, labelY, cw-textX-12, labelH, ipLabel, u.f.f8, th.dim)
	ip := u.displayIP()
	if ip == "" {
		u.txt(c, x1+textX, valueY, cw-textX-12, valueH, "—", u.f.f16b, th.faint)
	} else {
		// The copy affordance follows the value. The gap comes from the canvas's
		// own measurement: the character-width estimate is a few pixels short on
		// digits, and the icon used to sit on the last one.
		u.txt(c, x1+textX, valueY, cw-textX-36, valueH, ip, u.f.f16b, th.text)
		ipW := float64(u.measure(c, ip, u.f.f16b)) / u.k
		cx := x1 + textX + ipW + 7
		if cx > x1+cw-32 {
			cx = x1 + cw - 32
		}
		u.iconButton(c, cx, valueY+3, 20, "copyip", "copy", true)
	}

	// Country / region: the flag and the country name only (the reference
	// stopped at "美国 · 纽约" only because it had a city; the ask here is the
	// country).
	u.cardPlain(c, x2, y, cw, h)
	cc, _ := u.displayGeo()
	if cc == "" && !u.m.connected {
		// Idle: the public-IP probe may not have answered yet, so fall back to
		// the machine's own region instead of showing a globe and a dash.
		cc = osRegionCC()
	}
	if cc == "" {
		u.statBadgeAt(c, x2+badgeX, badgeY, badge, "globe")
	} else {
		// Flag 40x27 sits in the same box as the badge, so the three cards'
		// left edges line up whatever the leading element is.
		fh := badge * 0.675
		u.flagChip(c, x2+badgeX, badgeY+(badge-fh)/2, badge, fh, cc)
	}
	u.txt(c, x2+textX, labelY, cw-textX-12, labelH, tr("国家/地区"), u.f.f8, th.dim)
	if cc == "" {
		u.txt(c, x2+textX, valueY, cw-textX-12, valueH, "—", u.f.f16b, th.faint)
	} else {
		u.txt(c, x2+textX, valueY, cw-textX-12, valueH, regionLabel(cc), u.f.f16b, th.text)
	}

	// Latency: nothing at all while idle (there is no tunnel to measure), the
	// number and its unit once connected, a placeholder until the first sample.
	u.cardPlain(c, x3, y, cw, h)
	u.statBadgeAt(c, x3+badgeX, badgeY, badge, "clock")
	u.txt(c, x3+textX, labelY, cw-textX-12, labelH, tr("延迟"), u.f.f8, th.dim)
	ms := u.m.latency
	switch {
	case u.m.connected && ms > 0:
		num := itoa(ms)
		u.txt(c, x3+textX, valueY, 100, valueH, num, u.f.f16b, th.text)
		// The unit shares the number's baseline instead of floating mid-height.
		u.txt(c, x3+textX+u.textW(num, 13)+6, valueY+valueH-20, 36, 20, "ms", u.f.f8, th.dim)
	case u.m.connected:
		u.txt(c, x3+textX, valueY+4, cw-textX-12, 24, tr("检测中…"), u.f.f15, th.faint)
	}
}

// statBadgeAt is the round tinted icon at the head of a card column; size is
// the diameter, so the three cards can share one metric.
func (u *natUI) statBadgeAt(c *walk.Canvas, x, y, size float64, kind string) {
	u.circleFill(c, mix(th.accentSoft, th.accent, 0.14), x+size/2, y+size/2, size/2)
	u.icon(c, kind, x+size*0.28, y+size*0.28, size*0.44, th.accent)
}

// ---------------------------------------------------------------------------
// Rates card: upload / download with curves
// ---------------------------------------------------------------------------

func (u *natUI) paintRatesCard(c *walk.Canvas, x, y, w, h float64) {
	u.cardPlain(c, x, y, w, h)
	half := w / 2
	u.fillRect(c, mix(th.card, th.line, 0.6), u.r(x+half, y+20, 1, h-40))

	u.paintRateCol(c, x+homeCardPad, y, half-homeCardPad*2, "up", tr("上传"),
		u.m.upRates, th.accent, th.accentSoft)
	u.paintRateCol(c, x+half+homeCardPad, y, half-homeCardPad*2, "down", tr("下载"),
		u.m.downRates, th.ok, th.okSoft)
}

func (u *natUI) paintRateCol(c *walk.Canvas, x, y, w float64, kind, label string, rates []int64, line, badgeBg walk.Color) {
	// Round badge behind the arrow, like the mock.
	u.circleFill(c, badgeBg, x+18, y+29, 17)
	u.icon(c, kind, x+9, y+20, 18, line)
	u.txt(c, x+46, y+13, 140, 18, label, u.f.f9, th.dim)
	// Before the first sample the value is a placeholder, not a zero: "0 B/s"
	// would read as a connected-but-idle tunnel.
	num, unit := splitRate(rateText(rates))
	nc := th.text
	if len(rates) == 0 {
		nc = th.faint
	}
	u.txt(c, x+46, y+32, 200, 36, num, u.f.f16b, nc)
	if unit != "" {
		// The unit is a size smaller, as in the mock: "12.4" then "KB/s".
		u.txt(c, x+46+u.textW(num, 13)+6, y+44, 90, 22, unit, u.f.f8, th.dim)
	}

	// Curve area: a real series is smoothed and shaded; with no samples it
	// still carries a baseline and a state word, so the card never collapses
	// into a blank block.
	cy := y + 84
	ch := 42.0
	cw := w - 8
	if len(rates) > 1 {
		var peak int64
		for _, v := range rates {
			if v > peak {
				peak = v
			}
		}
		pts := u.curveSamples(x+2, cy, cw, ch, rates, peak, 5)
		base := cy + ch
		u.curveFill(c, pts, base, mix(th.card, line, 0.16), cw/float64(len(rates)*5)+0.8)
		u.polylineW(c, line, pts, 2.2)
	} else {
		u.fillRect(c, mix(th.card, th.line, 0.5), u.r(x+2, cy+ch-1, cw, 1))
		// Inside the plot area, not on its bottom edge: at the old offset the
		// hint sat against the card's border and read as clipped text.
		u.textR(c, tr("等待数据"), u.f.f8, th.faint, u.r(x+2, cy+1, cw, 18))
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
	case "proto":
		cx := u.homeCX()
		u.paintProtoPopup(c, cx-homeProtoW/2, homeProtoY, homeProtoW, homeProtoH)
	}
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
	return shellContentX + u.contentW() - 16 - 228, cardY + 40 + rowOff, 228, 30
}

// regionAnchor is the Psiphon egress dropdown in the DNS/exit card.
func (u *natUI) regionAnchor() (x, y, w, h float64) {
	_, _, _, exit := u.settingsTops()
	return u.settingsFieldAnchor(exit, 186)
}

// openvpnRegionAnchor is the VPN Gate egress dropdown, one exit-toggle below
// the Psiphon one in the same card.
func (u *natUI) openvpnRegionAnchor() (x, y, w, h float64) {
	_, _, _, exit := u.settingsTops()
	return u.settingsFieldAnchor(exit, 262)
}

// familyAnchor is the address-family box in the connection card.
func (u *natUI) familyAnchor() (x, y, w, h float64) {
	conn, _, _, _ := u.settingsTops()
	return u.settingsFieldAnchor(conn, 156)
}

// presetAnchor is the routing-preset dropdown in the split-rules card.
func (u *natUI) presetAnchor() (x, y, w, h float64) {
	_, routing, _, _ := u.settingsTops()
	return u.settingsFieldAnchor(routing, 4)
}

func (u *natUI) paintRegionPopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const (
		rowH = 34.0
		pad  = 6.0
		pw   = 300.0
	)
	items := 1 + len(psiphonRegions) // automatic + countries
	ph := pad*2 + float64(items)*rowH
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

	cur := u.m.set.PsiphonRegion
	ry := py + pad
	u.regionPopupRow(c, px, ry, pw, rowH, "", cur == "")
	ry += rowH
	for _, r := range psiphonRegions {
		u.regionPopupRow(c, px, ry, pw, rowH, r.cc, cur == r.cc)
		ry += rowH
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
			out = append(out, n)
		}
	}
	sortVPNGateNodesByLatency(out)
	return out
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

func vpnNodeLatencyLabel(n vpnGateNode) string {
	if n.LatencyMS > 0 {
		return trf("%dms", n.LatencyMS)
	}
	if n.PingMS > 0 {
		return trf("自报 %dms", n.PingMS)
	}
	return tr("未测")
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
		rowH    = 34.0
		pad     = 6.0
		pw      = 348.0
		headerH = 36.0
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
	ph := pad*2 + headerH + float64(bodyRows)*rowH
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
	if empty {
		note := u.m.vpnPoolNote
		if note == "" {
			note = tr("暂无 VPN Gate 节点，点右上角刷新获取")
		}
		col := th.faint
		if !u.m.vpnPoolBusy {
			col = th.accent
		}
		u.txt(c, px+16, py+pad+headerH+(rowH-20)/2, pw-32, 20, note, u.f.f9, col)
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
	top := py + pad + headerH
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
				trf("↳ 自动选 %s 里的节点", vpnCountryName(row.country)),
				vpnCountrySub(row.country), cur == row.cc && pin == "")
		case vpnRowNode:
			u.vpnNodePopupRow(c, px, ry, pw, rowH, row.node, pin != "" && pin == row.node.id())
		}
	}
}

// vpnPickerHeader is the dialog title row from the phone client: a fixed
// "出口地区" label and an always-visible refresh button. It is painted before
// any list because the one action a blocked network needs must never scroll
// away or vanish with the empty state.
func (u *natUI) vpnPickerHeader(c *walk.Canvas, x, y, w, h float64) {
	u.txt(c, x+16, y+(h-20)/2, w-140, 20, tr("出口地区"), u.f.f10b, th.text)
	bw, bh := 76.0, 26.0
	bx := x + w - 16 - bw
	by := y + (h-bh)/2
	br := u.r(bx, by, bw, bh)
	label := tr("刷新")
	col := th.accent
	bg := th.accentSoft
	if u.m.vpnPoolBusy {
		label = tr("刷新中…")
		col = th.faint
		bg = th.chip
	}
	u.fillRound(c, bg, br, ctrlRadius)
	u.textC(c, label, u.f.f9, col, br)
	if !u.m.vpnPoolBusy {
		u.addSpot("vpnrefresh", br, true)
	}
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
	u.textR(c, vpnNodeLatencyLabel(n), u.f.f8, th.faint, u.r(x+w-150, y+(h-18)/2, 96, 18))
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

var psiphonRegions = []regionOption{
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

// displayRegions covers codes shown on the home geo tile that are not
// selectable Psiphon egress options (the exit table must not offer the local
// country, but the tile still has to name it).
var displayRegions = map[string]regionOption{
	"CN": {"CN", "中国", "China"},
}

func regionOptionByCC(cc string) (regionOption, bool) {
	for _, r := range psiphonRegions {
		if r.cc == cc {
			return r, true
		}
	}
	if r, ok := displayRegions[cc]; ok {
		return r, true
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

// rateText shows a dash before the first sample arrives: "0 B/s" would read
// as a connected-but-idle tunnel on a disconnected home screen.
func rateText(v []int64) string {
	if len(v) == 0 {
		return "—"
	}
	return speedText(lastOf(v))
}

// splitRate separates "12.4 KB/s" into the number and its unit, so the card can
// draw the number large and the unit a size smaller (the mock's treatment).
func splitRate(s string) (string, string) {
	if i := strings.LastIndexByte(s, ' '); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}
