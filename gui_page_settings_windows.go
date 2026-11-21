//go:build windows

package main

import (
	"strings"

	"github.com/lxn/walk"

	"github.com/xhwarp/warp-client/internal/core"
)

// Settings is one vertical column of three cards: connection/capture, routing,
// and exit/startup. The knobs that used to fill a fourth "behaviour" card are
// internalized (forced defaults in normalize), so the page stays short enough
// to read at a glance. The column still scrolls on a short window; the header
// stays put and the content is clipped to the body rectangle.
const (
	setCardGap  = 14.0
	setConnBase = 252.0 // LAN sharing off: no credential rows at all
	setConnLan  = 376.0 // sharing on: + two credential rows and the hint line
	setRoutingH = 300.0
	setExitH    = 392.0
)

// setConnHeight follows the sharing switch. The credential rows do not exist
// while sharing is off — a username/password field for a listener that is not
// open is noise, and showing them made the page look like it had leaked them.
func (u *natUI) setConnHeight() float64 {
	if u.m.set.AllowLan {
		return setConnLan
	}
	return setConnBase
}

func (u *natUI) settingsContentH() float64 {
	return u.setConnHeight() + setCardGap + setRoutingH + setCardGap + setExitH
}

// settingsTops returns the top of each card in design coordinates for the
// current scroll offset: connection, routing, exit/startup.
func (u *natUI) settingsTops() (conn, routing, exit float64) {
	conn = shellBodyY - float64(u.m.setScroll)
	routing = conn + u.setConnHeight() + setCardGap
	exit = routing + setRoutingH + setCardGap
	return conn, routing, exit
}

// clampSetScroll keeps the scroll offset inside the content and records the
// maximum so the wheel and the scrollbar agree on the same range.
func (u *natUI) clampSetScroll() {
	max := int(u.settingsContentH() - shellBodyH + 0.5)
	if max < 0 {
		max = 0
	}
	u.m.setScrollMax = max
	if u.m.setScroll > max {
		u.m.setScroll = max
	}
	if u.m.setScroll < 0 {
		u.m.setScroll = 0
	}
}

func (u *natUI) paintSettings(c *walk.Canvas) {
	u.clampSetScroll()
	x, w := u.contentX(), u.contentW()
	clip := u.r(u.contentX(), shellBodyY, u.contentW(), shellBodyH)
	start := len(u.sp)
	u.clipCanvas(c, clip, func() {
		conn, routing, exit := u.settingsTops()
		u.paintSetConnection(c, x, conn, w)
		u.paintSetRouting(c, x, routing, w)
		u.paintSetExit(c, x, exit, w)
	})
	u.clipSpots(start, clip)
	u.paintSetScrollbar(c)
}

// scrollbarGeom returns the settings scrollbar in design units: the track's
// top and height, the thumb's top and height. Paint and hit-testing both read
// it, so the handle can never drift away from where it is drawn.
func (u *natUI) scrollbarGeom() (trackTop, trackH, thumbTop, thumbH float64) {
	trackTop = shellBodyY + 2
	trackH = shellBodyH - 4
	if u.m.setScrollMax <= 0 {
		return trackTop, trackH, 0, 0
	}
	total := shellBodyH + float64(u.m.setScrollMax)
	thumbH = trackH * shellBodyH / total
	if thumbH < 42 {
		thumbH = 42
	}
	off := float64(u.m.setScroll) / float64(u.m.setScrollMax)
	thumbTop = trackTop + off*(trackH-thumbH)
	return
}

// beginScrollDrag starts a drag on the settings scrollbar. Pressing the handle
// keeps the pointer's offset inside it; pressing the track jumps the handle
// there first, so a click means "go to this position" and a drag carries on
// from that point.
func (u *natUI) beginScrollDrag(py int) {
	if u.m.setScrollMax <= 0 {
		return
	}
	_, _, thumbTop, thumbH := u.scrollbarGeom()
	y := u.uy(py) - capH
	if y >= thumbTop && y <= thumbTop+thumbH {
		u.scrollGrabDY = y - thumbTop
	} else {
		u.scrollGrabDY = thumbH / 2
	}
	u.scrollDrag = true
	u.dragScrollTo(py)
}

// dragScrollTo maps the pointer's position on the track onto the scroll offset.
func (u *natUI) dragScrollTo(py int) {
	if u.m.setScrollMax <= 0 {
		return
	}
	trackTop, trackH, _, thumbH := u.scrollbarGeom()
	y := u.uy(py) - capH
	top := y - u.scrollGrabDY
	if top < trackTop {
		top = trackTop
	}
	if maxTop := trackTop + trackH - thumbH; top > maxTop {
		top = maxTop
	}
	span := trackH - thumbH
	if span <= 0 {
		u.m.setScroll = 0
	} else {
		u.m.setScroll = int((top - trackTop) / span * float64(u.m.setScrollMax))
	}
	u.clampSetScroll()
	u.invalidate()
}

// paintSetScrollbar is the slim indicator on the outer margin. It only appears
// when the column actually overflows, so the page does not look scrollable on a
// tall window.
func (u *natUI) paintSetScrollbar(c *walk.Canvas) {
	if u.m.setScrollMax <= 0 {
		return
	}
	trackX := u.dw - 12
	top, h, thumbY, thumbH := u.scrollbarGeom()
	u.fillRound(c, mix(th.line, th.card, 0.45), u.r(trackX, top, 4, h), 2)
	u.fillRound(c, mix(th.accent, th.card, 0.28), u.r(trackX, thumbY, 4, thumbH), 2)
	// A 4px bar is impossible to grab, so the clickable area is 18px wide and
	// spans the whole track: click to jump, drag the handle to follow.
	u.addSpot("set:scrollbar", u.r(trackX-7, top, 18, h), true)
}

// maskPassword renders a stored password as dots in the settings list. The edit
// dialog still shows the real value, so the user can change it; only the row
// label is masked.
func maskPassword(p string) string {
	if p == "" {
		return ""
	}
	n := len([]rune(p))
	if n > 24 {
		n = 24
	}
	return strings.Repeat("•", n)
}

// lanAuthHint says what the credential pair will do right now, including the
// half-filled case that would otherwise look configured but authenticate
// nothing.
func lanAuthHint(s clientSettings) string {
	if !s.AllowLan {
		return tr("开启局域网共享后可设置")
	}
	switch {
	case s.LanUser == "" && s.LanPass == "":
		return tr("留空表示不验证，局域网内任何人都能用")
	case s.LanUser == "" || s.LanPass == "":
		return tr("用户名和密码需同时填写才生效")
	default:
		return trf("已启用：其它设备需输入用户名 %s 与密码", s.LanUser)
	}
}

// paintSetConnection holds the way the host is captured (a dropdown now, not
// chips), the mixed port, LAN sharing and the tunnel family. Everything else
// the old card carried (API port, MTU, timeout, DNS leak protection) is
// internalized in normalize and no longer drawn at all.
func (u *natUI) paintSetConnection(c *walk.Canvas, x, y, w float64) {
	cy := u.card(c, x, y, w, u.setConnHeight(), tr("连接与接管"))
	s := u.m.set
	u.captureRow(c, x, cy, w)
	u.rowEdit(c, x, cy+52, w, "set:mixedport", tr("本地代理端口"),
		itoa(int64(s.MixedPort)), itoa(int64(core.DefaultMixedPort)))
	// One real capability, one switch: allow-lan widens the listener to "*" so
	// other devices can use this machine's IP:port. "LAN sharing" is the same
	// thing, so the label names both rather than faking a second toggle.
	// Spell out the exact address other devices must use. "127.0.0.1:7890" is
	// the single most common way this feature looks broken: on a phone that
	// loopback is the phone itself, and 7890 is another client's default port.
	lanAddr := "本机IP"
	if ip := u.m.localLan; ip != "" {
		lanAddr = ip
	}
	u.rowToggle(c, x, cy+104, w, "set:allowlan", tr("允许局域网访问（局域网共享）"),
		trf("其它设备填 %s:%d（HTTP 与 SOCKS5 同端口）", lanAddr, s.MixedPort), s.AllowLan, true)
	// Optional HTTP/SOCKS credentials, drawn only while sharing is on. Both
	// empty is the default and means the listener stays open to the LAN;
	// filling both makes mihomo demand them. Hiding the rows when sharing is
	// off keeps a password field from sitting on a page where it does nothing.
	if s.AllowLan {
		u.rowEdit(c, x, cy+156, w, "set:lanuser", tr("共享认证用户名"),
			s.LanUser, tr("留空表示不验证"))
		u.rowEdit(c, x, cy+208, w, "set:lanpass", tr("共享认证密码"),
			maskPassword(s.LanPass), tr("留空表示不验证"))
		// One line that states the effective state, so "filled in one box" is
		// not silently indistinguishable from "protected".
		hintCol := th.dim
		if (s.LanUser == "") != (s.LanPass == "") {
			hintCol = th.warn
		}
		u.txt(c, x+16, cy+246, w-32, 16, lanAuthHint(s), u.f.f8, hintCol)
		u.familyRow(c, x, cy+276, w)
		return
	}
	u.familyRow(c, x, cy+158, w)
}

// captureRow is the capture-mode dropdown: system proxy or TUN device.
func (u *natUI) captureRow(c *walk.Canvas, x, y, w float64) {
	u.txt(c, x+16, y+8, w-270, 20, tr("连接方式"), u.f.f10, th.text)
	box := u.r(x+w-16-228, y+4, 228, 30)
	u.fillRound(c, th.input, box, ctrlRadius)
	if u.m.hover == "drop:capture" {
		u.strokeRound(c, th.accentLine, box, ctrlRadius)
	}
	u.textL(c, captureLabel(u.m.set.CaptureMode), u.f.f10, th.text, u.r(x+w-16-228+10, y+4, 192, 30))
	u.icon(c, "chevron", x+w-16-22, y+4+9, 12, th.faint)
	u.addSpot("drop:capture", box, true)
}

func captureLabel(m string) string {
	if m == captureTun {
		return tr("TUN 虚拟网卡")
	}
	return tr("系统代理")
}

// paintCapturePopup lists the two capture modes with what each one actually
// covers, because "which programs does this catch" is the question the choice
// really answers.
func (u *natUI) paintCapturePopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const (
		rowH = 48.0
		pad  = 6.0
	)
	items := []struct{ mode, label, hint string }{
		{captureProxy, tr("系统代理"), tr("仅接管使用系统代理的程序")},
		{captureTun, tr("TUN 虚拟网卡"), tr("全机接管 · 需管理员权限")},
	}
	ph := pad*2 + float64(len(items))*rowH
	py := popupBelow(ay, ah, ph)
	box := u.r(ax, py, aw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.card, box, panelRadius)
	u.strokeRound(c, mix(th.card, rx(255, 255, 255), 0.55), box, panelRadius)

	cur := u.m.set.CaptureMode
	for i, it := range items {
		ry := py + pad + float64(i)*rowH
		id := "pickcapture:" + it.mode
		r := u.r(ax+6, ry, aw-12, rowH)
		if u.m.hover == id {
			u.fillRound(c, th.cardHover, r, ctrlRadius)
		}
		col := th.text
		if cur == it.mode {
			col = th.accent
		}
		u.txt(c, ax+16, ry+6, aw-44, 20, it.label, u.f.f10, col)
		u.txt(c, ax+16, ry+26, aw-44, 16, it.hint, u.f.f8, th.faint)
		if cur == it.mode {
			u.statusDot(c, ax+aw-24, ry+rowH/2, 3.5, th.accent)
		}
		u.addSpot(id, r, true)
	}
}

// familyV6OK is the live capability gate for the family selector. Stacked
// exits are v4-only; subscription mode has no WARP tunnel so the imported node
// decides (the selector stays open); otherwise the base protocol's inner MTU
// decides.
func (u *natUI) familyV6OK() bool {
	if u.m.psiphon || u.m.openvpn {
		return false
	}
	if u.m.set.ConnMode == "subscription" {
		return true
	}
	return protoV6Capable(u.m.proto)
}

// familyRow is the address-family dropdown. A configuration that cannot carry
// v6 disables it outright (the renderer would clamp the value anyway), with the
// reason written where the choice would be.
func (u *natUI) familyRow(c *walk.Canvas, x, y, w float64) {
	ok := u.familyV6OK()
	u.txt(c, x+16, y+2, w-270, 18, tr("IPv6 协议"), u.f.f10, th.text)
	sub := ""
	switch {
	case u.m.psiphon || u.m.openvpn:
		sub = tr("叠加出口仅支持 IPv4")
	case !ok:
		sub = tr("当前协议仅支持 IPv4")
	case u.m.set.ConnMode == "subscription":
		sub = tr("订阅节点需自身支持 IPv6")
	}
	if sub != "" {
		u.txt(c, x+16, y+20, w-270, 14, sub, u.f.f8, th.faint)
	}
	u.paintFamilyDropdown(c, x+w-16-228, y+4, 228, 30, ok)
}

func (u *natUI) paintFamilyDropdown(c *walk.Canvas, x, y, w, h float64, enabled bool) {
	box := u.r(x, y, w, h)
	u.fillRound(c, th.input, box, ctrlRadius)
	if u.m.hover == "drop:family" && enabled {
		u.strokeRound(c, th.accentLine, box, ctrlRadius)
	}
	col := th.text
	if !enabled {
		col = th.faint
	}
	u.textL(c, familyLabel(u.m.set.IPFamily), u.f.f10, col, u.r(x+10, y, w-36, h))
	u.icon(c, "chevron", x+w-22, y+h/2-6, 12, th.faint)
	u.addSpot("drop:family", box, enabled)
}

// familyLabel is the user-facing name of a tunnel family.
func familyLabel(f string) string {
	switch f {
	case famV6:
		return tr("仅 IPv6")
	case famBoth:
		return tr("IPv4 + IPv6（双栈）")
	default:
		return tr("仅 IPv4")
	}
}

// paintFamilyPopup lists the three families. The v6 rows are inert for a
// protocol whose inner MTU cannot carry v6.
func (u *natUI) paintFamilyPopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const (
		rowH = 36.0
		pad  = 6.0
	)
	items := []string{famV4, famV6, famBoth}
	ph := pad*2 + float64(len(items))*rowH
	py := popupBelow(ay, ah, ph)
	box := u.r(ax, py, aw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.card, box, panelRadius)
	u.strokeRound(c, mix(th.card, rx(255, 255, 255), 0.55), box, panelRadius)

	cur := u.m.set.IPFamily
	v6ok := u.familyV6OK()
	noV6 := tr("协议不支持")
	if u.m.psiphon || u.m.openvpn {
		noV6 = tr("出口仅 IPv4")
	}
	for i, f := range items {
		ry := py + pad + float64(i)*rowH
		id := "pickfamily:" + f
		r := u.r(ax+6, ry, aw-12, rowH)
		enabled := f == famV4 || v6ok
		if u.m.hover == id && enabled {
			u.fillRound(c, th.cardHover, r, ctrlRadius)
		}
		col := th.text
		if cur == f {
			col = th.accent
		} else if !enabled {
			col = th.faint
		}
		tw := aw - 40
		if !enabled {
			tw = aw - 130
		}
		u.txt(c, ax+16, ry+8, tw, 20, familyLabel(f), u.f.f10, col)
		if !enabled {
			u.txt(c, ax+aw-110, ry+10, 94, 18, noV6, u.f.f8, th.faint)
		} else if cur == f {
			u.statusDot(c, ax+aw-24, ry+rowH/2, 3.5, th.accent)
		}
		u.addSpot(id, r, enabled)
	}
}

// paintSetRouting gathers the routing preset, the default node and the domain
// lists. Presets replace the old global/rule/direct chips; the lists stay
// editable so a preset can still be tuned by hand.
func (u *natUI) paintSetRouting(c *walk.Canvas, x, y, w float64) {
	cy := u.card(c, x, y, w, setRoutingH, tr("分流规则"))
	s := u.m.set
	u.presetRow(c, x, cy, w)

	// The WARP endpoint pin means nothing in subscription mode — the front node
	// is picked on the mode page — so the field is inert there instead of
	// letting a dialog edit a value the session will never read.
	subMode := s.ConnMode == "subscription"
	nodeVal, nodePh := orEmpty(u.m.pin, u.m.status.Endpoint), tr("自动（延迟最低）")
	if subMode {
		nodeVal, nodePh = "", tr("订阅模式：前置节点在模式页选择")
	}
	u.rowEditState(c, x, cy+52, w, "set:picknode", tr("默认节点"), nodeVal, nodePh, !subMode)

	listsOn := s.ProxyMode != modeGlobal && s.ProxyMode != modeDirect
	u.rowEditState(c, x, cy+104, w, "set:domdirect", tr("直连域名"),
		s.DomainDirect, tr("域名后缀，如 example.com"), listsOn && s.ProxyMode != modeBlacklist)
	u.rowEditState(c, x, cy+156, w, "set:domproxy", tr("代理域名"),
		s.DomainProxy, tr("域名后缀，如 example.com"), listsOn)

	u.txt(c, x+16, cy+204, w-32, 36, presetHint(s.ProxyMode), u.f.f8, th.faint)
}

// presetRow is the routing-preset dropdown, laid out like the other rows.
func (u *natUI) presetRow(c *walk.Canvas, x, y, w float64) {
	u.txt(c, x+16, y+8, w-270, 20, tr("规则预设"), u.f.f10, th.text)
	u.paintPresetDropdown(c, x+w-16-228, y+4, 228, 30)
}

func (u *natUI) paintPresetDropdown(c *walk.Canvas, x, y, w, h float64) {
	box := u.r(x, y, w, h)
	u.fillRound(c, th.input, box, ctrlRadius)
	if u.m.hover == "drop:preset" {
		u.strokeRound(c, th.accentLine, box, ctrlRadius)
	}
	u.textL(c, presetLabel(u.m.set.ProxyMode), u.f.f10, th.text, u.r(x+10, y, w-36, h))
	u.icon(c, "chevron", x+w-22, y+h/2-6, 12, th.faint)
	u.addSpot("drop:preset", box, true)
}

// presetLabel / presetHint are the names and one-line explanations of the five
// routing presets.
func presetLabel(p string) string {
	switch p {
	case modeBypass:
		return tr("绕过大陆")
	case modeBlacklist:
		return tr("黑名单")
	case modeGlobal:
		return tr("全局")
	case modeDirect:
		return tr("直连")
	default:
		return tr("自定义")
	}
}

func presetHint(p string) string {
	switch p {
	case modeBypass:
		if !geoDataReady() {
			return tr("缺少 Geo 数据：点开「规则预设」选「绕过大陆」会自动下载")
		}
		return tr("国内站点与 IP 直连，其余流量走代理")
	case modeBlacklist:
		return tr("仅「代理域名」走代理，其余直连")
	case modeGlobal:
		return tr("所有流量走代理，域名列表不生效")
	case modeDirect:
		return tr("所有流量直连，不使用代理")
	default:
		return tr("代理域名走代理、直连域名绕过，其余走代理")
	}
}

// paintPresetPopup lists the presets. Bypass mainland needs the geo databases;
// when they are missing the row stays clickable and downloads them, because a
// greyed-out row that only says "missing" leaves the user with nothing to do.
func (u *natUI) paintPresetPopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const (
		rowH = 38.0
		pad  = 6.0
	)
	items := []string{modeBypass, modeBlacklist, modeGlobal, modeDirect, modeCustom}
	ph := pad*2 + float64(len(items))*rowH
	py := popupBelow(ay, ah, ph)
	box := u.r(ax, py, aw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.card, box, panelRadius)
	u.strokeRound(c, mix(th.card, rx(255, 255, 255), 0.55), box, panelRadius)

	cur := u.m.set.ProxyMode
	geo := geoDataReady()
	for i, p := range items {
		ry := py + pad + float64(i)*rowH
		id := "pickpreset:" + p
		r := u.r(ax+6, ry, aw-12, rowH)
		needsGeo := p == modeBypass && !geo
		if u.m.hover == id {
			u.fillRound(c, th.cardHover, r, ctrlRadius)
		}
		col := th.text
		if cur == p {
			col = th.accent
		}
		tw := aw - 40
		if needsGeo {
			tw = aw - 160
		}
		u.txt(c, ax+16, ry+9, tw, 20, presetLabel(p), u.f.f10, col)
		if needsGeo {
			u.txt(c, ax+aw-150, ry+11, 134, 18, tr("缺少 Geo · 点击下载"), u.f.f8, th.accent)
		} else if cur == p {
			u.statusDot(c, ax+aw-24, ry+rowH/2, 3.5, th.accent)
		}
		u.addSpot(id, r, true)
	}
}

// paintSetExit is the exit and startup card: the two stacked exits with their
// region pickers, then the two startup behaviours. DNS fields are internalized
// in normalize and not drawn anywhere on the page.
func (u *natUI) paintSetExit(c *walk.Canvas, x, y, w float64) {
	cy := u.card(c, x, y, w, setExitH, tr("出口与启动"))
	s := u.m.set

	v6OK := u.exitV6OK()
	psiOK := u.exitOK() && v6OK
	psiSub := tr("先连基础协议，再叠加 Psiphon 出口")
	if !v6OK {
		psiSub = tr("仅 IPv6 下不可用：Psiphon 服务器经 IPv4 出网")
	} else if !u.exitOK() {
		psiSub = tr("链式协议（双层隧道）下不可叠加 Psiphon")
	}
	u.rowToggle(c, x, cy, w, "psiphon", tr("Psiphon 出口"), psiSub, u.m.psiphon, psiOK)
	u.txt(c, x+16, cy+56, 120, 20, tr("出口地区"), u.f.f10, th.text)
	ax, ay, aw, ah := u.regionAnchor()
	u.paintRegionDropdownSmall(c, ax, ay, aw, ah, psiOK && u.m.psiphon)

	// V2: the same two-axis shape, but the exit is a VPN Gate relay rendered as
	// mihomo's own openvpn outbound. It is IPv4 end to end, so an IPv6-only
	// tunnel disables it outright.
	ovpnOK := psiOK && u.protoOK(probeOpenVPNProto)
	ovpnSub := tr("经 VPN Gate 公共节点出站（仅 IPv4）")
	if !ovpnOK {
		switch {
		case !v6OK:
			ovpnSub = tr("仅 IPv6 下不可用：VPN Gate 中继只有 IPv4")
		case !u.exitOK():
			ovpnSub = tr("链式协议（双层隧道）下不可叠加 OpenVPN")
		default:
			ovpnSub = tr("当前核心不支持 OpenVPN 出站")
		}
	}
	u.rowToggle(c, x, cy+104, w, "openvpn", tr("OpenVPN 出口"), ovpnSub, u.m.openvpn, ovpnOK)
	u.txt(c, x+16, cy+160, 120, 20, tr("出口地区"), u.f.f10, th.text)
	vx, vy, vw, vh := u.openvpnRegionAnchor()
	u.paintOpenVPNRegionDropdownSmall(c, vx, vy, vw, vh, ovpnOK && u.m.openvpn)

	u.rowToggle(c, x, cy+208, w, "set:autostart", tr("开机自动启动"),
		tr("写入当前用户的启动项"), s.AutoStart, true)
	u.rowToggle(c, x, cy+262, w, "set:autoconnect", tr("启动后自动连接"),
		tr("程序启动即连接上次的协议"), s.AutoConnect, true)

	switch {
	case s.CaptureMode == captureTun && !core.IsElevated():
		u.txt(c, x+16, cy+316, w-32, 18, tr("TUN 需要管理员权限：请以管理员身份重新运行"), u.f.f9, th.warn)
	case u.m.setDirty:
		u.txt(c, x+16, cy+316, w-32, 18, tr("有改动：重新连接后生效"), u.f.f9, th.warn)
	default:
		u.txt(c, x+16, cy+316, w-32, 18, tr("端口、地址族与接管方式在下次连接时生效"), u.f.f8, th.faint)
	}
}

// ---------------------------------------------------------------------------
// About + updates
// ---------------------------------------------------------------------------

// aboutLink is one clickable row of the link card: the label the user reads and
// the address the row opens. Every one of them is a GitHub URL — the About page
// never points at a folder on this disk, because a path is useless to anyone
// reading the page on another machine (or on a screenshot).
type aboutLink struct {
	id, label, url string
}

func aboutLinks() []aboutLink {
	return []aboutLink{
		{"about:project", tr("项目主页"), repoURL},
		{"about:releases", tr("发布页"), repoReleasesURL},
		{"about:issues", tr("问题反馈"), repoIssuesURL},
		{"about:notices", tr("第三方声明"), repoNoticesURL},
		{"about:license", tr("许可全文"), repoLicenseURL},
	}
}

// shortURL is the address without the scheme: the whole string then fits the
// card's value column, and "github.com/…" still reads as a link.
func shortURL(u string) string { return strings.TrimPrefix(u, "https://") }

// The About page is a single-column stack: one card per row, then the link card,
// then a two-line footer. The page does not scroll, so every row is sized from
// these constants and aboutLayout is asserted to end above the body box.
//
// One card per row is what the page needed: at two columns each card was ~420
// wide, which forced the action buttons to share the bottom edge and made four
// blocks of colour compete. Full width lets the fields sit in two columns with
// the actions on the title line.
const (
	aboutCardH    = 86.0  // title line + two field rows
	aboutLinkH    = 166.0 // title line + five link rows
	aboutGap      = 10.0
	aboutFootG    = 8.0
	aboutKVStep   = 22.0
	aboutLinkStep = 24.0
	aboutBtnH     = 26.0
	aboutBtnTop   = 6.0
	aboutBtnPadR  = 14.0
	aboutBtnGap   = 8.0
	aboutFieldCol = 84.0 // label column inside a field pair
	aboutFieldGap = 24.0 // gap between the two field columns
)

// aboutLayout returns the top of each card, of the link card and of the footer,
// in design units, for the body's own top edge.
func aboutLayout(bodyY float64) (card1, card2, card3, card4, links, footer float64) {
	card1 = bodyY
	card2 = card1 + aboutCardH + aboutGap
	card3 = card2 + aboutCardH + aboutGap
	card4 = card3 + aboutCardH + aboutGap
	links = card4 + aboutCardH + aboutGap
	footer = links + aboutLinkH + aboutFootG
	return
}

// aboutAct is one card action. Both treatments are quiet surfaces — a filled
// accent button here read as the only saturated thing on an otherwise pale page.
type aboutAct struct {
	id      string
	label   string
	primary bool
	enabled bool
}

// aboutAction draws one About action as a pale chip with a hairline rim. The
// card's verb keeps the heavier weight and the brighter text colour; its
// companion stays one step quieter. Nothing on this page is filled with the
// accent any more.
func (u *natUI) aboutAction(c *walk.Canvas, x, y, w, h float64, a aboutAct) {
	r := u.r(x, y, w, h)
	bg, fg := th.chip, th.chipText
	font := u.f.f10
	if a.primary {
		fg, font = th.text, u.f.f10b
	}
	if u.m.hover == a.id && a.enabled {
		bg = th.cardHover
	}
	if !a.enabled {
		bg, fg = mix(bg, th.card, 0.55), th.faint
	}
	u.fillRound(c, bg, r, ctrlRadius)
	u.strokeRound(c, th.line, r, ctrlRadius)
	u.textC(c, a.label, font, fg, r)
	if a.enabled {
		u.addSpot(a.id, r, true)
	}
}

// aboutActions pins the card's actions to the right of its title line. The slice
// is ordered [companion, verb] so the heavier verb ends up rightmost.
func (u *natUI) aboutActions(c *walk.Canvas, cardX, cardY, cardW float64, acts ...aboutAct) {
	by := cardY + aboutBtnTop
	bx := cardX + cardW - aboutBtnPadR
	for i := len(acts) - 1; i >= 0; i-- {
		a := acts[i]
		bw := float64(u.measure(c, a.label, u.f.f10b))/u.k + 24
		if bw < 80 {
			bw = 80
		}
		bx -= bw
		u.aboutAction(c, bx, by, bw, aboutBtnH, a)
		bx -= aboutBtnGap
	}
}

// aboutStrip is one full-width card: title on the left, its actions on the same
// line to the right, and the fields in two columns beneath.
func (u *natUI) aboutStrip(c *walk.Canvas, x, y, w float64, title string, fields [][2]string, acts ...aboutAct) {
	u.cardPlain(c, x, y, w, aboutCardH)
	u.txt(c, x+16, y+8, 200, 22, title, u.f.f11b, th.text)
	u.aboutActions(c, x, y, w, acts...)
	colW := (w - 32 - aboutFieldGap) / 2
	for i, f := range fields {
		col, row := i%2, i/2
		fx := x + 16 + float64(col)*(colW+aboutFieldGap)
		fy := y + 34 + float64(row)*aboutKVStep
		u.txt(c, fx, fy, aboutFieldCol, 20, f[0], u.f.f9, th.dim)
		u.txt(c, fx+aboutFieldCol, fy, colW-aboutFieldCol, 20, f[1], u.f.f9, th.text)
	}
}

func (u *natUI) paintAbout(c *walk.Canvas, x, y, w float64) {
	card1, card2, card3, card4, links, footer := aboutLayout(y)

	u.aboutStrip(c, x, card1, w, tr("本程序"), [][2]string{
		{tr("名称"), productName},
		{tr("版本"), shortVersion()},
		{tr("构建"), guiBuildKind()},
		{tr("核心版本"), orEmpty(u.m.coreVersion, tr("未探测"))},
	},
		aboutAct{"about:copydiag", tr("复制诊断信息"), false, true},
		aboutAct{"about:project", tr("打开项目主页"), true, true},
	)

	u.aboutStrip(c, x, card2, w, tr("开源与许可"), [][2]string{
		{tr("内核"), "mihomo " + orEmpty(u.m.coreVersion, tr("未探测")) + " · " + coreSizeText(u.m.coreSize)},
		{tr("内核许可"), "GPL-3.0"},
		{tr("协议引擎"), "WireGuard / AmneziaWG / MASQUE"},
		{tr("内核来源"), shortURL(coreRepoURL + "/releases")},
	},
		aboutAct{"upd:refresh", tr("重新探测内核"), false, !u.m.coreBusy},
		aboutAct{"upd:core", tr("检查/下载内核"), true, !u.m.coreBusy},
	)

	updID, updLabel := "upd:check", tr("检查更新")
	if u.m.updAvail != "" {
		updID, updLabel = "upd:install", trf("立即更新到 v%s", u.m.updAvail)
	}
	u.aboutStrip(c, x, card3, w, tr("客户端更新"), [][2]string{
		{tr("当前版本"), versionWithBuild()},
		{tr("最新版本"), orEmpty(u.m.updLatest, tr("尚未检查"))},
		{tr("状态"), orEmpty(u.m.updNote, tr("点击右侧按钮检查更新"))},
	},
		aboutAct{"about:releases", tr("打开发布页"), false, true},
		aboutAct{updID, updLabel, true, !u.m.updBusy},
	)

	stText, stColor := u.controlStatus()
	u.aboutStrip(c, x, card4, w, tr("远程控制"), [][2]string{
		{tr("控制码"), orEmpty(u.m.set.ControlCode, tr("未知"))},
		{tr("最近检查"), controlCheckedText(u.m.control)},
	},
		aboutAct{"about:copycode", tr("复制控制码"), false, true},
		aboutAct{"about:checkcontrol", tr("立即检查"), true, !u.m.controlBusy},
	)
	// The verdict has its own colour (green / amber / red), so it is painted by
	// hand into the second field row's left cell instead of going through the
	// neutral strip text.
	colW := (w - 32 - aboutFieldGap) / 2
	stY := card4 + 34 + aboutKVStep
	u.txt(c, x+16, stY, aboutFieldCol, 20, tr("状态"), u.f.f9, th.dim)
	u.txt(c, x+16+aboutFieldCol, stY, colW-aboutFieldCol, 20, stText, u.f.f9, stColor)

	// The link card: one address per row, full width, the whole row clickable.
	u.cardPlain(c, x, links, w, aboutLinkH)
	u.txt(c, x+16, links+8, 200, 22, tr("项目链接"), u.f.f11b, th.text)
	for i, ln := range aboutLinks() {
		ly := links + 34 + float64(i)*aboutLinkStep
		r := u.r(x+10, ly-1, w-20, aboutLinkStep-2)
		if u.m.hover == ln.id {
			// Neutral highlight: the address text is already off-accent, and a
			// blue wash under it would put the colour back.
			u.fillRound(c, th.cardHover, r, 7)
			u.strokeRound(c, th.line2, r, 7)
		}
		u.txt(c, x+20, ly+2, 96, 20, ln.label, u.f.f10, th.text)
		u.txt(c, x+120, ly+3, w-140, 18, shortURL(ln.url), u.f.f8, th.dim)
		u.addSpot(ln.id, r, true)
	}

	// Footer: the same sentence the startup notice opens with, kept on the page
	// so it is still there after the notice has been dismissed.
	yf := footer
	u.hline(c, x, yf-7, w, th.line2)
	u.txt(c, x+2, yf, w-4, 18, tr("本软件开源免费，仅供学习交流使用，禁止售卖！"), u.f.f10, th.text)
	u.txt(c, x+2, yf+20, w-4, 18,
		tr("本程序只在你自己的设备上配置一条加密隧道，不提供、不代理任何服务器资源；程序按「现状」提供，不对可用性、速度或适用性作任何承诺。"),
		u.f.f8, th.dim)
}

// controlStatus is the About card's verdict line: stopped outranks everything,
// then "checked and fine", then "never reached the list".
func (u *natUI) controlStatus() (string, walk.Color) {
	switch {
	case u.m.control.Stopped:
		return tr("已停用"), th.warn
	case u.m.control.Reached:
		return tr("正常"), th.ok
	default:
		return tr("未检查"), th.dim
	}
}

// controlCheckedText renders the last check as a compact timestamp, and says so
// when that check never got an answer.
func controlCheckedText(st controlState) string {
	if st.CheckedAt.IsZero() {
		return tr("尚未检查")
	}
	s := st.CheckedAt.Format("01-02 15:04")
	if !st.Reached {
		s += " · " + tr("未连上")
	}
	return s
}
