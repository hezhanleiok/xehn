//go:build windows

package main

import (
	"strings"

	"github.com/lxn/walk"

	"github.com/xhwarp/warp-client/internal/core"
)

// Settings is one vertical column of cards: capture, routing, behaviour, and
// DNS/exit. The column is taller than the window body, so the page scrolls;
// the header stays put and the content is clipped to the body rectangle.
const (
	setCardGap    = 14.0
	setConnH      = 316.0
	setRoutingH   = 244.0
	setBehaviourH = 236.0
	setExitH      = 376.0
)

func (u *natUI) settingsContentH() float64 {
	return setConnH + setCardGap + setRoutingH + setCardGap + setBehaviourH + setCardGap + setExitH
}

// settingsTops returns the top of each card in design coordinates for the
// current scroll offset: connection, routing, behaviour, DNS/exit.
func (u *natUI) settingsTops() (conn, routing, behaviour, exit float64) {
	conn = shellBodyY - float64(u.m.setScroll)
	routing = conn + setConnH + setCardGap
	behaviour = routing + setRoutingH + setCardGap
	exit = behaviour + setBehaviourH + setCardGap
	return conn, routing, behaviour, exit
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
	x, w := shellContentX, u.contentW()
	clip := u.r(shellContentX, shellBodyY, u.contentW(), shellBodyH)
	start := len(u.sp)
	u.clipCanvas(c, clip, func() {
		conn, routing, behaviour, exit := u.settingsTops()
		u.paintSetConnection(c, x, conn, w)
		u.paintSetRouting(c, x, routing, w)
		u.paintSetBehaviour(c, x, behaviour, w)
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

// paintSetConnection holds the local proxy and the way the host is captured:
// the mixed port, LAN access, the API port, the tunnel's address family, MTU,
// and the two persistence actions.
func (u *natUI) paintSetConnection(c *walk.Canvas, x, y, w float64) {
	cy := u.card(c, x, y, w, setConnH, tr("连接与接管"))
	s := u.m.set
	u.rowChips(c, x, cy, w, "set:capture:", tr("接管方式"),
		[]string{captureProxy, captureTun},
		[]string{tr("系统代理"), tr("VPN / TUN")}, s.CaptureMode)
	u.rowEdit(c, x, cy+38, w, "set:mixedport", tr("本地代理端口"),
		itoa(int64(s.MixedPort)), itoa(int64(core.DefaultMixedPort)))
	u.rowToggle(c, x, cy+76, w, "set:allowlan", tr("允许局域网访问"),
		tr("局域网内其它设备可通过本机 IP:端口 使用代理"), s.AllowLan, true)
	u.rowEdit(c, x, cy+114, w, "set:apiport", tr("API 端口"),
		itoa(int64(s.APIPort)), itoa(int64(core.DefaultAPIPort)))
	u.familyRow(c, x, cy+152, w)
	u.rowEdit(c, x, cy+190, w, "set:mtu", tr("MTU"), itoa(int64(s.MTU)), tr("0 = 自动"))

	const bw = 180.0
	u.button(c, x+16, cy+232, bw, 34, "set:connect", tr("重新连接以应用"), true, u.m.connected)
	u.button(c, x+26+bw, cy+232, bw, 34, "set:reset", tr("恢复默认"), false, true)
}

// familyRow is the address-family dropdown. A protocol that cannot carry v6
// disables it outright (the renderer would clamp the value anyway), with the
// reason written where the choice would be.
func (u *natUI) familyRow(c *walk.Canvas, x, y, w float64) {
	ok := protoV6Capable(u.m.proto)
	u.txt(c, x+16, y+2, w-270, 18, tr("地址族"), u.f.f10, th.text)
	if !ok {
		u.txt(c, x+16, y+20, w-270, 14, tr("当前协议仅支持 IPv4"), u.f.f8, th.faint)
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
	v6ok := protoV6Capable(u.m.proto)
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
			u.txt(c, ax+aw-110, ry+10, 94, 18, tr("协议不支持"), u.f.f8, th.faint)
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

	u.rowEdit(c, x, cy+38, w, "set:picknode", tr("默认节点"),
		orEmpty(u.m.pin, u.m.status.Endpoint), tr("自动（延迟最低）"))

	listsOn := s.ProxyMode != modeGlobal && s.ProxyMode != modeDirect
	u.rowEditState(c, x, cy+76, w, "set:domdirect", tr("直连域名"),
		s.DomainDirect, tr("域名后缀，如 example.com"), listsOn && s.ProxyMode != modeBlacklist)
	u.rowEditState(c, x, cy+114, w, "set:domproxy", tr("代理域名"),
		s.DomainProxy, tr("域名后缀，如 example.com"), listsOn)

	u.txt(c, x+16, cy+154, w-32, 36, presetHint(s.ProxyMode), u.f.f8, th.faint)
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

// paintSetBehaviour is the startup/behaviour card.
func (u *natUI) paintSetBehaviour(c *walk.Canvas, x, y, w float64) {
	cy := u.card(c, x, y, w, setBehaviourH, tr("启动与行为"))
	s := u.m.set
	u.rowToggle(c, x, cy, w, "set:autostart", tr("开机自动启动"),
		tr("写入当前用户的启动项"), s.AutoStart, true)
	u.rowToggle(c, x, cy+38, w, "set:autoconnect", tr("启动后自动连接"),
		tr("程序启动即连接上次的协议"), s.AutoConnect, true)
	u.rowToggle(c, x, cy+76, w, "set:rescan", tr("连接前重新扫描"),
		tr("连接时重新扫描端点，耗时更长但更新"), s.Rescan, true)
	u.rowToggle(c, x, cy+114, w, "set:autorepair", tr("自动修复（健康守护）"),
		tr("会话断开后由后台守护自动重建"), s.AutoRepair, true)
	u.rowEdit(c, x, cy+152, w, "set:timeout", tr("连接超时（秒）"),
		itoa(int64(s.TimeoutSec)), "2")
}

// paintSetExit is the DNS and Psiphon card. Leak protection sits next to the
// resolver fields because it changes how those resolvers are reached.
func (u *natUI) paintSetExit(c *walk.Canvas, x, y, w float64) {
	cy := u.card(c, x, y, w, setExitH, tr("DNS 与出口"))
	s := u.m.set
	u.rowEdit(c, x, cy, w, "set:dns", tr("自定义 DNS"),
		s.DNSCustom, tr("逗号分隔，如 223.5.5.5, 1.1.1.1"))
	u.rowChips(c, x, cy+38, w, "set:dns:", tr("常用"),
		dnsPresetIDs(), dnsPresetLabels(), currentDNSPreset(s.DNSCustom))
	u.rowToggle(c, x, cy+76, w, "set:dnsdi", tr("不下发 DNS"),
		tr("不向隧道提供解析器，全部用系统 DNS"), s.DNSOff, true)

	leakOK := !s.DNSOff && s.ProxyMode != modeDirect
	// The subtitle has to state the coverage, not just the mechanism: in system
	// proxy mode only the programs that use the proxy are covered, and that
	// distinction is what users keep asking about.
	leakSub := tr("系统代理：走代理的程序解析经隧道，不走代理的仍会漏")
	if s.CaptureMode == captureTun {
		leakSub = tr("TUN：全机 53 端口被接管，任何程序都绕不过")
	}
	if s.DNSOff {
		leakSub = tr("不下发 DNS 时使用系统解析，无法防泄露")
	} else if s.ProxyMode == modeDirect {
		leakSub = tr("直连模式不经过代理，无法防泄露")
	}
	u.rowToggle(c, x, cy+114, w, "set:dnsleak", tr("防止 DNS 泄露"),
		leakSub, s.DNSLeak && leakOK, leakOK)

	psiOK := !protoChained(u.m.proto)
	u.rowToggle(c, x, cy+152, w, "psiphon", tr("Psiphon 出口"),
		tr("先连基础协议，再叠加 Psiphon 出口"), u.m.psiphon, psiOK)
	u.txt(c, x+16, cy+192, 120, 20, tr("出口地区"), u.f.f10, th.text)
	ax, ay, aw, ah := u.regionAnchor()
	u.paintRegionDropdownSmall(c, ax, ay, aw, ah, psiOK && u.m.psiphon)

	// V2: the same two-axis shape, but the exit is a VPN Gate relay rendered as
	// mihomo's own openvpn outbound. It is IPv4-only, so the sub line says so
	// instead of letting the family selector quietly disagree.
	ovpnOK := psiOK && u.protoOK(probeOpenVPNProto)
	u.rowToggle(c, x, cy+228, w, "openvpn", tr("OpenVPN 出口"),
		tr("经 VPN Gate 公共节点出站（仅 IPv4）"), u.m.openvpn, ovpnOK)
	u.txt(c, x+16, cy+268, 120, 20, tr("出口地区"), u.f.f10, th.text)
	vx, vy, vw, vh := u.openvpnRegionAnchor()
	u.paintOpenVPNRegionDropdownSmall(c, vx, vy, vw, vh, ovpnOK && u.m.openvpn)

	switch {
	case u.m.set.CaptureMode == captureTun && !core.IsElevated():
		u.txt(c, x+16, cy+300, w-32, 18, tr("TUN 需要管理员权限：请以管理员身份重新运行"), u.f.f9, th.warn)
	case u.m.setDirty:
		u.txt(c, x+16, cy+300, w-32, 18, tr("有改动：重新连接后生效"), u.f.f9, th.warn)
	default:
		u.txt(c, x+16, cy+300, w-32, 18, tr("端口、地址族与接管方式在下次连接时生效"), u.f.f8, th.faint)
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

// The About page is a fixed 3-row grid plus a two-line footer. The heights are
// named (and asserted by aboutLayout) because the page does not scroll: a card
// that grows past the body box is clipped, and clipping a licence line is the
// one thing this page must not do.
const (
	aboutRow1H = 186.0 // 本程序 / 开源与许可
	aboutRow2H = 182.0 // 客户端更新 / 远程控制
	aboutRow3H = 152.0 // 项目链接
	aboutGap   = 14.0
	aboutFootG = 8.0 // gap between the last card and the footer
)

// aboutLayout returns the top of each row and of the footer, in design units,
// for the body's own top edge.
func aboutLayout(bodyY float64) (row1, row2, row3, footer float64) {
	row1 = bodyY
	row2 = row1 + aboutRow1H + aboutGap
	row3 = row2 + aboutRow2H + aboutGap
	footer = row3 + aboutRow3H + aboutFootG
	return
}

func (u *natUI) paintAbout(c *walk.Canvas, x, y, w float64) {
	half := (w - aboutGap) / 2
	rx := x + half + aboutGap
	// Two buttons per card row, 16px of padding on both sides and 10 between:
	// the right button has to clear the card's rim, not sit on it.
	bw := (half - 16 - 16 - 10) / 2
	row1, row2, row3, footer := aboutLayout(y)

	// Row 1 — what this build is, and what it is built from.
	cy := u.card(c, x, row1, half, aboutRow1H, tr("本程序"))
	for _, kv := range [][2]string{
		{tr("名称"), productName},
		{tr("版本"), shortVersion()},
		{tr("构建"), guiBuildKind()},
		{tr("核心版本"), orEmpty(u.m.coreVersion, tr("未探测"))},
	} {
		u.kv(c, x, cy, half, kv[0], kv[1])
		cy += 24
	}
	u.button(c, x+16, row1+146, bw, 34, "about:copydiag", tr("复制诊断信息"), false, true)
	u.button(c, x+16+bw+10, row1+146, bw, 34, "about:project", tr("打开项目主页"), false, true)

	cy = u.card(c, rx, row1, half, aboutRow1H, tr("开源与许可"))
	for _, kv := range [][2]string{
		{tr("内核"), "mihomo " + orEmpty(u.m.coreVersion, tr("未探测")) + " · " + coreSizeText(u.m.coreSize)},
		{tr("内核许可"), "GPL-3.0"},
		{tr("协议引擎"), "WireGuard / AmneziaWG / MASQUE"},
		{tr("内核来源"), shortURL(coreRepoURL + "/releases")},
	} {
		u.kv(c, rx, cy, half, kv[0], kv[1])
		cy += 24
	}
	u.button(c, rx+16, row1+146, bw, 34, "upd:core", tr("检查/下载内核"), true, !u.m.coreBusy)
	u.button(c, rx+16+bw+10, row1+146, bw, 34, "upd:refresh", tr("重新探测内核"), false, !u.m.coreBusy)

	// Row 2 — updates, and the remote-control identity this install carries.
	y2 := row2
	cy = u.card(c, x, y2, half, aboutRow2H, tr("客户端更新"))
	u.kv(c, x, cy, half, tr("当前版本"), versionWithBuild())
	u.kv(c, x, cy+24, half, tr("最新版本"), orEmpty(u.m.updLatest, tr("尚未检查")))
	u.kv(c, x, cy+48, half, tr("状态"), orEmpty(u.m.updNote, tr("点击下方按钮检查更新")))
	updID, updLabel := "upd:check", tr("检查更新")
	if u.m.updAvail != "" {
		updID, updLabel = "upd:install", trf("立即更新到 v%s", u.m.updAvail)
	}
	u.button(c, x+16, y2+140, bw, 34, updID, updLabel, true, !u.m.updBusy)
	u.button(c, x+16+bw+10, y2+140, bw, 34, "about:releases", tr("打开发布页"), false, true)

	cy = u.card(c, rx, y2, half, aboutRow2H, tr("远程控制"))
	u.kv(c, rx, cy, half, tr("控制码"), orEmpty(u.m.set.ControlCode, tr("未知")))
	u.txt(c, rx+16, cy+24, 84, 22, tr("状态"), u.f.f9, th.dim)
	stText, stColor := u.controlStatus()
	u.txt(c, rx+16+84, cy+24, half-32-84, 22, stText, u.f.f9, stColor)
	u.kv(c, rx, cy+48, half, tr("最近检查"), controlCheckedText(u.m.control))
	u.button(c, rx+16, y2+140, bw, 34, "about:copycode", tr("复制控制码"), false, true)
	u.button(c, rx+16+bw+10, y2+140, bw, 34, "about:checkcontrol", tr("立即检查"), true, !u.m.controlBusy)

	// Row 3 — every address the page offers, as one clickable list.
	y3 := row3
	cy = u.card(c, x, y3, w, aboutRow3H, tr("项目链接"))
	for i, ln := range aboutLinks() {
		ly := cy + float64(i)*22
		r := u.r(x+8, ly-2, w-16, 22)
		if u.m.hover == ln.id {
			u.fillRound(c, mix(th.card, th.accentSoft, 0.5), r, 8)
		}
		u.txt(c, x+16, ly, 110, 20, ln.label, u.f.f10, th.text)
		u.txt(c, x+130, ly, w-146, 20, shortURL(ln.url), u.f.f8, th.accent)
		u.addSpot(ln.id, r, true)
	}

	// Footer: the same sentence the startup notice opens with, kept on the page
	// so it is still there after the notice has been dismissed.
	yf := footer
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
