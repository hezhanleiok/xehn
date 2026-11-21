//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lxn/walk"
)

// Mode page, matching the approved two-card + table design. The top row carries
// search / latency-test / add; below it a "connection mode" card (dropdown +
// protocol chips) sits beside a "current node" card; then a filter + sort row;
// then one scrolling table of real measured nodes for whichever mode is active.
// Every number shown is observed on this machine, never a catalogue entry.
func (u *natUI) paintNodes(c *walk.Canvas) {
	x, y := u.contentX(), shellBodyY
	w := u.contentW()
	sub := u.m.set.ConnMode == "subscription"

	u.paintModeTopBar(c, x, w, sub)

	gap := 16.0
	lw := (w - gap) * 0.52
	rw := w - gap - lw
	cardH := u.modeConnCardH(lw, sub)
	u.paintModeConnCard(c, x, y, lw, cardH, sub)
	u.paintModeNodeCard(c, x+lw+gap, y, rw, cardH, sub)

	rowY := y + cardH + 14
	u.paintModeFilterRow(c, x, rowY, w, sub)

	tableY := rowY + 40
	tableH := u.dh - 14 - tableY
	if tableH < 160 {
		tableH = 160
	}
	u.cardPlain(c, x, tableY, w, tableH)
	u.paintModeTable(c, x, tableY, w, tableH, sub)
}

// paintModeTopBar shares the page-head row: search on the left of the group,
// then the latency test, then (subscription only) the blue add button.
func (u *natUI) paintModeTopBar(c *walk.Canvas, x, w float64, sub bool) {
	const h = 34.0
	yy := 20.0
	right := x + w
	const addW, delayW, searchW = 76.0, 92.0, 250.0
	ax := right
	if sub {
		ax = right - addW
		u.button(c, ax, yy, addW, h, "drop:addmenu", tr("+ 添加"), true, true)
	}
	dx := ax - 8 - delayW
	delayID := "rescannow"
	if sub {
		delayID = "subdelay"
	}
	u.button(c, dx, yy, delayW, h, delayID, tr("延迟测试"), false,
		!u.subDelayBusy.Load() && !u.m.working && !u.m.connecting)
	sx := dx - 8 - searchW
	u.inputBox(c, sx, yy, searchW, h, "nodesearch", u.m.nodeSearch, tr("搜索节点 / 国家 / IP"))
	if u.m.nodeSearch != "" {
		u.icon(c, "close", sx+searchW-26, yy+10, 14, th.dim)
		u.addSpot("nodesearch:clear", u.r(sx+searchW-32, yy+4, 26, 26), true)
	} else {
		u.icon(c, "search", sx+searchW-26, yy+9, 16, th.faint)
	}
	// Subscription mode adds the source selector left of the search box; it
	// opens the manager (import / edit / delete / switch).
	if sub {
		u.paintSubPill(c, x, w)
	}
}

// modeProtos is the chip order in the connection-mode card.
var modeProtos = []string{protoWG, protoAWG, protoWWarp, protoMASQUE, protoMASQUEH2, protoMASQUEMASQUE}

func modeProtoChip(p string) string {
	switch p {
	case protoWG:
		return "WireGuard"
	case protoAWG:
		return "AWG"
	case protoWWarp:
		return "GOOL"
	case protoMASQUE:
		return "MASQUE"
	case protoMASQUEH2:
		return "MASQUE-H2"
	case protoMASQUEMASQUE:
		return "MASQUE-MM"
	}
	return strings.ToUpper(p)
}

// modeConnCardH grows with the number of protocol-chip rows so narrow windows
// wrap the chips instead of clipping them.
func (u *natUI) modeConnCardH(w float64, sub bool) float64 {
	if sub {
		return 124
	}
	inner := w - 32
	rows, cx := 1, 0.0
	for _, p := range modeProtos {
		cw := chipWidth(modeProtoChip(p)) + 6
		if cx+cw > inner && cx > 0 {
			rows++
			cx = 0
		}
		cx += cw
	}
	return 124 + float64(rows)*34
}

func (u *natUI) paintModeConnCard(c *walk.Canvas, x, y, w, h float64, sub bool) {
	u.cardPlain(c, x, y, w, h)
	u.txt(c, x+16, y+12, w-32, 16, tr("连接模式"), u.f.f8, th.dim)

	bx, by, bw, bh := x+16, y+34, w-32, 56.0
	box := u.r(bx, by, bw, bh)
	u.fillRound(c, th.input, box, ctrlRadius)
	if u.m.hover == "drop:connmode" {
		u.strokeRound(c, th.accentLine, box, ctrlRadius)
	} else {
		u.strokeRound(c, th.line, box, ctrlRadius)
	}
	is := 34.0
	ix, iy := bx+12, by+(bh-is)/2
	u.fillRound(c, mix(th.accent2, th.card, 0.82), u.r(ix, iy, is, is), 9)
	if sub {
		u.icon(c, "list", ix+is*0.24, iy+is*0.24, is*0.52, th.accent2)
	} else {
		u.icon(c, "globe", ix+is*0.24, iy+is*0.24, is*0.52, th.accent2)
	}
	tx := ix + is + 12
	title, subtitle := tr("WARP 模式"), tr("Cloudflare · WARP / MASQUE 隧道")
	if sub {
		title, subtitle = tr("订阅模式"), tr("Subscription · 前置节点 + 可选出口")
	}
	u.txt(c, tx, by+9, bw-(tx-bx)-40, 20, title, u.f.f10b, th.text)
	u.txt(c, tx, by+30, bw-(tx-bx)-40, 16, subtitle, u.f.f8, th.dim)
	u.icon(c, "chevron", bx+bw-28, by+bh/2-6, 13, th.faint)
	u.addSpot("drop:connmode", box, true)

	desc := tr("直连 Cloudflare WARP 隧道，支持多种隧道协议与端点选择。")
	if sub {
		desc = tr("前置节点来自导入的订阅，可叠加 OpenVPN / Psiphon 出口链。")
	}
	u.txt(c, x+16, by+bh+10, w-32, 16, desc, u.f.f8, th.faint)

	if !sub {
		cx, cy := x+16, y+122
		for _, p := range modeProtos {
			cw := chipWidth(modeProtoChip(p))
			if cx+cw > x+w-16 && cx > x+16 {
				cx = x + 16
				cy += 34
			}
			u.chipAt(c, "proto:"+p, modeProtoChip(p), cx, cy, u.m.proto == p, !u.m.working && !u.m.connecting)
			cx += cw + 6
		}
	}
}

// modeNodeInfo is the identity shown in the current-node card.
type modeNodeInfo struct {
	name, cc, ip, region, host string
	ms                         int
	hasMS                      bool
}

func (u *natUI) modeCurrentNode(sub bool) modeNodeInfo {
	if sub {
		name, cc, ms, has := u.homeActiveProxy()
		info := modeNodeInfo{name: name, cc: cc, ms: ms, hasMS: has}
		if name == "" {
			info.name = tr("未导入节点")
		}
		for _, p := range u.m.set.CustomProxies {
			if p.Name == name {
				if s, ok := p.Fields["server"].(string); ok {
					info.ip = s
				}
				break
			}
		}
		if cc != "" {
			info.region = regionName(cc)
		}
		return info
	}
	if u.m.pin == "" {
		info := modeNodeInfo{name: tr("自动选择（推荐）"), region: "Anycast", host: "engage.cloudflareclient.com"}
		if u.m.connected {
			info.ip = u.displayIP()
			info.ms = int(u.m.latency)
			info.hasMS = u.m.latency > 0
		}
		return info
	}
	for _, ce := range u.m.endpoints {
		if ce.Endpoint == u.m.pin {
			cc := ce.NodeISO
			if cc == "" {
				cc = ce.Country
			}
			name := ce.Endpoint
			if ce.NodeCity != "" {
				name = ce.NodeCity + " · " + ce.Endpoint
			}
			ms := ce.TunPingMS
			if ms == 0 {
				ms = ce.EpPingMS
			}
			return modeNodeInfo{name: name, cc: cc, ip: ce.IP, region: regionName(cc), ms: int(ms), hasMS: ms > 0}
		}
	}
	return modeNodeInfo{name: u.m.pin}
}

func (u *natUI) paintModeNodeCard(c *walk.Canvas, x, y, w, h float64, sub bool) {
	u.cardPlain(c, x, y, w, h)
	u.txt(c, x+16, y+12, w-110, 16, tr("当前节点"), u.f.f8, th.dim)
	badge, bcol := tr("WARP"), th.ok
	if sub {
		badge, bcol = tr("订阅"), th.accent2
	}
	bw := chipWidth(badge)
	br := u.r(x+w-16-bw, y+10, bw, 20)
	u.fillRound(c, mix(bcol, th.card, 0.85), br, 10)
	u.textC(c, badge, u.f.f8, bcol, br)

	info := u.modeCurrentNode(sub)
	iy := y + 44
	if info.cc != "" {
		u.flagChip(c, x+16, iy, 34, 23, info.cc)
	} else {
		u.fillRound(c, mix(th.accent2, th.card, 0.82), u.r(x+16, iy-3, 30, 30), 15)
		u.icon(c, "globe", x+16+7, iy+4, 16, th.accent2)
	}
	nx := x + 16 + 44
	numX := x + w - 16 - 72 - 12 - 64
	u.txt(c, nx, iy-4, w-(nx-x)-110, 22, clipName(info.name), u.f.f13b, th.text)
	subline := strings.TrimSpace(strings.Join([]string{info.ip, info.region, info.host}, "   "))
	u.txt(c, nx, iy+20, numX-10-nx, 16, orDash(subline), u.f.f8, th.dim)

	// Right: big latency, its unit, and the in-use pill.
	pill := u.r(x+w-16-72, iy, 72, 24)
	if u.m.connected {
		u.fillRound(c, th.okSoft, pill, 12)
		u.statusDot(c, x+w-16-72+11, iy+12, 3, th.ok)
		u.textC(c, tr("使用中"), u.f.f8, th.ok, u.r(x+w-16-72+10, iy, 62, 24))
	} else {
		u.fillRound(c, th.inset, pill, 12)
		u.textC(c, tr("未连接"), u.f.f8, th.faint, pill)
	}
	numW := 64.0
	num, ncol := "—", th.faint
	if info.hasMS {
		num, ncol = itoa(int64(info.ms)), homeLatColor(info.ms)
	}
	u.textR(c, num, u.f.f17b, ncol, u.r(numX, iy-6, numW, 26))
	u.textR(c, tr("ms 延迟"), u.f.f8, th.dim, u.r(numX, iy+20, numW, 16))
}

// modeCounts returns total / working / timeout / starred for the active mode.
func (u *natUI) modeCounts(sub bool) (total, working, timeout, starred int) {
	if sub {
		for _, p := range u.m.set.CustomProxies {
			// The footer counts what the table shows: with a subscription
			// selected the view is that source's nodes, not the whole pool.
			if u.m.set.ActiveSub != "" && p.SubID != u.m.set.ActiveSub {
				continue
			}
			total++
			if p.DelayMS > 0 {
				working++
			}
			if p.DelayErr {
				timeout++
			}
			if u.m.set.starred(p.Name) {
				starred++
			}
		}
		return
	}
	for _, ce := range u.m.endpoints {
		total++
		if ce.Working {
			working++
		} else {
			timeout++
		}
		if u.m.set.starred(ce.Endpoint) {
			starred++
		}
	}
	return
}

func (u *natUI) paintModeFilterRow(c *walk.Canvas, x, y, w float64, sub bool) {
	total, working, _, starred := u.modeCounts(sub)
	allLabel := trf("全部 %d", total)
	if !sub {
		allLabel = trf("WARP 端点 %d", total)
	}
	chips := []struct{ id, label string }{
		{"all", allLabel},
		{"working", trf("可用 %d", working)},
		{"starred", trf("★ 收藏 %d", starred)},
	}
	cx := x
	for _, ch := range chips {
		cw := chipWidth(ch.label)
		u.chipAt(c, "nodefilter:"+ch.id, ch.label, cx, y, u.m.nodeFilter == ch.id, true)
		cx += cw + 6
	}

	sortW := chipWidth(tr("延迟")) + chipWidth(tr("名称")) + 8
	sx := x + w - sortW
	u.segmentedSort(c, sx, y, sortW)
	if sub {
		lw := float64(u.measure(c, tr("自动选点"), u.f.f9))/u.k + 8
		tx := sx - 14 - lw - 44
		u.switchAt(c, "subauto", tx, y+1, u.m.set.SubAutoSelect, true)
		u.txt(c, tx+44+8, y+5, lw, 20, tr("自动选点"), u.f.f9, th.dim)
		u.addSpot("subauto", u.r(tx, y, 44+8+lw, 28), true)
	}
}

// segmentedSort is the recessed two-segment 延迟 /名称 control.
func (u *natUI) segmentedSort(c *walk.Canvas, x, y, w float64) {
	r := u.r(x, y, w, 28)
	u.fillRound(c, th.chip, r, ctrlRadius)
	u.strokeRound(c, th.line, r, ctrlRadius)
	half := (w - 8) / 2
	for i, s := range nodeSorts {
		sr := u.r(x+4+float64(i)*half, y+3, half, 22)
		active := u.m.nodeSort == s.id
		switch {
		case active:
			u.fillRound(c, th.accentSoft, sr, ctrlRadius-2)
		case u.m.hover == "nodesort:"+s.id:
			u.fillRound(c, th.cardHover, sr, ctrlRadius-2)
		}
		col := th.chipText
		if active {
			col = th.accent
		}
		u.textC(c, tr(s.label), u.f.f9, col, sr)
		u.addSpot("nodesort:"+s.id, sr, true)
	}
}

// modeRow unifies the two tables: an auto selector row plus WARP endpoints, or
// the imported subscription proxies.
type modeRow struct {
	auto bool
	ce   cachedEndpoint
	p    ProxySpec
}

func (u *natUI) modeRows(sub bool) []modeRow {
	if sub {
		proxies := u.subscriptionRows()
		out := make([]modeRow, 0, len(proxies))
		for _, p := range proxies {
			out = append(out, modeRow{p: p})
		}
		return out
	}
	endpoints := u.visibleNodeRows()
	out := make([]modeRow, 0, len(endpoints)+1)
	if u.m.nodeFilter == "all" && strings.TrimSpace(u.m.nodeSearch) == "" {
		out = append(out, modeRow{auto: true})
	}
	for _, ce := range endpoints {
		out = append(out, modeRow{ce: ce})
	}
	return out
}

func (u *natUI) paintModeTable(c *walk.Canvas, x, y, w, h float64, sub bool) {
	const headH, footH, rowH = 36.0, 30.0, 58.0
	u.txt(c, x+58, y+10, 200, 18, tr("节点"), u.f.f8, th.faint)
	u.txt(c, x+w*0.42, y+10, 120, 18, tr("国家 / 地区"), u.f.f8, th.faint)
	u.txt(c, x+w*0.56, y+10, 140, 18, tr("IP 地址"), u.f.f8, th.faint)
	latCol := th.faint
	if u.m.nodeSort == "latency" {
		latCol = th.accent
	}
	u.txt(c, x+w*0.74, y+10, 40, 18, tr("延迟"), u.f.f8, latCol)
	if u.m.nodeSort == "latency" {
		u.icon(c, "up", x+w*0.74+30, y+11, 12, latCol)
	}
	u.textR(c, tr("选中"), u.f.f8, th.faint, u.r(x+w-90, y+10, 74, 18))
	u.hline(c, x+16, y+headH, w-32, th.line)

	rows := u.modeRows(sub)
	gridY := y + headH + 4
	if len(rows) == 0 {
		msg := tr("无匹配节点")
		if sub && len(u.m.set.CustomProxies) == 0 {
			msg = tr("订阅模式下还没有节点，请用「+ 添加」导入")
		} else if !sub && len(u.m.endpoints) == 0 {
			msg = tr("缓存中暂无节点，点击「延迟测试」重新扫描")
		}
		u.textC(c, msg, u.f.f10, th.faint, u.r(x+16, y+h/2-12, w-32, 24))
		u.m.nodeVisibleRows, u.m.subVisibleRows, u.m.subMaxScroll = 0, 0, 0
		u.paintModeFooter(c, x, y, w, h, sub)
		return
	}
	maxRows := int((h - headH - footH - 8) / rowH)
	if maxRows < 1 {
		maxRows = 1
	}
	maxScroll := len(rows) - maxRows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if u.m.scroll > maxScroll {
		u.m.scroll = maxScroll
	}
	if u.m.scroll < 0 {
		u.m.scroll = 0
	}
	u.m.nodeVisibleRows = maxRows
	u.m.subVisibleRows = maxRows
	u.m.subMaxScroll = maxScroll
	end := u.m.scroll + maxRows
	if end > len(rows) {
		end = len(rows)
	}
	for i, r := range rows[u.m.scroll:end] {
		ry := gridY + float64(i)*rowH
		switch {
		case sub:
			u.subTableRow(c, x, ry, w, rowH, r.p)
		case r.auto:
			u.warpAutoRow(c, x, ry, w, rowH)
		default:
			u.warpTableRow(c, x, ry, w, rowH, r.ce)
		}
	}
	if maxScroll > 0 {
		listH := float64(maxRows) * rowH
		thumbH := listH * float64(maxRows) / float64(len(rows))
		if thumbH < 20 {
			thumbH = 20
		}
		thumbY := gridY + (listH-thumbH)*float64(u.m.scroll)/float64(maxScroll)
		u.fillRound(c, th.line, u.r(x+w-7, gridY, 3, listH), 2)
		u.fillRound(c, th.faint, u.r(x+w-7, thumbY, 3, thumbH), 2)
	}
	u.paintModeFooter(c, x, y, w, h, sub)
}

func (u *natUI) paintModeFooter(c *walk.Canvas, x, y, w, h float64, sub bool) {
	const footH = 30.0
	u.hline(c, x+16, y+h-footH, w-32, th.line)
	total, working, timeout, _ := u.modeCounts(sub)
	u.txt(c, x+16, y+h-footH+7, 420, 18,
		trf("共 %d 个节点 · 可用 %d · 超时 %d", total, working, timeout), u.f.f8, th.dim)
	last := u.m.scanAt
	if sub {
		last = u.m.subTestAt
	}
	if !last.IsZero() {
		u.textR(c, tr("上次测试 ")+last.Format("15:04:05"), u.f.f8, th.faint, u.r(x+w-200, y+h-footH+7, 184, 18))
	}
}

// modeRowBg paints the active / hover backing and the active left bar.
func (u *natUI) modeRowBg(c *walk.Canvas, x, y, w, h float64, id string, active bool) {
	row := u.r(x+8, y+2, w-16, h-4)
	switch {
	case active:
		u.fillRound(c, th.accentSoft, row, 9)
		u.fillRound(c, th.accent2, u.r(x+8, y+2, 3, h-4), 1.5)
	case u.m.hover == id:
		u.fillRound(c, th.cardHover, row, 9)
	}
}

// modeSelectCell is the right-hand 使用中 pill or 选择 radio.
func (u *natUI) modeSelectCell(c *walk.Canvas, x, y, w, h float64, active bool) {
	selX := x + w - 90
	if active && u.m.connected {
		pill := u.r(selX, y+(h-24)/2, 74, 24)
		u.fillRound(c, mix(th.accent2, th.card, 0.85), pill, 12)
		u.strokeRound(c, th.accent2, pill, 12)
		u.textC(c, tr("使用中"), u.f.f8, th.accent2, pill)
		return
	}
	u.circleStrokeW(c, th.faint, selX+10, y+h/2, 7, 1.5)
	u.txt(c, selX+24, y+(h-18)/2, 50, 18, tr("选择"), u.f.f9, th.dim)
}

// modeStar is the favourite glyph at the right edge of the node column.
func (u *natUI) modeStar(c *walk.Canvas, x, y, w, h float64, key string) {
	star, col := "☆", th.faint
	if u.m.set.starred(key) {
		star, col = "★", th.warn
	}
	sx := x + w*0.42 - 30
	u.textC(c, star, u.f.f10, col, u.r(sx, y+(h-24)/2, 24, 24))
	u.addSpot("star:"+key, u.r(sx, y+(h-24)/2, 24, 24), true)
}

// modeLatency draws the signal bars plus the coloured millisecond value.
func (u *natUI) modeLatency(c *walk.Canvas, x, y, w, h float64, ms int, timeout bool) {
	col := homeLatColor(ms)
	txt := latencyText(int64(ms))
	if timeout {
		txt, col = tr("超时"), th.bad
	}
	u.bars(c, x+w*0.74, y+(h-16)/2, int64(ms), col)
	u.txt(c, x+w*0.74+30, y+(h-18)/2, 76, 18, txt, u.f.f10b, col)
}

// subLatency is the subscription node's delay cell with three live states:
// 未检测 (never measured) → 测试中 (a turning spinner while the test runs) →
// the measured ms, or 超时 when the node was tested and did not answer.
func (u *natUI) subLatency(c *walk.Canvas, x, y, w, h float64, p ProxySpec) {
	bx := x + w*0.74
	if u.m.subTesting[p.Name] {
		u.spinner(c, bx+8, y+h/2, 7, th.accent2)
		u.txt(c, bx+30, y+(h-18)/2, 76, 18, tr("测试中"), u.f.f9, th.accent2)
		return
	}
	if p.DelayMS <= 0 && !p.DelayErr {
		u.bars(c, bx, y+(h-16)/2, 0, th.faint)
		u.txt(c, bx+30, y+(h-18)/2, 76, 18, tr("未检测"), u.f.f9, th.faint)
		return
	}
	u.modeLatency(c, x, y, w, h, p.DelayMS, p.DelayErr)
}

func (u *natUI) warpAutoRow(c *walk.Canvas, x, y, w, h float64) {
	active := u.m.pin == ""
	u.modeRowBg(c, x, y, w, h, "pin:clear", active)
	u.fillRound(c, mix(th.accent2, th.card, 0.82), u.r(x+20, y+(h-30)/2, 30, 30), 15)
	u.icon(c, "globe", x+20+7, y+(h-30)/2+7, 16, th.accent2)
	u.txt(c, x+58, y+9, w*0.42-100, 20, tr("自动选择（推荐）"), u.f.f10b, th.text)
	u.txt(c, x+58, y+31, w*0.42-100, 16, "Cloudflare WARP", u.f.f8, th.faint)
	u.txt(c, x+w*0.42, y+(h-18)/2, w*0.14-10, 18, "Anycast", u.f.f9, th.dim)
	ip := "—"
	if u.m.connected {
		ip = u.displayIP()
	}
	u.txt(c, x+w*0.56, y+(h-18)/2, w*0.18-10, 18, ip, u.f.fmono, th.dim)
	ms := 0
	if u.m.connected {
		ms = int(u.m.latency)
	}
	u.modeLatency(c, x, y, w, h, ms, false)
	u.modeSelectCell(c, x, y, w, h, active)
	u.addSpot("pin:clear", u.r(x+8, y+2, w-100, h-4), true)
}

func (u *natUI) warpTableRow(c *walk.Canvas, x, y, w, h float64, ce cachedEndpoint) {
	active := u.m.pin == ce.Endpoint
	u.modeRowBg(c, x, y, w, h, "row:"+ce.Endpoint, active)
	cc := ce.NodeISO
	if cc == "" {
		cc = ce.Country
	}
	u.flagChip(c, x+20, y+(h-20)/2, 28, 20, cc)
	name := ce.Endpoint
	if ce.NodeCity != "" {
		name = ce.NodeCity + " · " + ce.Endpoint
	}
	u.txt(c, x+58, y+9, w*0.42-100, 20, name, u.f.f10b, th.text)
	u.txt(c, x+58, y+31, w*0.42-100, 16, "Cloudflare WARP", u.f.f8, th.faint)
	u.modeStar(c, x, y, w, h, ce.Endpoint)
	region := "—"
	if cc != "" {
		region = regionName(cc)
	}
	u.txt(c, x+w*0.42, y+(h-18)/2, w*0.14-10, 18, region, u.f.f9, th.dim)
	u.txt(c, x+w*0.56, y+(h-18)/2, w*0.18-10, 18, orDash(ce.IP), u.f.fmono, th.dim)
	ms := ce.TunPingMS
	if ms == 0 {
		ms = ce.EpPingMS
	}
	u.modeLatency(c, x, y, w, h, int(ms), !ce.Working && ms == 0)
	u.modeSelectCell(c, x, y, w, h, active)
	u.addSpot("row:"+ce.Endpoint, u.r(x+8, y+2, w-100, h-4), true)
}

func (u *natUI) subTableRow(c *walk.Canvas, x, y, w, h float64, p ProxySpec) {
	activeName := u.m.set.ActiveProxy
	if u.m.set.SubAutoSelect {
		if best := bestMeasuredProxy(u.subscriptionRows()); best != "" {
			activeName = best
		}
	}
	active := p.Name == activeName
	u.modeRowBg(c, x, y, w, h, "subpick:"+p.Name, active)
	if p.CC != "" {
		u.flagChip(c, x+20, y+(h-20)/2, 28, 20, p.CC)
	} else {
		u.icon(c, "globe", x+24, y+(h-16)/2, 16, th.faint)
	}
	u.txt(c, x+58, y+8, w*0.42-100, 20, clipName(p.Name), u.f.f10b, th.text)
	// Source tag: the proxy protocol, which is real per-node data.
	tag := p.Type
	if tag == "" {
		tag = tr("订阅")
	}
	tw := chipWidth(tag)
	tr_ := u.r(x+58, y+30, tw, 18)
	u.fillRound(c, mix(th.accent2, th.card, 0.85), tr_, 9)
	u.textC(c, tag, u.f.f8, th.accent2, tr_)
	u.modeStar(c, x, y, w, h, p.Name)
	region := "—"
	if p.CC != "" {
		region = regionName(p.CC)
	}
	u.txt(c, x+w*0.42, y+(h-18)/2, w*0.14-10, 18, region, u.f.f9, th.dim)
	ip := "—"
	if s, ok := p.Fields["server"].(string); ok && s != "" {
		ip = s
	}
	u.txt(c, x+w*0.56, y+(h-18)/2, w*0.18-10, 18, ip, u.f.fmono, th.dim)
	u.subLatency(c, x, y, w, h, p)
	u.modeSelectCell(c, x, y, w, h, active)
	u.addSpot("subpick:"+p.Name, u.r(x+8, y+2, w-100, h-4), true)
}

// ---------------------------------------------------------------------------
// Dropdowns: connection mode picker and the add menu
// ---------------------------------------------------------------------------

func (u *natUI) modeConnAnchor() (x, y, w, h float64) {
	cx, cw := u.contentX(), u.contentW()
	lw := (cw - 16) * 0.52
	return cx + 16, shellBodyY + 34, lw - 32, 56
}

func (u *natUI) modeAddAnchor() (x, y, w, h float64) {
	return u.contentX() + u.contentW() - 76, 20, 76, 34
}

func (u *natUI) paintConnModePopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const rowH, pad = 52.0, 6.0
	ph := pad*2 + 2*rowH
	px, py := ax, popupBelow(ay, ah, ph)
	box := u.r(px, py, aw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.overlay, box, panelRadius)
	u.strokeRound(c, th.line, box, panelRadius)
	items := []struct{ mode, icon, title, sub string }{
		{"subscription", "list", tr("订阅模式"), tr("导入 Clash 订阅 / 节点作为前置")},
		{"warp", "globe", tr("WARP 模式"), tr("Cloudflare WARP / MASQUE 隧道")},
	}
	for i, it := range items {
		ry := py + pad + float64(i)*rowH
		id := "connmode:" + it.mode
		r := u.r(px+6, ry, aw-12, rowH)
		if u.m.hover == id {
			u.fillRound(c, th.cardHover, r, ctrlRadius)
		}
		is := 30.0
		ix, iy := px+14, ry+(rowH-is)/2
		u.fillRound(c, mix(th.accent2, th.card, 0.82), u.r(ix, iy, is, is), 8)
		u.icon(c, it.icon, ix+is*0.24, iy+is*0.24, is*0.52, th.accent2)
		tx := ix + is + 12
		u.txt(c, tx, ry+8, aw-(tx-px)-40, 18, it.title, u.f.f10b, th.text)
		u.txt(c, tx, ry+28, aw-(tx-px)-40, 14, it.sub, u.f.f8, th.dim)
		if u.m.set.ConnMode == it.mode {
			u.textC(c, "✓", u.f.f10, th.accent2, u.r(px+aw-36, ry, 28, rowH))
		}
		u.addSpot(id, r, true)
	}
}

func (u *natUI) paintAddMenuPopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	const rowH, pad = 50.0, 6.0
	items := []struct {
		id, icon, title, sub string
		col                  walk.Color
	}{
		{"suburl", "link", tr("订阅地址"), tr("粘贴 URL，导入整份订阅"), th.accent2},
		{"subsingle", "nodes", tr("单个节点"), tr("粘贴 ss:// vmess:// trojan:// 分享链接"), th.up},
		{"subclip", "copy", tr("剪贴板导入"), tr("自动识别剪贴板中的链接或订阅"), th.ok},
		{"subfile", "folder", tr("配置文件"), tr("导入 Clash YAML / JSON 配置"), th.vio},
		{"subqr", "grid", tr("二维码"), tr("选择二维码图片导入节点"), th.warn},
		{"subrefresh", "refresh", tr("刷新订阅"), tr("重新下载已记住的订阅源"), th.mag},
	}
	pw := 300.0
	ph := pad*2 + float64(len(items))*rowH
	px := ax + aw - pw
	if px < 8 {
		px = 8
	}
	py := popupBelow(ay, ah, ph)
	box := u.r(px, py, pw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.overlay, box, panelRadius)
	u.strokeRound(c, th.line, box, panelRadius)
	for i, it := range items {
		ry := py + pad + float64(i)*rowH
		r := u.r(px+6, ry, pw-12, rowH)
		if u.m.hover == it.id {
			u.fillRound(c, th.cardHover, r, ctrlRadius)
		}
		is := 30.0
		ix, iy := px+14, ry+(rowH-is)/2
		u.fillRound(c, mix(it.col, th.card, 0.82), u.r(ix, iy, is, is), 8)
		u.icon(c, it.icon, ix+is*0.24, iy+is*0.24, is*0.52, it.col)
		tx := ix + is + 12
		u.txt(c, tx, ry+7, pw-(tx-px)-20, 18, it.title, u.f.f10b, th.text)
		u.txt(c, tx, ry+27, pw-(tx-px)-20, 14, it.sub, u.f.f8, th.dim)
		u.addSpot(it.id, r, true)
	}
}

// subscriptionRows filters and orders the imported proxies. Default is
// measured latency ascending with untested nodes last — the same ordering a
// Clash client shows after a delay test. The top chip switches to name order.
func (u *natUI) subscriptionRows() []ProxySpec {
	out := make([]ProxySpec, 0, len(u.m.set.CustomProxies))
	needle := strings.ToLower(strings.TrimSpace(u.m.nodeSearch))
	for _, p := range u.m.set.CustomProxies {
		// ActiveSub is a view filter: "" shows every subscription, otherwise
		// only the nodes imported from the selected source.
		if u.m.set.ActiveSub != "" && p.SubID != u.m.set.ActiveSub {
			continue
		}
		switch u.m.nodeFilter {
		case "working":
			if p.DelayMS <= 0 {
				continue
			}
		case "starred":
			if !u.m.set.starred(p.Name) {
				continue
			}
		}
		if needle != "" && !strings.Contains(strings.ToLower(p.Name+" "+p.Type), needle) {
			continue
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if u.m.nodeSort == "name" {
			return a.Name < b.Name
		}
		// Delay order mirrors a Clash client: measured nodes ascending, then
		// the ones never tested, then the dead ones — 超时 always sinks to the
		// bottom instead of interleaving with real numbers.
		rank := func(p ProxySpec) int {
			switch {
			case p.DelayMS > 0:
				return 0
			case p.DelayErr:
				return 2
			default:
				return 1
			}
		}
		ra, rb := rank(a), rank(b)
		if ra != rb {
			return ra < rb
		}
		if ra == 0 && a.DelayMS != b.DelayMS {
			return a.DelayMS < b.DelayMS
		}
		return a.Name < b.Name
	})
	return out
}

// clipName keeps a long subscription name inside its card.
func clipName(s string) string {
	r := []rune(s)
	if len(r) <= 24 {
		return s
	}
	return string(r[:23]) + "…"
}

// autoDelayTest runs the latency pass by itself a beat after the node list was
// published. The short delay matters: the rows (and their 未检测 state) must be
// on screen first, then the spinners take over — the same sequence the user
// gets when clicking 延迟测试, minus the click. A running test wins; the import
// that just finished is measured by the next pass instead of fighting it.
func (u *natUI) autoDelayTest() {
	go func() {
		select {
		case <-u.ctx.Done():
			return
		case <-time.After(450 * time.Millisecond):
		}
		u.sync(func() {
			if u.m.connecting || u.m.working {
				return
			}
			u.testSubscriptionDelays()
		})
	}()
}

// testSubscriptionDelays measures every imported proxy with mihomo's own
// /proxies/{name}/delay API. A live subscription session is reused; otherwise
// a throwaway core on private ports is started and stopped around the test.
func (u *natUI) testSubscriptionDelays() {
	if !u.subDelayBusy.CompareAndSwap(false, true) {
		u.addLog(tr("延迟测试正在进行中"), false)
		return
	}
	// Test the subscription in view (ActiveSub), or every node when showing all.
	proxies := make([]ProxySpec, 0, len(u.m.set.CustomProxies))
	for _, p := range u.m.set.CustomProxies {
		if u.m.set.ActiveSub == "" || p.SubID == u.m.set.ActiveSub {
			proxies = append(proxies, p)
		}
	}
	if len(proxies) == 0 {
		u.subDelayBusy.Store(false)
		u.addLog(tr("订阅模式下还没有节点，请用上方按钮导入"), true)
		return
	}
	// Mark every target as "测试中" so the list animates from 未检测 through a
	// spinner to the measured value. Cleared when the results land.
	u.m.subTesting = make(map[string]bool, len(proxies))
	for _, p := range proxies {
		u.m.subTesting[p.Name] = true
	}
	apiPort := 0
	if u.m.connected && u.m.set.ConnMode == "subscription" && u.m.status.APIPort > 0 {
		apiPort = u.m.status.APIPort
	}
	u.addLog(tr("开始延迟测试")+": "+itoa(int64(len(proxies)))+tr(" 个节点"), false)
	u.invalidate()
	go func() {
		defer u.subDelayBusy.Store(false)
		logf := func(s string) { u.sync(func() { u.addLog(s, false) }) }
		var results map[string]int
		var failed map[string]bool
		var countries map[string]string
		var err error
		if apiPort > 0 {
			results, failed = measureProxyDelays(u.ctx, apiPort, proxies, logf)
			// The live core cannot take new per-node listeners, so the country
			// pass gets its own throwaway core — best effort, never fatal.
			countries = geoPass(u.ctx, proxies, results, logf)
		} else {
			rep, rerr := runSubscriptionDelayTest(u.ctx, proxies, logf)
			results, failed, countries, err = rep.MS, rep.Failed, rep.CC, rerr
		}
		u.sync(func() {
			u.m.subTesting = nil
			if err != nil {
				u.addLog(tr("延迟测试失败")+": "+err.Error(), true)
				u.invalidate()
				return
			}
			for i := range u.m.set.CustomProxies {
				p := &u.m.set.CustomProxies[i]
				if d, ok := results[p.Name]; ok {
					p.DelayMS, p.DelayErr = d, false
				} else if failed[p.Name] {
					// Tested and did not answer: the card says 超时 in red,
					// which is different from "not measured yet" (未检测).
					p.DelayMS, p.DelayErr = 0, true
				}
				if cc, ok := countries[p.Name]; ok && cc != "" {
					p.CC = cc
				}
			}
			ok := len(results)
			if u.m.set.SubAutoSelect {
				if best := bestMeasuredProxy(u.m.set.CustomProxies); best != "" {
					u.m.set.ActiveProxy = best
				}
			}
			if serr := saveSettings(u.m.set); serr != nil {
				u.addLog(tr("设置保存失败: ")+serr.Error(), true)
			}
			u.m.subTestAt = time.Now()
			u.m.scroll = 0
			u.addLog(tr("延迟测试完成")+": "+itoa(int64(ok))+"/"+itoa(int64(len(proxies)))+tr(" 个有响应"), false)
			u.invalidate()
		})
	}()
}

// toggleSubAuto switches between manual node picking and always using the
// lowest measured delay. The connect path reads the same flag in settings.go.
func (u *natUI) toggleSubAuto() {
	u.m.set.SubAutoSelect = !u.m.set.SubAutoSelect
	if u.m.set.SubAutoSelect {
		if best := bestMeasuredProxy(u.m.set.CustomProxies); best != "" {
			u.m.set.ActiveProxy = best
			u.addLog(tr("已开启自动选点")+": "+best, false)
		} else {
			u.addLog(tr("已开启自动选点")+" · "+tr("请先做一次延迟测试"), false)
		}
	} else {
		u.addLog(tr("已切换为手动选点"), false)
	}
	if err := saveSettings(u.m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	}
	u.invalidate()
}

type nodeFilterDef struct{ id, label string }

var nodeSorts = []nodeFilterDef{
	{"latency", "延迟"},
	{"name", "名称"},
}

// visibleNodeRows applies the search box, the filter and the sort to the scan
// cache. Starred endpoints come first for their sort key, because a favourite
// that still needs scrolling for is not a favourite.
func (u *natUI) visibleNodeRows() []cachedEndpoint {
	out := make([]cachedEndpoint, 0, len(u.m.endpoints))
	needle := strings.ToLower(strings.TrimSpace(u.m.nodeSearch))
	for _, ce := range u.m.endpoints {
		switch u.m.nodeFilter {
		case "working":
			if !ce.Working {
				continue
			}
		case "starred":
			if !u.m.set.starred(ce.Endpoint) {
				continue
			}
		}
		if needle != "" {
			hay := strings.ToLower(strings.Join([]string{
				ce.Endpoint, ce.IP, ce.Country, ce.Colo, ce.NodeCity, ce.NodeISO,
			}, " "))
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		out = append(out, ce)
	}
	less := func(i, j int) bool {
		a, b := out[i], out[j]
		sa, sb := u.m.set.starred(a.Endpoint), u.m.set.starred(b.Endpoint)
		if sa != sb {
			return sa
		}
		if u.m.nodeSort == "name" {
			return a.Endpoint < b.Endpoint
		}
		la, lb := a.TunPingMS, b.TunPingMS
		if la == 0 {
			la = a.EpPingMS
		}
		if lb == 0 {
			lb = b.EpPingMS
		}
		if la == 0 {
			la = 1 << 30
		}
		if lb == 0 {
			lb = 1 << 30
		}
		return la < lb
	}
	sort.SliceStable(out, less)
	return out
}

// ---------------------------------------------------------------------------
// 订阅导入动作
// ---------------------------------------------------------------------------

// isQRImage 按扩展名判断导入文件是否为二维码图片。
func isQRImage(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".bmp":
		return true
	}
	return false
}

// isSubscriptionURL 判断一段文本是否是单个 http(s) 订阅地址（而非节点链接）。
func isSubscriptionURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return false
	}
	lo := strings.ToLower(s)
	return strings.HasPrefix(lo, "http://") || strings.HasPrefix(lo, "https://")
}

// parseSubscriptionContent 把一段订阅内容解析成节点：单个订阅 URL 先拉取再
// 解析，其余（base64 / Clash YAML / 一行行 URI）直接交给 ParseSubscription。
// 网络请求用 u.ctx，窗口退出即取消。
func (u *natUI) parseSubscriptionContent(content string) (*ParsedInput, error) {
	content = strings.TrimSpace(content)
	if isSubscriptionURL(content) {
		raw, err := FetchSubscription(u.ctx, content, defaultFetchTimeout)
		if err != nil {
			return nil, err
		}
		return ParseSubscription(raw)
	}
	return ParseSubscription([]byte(content))
}

// parseAndApplyAsync 在后台解析订阅内容，并回到 GUI 线程写回设置。src 是这次
// 导入对应的订阅源（已生成 ID）；只有解析出节点才登记进 SubSources，避免失败的
// 导入留下空订阅。新导入的节点全部打上 src.ID，并把视图切到该订阅以便立即可见。
func (u *natUI) parseAndApplyAsync(content string, src SubSource) {
	go func() {
		parsed, err := u.parseSubscriptionContent(content)
		u.sync(func() {
			if err != nil {
				u.addLog(tr("导入失败")+": "+err.Error(), true)
				u.invalidate()
				return
			}
			if len(parsed.Proxies) == 0 {
				u.addLog(tr("导入失败")+": "+tr("未解析到有效节点"), true)
				u.invalidate()
				return
			}
			isNew := u.m.set.subSourceByID(src.ID) == nil
			if isNew {
				u.m.set.SubSources = append(u.m.set.SubSources, src)
			}
			u.applyImportedProxies(parsed.Proxies, src.ID, src.Kind)
			if isNew {
				u.m.set.ActiveSub = src.ID
				u.m.scroll = 0
				if serr := saveSettings(u.m.set); serr != nil {
					u.addLog(tr("设置保存失败: ")+serr.Error(), true)
				}
				u.invalidate()
			}
			// Show the rows first, then measure them without being asked.
			u.autoDelayTest()
		})
	}()
}

// refreshSubscriptions re-downloads every URL-kind subscription and rebuilds
// its nodes. Nodes from file/clipboard/QR/single sources and orphans are kept
// verbatim, and a source that fails to fetch keeps its old nodes rather than
// vanishing on a transient network error. The fetch runs through the live
// subscription tunnel when there is one (FetchSubscription reads state.json).
func (u *natUI) refreshSubscriptions() {
	if !u.subRefreshBusy.CompareAndSwap(false, true) {
		u.addLog(tr("订阅刷新正在进行中"), false)
		return
	}
	var urlSrcs []SubSource
	urlIDs := map[string]bool{}
	for _, src := range u.m.set.SubSources {
		if src.Kind == "url" && src.URL != "" {
			urlSrcs = append(urlSrcs, src)
			urlIDs[src.ID] = true
		}
	}
	if len(urlSrcs) == 0 {
		u.subRefreshBusy.Store(false)
		u.addLog(tr("没有可刷新的订阅链接：请先用「订阅链接」导入一次"), true)
		return
	}
	u.addLog(trf("刷新订阅节点：%d 个订阅源…", len(urlSrcs)), false)
	u.invalidate()
	// Snapshot the old nodes by source so a failed fetch can fall back to them,
	// and old measurements so a refresh never throws away latency already paid for.
	oldBySub := map[string][]ProxySpec{}
	oldMS := map[string]ProxySpec{}
	for _, p := range u.m.set.CustomProxies {
		oldBySub[p.SubID] = append(oldBySub[p.SubID], p)
		oldMS[p.Name] = p
	}
	// Everything the worker reads from the model is copied here, on the GUI
	// thread: the user can import, delete or rename while the refresh runs.
	liveNodes := append([]ProxySpec(nil), u.m.set.CustomProxies...)
	subNames := proxySubNames(u.m.set)
	go func() {
		defer u.subRefreshBusy.Store(false)
		var all []ProxySpec
		owner := map[string]string{}
		// add keeps one row per (source, name) pair. A name another source
		// already owns is renamed rather than dropped, and a name that did not
		// change keeps the latency already measured for it.
		add := func(p ProxySpec, subID string) {
			if p.Name == "" {
				return
			}
			old, hadOld := oldMS[p.Name]
			if prev, exists := owner[p.Name]; exists {
				if prev == subID {
					return
				}
				p.Name = uniqueProxyNameIn(p.Name, subID, owner, subNames)
			}
			owner[p.Name] = subID
			p.SubID = subID
			if hadOld {
				p.DelayMS, p.DelayErr, p.CC = old.DelayMS, old.DelayErr, old.CC
			}
			all = append(all, p)
		}
		// Non-URL nodes (file/clipboard/QR/single/orphan) are never re-fetched.
		for _, p := range liveNodes {
			if !urlIDs[p.SubID] {
				add(p, p.SubID)
			}
		}
		var lastErr error
		for _, src := range urlSrcs {
			ctx, cancel := context.WithTimeout(u.ctx, subscriptionTotalTimeout)
			body, err := FetchSubscription(ctx, src.URL, defaultFetchTimeout)
			cancel()
			if err != nil {
				lastErr = err
				for _, p := range oldBySub[src.ID] {
					add(p, src.ID)
				}
				continue
			}
			parsed, perr := ParseSubscription(body)
			if perr != nil {
				lastErr = perr
				for _, p := range oldBySub[src.ID] {
					add(p, src.ID)
				}
				continue
			}
			for _, p := range parsed.Proxies {
				add(p, src.ID)
			}
		}
		u.sync(func() {
			if len(all) == 0 {
				msg := tr("订阅刷新失败：没有拿到任何节点")
				if lastErr != nil {
					msg += "（" + lastErr.Error() + "）"
				}
				u.addLog(msg, true)
				u.invalidate()
				return
			}
			// A subscription deleted while the fetch ran must not come back: its
			// nodes were rebuilt from a snapshot taken before the delete.
			alive := make(map[string]bool, len(u.m.set.SubSources))
			for _, src := range u.m.set.SubSources {
				alive[src.ID] = true
			}
			kept := all[:0]
			for _, p := range all {
				if p.SubID == "" || alive[p.SubID] {
					kept = append(kept, p)
				}
			}
			all = kept
			if len(all) == 0 {
				u.addLog(tr("订阅刷新完成：订阅已被删除，未写回任何节点"), false)
				u.invalidate()
				return
			}
			u.m.set.CustomProxies = all
			// A pinned node that disappeared falls back to the first row so the
			// render never names an outbound that is not in the config.
			found := false
			for _, p := range all {
				if p.Name == u.m.set.ActiveProxy {
					found = true
					break
				}
			}
			if !found {
				u.m.set.ActiveProxy = all[0].Name
			}
			if err := saveSettings(u.m.set); err != nil {
				u.addLog(tr("设置保存失败: ")+err.Error(), true)
			}
			u.m.scroll = 0
			u.addLog(trf("订阅刷新完成：%d 个节点", len(all)), false)
			u.invalidate()
			// Refreshed nodes are new endpoints: measure them without a click.
			u.autoDelayTest()
		})
	}()
}

// proxyNameOwner maps every live proxy name to the subscription that owns it.
func (u *natUI) proxyNameOwner() map[string]string {
	owner := make(map[string]string, len(u.m.set.CustomProxies))
	for _, p := range u.m.set.CustomProxies {
		owner[p.Name] = p.SubID
	}
	return owner
}

// proxySubNames snapshots the subscription id → display name table. Workers get
// this instead of reading u.m.set themselves.
func proxySubNames(s clientSettings) map[string]string {
	m := make(map[string]string, len(s.SubSources))
	for _, src := range s.SubSources {
		m[src.ID] = src.Name
	}
	return m
}

// uniqueProxyNameIn keeps mihomo's proxy-name uniqueness without dropping a
// node. Two subscriptions commonly ship the same "香港 01": the second one gets
// a "·<订阅名>" suffix (and a numeric tail if that is taken too) instead of being
// silently discarded, which is what the old global-name de-dupe did.
//
// Pure by design: it reads only the tables it is handed, so a worker goroutine
// can call it while the user edits settings on the GUI thread.
func uniqueProxyNameIn(name, subID string, owner, subNames map[string]string) string {
	if _, taken := owner[name]; !taken {
		return name
	}
	suffix := ""
	if n := subNames[subID]; n != "" {
		suffix = " · " + n
	}
	cand := name + suffix
	if _, taken := owner[cand]; !taken {
		return cand
	}
	for i := 2; i < 1000; i++ {
		c := cand + " (" + itoa(int64(i)) + ")"
		if _, taken := owner[c]; !taken {
			return c
		}
	}
	return cand
}

// applyImportedProxies 把解析出的节点追加进 CustomProxies，每个节点打上来源订阅
// subID，总数封顶 512，保存并汇报条数。同一订阅里重复导入的同名节点跳过；
// 来自其它订阅的同名节点改名保留，绝不静默丢弃。所有 model 写入都在 GUI 线程完成。
func (u *natUI) applyImportedProxies(proxies []ProxySpec, subID, kindLabel string) {
	if len(proxies) == 0 {
		u.addLog(tr("导入失败")+": "+tr("未解析到有效节点"), true)
		u.invalidate()
		return
	}
	owner := u.proxyNameOwner()
	subNames := proxySubNames(u.m.set)
	added, renamed := 0, 0
	for _, p := range proxies {
		if len(u.m.set.CustomProxies) >= 512 {
			break
		}
		if p.Name == "" {
			continue
		}
		if prev, exists := owner[p.Name]; exists {
			if prev == subID {
				continue // same source imported again: drop the duplicate
			}
			p.Name = uniqueProxyNameIn(p.Name, subID, owner, subNames)
			renamed++
		}
		owner[p.Name] = subID
		p.SubID = subID
		u.m.set.CustomProxies = append(u.m.set.CustomProxies, p)
		added++
	}
	if err := saveSettings(u.m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	}
	msg := tr("导入成功") + ": " + itoa(int64(added)) + " " + kindLabel
	if renamed > 0 {
		msg += trf("（%d 个同名节点已自动改名）", renamed)
	}
	u.addLog(msg, false)
	u.invalidate()
}

// importSubscriptionURL 弹框取「名字 + 订阅地址 + 分组」→ 拉取 → 解析 → 写回。
func (u *natUI) importSubscriptionURL() {
	src, ok := u.promptSubscription(tr("导入订阅"), SubSource{Kind: "url"}, true)
	if !ok {
		return
	}
	u.parseAndApplyAsync(src.URL, src)
}

// importSingleProxy 弹框取一条分享链接（ss:// / vmess:// / trojan://）→ 解析，
// 再让用户为这一组节点命名/分组。
func (u *natUI) importSingleProxy() {
	raw, ok := u.promptText(tr("单个节点"), tr("粘贴 ss:// / vmess:// / trojan:// 分享链接"), "")
	if !ok {
		return
	}
	if raw = strings.TrimSpace(raw); raw == "" {
		return
	}
	u.importContentAsSource(raw, "single", tr("单个节点"))
}

// importSubscriptionFile 选文件 → 图片走二维码解码，文本/配置走订阅解析。
func (u *natUI) importSubscriptionFile() {
	path, ok, err := PickImportFile(u.mw)
	if err != nil {
		u.addLog(tr("导入失败")+": "+err.Error(), true)
		return
	}
	if !ok {
		return
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if isQRImage(path) {
		content, derr := DecodeQRFile(path)
		if derr != nil {
			u.addLog(tr("导入失败")+": "+derr.Error(), true)
			return
		}
		u.importContentAsSource(content, "file", name)
		return
	}
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		u.addLog(tr("导入失败")+": "+rerr.Error(), true)
		return
	}
	u.importContentAsSource(string(raw), "file", name)
}

// importSubscriptionClipboard 从剪贴板取文本或二维码 → 解析订阅。
func (u *natUI) importSubscriptionClipboard() {
	content, src, err := ImportFromClipboard()
	if err != nil {
		u.addLog(tr("导入失败")+": "+err.Error(), true)
		return
	}
	kind, name := "clipboard", tr("剪贴板订阅")
	if src == "qr" {
		kind, name = "qr", tr("二维码订阅")
	}
	u.importContentAsSource(content, kind, name)
}

// importSubscriptionQR 选二维码图片 → 解码 → 内容是 URL 则拉取，否则解析。
func (u *natUI) importSubscriptionQR() {
	path, ok, err := PickImportFile(u.mw)
	if err != nil {
		u.addLog(tr("导入失败")+": "+err.Error(), true)
		return
	}
	if !ok {
		return
	}
	content, derr := DecodeQRFile(path)
	if derr != nil {
		u.addLog(tr("导入失败")+": "+derr.Error(), true)
		return
	}
	u.importContentAsSource(content, "qr", tr("二维码订阅"))
}

// importContentAsSource 为非 URL 导入（文件/剪贴板/二维码/单节点）登记订阅源：
// 内容已取到，弹「名字 + 分组」框确认后生成 SubSource 并解析写回。若内容本身是
// 一个订阅 URL，则升级为可刷新的 url 源。
func (u *natUI) importContentAsSource(content, kind, defaultName string) {
	content = strings.TrimSpace(content)
	if content == "" {
		return
	}
	seed := SubSource{Name: defaultName, Kind: kind}
	showURL := false
	if isSubscriptionURL(content) {
		seed.Kind, seed.URL, showURL = "url", content, true
		if seed.Name == "" || seed.Name == defaultName {
			seed.Name = subNameFromURL(content)
		}
	}
	src, ok := u.promptSubscription(tr("导入订阅"), seed, showURL)
	if !ok {
		return
	}
	u.parseAndApplyAsync(content, src)
}

// toggleConnMode 在 "warp" / "subscription" 间切换连接模式并保存。
func (u *natUI) toggleConnMode() {
	next := "subscription"
	label := tr("订阅模式")
	if u.m.set.ConnMode == "subscription" {
		next = "warp"
		label = tr("WARP 模式")
	}
	u.m.set.ConnMode = next
	// Re-clamp the live copy to the new mode's rules (the family gate differs
	// between WARP and subscription), matching what saveSettings normalizes.
	u.m.set.normalize()
	u.m.pin = u.m.set.Pin
	if err := saveSettings(u.m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	}
	u.addLog(tr("模式切换")+": "+label, false)
	u.invalidate()
}

// pickSubscriptionProxy 把某个已导入的订阅节点设为当前前置节点并保存设置。
// name 必须存在于 CustomProxies，否则仅记录一条错误日志。
func (u *natUI) pickSubscriptionProxy(name string) {
	found := false
	for _, p := range u.m.set.CustomProxies {
		if p.Name == name {
			found = true
			break
		}
	}
	if !found {
		u.addLog(tr("前置节点设置失败")+": "+name, true)
		u.invalidate()
		return
	}
	u.m.set.ActiveProxy = name
	// Picking a node by hand is an explicit override of automatic selection.
	u.m.set.SubAutoSelect = false
	if err := saveSettings(u.m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	}
	u.addLog(tr("当前前置节点")+": "+name, false)
	u.invalidate()
}
