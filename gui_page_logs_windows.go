//go:build windows

package main

import (
	"strings"

	"github.com/lxn/walk"
)

var logTabIDs = []string{"run", "conn", "debug"}

func (u *natUI) paintLogs(c *walk.Canvas) {
	x, y, w := u.contentX(), shellBodyY, u.contentW()
	labels := []string{tr("运行日志"), tr("连接记录"), tr("调试信息")}
	u.subtabs(c, x, y, "logtab:", logTabIDs, labels, u.m.logTab)
	u.paintLogActions(c, x, y, w)

	top := y + 46
	switch u.m.logTab {
	case "conn":
		u.paintSessions(c, x, top, w)
	case "debug":
		u.paintDebug(c, x, top, w)
	default:
		u.paintRunLog(c, x, top, w)
	}
}

// paintLogActions puts the tab's actions on the tab line itself, flush with the
// card's right padding. The card below is then free for content on every tab.
// Widths follow the label because the English strings are roughly twice as wide
// as the Chinese ones and would otherwise overflow.
func (u *natUI) paintLogActions(c *walk.Canvas, x, y, w float64) {
	const btnH = 30.0
	btnW := func(label string) float64 {
		bw := chipWidth(label) + 8
		if bw < 80 {
			bw = 80
		}
		return bw
	}
	switch u.m.logTab {
	case "conn":
		return
	case "debug":
		specs := []struct {
			id, label string
			primary   bool
		}{
			{"about:copydiag", tr("复制诊断信息"), true},
			{"about:opendata", tr("打开数据目录"), false},
			{"upd:refresh", tr("重新探测内核"), false},
		}
		widths := make([]float64, len(specs))
		total := 0.0
		for i, s := range specs {
			widths[i] = btnW(s.label)
			total += widths[i]
		}
		bx := x + w - 16 - total - 8*float64(len(specs)-1)
		for i, s := range specs {
			enabled := true
			if s.id == "upd:refresh" {
				enabled = !u.m.coreBusy
			}
			u.button(c, bx, y, widths[i], btnH, s.id, s.label, s.primary, enabled)
			bx += widths[i] + 8
		}
	default:
		copyW := btnW(tr("复制"))
		clearW := btnW(tr("清空日志"))
		bx := x + w - 16 - copyW
		u.button(c, bx, y, copyW, btnH, "logcopy", tr("复制"), false, len(u.m.logs) > 0)
		bx -= 8 + clearW
		u.button(c, bx, y, clearW, btnH, "logclear", tr("清空日志"), false, len(u.m.logs) > 0)
	}
}

// paintRunLog is a light log reader: newest at the bottom, one line per entry,
// level tagged. It shares the session list's card surface and text colours so
// the two views read as one material, and it always follows the newest line.
func (u *natUI) paintRunLog(c *walk.Canvas, x, y, w float64) {
	h := 670 - y
	u.cardPlain(c, x, y, w, h)

	const lineH = 24.0
	rows := int((h - 28) / lineH)
	if rows < 1 {
		rows = 1
	}
	u.m.logVisibleRows = rows
	all := u.m.logs
	maxScroll := len(all) - rows
	if maxScroll < 0 {
		maxScroll = 0
	}
	// logScroll counts lines up from the newest, so 0 keeps following live
	// output; the clamp also handles a resize that fits more rows.
	if u.m.logScroll < 0 {
		u.m.logScroll = 0
	}
	if u.m.logScroll > maxScroll {
		u.m.logScroll = maxScroll
	}
	if len(all) == 0 {
		u.textC(c, tr("暂无日志"), u.f.f9, th.faint, u.r(x+16, y+h/2-20, w-32, 20))
		return
	}
	end := len(all) - u.m.logScroll
	start := end - rows
	if start < 0 {
		start = 0
	}
	lines := all[start:end]
	ly := y + 14
	for _, l := range lines {
		// Level pill: a soft tinted chip carries the level so a wall of core
		// chatter stays scannable, and warnings/errors jump out by colour.
		tag, pillBg, pillCol := "INFO", th.inset, th.dim
		msgCol := th.text
		switch {
		case l.lv == 2:
			tag, pillBg, pillCol, msgCol = "ERR", th.badSoft, th.bad, th.bad
		case l.lv == 1:
			tag, pillBg, pillCol, msgCol = "WARN", th.warnSoft, th.warn, th.warn
		case l.core:
			tag, pillBg, pillCol = "CORE", mix(th.vio, th.card, 0.86), th.vio
		}
		u.txt(c, x+16, ly, 62, lineH, l.at.Format("15:04:05"), u.f.fmono, th.faint)
		pill := u.r(x+84, ly+3, 50, lineH-6)
		u.fillRound(c, pillBg, pill, 5)
		u.textC(c, tag, u.f.f8, pillCol, pill)
		u.txt(c, x+142, ly, w-158, lineH, l.text, u.f.fmono, msgCol)
		ly += lineH
	}
	u.paintLogScrollbar(c, x, y, w, h)
}

// runLogBox is the run-log card's box in design units. Paint and the scrollbar
// drag handlers both derive their geometry from it so the handle can never
// drift from the card it belongs to.
func (u *natUI) runLogBox() (x, y, w, h float64) {
	x, w = u.contentX(), u.contentW()
	y = shellBodyY + 46
	h = 670 - y
	return
}

// logScrollbarGeom returns the run-log scrollbar in design units plus the
// largest scroll offset. logScroll counts up from the newest line, so the thumb
// rests at the bottom while following live output and climbs toward the top as
// the reader scrolls back into history.
func (u *natUI) logScrollbarGeom(x, y, w, h float64) (trackX, trackTop, trackH, thumbTop, thumbH float64, maxScroll int) {
	trackX = x + w - 12
	trackTop = y + 8
	trackH = h - 16
	rows := u.m.logVisibleRows
	if rows < 1 {
		rows = 1
	}
	maxScroll = len(u.m.logs) - rows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if maxScroll <= 0 {
		return trackX, trackTop, trackH, 0, 0, 0
	}
	thumbH = trackH * float64(rows) / float64(len(u.m.logs))
	if thumbH < 42 {
		thumbH = 42
	}
	off := float64(maxScroll-u.m.logScroll) / float64(maxScroll)
	thumbTop = trackTop + off*(trackH-thumbH)
	return
}

// paintLogScrollbar is the slim draggable indicator on the card's right margin.
// It only appears when history spills past one screen; the thumb brightens on
// hover and while grabbed so the handle reads as interactive, not decoration.
func (u *natUI) paintLogScrollbar(c *walk.Canvas, x, y, w, h float64) {
	trackX, trackTop, trackH, thumbTop, thumbH, maxScroll := u.logScrollbarGeom(x, y, w, h)
	if maxScroll <= 0 {
		return
	}
	u.fillRound(c, mix(th.line, th.card, 0.45), u.r(trackX, trackTop, 4, trackH), 2)
	thumbCol := mix(th.accent, th.card, 0.28)
	if u.m.hover == "log:scrollbar" || u.logDrag {
		thumbCol = mix(th.accent, th.card, 0.08)
	}
	u.fillRound(c, thumbCol, u.r(trackX, thumbTop, 4, thumbH), 2)
	// A wider grab strip than the 4px thumb so the handle is easy to catch.
	u.addSpot("log:scrollbar", u.r(x+w-16, y+8, 14, h-16), true)
}

// beginLogDrag starts a drag on the run-log scrollbar, same contract as the
// settings one: pressing the handle keeps the pointer's offset inside it,
// pressing the track jumps the handle there first and carries on from there.
func (u *natUI) beginLogDrag(py int) {
	x, y, w, h := u.runLogBox()
	_, _, _, thumbTop, thumbH, maxScroll := u.logScrollbarGeom(x, y, w, h)
	if maxScroll <= 0 {
		return
	}
	yy := u.uy(py) - capH
	if yy >= thumbTop && yy <= thumbTop+thumbH {
		u.logGrabDY = yy - thumbTop
	} else {
		u.logGrabDY = thumbH / 2
	}
	u.logDrag = true
	u.dragLogTo(py)
}

// dragLogTo maps the pointer's position on the track onto logScroll. The thumb
// runs bottom (newest) to top (oldest), so the offset is inverted back into the
// lines-up-from-newest count the reader uses.
func (u *natUI) dragLogTo(py int) {
	x, y, w, h := u.runLogBox()
	_, trackTop, trackH, _, thumbH, maxScroll := u.logScrollbarGeom(x, y, w, h)
	if maxScroll <= 0 {
		return
	}
	yy := u.uy(py) - capH
	top := yy - u.logGrabDY
	if top < trackTop {
		top = trackTop
	}
	if maxTop := trackTop + trackH - thumbH; top > maxTop {
		top = maxTop
	}
	span := trackH - thumbH
	if span <= 0 {
		u.m.logScroll = 0
	} else {
		off := (top - trackTop) / span
		u.m.logScroll = int((1 - off) * float64(maxScroll))
	}
	if u.m.logScroll < 0 {
		u.m.logScroll = 0
	}
	if u.m.logScroll > maxScroll {
		u.m.logScroll = maxScroll
	}
	u.invalidate()
}

// paintSessions shows only the connection pipeline's own lines: the connect
// attempts, the endpoint chosen, and the disconnect. Core chatter is filtered
// out, so this is a history of sessions rather than a dump.
func (u *natUI) paintSessions(c *walk.Canvas, x, y, w float64) {
	h := 670 - y
	u.cardPlain(c, x, y, w, h)
	var lines []natLog
	for _, l := range u.m.logs {
		if l.stage {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		u.textC(c, tr("暂无连接记录"), u.f.f10, th.faint, u.r(x+16, y+h/2-24, w-32, 22))
		u.textC(c, tr("连接事件会显示在这里"), u.f.f8, th.faint, u.r(x+16, y+h/2, w-32, 20))
		return
	}
	const lineH = 30.0
	rows := int((h - 40) / lineH)
	if len(lines) > rows {
		lines = lines[len(lines)-rows:]
	}
	ly := y + 18
	for _, l := range lines {
		col := th.text
		icon := "bolt"
		if l.lv == 2 {
			col, icon = th.bad, "close"
		} else if l.lv == 1 {
			col = th.warn
		}
		u.icon(c, icon, x+20, ly+6, 14, col)
		u.txt(c, x+44, ly, 70, 22, l.at.Format("15:04:05"), u.f.f9, th.dim)
		u.txt(c, x+118, ly, w-140, 22, l.text, u.f.f9, col)
		ly += lineH
		u.hline(c, x+16, ly-4, w-32, th.line)
	}
}

// paintDebug previews the support snapshot: the environment block first, then
// the newest log lines. The full log lives on its own tab, so repeating all of
// it here only made this tab a dimmer copy of that one.
func (u *natUI) paintDebug(c *walk.Canvas, x, y, w float64) {
	h := 670 - y
	u.cardPlain(c, x, y, w, h)

	const (
		lineH = 24.0
		pad   = 16.0
	)
	lines := strings.Split(strings.TrimSpace(u.diagHeader()), "\r\n")
	rows := int((h - pad*2) / lineH)
	if len(lines) > rows {
		lines = lines[:rows]
	}
	if room := rows - len(lines) - 1; room > 0 {
		logs := u.m.logs
		if len(logs) > room {
			logs = logs[len(logs)-room:]
		}
		if len(logs) > 0 {
			lines = append(lines, "")
			for _, l := range logs {
				lines = append(lines, "log "+l.at.Format("15:04:05")+" "+l.text)
			}
		}
	}
	ly := y + pad
	for _, l := range lines {
		u.txt(c, x+16, ly, w-32, lineH, l, u.f.fmono, th.text)
		ly += lineH
	}
}
