//go:build windows

package main

import (
	"context"
	"sort"
	"strings"

	"github.com/lxn/walk"
)

// ---------------------------------------------------------------------------
// 订阅管理：导入（名字 + 地址 + 分组）、编辑、删除、切换。
//
// 视图过滤 ActiveSub 只决定节点页显示哪一份订阅；连接管线仍用 ActiveProxy 跑
// 全量 CustomProxies，所以切换视图不会断开正在跑的隧道。
// ---------------------------------------------------------------------------

// The manager list shows at most this many rows before it scrolls; the wheel
// handler needs the same two numbers the painter uses.
const (
	subMgrMaxRows  = 7
	subMgrRowH     = 50.0
	subRefreshBtnW = 34.0
)

// promptSubscription 是订阅导入/编辑框：名字、（URL 源才有的）地址、分组三个
// 字段。seed 携带已有值（编辑时）与 Kind/ID；showURL 决定是否显示地址栏。返回
// 的 SubSource 保留 seed.ID（新导入时为空，末尾生成），名字留空则按地址主机名
// 自动命名。校验失败时对话框保持打开并在框内报错。
func (u *natUI) promptSubscription(title string, seed SubSource, showURL bool) (SubSource, bool) {
	dlg, err := walk.NewDialogWithFixedSize(u.mw)
	if err != nil {
		u.addLog(tr("打开输入框失败")+": "+err.Error(), true)
		return SubSource{}, false
	}
	bg, _ := walk.NewSolidColorBrush(dialogSurface())
	if bg != nil {
		dlg.SetBackground(bg)
	}
	icon := styleDialog(dlg)
	defer func() {
		dlg.Dispose()
		if icon != nil {
			icon.Dispose()
		}
		if bg != nil {
			bg.Dispose()
		}
	}()
	dlg.SetTitle(title)

	vbox := walk.NewVBoxLayout()
	_ = vbox.SetMargins(walk.Margins{HNear: 24, VNear: 18, HFar: 24, VFar: 16})
	_ = vbox.SetSpacing(6)
	if err := dlg.SetLayout(vbox); err != nil {
		u.addLog(tr("输入框布局失败")+": "+err.Error(), true)
		return SubSource{}, false
	}

	addField := func(label, value string, maxLen int) *walk.LineEdit {
		if lbl, lerr := walk.NewLabel(dlg); lerr == nil {
			_ = lbl.SetText(label)
			lbl.SetTextColor(rx(96, 104, 120))
		}
		le, lerr := walk.NewLineEdit(dlg)
		if lerr != nil {
			return nil
		}
		_ = le.SetText(value)
		le.SetMaxLength(maxLen)
		le.SetTextColor(rx(28, 32, 40))
		_ = le.SetMinMaxSize(walk.Size{Width: 420, Height: 26}, walk.Size{Width: 420})
		return le
	}

	nameLE := addField(tr("订阅名字"), seed.Name, 64)
	var urlLE *walk.LineEdit
	if showURL {
		urlLE = addField(tr("订阅地址"), seed.URL, 512)
	}
	groupLE := addField(tr("分组（可选，如「机场」「自建」）"), seed.Group, 32)
	if nameLE == nil || groupLE == nil || (showURL && urlLE == nil) {
		u.addLog(tr("输入框创建失败"), true)
		return SubSource{}, false
	}

	errLabel, _ := walk.NewLabel(dlg)
	if errLabel != nil {
		_ = errLabel.SetText(" ")
		errLabel.SetTextColor(rx(198, 60, 60))
	}

	row, err := walk.NewComposite(dlg)
	if err != nil {
		u.addLog(tr("输入框创建失败")+": "+err.Error(), true)
		return SubSource{}, false
	}
	hbox := walk.NewHBoxLayout()
	_ = hbox.SetMargins(walk.Margins{})
	_ = hbox.SetSpacing(8)
	_ = row.SetLayout(hbox)
	if sp, serr := walk.NewHSpacer(row); serr == nil {
		_ = sp
	}
	ok, err := walk.NewPushButton(row)
	if err != nil {
		u.addLog(tr("输入框创建失败")+": "+err.Error(), true)
		return SubSource{}, false
	}
	_ = ok.SetText(tr("确定"))
	_ = ok.SetMinMaxSize(walk.Size{Width: 92, Height: 30}, walk.Size{Width: 92, Height: 30})
	cancel, err := walk.NewPushButton(row)
	if err != nil {
		u.addLog(tr("输入框创建失败")+": "+err.Error(), true)
		return SubSource{}, false
	}
	_ = cancel.SetText(tr("取消"))
	_ = cancel.SetMinMaxSize(walk.Size{Width: 92, Height: 30}, walk.Size{Width: 92, Height: 30})
	_ = dlg.SetDefaultButton(ok)
	_ = dlg.SetCancelButton(cancel)

	accepted := seed
	fail := func(msg string, focus *walk.LineEdit) {
		if errLabel != nil {
			_ = errLabel.SetText("⚠ " + msg)
		}
		if focus != nil {
			focus.SetFocus()
		}
	}
	submit := func() {
		name := strings.TrimSpace(normalizeFieldInput(nameLE.Text()))
		group := strings.TrimSpace(normalizeFieldInput(groupLE.Text()))
		url := ""
		if urlLE != nil {
			url = strings.TrimSpace(normalizeFieldInput(urlLE.Text()))
		}
		if showURL {
			if url == "" {
				fail(tr("请输入订阅地址"), urlLE)
				return
			}
			if !isSubscriptionURL(url) {
				fail(tr("订阅地址需以 http:// 或 https:// 开头"), urlLE)
				return
			}
		}
		if name == "" {
			if url != "" {
				name = subNameFromURL(url)
			} else {
				name = tr("订阅")
			}
		}
		kind := seed.Kind
		if kind == "" {
			if url != "" {
				kind = "url"
			} else {
				kind = "single"
			}
		}
		accepted = SubSource{ID: seed.ID, Name: name, URL: url, Group: group, Kind: kind}
		dlg.Accept()
	}
	ok.Clicked().Attach(submit)
	cancel.Clicked().Attach(func() { dlg.Cancel() })
	if showURL && seed.URL == "" {
		urlLE.SetFocus()
	} else {
		nameLE.SetFocus()
		nameLE.SetTextSelection(0, len([]rune(seed.Name)))
	}

	if dlg.Run() != walk.DlgCmdOK {
		return SubSource{}, false
	}
	if accepted.ID == "" {
		accepted.ID = newSubID()
	}
	return accepted, true
}

// modeSubAnchor is the subscription pill in the nodes-page top bar (left of the
// search box). Its width adapts to the space the right-aligned button group
// leaves, so the pill never collides with search at the minimum window width.
func (u *natUI) modeSubAnchor(x, w float64) (float64, float64, float64, float64) {
	// The pill belongs to the right-aligned tool group, not to the page head:
	// the "模式" title and its subtitle own the left edge of the same band, so
	// the pill is right-aligned against the search box (add 76 + gap 8 + delay
	// 92 + gap 8 + search 250 = 434), leaving room for the refresh button on
	// its right, and only grows leftward while it still clears the head.
	right := x + w - 434 - 8
	pillRight := right - subRefreshBtnW - 8
	pw := 220.0
	if minLeft := x + 190; pillRight-pw < minLeft {
		pw = pillRight - minLeft
	}
	if pw < 110 {
		return pillRight, 20, 0, 34 // no room: the head and search keep the band
	}
	return pillRight - pw, 20, pw, 34
}

// paintSubPill draws the current-subscription selector plus the refresh button
// that re-pulls it. It yields to the search box when the window is too narrow.
func (u *natUI) paintSubPill(c *walk.Canvas, x, w float64) {
	px, py, pw, ph := u.modeSubAnchor(x, w)
	if pw < 110 {
		return
	}
	r := u.r(px, py, pw, ph)
	u.fillRound(c, th.chip, r, ctrlRadius)
	u.strokeRound(c, th.line, r, ctrlRadius)
	u.icon(c, "list", px+12, py+9, 16, th.accent2)
	label := tr("全部订阅")
	if src := u.m.set.subSourceByID(u.m.set.ActiveSub); src != nil {
		label = src.Name
	}
	u.txt(c, px+34, py+8, pw-58, 18, label, u.f.f9, th.text)
	u.icon(c, "chevron", px+pw-22, py+12, 12, th.dim)
	u.addSpot("drop:submgr", r, true)

	// Refresh: re-download the subscription in view so a node list that changed
	// on the server shows up without re-importing anything.
	busy := u.subRefreshBusy.Load()
	bx := px + pw + 8
	br := u.r(bx, py, subRefreshBtnW, ph)
	if !busy && u.m.hover == "subrefreshcur" {
		u.fillRound(c, th.cardHover, br, ctrlRadius)
	}
	u.strokeRound(c, th.line, br, ctrlRadius)
	col := th.dim
	if busy {
		col = th.faint
	}
	u.icon(c, "refresh", bx+(subRefreshBtnW-16)/2, py+9, 16, col)
	if !busy {
		u.addSpot("subrefreshcur", br, true)
	}
}

// paintSubMgrPopup is the subscription manager: a fixed "全部订阅" row, the
// scrollable list of sources (sorted by group then name, each with edit/delete),
// and a fixed "导入订阅" footer. Clicking a row body switches the view to it.
func (u *natUI) paintSubMgrPopup(c *walk.Canvas, ax, ay, aw, ah float64) {
	subs := append([]SubSource(nil), u.m.set.SubSources...)
	sort.SliceStable(subs, func(i, j int) bool {
		if subs[i].Group != subs[j].Group {
			return subs[i].Group < subs[j].Group
		}
		return subs[i].Name < subs[j].Name
	})
	const (
		headH = 30.0
		allH  = 42.0
		rowH  = subMgrRowH
		footH = 42.0
		pad   = 8.0
	)
	visible := len(subs)
	if visible > subMgrMaxRows {
		visible = subMgrMaxRows
	}
	if visible < 1 {
		visible = 1
	}
	listH := float64(visible) * rowH
	ph := pad*2 + headH + allH + listH + footH
	pw := 360.0
	px := ax
	if px+pw > u.dw-8 {
		px = u.dw - 8 - pw
	}
	if px < 8 {
		px = 8
	}
	py := popupBelow(ay, ah, ph)
	box := u.r(px, py, pw, ph)
	u.shadowRound(c, box, panelRadius, shadowTint(), th.window)
	u.fillRound(c, th.overlay, box, panelRadius)
	u.strokeRound(c, th.line, box, panelRadius)

	u.txt(c, px+16, py+pad, pw-140, headH, tr("订阅管理"), u.f.f9, th.faint)
	u.textR(c, trf("%d 个订阅", len(subs)), u.f.f8, th.faint, u.r(px+pw-118, py+pad, 102, headH))

	// "全部订阅" row.
	allY := py + pad + headH
	u.hline(c, px+12, allY, pw-24, th.line2)
	allR := u.r(px+8, allY+4, pw-16, allH-8)
	switch {
	case u.m.set.ActiveSub == "":
		u.fillRound(c, mix(th.accent2, th.card, 0.90), allR, ctrlRadius)
	case u.m.hover == "subswitch:":
		u.fillRound(c, th.cardHover, allR, ctrlRadius)
	}
	u.icon(c, "globe", px+18, allY+(allH-16)/2, 16, th.accent2)
	u.txt(c, px+44, allY+5, pw-100, 18, tr("全部订阅"), u.f.f10b, th.text)
	u.txt(c, px+44, allY+23, pw-100, 14, trf("显示全部 %d 个节点", len(u.m.set.CustomProxies)), u.f.f8, th.dim)
	if u.m.set.ActiveSub == "" {
		u.textC(c, "✓", u.f.f12b, th.accent2, u.r(px+pw-44, allY, 32, allH))
	}
	u.addSpot("subswitch:", allR, true)

	// Source list.
	listY := allY + allH
	maxScroll := len(subs) - visible
	if maxScroll < 0 {
		maxScroll = 0
	}
	if u.m.subMgrScroll > maxScroll {
		u.m.subMgrScroll = maxScroll
	}
	if u.m.subMgrScroll < 0 {
		u.m.subMgrScroll = 0
	}
	if len(subs) == 0 {
		u.textC(c, tr("还没有订阅，点下方「导入订阅」"), u.f.f9, th.faint, u.r(px+16, listY+12, pw-32, 24))
	}
	for i := 0; i < visible; i++ {
		idx := u.m.subMgrScroll + i
		if idx >= len(subs) {
			break
		}
		src := subs[idx]
		ry := listY + float64(i)*rowH
		rr := u.r(px+8, ry+2, pw-16, rowH-4)
		active := src.ID == u.m.set.ActiveSub
		bodyID := "subswitch:" + src.ID
		switch {
		case active:
			u.fillRound(c, mix(th.accent2, th.card, 0.90), rr, ctrlRadius)
		case u.m.hover == bodyID:
			u.fillRound(c, th.cardHover, rr, ctrlRadius)
		}
		u.txt(c, px+18, ry+6, pw-118, 18, clipName(src.Name), u.f.f10b, th.text)
		group := src.Group
		if group == "" {
			group = tr("未分组")
		}
		u.txt(c, px+18, ry+26, pw-118, 14, group+" · "+trf("%d 个节点", u.m.set.nodesOfSub(src.ID)), u.f.f8, th.dim)
		if active {
			u.textC(c, "✓", u.f.f10b, th.accent2, u.r(px+pw-110, ry, 22, rowH))
		}
		// Body click switches; the icon buttons sit to its right and are added
		// last so they win any hit-test overlap.
		u.addSpot(bodyID, u.r(px+8, ry+2, pw-16-70, rowH-4), true)
		u.iconButton(c, px+pw-72, ry+(rowH-28)/2, 28, "subedit:"+src.ID, "edit", true)
		u.iconButton(c, px+pw-40, ry+(rowH-28)/2, 28, "subdel:"+src.ID, "trash", true)
	}
	if maxScroll > 0 {
		thumbH := listH * float64(visible) / float64(len(subs))
		if thumbH < 20 {
			thumbH = 20
		}
		thumbY := listY + (listH-thumbH)*float64(u.m.subMgrScroll)/float64(maxScroll)
		u.fillRound(c, th.line, u.r(px+pw-6, listY, 3, listH), 2)
		u.fillRound(c, th.faint, u.r(px+pw-6, thumbY, 3, thumbH), 2)
	}

	// "导入订阅" footer.
	footY := listY + listH
	u.hline(c, px+12, footY, pw-24, th.line2)
	footR := u.r(px+8, footY+4, pw-16, footH-8)
	if u.m.hover == "submgr:import" {
		u.fillRound(c, th.cardHover, footR, ctrlRadius)
	}
	u.icon(c, "link", px+18, footY+(footH-16)/2, 16, th.accent2)
	u.txt(c, px+44, footY+5, pw-80, 18, tr("导入订阅"), u.f.f10b, th.accent2)
	u.txt(c, px+44, footY+23, pw-80, 14, tr("名字 + 地址 + 分组"), u.f.f8, th.dim)
	u.addSpot("submgr:import", footR, true)
}

// switchSubscription changes the node-page view filter. It is not a connection
// change, so it saves without marking the session dirty.
func (u *natUI) switchSubscription(id string) {
	u.m.dropOpen = ""
	if id != "" && u.m.set.subSourceByID(id) == nil {
		return
	}
	u.m.set.ActiveSub = id
	u.m.scroll = 0
	if err := saveSettings(u.m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	}
	if id == "" {
		u.addLog(tr("已切换到全部订阅"), false)
	} else {
		u.addLog(tr("已切换订阅")+": "+u.m.set.subSourceByID(id).Name, false)
	}
	u.invalidate()
}

// editSubscription edits a source's name/group/URL. A changed URL re-fetches
// that source's nodes; name/group are metadata only.
func (u *natUI) editSubscription(id string) {
	src := u.m.set.subSourceByID(id)
	if src == nil {
		return
	}
	old := *src
	edited, ok := u.promptSubscription(tr("编辑订阅"), old, old.Kind == "url")
	if !ok {
		return
	}
	edited.ID = old.ID
	edited.Kind = old.Kind
	urlChanged := old.Kind == "url" && edited.URL != old.URL
	*src = edited
	if err := saveSettings(u.m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	}
	u.addLog(tr("已保存订阅")+": "+edited.Name, false)
	u.invalidate()
	if urlChanged {
		u.refetchOneSource(edited)
	}
}

// deleteSubscription removes a source and its nodes after confirmation, then
// repairs the view filter and the active front node so neither names a ghost.
func (u *natUI) deleteSubscription(id string) {
	src := u.m.set.subSourceByID(id)
	if src == nil {
		return
	}
	n := u.m.set.nodesOfSub(id)
	if !u.confirm(tr("删除订阅"), trf("删除「%s」及其 %d 个节点？此操作不可撤销。", src.Name, n)) {
		return
	}
	subs := u.m.set.SubSources[:0]
	for _, s := range u.m.set.SubSources {
		if s.ID != id {
			subs = append(subs, s)
		}
	}
	u.m.set.SubSources = subs
	nodes := u.m.set.CustomProxies[:0]
	for _, p := range u.m.set.CustomProxies {
		if p.SubID != id {
			nodes = append(nodes, p)
		}
	}
	u.m.set.CustomProxies = nodes
	if u.m.set.ActiveSub == id {
		u.m.set.ActiveSub = ""
	}
	found := false
	for _, p := range u.m.set.CustomProxies {
		if p.Name == u.m.set.ActiveProxy {
			found = true
			break
		}
	}
	if !found {
		u.m.set.ActiveProxy = ""
		if len(u.m.set.CustomProxies) > 0 {
			u.m.set.ActiveProxy = u.m.set.CustomProxies[0].Name
		}
	}
	if u.m.connected {
		u.m.setDirty = true
	}
	if err := saveSettings(u.m.set); err != nil {
		u.addLog(tr("设置保存失败: ")+err.Error(), true)
	}
	u.addLog(tr("已删除订阅")+": "+src.Name, false)
	u.m.scroll = 0
	u.invalidate()
}

// refetchOneSource re-downloads a single URL source and replaces just its nodes,
// keeping every other source's nodes and the measurements already paid for. On
// failure the old nodes are left intact.
func (u *natUI) refetchOneSource(src SubSource) {
	if src.Kind != "url" || src.URL == "" {
		return
	}
	if !u.subRefreshBusy.CompareAndSwap(false, true) {
		u.addLog(tr("订阅刷新正在进行中"), false)
		return
	}
	u.addLog(trf("更新订阅：%s…", src.Name), false)
	u.invalidate()
	go func() {
		defer u.subRefreshBusy.Store(false)
		ctx, cancel := context.WithTimeout(u.ctx, subscriptionTotalTimeout)
		body, err := FetchSubscription(ctx, src.URL, defaultFetchTimeout)
		cancel()
		var parsed *ParsedInput
		if err == nil {
			parsed, err = ParseSubscription(body)
		}
		u.sync(func() {
			if err != nil {
				u.addLog(tr("订阅更新失败")+": "+err.Error(), true)
				u.invalidate()
				return
			}
			// The source may have been deleted while the fetch was in flight;
			// writing its nodes back would resurrect a subscription the user
			// just removed.
			if u.m.set.subSourceByID(src.ID) == nil {
				u.addLog(tr("订阅更新完成：该订阅已被删除，未写回节点"), false)
				u.invalidate()
				return
			}
			var keep []ProxySpec
			oldMS := map[string]ProxySpec{}
			for _, p := range u.m.set.CustomProxies {
				if p.SubID != src.ID {
					keep = append(keep, p)
				}
				oldMS[p.Name] = p
			}
			seen := map[string]bool{}
			for _, p := range keep {
				seen[p.Name] = true
			}
			all := keep
			for _, p := range parsed.Proxies {
				if p.Name == "" || seen[p.Name] {
					continue
				}
				seen[p.Name] = true
				p.SubID = src.ID
				if old, ok := oldMS[p.Name]; ok {
					p.DelayMS, p.DelayErr, p.CC = old.DelayMS, old.DelayErr, old.CC
				}
				all = append(all, p)
			}
			u.m.set.CustomProxies = all
			found := false
			for _, p := range all {
				if p.Name == u.m.set.ActiveProxy {
					found = true
					break
				}
			}
			if !found && len(all) > 0 {
				u.m.set.ActiveProxy = all[0].Name
			}
			if serr := saveSettings(u.m.set); serr != nil {
				u.addLog(tr("设置保存失败: ")+serr.Error(), true)
			}
			u.addLog(trf("订阅更新完成：%d 个节点", len(parsed.Proxies)), false)
			u.invalidate()
			// Fresh endpoints deserve a fresh measurement, same as an import.
			u.autoDelayTest()
		})
	}()
}

// refreshCurrentSub re-pulls the subscription the node page is filtered to, or
// every URL source when the view is "全部订阅". It is the toolbar refresh
// button's action: the node list follows the server without a re-import.
func (u *natUI) refreshCurrentSub() {
	u.m.dropOpen = ""
	u.invalidate()
	if src := u.m.set.subSourceByID(u.m.set.ActiveSub); src != nil {
		if src.Kind != "url" || src.URL == "" {
			u.addLog(tr("「")+src.Name+tr("」不是订阅链接，没有可刷新的节点"), true)
			return
		}
		u.refetchOneSource(*src)
		return
	}
	u.refreshSubscriptions()
}

// subMgrImport closes the manager and opens the import dialog.
func (u *natUI) subMgrImport() {
	u.m.dropOpen = ""
	u.invalidate()
	u.importSubscriptionURL()
}
