//go:build windows

package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lxn/walk"

	"github.com/xhwarp/warp-client/internal/core"
)

// This file is the home traffic card's data layer: the live application-share
// poll, the connection classifier behind it, the byte/axis formatters, and the
// latency-sorted node list the home front-node picker reads. Painting lives in
// gui_page_home_windows.go; nothing here draws.
//
// Honesty rule: every number the share band shows is classified from the core's
// real /connections table. A session with no classified bytes hides the band
// rather than drawing a fabricated split, and the cumulative session total is a
// separate counter (the core's uploadTotal/downloadTotal), labelled differently
// so the two real figures are never conflated.

// Share category slots, indexed into natModel.shareBytes. The order matches the
// reference legend and the donut/bar colour order in shareCats.
const (
	shareStream = iota // 流媒体视频
	shareWeb           // 网页浏览
	shareFile          // 文件传输
	shareGame          // 游戏加速
	shareOther         // 其他
)

// Classification keyword sets. The haystack is the lowercased process, process
// path, host, rule, rule payload and chain names of one live connection — enough
// to place the overwhelming majority of real traffic without a geo database.
// Order matters: a game launcher that also streams is a game, a video site is
// streaming before it is generic web, and a download tool is file transfer.
var (
	streamKeys = []string{
		"youtube", "netflix", "twitch", "bilibili", "douyin", "tiktok", "spotify",
		"hulu", "disney", "iqiyi", "youku", "v.qq", "video", "stream", "media",
		"plex", "emby", "jellyfin", "abema", "niconico", "wetv", "mgtv", "hbo",
		"primevideo", "soundcloud", "podcast",
	}
	gameKeys = []string{
		"steam", "epicgames", "riot", "league", "valorant", "battle.net",
		"blizzard", "origin", "ea.com", "playstation", "xbox", "nintendo",
		"genshin", "mihoyo", "hoyoverse", "pubg", "fortnite", "minecraft",
		"roblox", "game", "gaming", "wow", "dota", "csgo", "apex", "overwatch",
	}
	fileKeys = []string{
		"download", "torrent", "qbittorrent", "transmission", "aria2", "thunder",
		"xunlei", "baidunetdisk", "pan.baidu", "aliyundrive", "115", "mega",
		"dropbox", "onedrive", "drive.google", "sftp", "ftp", "rsync", "wget",
		"curl", "idm", "fdm", "windowsupdate", "delivery", "update",
	}
)

// classifyConn places one live connection into a share category. Game wins over
// streaming wins over file transfer; anything else with a host is web browsing,
// and a bare IP connection with no signal at all is "other".
func classifyConn(c core.Connection) int {
	hay := strings.ToLower(c.Metadata.Process + " " + c.Metadata.ProcessPath + " " +
		c.Metadata.Host + " " + c.Rule + " " + c.RulePayload + " " + strings.Join(c.Chains, " "))
	switch {
	case containsAny(hay, gameKeys):
		return shareGame
	case containsAny(hay, streamKeys):
		return shareStream
	case containsAny(hay, fileKeys):
		return shareFile
	case c.Metadata.Host != "":
		return shareWeb
	default:
		return shareOther
	}
}

// shareLoop polls the core's connection table every 2s while a session is up and
// publishes the per-category byte split plus the cumulative session totals. It
// reads the disk state (like statusLoop) rather than the model off-thread, and
// only publishes through u.sync while still connected, so a disconnect that
// lands during the fetch is not undone by a stale snapshot.
func (u *natUI) shareLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-t.C:
		}
		st, err := loadState()
		if err != nil || !st.Connected || st.APIPort == 0 {
			continue
		}
		snap, err := core.Connections(st.APIPort)
		if err != nil || snap == nil {
			continue
		}
		var bytes [5]int64
		var total int64
		for _, conn := range snap.Connections {
			b := conn.Upload + conn.Download
			if b <= 0 {
				continue
			}
			bytes[classifyConn(conn)] += b
			total += b
		}
		up, down := snap.UploadTotal, snap.DownloadTotal
		u.sync(func() {
			if !u.m.connected {
				return
			}
			u.m.shareBytes = bytes
			u.m.shareTotal = total
			u.m.sessionUp = up
			u.m.sessionDown = down
			u.invalidate()
		})
	}
}

// byteText formats a cumulative byte count for the stat tiles and share rows.
func byteText(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// nicePeak rounds a bytes/sec peak up to a clean 1/2/5 × 10^n axis maximum so the
// gridline labels read as round numbers. The floor keeps an idle chart from
// collapsing to a zero scale.
func nicePeak(v int64) int64 {
	const floor = 1 << 10 // 1 KB/s
	if v < floor {
		return floor
	}
	mag := int64(1)
	for mag*10 <= v {
		mag *= 10
	}
	for _, m := range []int64{1, 2, 5, 10} {
		if mag*m >= v {
			return mag * m
		}
	}
	return mag * 10
}

// axisRate labels a gridline at fraction f of the peak, in the unit that keeps
// the number short: MB/s for big peaks, KB/s otherwise, and a bare 0 at the base.
func axisRate(peak int64, f float64) string {
	v := int64(float64(peak) * f)
	if v <= 0 {
		return "0"
	}
	if peak >= 1<<20 {
		return fmt.Sprintf("%.0f MB/s", float64(v)/(1<<20))
	}
	return fmt.Sprintf("%.0f KB/s", float64(v)/(1<<10))
}

// maxSeries is the largest sample across two rate rings, the chart's raw peak.
func maxSeries(a, b []int64) int64 {
	var m int64
	for _, v := range a {
		if v > m {
			m = v
		}
	}
	for _, v := range b {
		if v > m {
			m = v
		}
	}
	return m
}

// lastN returns the final n samples of a ring (or the whole ring if shorter).
func lastN(a []int64, n int) []int64 {
	if len(a) > n {
		return a[len(a)-n:]
	}
	return a
}

// homeNodeRows is every imported front node, latency-sorted (measured ascending,
// then untested, then dead), independent of the node page's search/sort state —
// the home picker always shows the full list in quality order.
func (u *natUI) homeNodeRows() []ProxySpec {
	out := append([]ProxySpec(nil), u.m.set.CustomProxies...)
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
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
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

// homeNodeVisible is how many list rows fit between the pill and the frame,
// whichever side (below or above) has more room. It mirrors paintHomeNodePopup's
// fixed chrome so the wheel's scroll bound and the painted row count agree.
func (u *natUI) homeNodeVisible() int {
	g := u.homeLayout()
	const fixed = 30 + 44 + 32 + 16 // head + auto + foot + padding
	const rowH = 36.0
	below := u.dh - 8 - (g.ddY + g.ddH + 8)
	above := g.ddY - 16
	avail := below
	if above > avail {
		avail = above
	}
	v := int((avail - fixed) / rowH)
	if v < 1 {
		v = 1
	}
	if v > 8 {
		v = 8
	}
	if n := len(u.homeNodeRows()); v > n {
		v = n
	}
	return v
}

// homeActiveProxy resolves the node the home pill names: the auto pick (lowest
// measured latency) when auto-select is on, otherwise the manual ActiveProxy,
// falling back to the first sorted row. It returns the node's flag and measured
// delay so the pill can show them without a second lookup.
func (u *natUI) homeActiveProxy() (name, cc string, ms int, hasMS bool) {
	rows := u.homeNodeRows()
	if len(rows) == 0 {
		return "", "", 0, false
	}
	pick := u.m.set.ActiveProxy
	if u.m.set.SubAutoSelect {
		if best := bestMeasuredProxy(rows); best != "" {
			pick = best
		}
	}
	if pick == "" {
		pick = rows[0].Name
	}
	for _, p := range rows {
		if p.Name == pick {
			return p.Name, p.CC, p.DelayMS, p.DelayMS > 0
		}
	}
	// ActiveProxy may name a node that is no longer in the list.
	return pick, "", 0, false
}

// homeLatColor is the delay colour ramp shared by the pill and the node rows:
// green under 100ms, amber under 200ms, red beyond, faint when unmeasured.
// homeLatColor grades a measured delay. The bands are wide on purpose: a CDN
// front node across the Pacific legitimately sits at 200-300ms, and painting it
// red read as "this node is broken" while the same node pulled 700+ Mbps in a
// speed test. Green now means "normal for a cross-border tunnel".
func homeLatColor(ms int) walk.Color {
	switch {
	case ms <= 0:
		return th.faint
	case ms < 250:
		return th.ok2
	case ms < 600:
		return th.warn
	default:
		return th.bad
	}
}