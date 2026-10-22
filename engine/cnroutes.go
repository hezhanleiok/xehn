package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xhwarp/android-engine/warp"
)

// 大陆 IP 段（CN CIDR）的运行时拉取。
//
// 为什么不在包里内置：这份数据每月都在变，内置就等于随包发一份会过期的快照，
// 而且 APK 立刻变大 200 KB。为什么是「连上之后再拉」：VpnService 的路由表必须在
// `establish()` 之前确定，那时隧道还没起来；被墙的网络里直接拉也拉不到。所以顺序
// 是「先用缓存连上 → 在隧道里拉 → 落盘 → 下次连接生效」（和 Psiphon 地区表同理）。

// cnRouteSources 是数据源，按顺序尝试。第一个是社区维护的 china_ip_list，
// 第二个是 clang.cn 的镜像；两个都拉不到就保留旧缓存，不做任何破坏性操作。
var cnRouteSources = []string{
	"https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
	"https://ispip.clang.cn/all_cn.txt",
}

const (
	// cnRoutesTTL 是缓存多久算过期。过期只是「该刷新了」，不影响使用。
	cnRoutesTTL = 7 * 24 * time.Hour
	// 少于这个条数就认为是坏数据（正常在 8000 条上下），宁可当没有。
	cnRoutesMinCount = 100
)

// cnRoutesPath 是缓存文件：一行一个 CIDR，文件 mtime 即拉取时间。
func (b *warpBackend) cnRoutesPath() string {
	return filepath.Join(b.workDir, "cn-cidrs.txt")
}

// needsCNRoutes 报告「现在该不该刷新大陆路由表」：
// 只有「绕过大陆」策略用得上它，且缓存缺失或过期才值得拉。
func (b *warpBackend) needsCNRoutes() bool {
	b.mu.Lock()
	rs := b.rules
	b.mu.Unlock()
	if rs.Policy() != warp.PolicyBypassCN {
		return false
	}
	cidrs, fetched := b.loadCNRoutes()
	return len(cidrs) == 0 || time.Since(fetched) > cnRoutesTTL
}

// CNRoutesInfoJSON 给设置页显示：条数、拉取时间、是否过期。
func (b *warpBackend) CNRoutesInfoJSON() string {
	cidrs, fetched := b.loadCNRoutes()
	info := map[string]any{
		"count":   len(cidrs),
		"fetched": fetched.UnixMilli(),
		"stale":   len(cidrs) == 0 || time.Since(fetched) > cnRoutesTTL,
		"path":    b.cnRoutesPath(),
	}
	raw, err := json.Marshal(info)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// loadCNRoutes 读缓存。返回条数与拉取时间（文件不存在时两者都为空/零）。
func (b *warpBackend) loadCNRoutes() ([]string, time.Time) {
	path := b.cnRoutesPath()
	st, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}
	}
	out := make([]string, 0, 8192)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, st.ModTime()
}

// refreshCNRoutes 拉一次并落盘，返回 (条数, 错误)。
//
// 调用时机很关键：必须在**隧道已经建立之后**调用 —— 在 fd 模式下这个 HTTP 请求
// 会被系统路由进 tun，也就是「用当前隧道拉」，被墙的网络里这是唯一可行的路径。
func (b *warpBackend) refreshCNRoutes(ctx context.Context, report func(string)) (int, error) {
	client := &http.Client{Timeout: 25 * time.Second}
	var lastErr error
	for _, src := range cnRouteSources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "xhwarp-android")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if report != nil {
				report(fmt.Sprintf("CN 路由表拉取失败（%s）：%v", hostOf(src), err))
			}
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if rerr != nil || resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", hostOf(src), resp.StatusCode)
			continue
		}
		cidrs := parseCIDRLines(string(body))
		if len(cidrs) < cnRoutesMinCount {
			lastErr = fmt.Errorf("%s: 只解析到 %d 条，数据不可信", hostOf(src), len(cidrs))
			if report != nil {
				report(lastErr.Error())
			}
			continue
		}
		if err := os.MkdirAll(b.workDir, 0o755); err != nil {
			return 0, err
		}
		if err := os.WriteFile(b.cnRoutesPath(), []byte(strings.Join(cidrs, "\n")+"\n"), 0o644); err != nil {
			return 0, err
		}
		if report != nil {
			report(fmt.Sprintf("CN 路由表已更新：%d 条（来源 %s）", len(cidrs), hostOf(src)))
		}
		return len(cidrs), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用数据源")
	}
	return 0, lastErr
}

// parseCIDRLines 只保留合法的 IPv4 CIDR 并去重。
//
// 只留 v4：IPv6 的 CN 段数据源不一致，而且多数手机网络是 v4 出口；v6 继续走全局。
func parseCIDRLines(text string) []string {
	seen := make(map[string]bool, 8192)
	out := make([]string, 0, 8192)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 有些源每行带逗号或空格分隔的附加字段，只取第一段。
		if i := strings.IndexAny(line, ", \t"); i > 0 {
			line = line[:i]
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		s := p.Masked().String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func hostOf(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rawURL = rawURL[i+3:]
	}
	if i := strings.IndexByte(rawURL, '/'); i > 0 {
		return rawURL[:i]
	}
	return rawURL
}
