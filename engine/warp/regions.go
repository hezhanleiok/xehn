package warp

import (
	"sort"
	"strings"
	"sync/atomic"
)

// Psiphon 的「落地地区」。
//
// 这里只有一套规则，三处共用（选择器展示 / 连接前预检 / 下发给 tunnel-core），
// 免得出现「界面上能选、实际没生效」这种自相矛盾。

// knownExitRegions 是「一次都没连过、它还没上报过」时的兜底列表。
//
// 抄的是 psiphon-tunnel-core 实测上报值（2026-10-21 日志）。
// 为什么不用一张「全世界国家」表：桌面版踩过 —— 手写的 44 国表里有 HK/TW/CN/RU，
// 选中之后 Psiphon 连三分钟然后失败，因为它的服务器根本不去那些地方落地。
// 列表必须只包含它真能给的地区，宁可少列。
var knownExitRegions = []string{
	"AT", "AU", "BE", "BR", "CA", "CH", "CZ", "DE", "DK", "ES",
	"FI", "FR", "GB", "ID", "IE", "IN", "IT", "JP", "LT", "NL",
	"NO", "PL", "RO", "RS", "SE", "SG", "US",
}

// psiphonRegions 是最近一次由 Psiphon 自己上报的地区表（AvailableEgressRegions）。
var psiphonRegions atomic.Value // []string

// SetPsiphonRegions 覆盖地区表：连接中由 notice 更新，启动时由磁盘缓存预置。
func SetPsiphonRegions(list []string) {
	if l := normalizeRegions(list); len(l) > 0 {
		psiphonRegions.Store(l)
	}
}

// PsiphonRegions 返回当前可用地区：上报优先，没有上报就用兜底表。
func PsiphonRegions() []string {
	if v, ok := psiphonRegions.Load().([]string); ok && len(v) > 0 {
		return append([]string(nil), v...)
	}
	return append([]string(nil), knownExitRegions...)
}

// PsiphonRegionsReported 报告当前表是不是「真实上报」—— 只有真实上报才值得落盘，
// 把兜底表当上报存下来会让下次启动误以为「上次连过」。
func PsiphonRegionsReported() bool {
	_, ok := psiphonRegions.Load().([]string)
	return ok
}

// NormalizeRegion 把用户输入规整成 ISO-3166-1 alpha-2（大写）。
// 空串（或 "auto" 之类不合法值）返回空串 = 自动，由 Psiphon 自己挑。
func NormalizeRegion(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 {
		return ""
	}
	for i := 0; i < 2; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return ""
		}
	}
	return s
}

// RegionOffered 是唯一的判定谓词：这个地区本次给不给。空串（自动）永远算给。
func RegionOffered(list []string, cc string) bool {
	cc = NormalizeRegion(cc)
	if cc == "" {
		return true
	}
	for _, r := range list {
		if r == cc {
			return true
		}
	}
	return false
}

// normalizeRegions 去重 + 只留合法的两位字母 + 排序（日志与 UI 都按字母序，
// 两次上报之间的顺序差异不会造成无谓的「列表变了」）。
func normalizeRegions(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		cc := NormalizeRegion(r)
		if cc == "" || seen[cc] {
			continue
		}
		seen[cc] = true
		out = append(out, cc)
	}
	sort.Strings(out)
	return out
}
