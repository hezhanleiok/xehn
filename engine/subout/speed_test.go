package subout

import "testing"

// TestRankCacheRoundTrip 验证测速缓存能存能读，并且真的改变了节点顺序。
//
// 这条缓存是「第二次连接不用等 20–40 秒」的全部依据：写不进去或读不回来，
// 用户每次连都得重新测速，体验会退化回第一版。
func TestRankCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	saved := RankDir
	RankDir = dir
	t.Cleanup(func() { RankDir = saved })

	ranked := []RankResult{
		{Name: "slow", Bps: 1000},
		{Name: "fast", Bps: 9000},
	}
	if !SaveRank("ZZ", ranked) {
		t.Fatal("测速结果没写进缓存")
	}
	got := LoadRank("ZZ")
	if len(got) != 2 {
		t.Fatalf("缓存读回来 %d 条，期望 2", len(got))
	}

	nodes := []map[string]any{
		{"name": "slow", "type": "vless", "server": "1.2.3.4", "port": 443},
		{"name": "other", "type": "vless", "server": "1.2.3.5", "port": 443},
		{"name": "fast", "type": "vless", "server": "1.2.3.6", "port": 443},
	}
	sorted := SortByRank(nodes, got)
	if len(sorted) != 3 {
		t.Fatalf("排序后节点数变了：%d", len(sorted))
	}
	if sorted[0]["name"] != "fast" {
		t.Fatalf("最快的没排第一，实际是 %v", sorted[0]["name"])
	}
	if sorted[len(sorted)-1]["name"] != "other" {
		t.Fatalf("没测到的节点应排最后，实际是 %v", sorted[len(sorted)-1]["name"])
	}
}

// TestSortByRankIgnoresBadOrder 验证即使缓存的顺序是乱的，也按速度重排
// （旧版本写进去的数据没排好，不能照着用）。
func TestSortByRankIgnoresBadOrder(t *testing.T) {
	nodes := []map[string]any{
		{"name": "a", "type": "vless"},
		{"name": "b", "type": "vless"},
	}
	ranked := []RankResult{{Name: "a", Bps: 10}, {Name: "b", Bps: 900}}
	sorted := SortByRank(nodes, ranked)
	if sorted[0]["name"] != "b" {
		t.Fatalf("没按速度重排，第一名是 %v", sorted[0]["name"])
	}
}
