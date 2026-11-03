package engine

import (
	"context"
	"strings"
	"testing"
)

// TestTestOpenVPNNodesEmpty 保证「没给节点」这一路不会被当成一次真的探测：
// 它必须在碰网络（建 WARP 上游）之前就报错返回，否则界面点一下就要等 60s。
func TestTestOpenVPNNodesEmpty(t *testing.T) {
	b := &warpBackend{workDir: t.TempDir()}
	report := func(string) {}
	if _, err := b.TestOpenVPNNodes(context.Background(), nil, "", 0, report); err == nil {
		t.Fatal("空节点列表应当报错")
	}
	if _, err := b.TestOpenVPNNodes(context.Background(), []string{"不存在-1.2.3.4-1194"}, "", 0, report); err == nil {
		t.Fatal("缓存里没有配置的节点应当报错（提示先刷新列表）")
	}
}

// TestProbeSummary 对着界面日志里那句话做一次断言：成功要带毫秒数，失败要带原因。
func TestProbeSummary(t *testing.T) {
	ok := probeSummary(OpenVPNProbe{ID: "x", MS: 1234, OK: true})
	if !strings.Contains(ok, "成功") || !strings.Contains(ok, "1234ms") {
		t.Fatalf("成功结果格式不对: %q", ok)
	}
	bad := probeSummary(OpenVPNProbe{ID: "x", OK: false, Error: "AUTH_FAILED"})
	if !strings.Contains(bad, "失败") || !strings.Contains(bad, "AUTH_FAILED") {
		t.Fatalf("失败结果格式不对: %q", bad)
	}
}
