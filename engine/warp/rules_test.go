package warp

import (
	"net/netip"
	"testing"
)

func mustIP(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad ip %q: %v", s, err)
	}
	return a
}

// 自定义规则必须「首个命中即停」，并且域名规则要覆盖子域。
func TestRuleSetDecideCustom(t *testing.T) {
	rs, skipped := NewRuleSet("global", `
# 注释行
direct,example.com

proxy,1.2.3.0/24
direct,8.8.8.8
`)
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	cases := []struct {
		host string
		ip   netip.Addr
		want RuleAction
	}{
		{"example.com", netip.Addr{}, ActionDirect},
		{"www.example.com", netip.Addr{}, ActionDirect}, // 子域
		{"notexample.com", netip.Addr{}, ActionProxy},   // 不能误伤
		{"", mustIP(t, "1.2.3.4"), ActionProxy},         // CIDR 命中
		{"", mustIP(t, "1.2.4.4"), ActionProxy},         // 不在 CIDR 里，走默认
		{"", mustIP(t, "8.8.8.8"), ActionDirect},        // 单 IP
	}
	for _, c := range cases {
		if got := rs.Decide(c.host, c.ip); got != c.want {
			t.Errorf("Decide(%q,%v) = %s, want %s", c.host, c.ip, got, c.want)
		}
	}
	if rs.RuleCount() != 3 {
		t.Errorf("RuleCount = %d, want 3", rs.RuleCount())
	}
}

// 三种策略的默认动作：全局=代理、黑名单=直连、绕过大陆=按域名。
func TestRuleSetPolicyDefaults(t *testing.T) {
	global, _ := NewRuleSet("global", "")
	if got := global.Decide("example.org", netip.Addr{}); got != ActionProxy {
		t.Errorf("global: got %s, want proxy", got)
	}

	// 黑名单模式：只有规则里写 proxy 的才走隧道。
	bl, _ := NewRuleSet("blacklist", "proxy,blocked.example\n")
	if got := bl.Decide("other.example", netip.Addr{}); got != ActionDirect {
		t.Errorf("blacklist default: got %s, want direct", got)
	}
	if got := bl.Decide("api.blocked.example", netip.Addr{}); got != ActionProxy {
		t.Errorf("blacklist hit: got %s, want proxy", got)
	}

	// 绕过大陆：.cn 与内置表直连，其余走隧道。
	cn, _ := NewRuleSet("bypass-cn", "")
	for _, h := range []string{"www.taobao.com", "foo.gov.cn", "bilibili.com"} {
		if got := cn.Decide(h, netip.Addr{}); got != ActionDirect {
			t.Errorf("bypass-cn %q: got %s, want direct", h, got)
		}
	}
	if got := cn.Decide("example.org", netip.Addr{}); got != ActionProxy {
		t.Errorf("bypass-cn foreign: got %s, want proxy", got)
	}
}

// 写错的行要被计数（引擎会写日志），不能静默吞掉。
func TestRuleSetSkipsBadLines(t *testing.T) {
	rs, skipped := NewRuleSet("global", `
whatever,example.com
direct
direct,
proxy,999.1.1.1/24
direct,good.example
`)
	if skipped != 4 {
		t.Errorf("skipped = %d, want 4", skipped)
	}
	if rs.RuleCount() != 1 {
		t.Errorf("RuleCount = %d, want 1", rs.RuleCount())
	}
}

// nil 规则集等于「全部走隧道」——Psiphon 的上游 SOCKS 就是靠这个保证不被分流。
func TestNilRuleSetIsAllProxy(t *testing.T) {
	var rs *RuleSet
	if got := rs.Decide("example.com", netip.Addr{}); got != ActionProxy {
		t.Errorf("nil RuleSet: got %s, want proxy", got)
	}
	if rs.RuleCount() != 0 || rs.Policy() != PolicyGlobal {
		t.Errorf("nil RuleSet accessors misbehave")
	}
}
