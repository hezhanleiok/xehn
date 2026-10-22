package warp

import (
	"net/netip"
	"strings"
)

// 分流规则（当前只在「仅代理」模式生效）。
//
// 为什么执行点在本地 SOCKS 服务：VPN 模式下我们只拿到 IP，**看不到域名**
// （HTTP/3 连 SNI 都嗅不到），按域名分流在那里做不到。代理模式的 SOCKS5 握手
// 本身就带目标域名，逐条判定才成立。设计见 docs/connection-modes-and-rules.md。

// RoutePolicy 是三种内置策略。
type RoutePolicy string

const (
	// PolicyGlobal：全部走隧道（默认）。
	PolicyGlobal RoutePolicy = "global"
	// PolicyBypassCN：大陆域名直连，其余走隧道。
	PolicyBypassCN RoutePolicy = "bypass-cn"
	// PolicyBlacklist：只有命中自定义规则里 proxy 的走隧道，其余直连。
	PolicyBlacklist RoutePolicy = "blacklist"
)

// RuleAction 是一条规则的动作。
type RuleAction string

const (
	ActionDirect RuleAction = "direct"
	ActionProxy  RuleAction = "proxy"
)

type rule struct {
	action RuleAction
	domain string       // 小写、无前导点；与 prefix 只会有一个有效
	prefix netip.Prefix // CIDR
}

// RuleSet 是「策略 + 自定义规则 + 内置表」的组合，只读，可并发使用。
type RuleSet struct {
	policy RoutePolicy
	custom []rule
}

// NormalizePolicy 把 UI/配置里的字符串规整成三种之一，未知值退回全局。
func NormalizePolicy(p string) RoutePolicy {
	switch RoutePolicy(strings.ToLower(strings.TrimSpace(p))) {
	case PolicyBypassCN:
		return PolicyBypassCN
	case PolicyBlacklist:
		return PolicyBlacklist
	default:
		return PolicyGlobal
	}
}

// NewRuleSet 解析策略与自定义规则文本。返回的第二个值是「跳过的行数」，
// 调用方应当把它写进日志 —— 规则写错时不能静默。
//
// 一行一条，`动作,目标`：
//
//	direct,example.com     # 该域名及其所有子域直连
//	proxy,1.2.3.0/24       # 该网段走隧道
//	direct,8.8.8.8         # 单个 IP
//
// 空行和 # 开头的行是注释；动作只认 direct / proxy。
func NewRuleSet(policy, text string) (*RuleSet, int) {
	rs := &RuleSet{policy: NormalizePolicy(policy)}
	skipped := 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// 允许行尾注释：`direct,a.com  # 备注`
		if i := strings.IndexAny(line, "#"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		action, target, ok := strings.Cut(line, ",")
		if !ok {
			skipped++
			continue
		}
		a := RuleAction(strings.ToLower(strings.TrimSpace(action)))
		if a != ActionDirect && a != ActionProxy {
			skipped++
			continue
		}
		target = strings.TrimSpace(target)
		if target == "" {
			skipped++
			continue
		}
		if p, err := netip.ParsePrefix(target); err == nil {
			rs.custom = append(rs.custom, rule{action: a, prefix: p.Masked()})
			continue
		}
		if addr, err := netip.ParseAddr(target); err == nil {
			rs.custom = append(rs.custom, rule{
				action: a,
				prefix: netip.PrefixFrom(addr, addr.BitLen()).Masked(),
			})
			continue
		}
		// 域名：去掉 * 与前导点，统一小写（`*.example.com` 与 `.example.com` 同义）
		d := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(target, "*"), "."))
		if d == "" || !strings.Contains(d, ".") && d != "localhost" {
			skipped++
			continue
		}
		// 长得像 IP/CIDR 却解析失败的（例如 `999.1.1.1/24`），绝不能被当成域名 ——
		// 那会变成一条永远匹配不上的规则，用户还以为自己分流生效了。
		if strings.Contains(d, "/") || strings.Trim(d, "0123456789.") == "" {
			skipped++
			continue
		}
		rs.custom = append(rs.custom, rule{action: a, domain: d})
	}
	return rs, skipped
}

// Policy 返回生效策略（给日志与 UI 用）。
func (r *RuleSet) Policy() RoutePolicy {
	if r == nil {
		return PolicyGlobal
	}
	return r.policy
}

// RuleCount 返回自定义规则条数。
func (r *RuleSet) RuleCount() int {
	if r == nil {
		return 0
	}
	return len(r.custom)
}

// Decide 决定一条连接走隧道（proxy）还是直连（direct）。
//
// 顺序：自定义规则（首个命中即停）→ 内置表（绕过大陆时的 CN 域名）→ 策略默认。
// host 可以是域名或 IP 字符串；两者都可能为空（只知道其中一个时）。
func (r *RuleSet) Decide(host string, ip netip.Addr) RuleAction {
	if r == nil {
		return ActionProxy
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if addr, err := netip.ParseAddr(host); err == nil && !ip.IsValid() {
		ip = addr
	}

	for _, ru := range r.custom {
		if ru.matches(host, ip) {
			return ru.action
		}
	}

	switch r.policy {
	case PolicyBypassCN:
		if isChinaDomain(host) {
			return ActionDirect
		}
		// IP 级大陆判定要完整的 CN CIDR 表（见 docs 第 4 节第 3 步），
		// 这一版还没有，所以 IP 目标一律走隧道 —— 宁可多走一点，也不误判直连。
		return ActionProxy
	case PolicyBlacklist:
		// 黑名单模式：只有规则里明确写 proxy 的才走隧道。
		return ActionDirect
	default:
		return ActionProxy
	}
}

func (ru rule) matches(host string, ip netip.Addr) bool {
	if ru.prefix.IsValid() {
		return ip.IsValid() && ru.prefix.Contains(ip)
	}
	if ru.domain == "" || host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false // 域名规则不匹配 IP 目标
	}
	return host == ru.domain || strings.HasSuffix(host, "."+ru.domain)
}

// builtinCNDomains 是「绕过大陆」用的内置域名表。
//
// 这是骨架，不是完整 geosite:cn：只覆盖最常见的站点，够验证分流是否生效。
// 完整数据（含 CN CIDR）按 docs 第 4 节第 3 步换掉这个常量。
// 全部按「后缀匹配」使用：写 example.com 会同时命中 www.example.com。
var builtinCNDomains = []string{
	"baidu.com", "bdstatic.com", "qq.com", "gtimg.com", "qpic.com", "qlogo.cn",
	"taobao.com", "tmall.com", "alicdn.com", "aliyun.com", "alipay.com", "aliyuncs.com",
	"jd.com", "360buyimg.com", "bilibili.com", "hdslb.com", "douyin.com",
	"bytedance.com", "byteimg.com", "toutiao.com", "weibo.com", "sina.com.cn",
	"sohu.com", "163.com", "126.net", "netease.com", "iqiyi.com", "youku.com",
	"zhihu.com", "douban.com", "csdn.net", "jianshu.com", "gitee.com",
	"mi.com", "xiaomi.com", "huawei.com", "oppo.com", "vivo.com", "meizu.com",
	"didi.com", "meituan.com", "dianping.com", "ctrip.com", "12306.cn",
	"zhaopin.com", "58.com", "kuaishou.com", "pinduoduo.com", "yangkeduo.com",
	"tencent.com", "weixin.qq.com", "wx.qq.com", "alibaba.com", "ximalaya.com",
}

// isChinaDomain 判断域名是否属于「绕过大陆」里的直连集合。
func isChinaDomain(host string) bool {
	if host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	if strings.HasSuffix(host, ".cn") || host == "cn" {
		return true
	}
	for _, d := range builtinCNDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
