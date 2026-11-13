package subout

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Options 是一次「订阅出口」启动所需的全部参数。
type Options struct {
	// TUNFD 是 VpnService 建好的 tun fd，交给 mihomo 的 tun（file-descriptor 模式）。
	//
	// 关键前提：**引擎必须用 `-tags cmfa` 编译**。mihomo 的
	// `listener/sing_tun/server_android.go` 构建条件是 `android && !cmfa`，它会在建
	// tun 时读 /data/system/packages.xml 生成 UID 分应用规则 —— 非 root 必然
	// `permission denied`，而且返回 error 导致 tun 根本起不来（真机日志：
	// `Start TUN listening error: build android rules: ... permission denied`）。
	// 带 cmfa 后走空实现，tun 正常启动（CMFA 官方同款做法）。
	TUNFD int
	// MixedPort 是 mihomo 的 SOCKS/HTTP 入站（保留：本地代理/调试可用）。
	MixedPort int
	// DNSPort 是 mihomo 的 DNS 监听端口。
	DNSPort int
	// Interface 是物理网卡名（wlan0 / rmnet_data0 …）。
	//
	// 必须绑它：mihomo 的出口 socket、DNS 查询都要绕开 VPN 路由，否则会
	// 「自己抓自己」—— 表现是连上就卡死、DNS 解析超时。
	Interface string
	// MTU 与 tun 一致（WARP 1280 / 订阅出口同样 1280）。
	MTU int
	// BridgeAddr 是本引擎提供的本地 SOCKS5（127.0.0.1:port），出站经 WARP。
	// 订阅节点全部以它为 dialer-proxy。
	BridgeAddr string
	// Proxies 是 Clash 格式的节点定义（来自订阅，字段原样透传）。
	Proxies []map[string]any
	// Group 是策略组名（默认 "订阅出口"）。
	Group string
	// Select 指定默认选中的节点名；空 = 组的第一个。
	Select string
}

// bridgeName 是本地 SOCKS5 桥在配置里的名字。
const bridgeName = "warp-bridge"

// BuildConfig 生成一份最小可用的 mihomo 配置。
//
// 只做三件事：tun 接 fd、节点全部经 warp-bridge 出去、所有流量走一个 select 组。
// 分流规则、DNS 策略都保持最简 —— 先把「能出去、出口是国家」跑通。
func BuildConfig(o Options) (string, error) {
	if o.MixedPort <= 0 {
		return "", fmt.Errorf("缺少 mixed-port，订阅出口无法接管数据面")
	}
	if o.TUNFD <= 0 {
		return "", fmt.Errorf("缺少 tun fd，订阅出口无法接管数据面")
	}
	if strings.TrimSpace(o.BridgeAddr) == "" {
		return "", fmt.Errorf("缺少本地 SOCKS5 桥地址")
	}
	if len(o.Proxies) == 0 {
		return "", fmt.Errorf("订阅里没有可用节点")
	}

	group := o.Group
	if group == "" {
		group = "订阅出口"
	}

	proxies := make([]map[string]any, 0, len(o.Proxies)+1)
	proxies = append(proxies, map[string]any{
		"name":   bridgeName,
		"type":   "socks5",
		"server": "127.0.0.1",
		"port":   portOf(o.BridgeAddr),
		// **不能写 udp: true**：那会让 mihomo 先尝试 UDP ASSOCIATE，而本引擎的
		// SOCKS5 服务端只做 TCP CONNECT —— 握手被拒后整个 outbound 都不可用，
		// 表现是所有节点 health check 全 65535（真机 2026-11-13）。
		"udp": false,
	})

	names := make([]string, 0, len(o.Proxies))
	for _, p := range o.Proxies {
		name, _ := p["name"].(string)
		if name == "" || name == bridgeName {
			continue
		}
		// 关键：节点的出站连接先经本地 SOCKS5 → WARP netstack。
		// 这就是「WARP 前置 → 订阅节点」，与电脑版 openvpn + dialer-proxy 同构。
		p["dialer-proxy"] = bridgeName
		proxies = append(proxies, p)
		names = append(names, name)
	}
	if len(names) == 0 {
		return "", fmt.Errorf("订阅里没有合法节点")
	}

	cfg := map[string]any{
		"mixed-port":       o.MixedPort,
		"allow-lan":        false,
		"mode":             "rule",
		"log-level":        "info",
		"ipv6":             false,
		"find-process-mode": "off",
		"geodata-mode":     false,
		"unified-delay":    true,
		"tcp-concurrent":   true,
		// tun 由**内核自己**接管（fd 模式）：sing-tun 那条路是 CMFA 天天在跑的成熟
		// 实现，比我们自己写 tun2socks 可靠。前提是编译带 `-tags cmfa`（见 Options.TUNFD）。
		"tun": map[string]any{
			"enable":                true,
			"device":                "xehn-sub",
			"stack":                 "gvisor",
			"mtu":                   mtuOrDefault(o.MTU),
			"file-descriptor":       o.TUNFD,
			// 路由由 VpnService 管，内核不要碰系统路由表。
			"auto-route":            false,
			"auto-detect-interface": false,
			// **绝对不要 dns-hijack**：内核自己的 DNS 查询走系统路由 → 进 tun
			// → 又被 hijack 抓回自己 → `dial udp 198.18.0.1 -> 1.1.1.1:53:
			// i/o timeout`（2026-11-13 真机，39 条 [TCP] 全是 dns resolve failed）。
			// 关掉之后 UDP:53 按规则走代理，由节点侧解析（出口与解析器同国，
			// 也不会有 DNS 泄漏）。
		},
		"proxies": proxies,
		// 用 url-test 而不是 select：订阅里第一条极可能是死节点，select 会把它钉死，
		// 表现就是「连上了、所有网站打不开」。url-test 会周期性测
		// `generate_204`，自动切到当下能通的节点；tolerance 避免来回抖。
		"proxy-groups": []map[string]any{{
			"name":      group,
			"type":      "url-test",
			"url":       "http://www.gstatic.com/generate_204",
			"interval":  60,
			"tolerance": 50,
			"lazy":      false,
			"proxies":   names,
		}},
		"rules": []string{"MATCH," + group},
		// **内核 DNS 必须关**：见上面 dns-hijack 的说明。节点域名已经在上层
		// 用宿主解析成 IP，内核不需要任何 DNS；应用流量的域名交给节点侧解析。
		"dns": map[string]any{
			"enable": false,
			"ipv6":   false,
		},
	}
	// **不绑 interface-name**：内核的所有出站都先到本地 SOCKS 桥（127.0.0.1），
	// 绑到 wlan0 会让连回环的那一步直接失败（2026-11-13 真机：所有节点
	// health check 全 65535）。内核不再需要任何直连，也就不需要绑网卡。

	buf, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("生成配置失败: %w", err)
	}
	return string(buf), nil
}

// mtuOrDefault 归一化 tun MTU。
func mtuOrDefault(mtu int) int {
	if mtu < 576 || mtu > 9000 {
		return 1280
	}
	return mtu
}

// portOf 从 "host:port" 里取端口；取不到返回 0（BuildConfig 会因此报错）。
func portOf(addr string) int {
	i := strings.LastIndex(addr, ":")
	if i < 0 || i == len(addr)-1 {
		return 0
	}
	p := 0
	for _, c := range addr[i+1:] {
		if c < '0' || c > '9' {
			return 0
		}
		p = p*10 + int(c-'0')
	}
	return p
}
