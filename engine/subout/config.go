package subout

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Options 是一次「订阅出口」启动所需的全部参数。
type Options struct {
	// TUNFD 是 VpnService 建好的 tun fd。mihomo 用 tun.file-descriptor 接管，
	// 不再自己建网卡（Android 上也只有这一个 tun 可用）。
	TUNFD int
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
	if o.TUNFD <= 0 {
		return "", fmt.Errorf("没有 tun fd，订阅出口无法接管数据面")
	}
	if strings.TrimSpace(o.BridgeAddr) == "" {
		return "", fmt.Errorf("缺少本地 SOCKS5 桥地址")
	}
	if len(o.Proxies) == 0 {
		return "", fmt.Errorf("订阅里没有可用节点")
	}

	mtu := o.MTU
	if mtu < 576 || mtu > 9000 {
		mtu = 1280
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
		"udp":    true,
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
		"mixed-port":       0,
		"allow-lan":        false,
		"mode":             "rule",
		"log-level":        "warning",
		"ipv6":             false,
		"find-process-mode": "off",
		"geodata-mode":     false,
		"unified-delay":    true,
		"tcp-concurrent":   true,
		"tun": map[string]any{
			"enable":                true,
			"device":                "xehn-sub",
			"stack":                 "gvisor",
			"mtu":                   mtu,
			"file-descriptor":       o.TUNFD,
			// 路由由 VpnService 管；内核不要去改系统路由/网卡，否则会与
			// Android 的 VPN 路由表打架（曾经在别的项目上表现为整个网络中断）。
			"auto-route":            false,
			"auto-detect-interface": false,
			"dns-hijack":            []string{},
		},
		"proxies": proxies,
		"proxy-groups": []map[string]any{{
			"name":    group,
			"type":    "select",
			"proxies": names,
		}},
		"rules": []string{"MATCH," + group},
		"dns": map[string]any{
			"enable":        true,
			"ipv6":          false,
			"listen":        "0.0.0.0:0",
			"enhanced-mode": "redir-host",
			"nameserver":    []string{"1.1.1.1", "8.8.8.8"},
		},
	}
	// 绑物理网卡：mihomo 自己发起的 DNS / 直连必须绕开 tun。
	if iface := strings.TrimSpace(o.Interface); iface != "" {
		cfg["interface-name"] = iface
	}

	buf, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("生成配置失败: %w", err)
	}
	return string(buf), nil
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
