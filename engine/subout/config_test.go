package subout

import (
	"testing"

	"github.com/metacubex/mihomo/config"
)

// TestBuildConfigParses 用真实节点形态的配置走一遍 mihomo 的解析器。
//
// 存在的意义（2026-11-13 真机）：`dns.fallback-filter.geoip: true` 会让 mihomo
// 在 tun 起来之前下载 geoip.metadb，那条请求走 UDP DNS 必然超时，于是整个配置
// 解析失败、连接直接失败 —— 这种错误在手机上试一次要两分钟，在单测里 0.1 秒。
// 以后凡是改 BuildConfig 的 YAML，都先过这个测试。
func TestBuildConfigParses(t *testing.T) {
	yamlText, err := BuildConfig(Options{
		TUNFD:      1,
		MTU:        1280,
		MixedPort:  7890,
		BridgeAddr: "127.0.0.1:7891",
		Group:      "订阅出口",
		Proxies: []map[string]any{
			{
				"name": "jp-1", "type": "vless", "server": "203.0.113.7", "port": 443,
				"uuid": "11111111-2222-3333-4444-555555555555", "tls": true,
				"servername": "example.com", "network": "ws",
				"ws-opts": map[string]any{"path": "/x", "headers": map[string]any{"Host": "example.com"}},
			},
			{
				"name": "jp-2", "type": "trojan", "server": "203.0.113.8", "port": 443,
				"password": "pw", "sni": "example.org",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}
	if _, err := config.Parse([]byte(yamlText)); err != nil {
		t.Fatalf("mihomo 解析配置失败（这类错误在手机上表现为「订阅出口失败：配置解析失败」）:\n%v\n\n--- 配置 ---\n%s", err, yamlText)
	}
}

// TestBuildConfigRejectsEmpty 保证缺关键参数时明确报错，而不是生成一份坏配置。
func TestBuildConfigRejectsEmpty(t *testing.T) {
	if _, err := BuildConfig(Options{MixedPort: 7890, BridgeAddr: "127.0.0.1:1"}); err == nil {
		t.Fatal("没有 tun fd 时应当报错")
	}
	if _, err := BuildConfig(Options{TUNFD: 1, BridgeAddr: "127.0.0.1:1"}); err == nil {
		t.Fatal("没有 mixed-port 时应当报错")
	}
	if _, err := BuildConfig(Options{TUNFD: 1, MixedPort: 7890, BridgeAddr: "127.0.0.1:1"}); err == nil {
		t.Fatal("没有节点时应当报错")
	}
}
