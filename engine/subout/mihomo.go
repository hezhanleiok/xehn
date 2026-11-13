// Package subout 内嵌 mihomo 内核，实现「订阅出口」。
//
// 结构（与电脑版完全同构）：
//
//	应用 → 系统 tun(fd) → mihomo(tun 入站) → 订阅节点 outbound
//	                                          └─ dialer-proxy: warp-bridge（本地 SOCKS5）
//	                                               └─ 本引擎的 WARP netstack → 节点
//
// 为什么用「本地 SOCKS5 桥」而不是给 mihomo 注册自定义 outbound：
// mihomo 的 adapter.ParseProxy 是固定 switch，没有对外注册扩展点；而一个
// 127.0.0.1 的 socks5 出站它原生支持，且这个 SOCKS 正好可以复用本引擎已有的
// 「socksPath → WARP netstack」能力（Psiphon 出口就是这么链的）。
// 于是「WARP 前置 → 订阅节点」这件事不用改 mihomo 一行代码。
package subout

import (
	"fmt"
	"sync"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
)

var (
	mu      sync.Mutex
	running bool
)

// Start 用一段完整的 mihomo 配置启动内核；重复调用等于热重载。
//
// yamlText 由本包的上层（engine）生成：proxies/proxy-groups/tun/rules 全在里面。
// tun 用 `file-descriptor` 接上层建好的 fd，内核不再自己建网卡。
func Start(yamlText string) error {
	mu.Lock()
	defer mu.Unlock()
	// mihomo 默认 INFO 会把每个连接都打出来，Android 日志会被刷爆。
	log.SetLevel(log.WARNING)
	cfg, err := executor.ParseWithBytes([]byte(yamlText))
	if err != nil {
		return fmt.Errorf("配置解析失败: %w", err)
	}
	executor.ApplyConfig(cfg, true)
	running = true
	return nil
}

// Stop 关掉内核。tun fd 的所有权在 Kotlin 侧（VpnService），这里只管内核。
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	executor.Shutdown()
	running = false
}

// Running 报告内核当前是否在跑。
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}
