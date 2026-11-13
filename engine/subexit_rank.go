package engine

import (
	"sync"
	"time"

	"github.com/xhwarp/android-engine/subout"
)

// 订阅出口的「选最快 + 定时重测」。
//
// 端到端验证通过只说明「现在这条隧道能用」，不说明它是最快的那个节点。
// 这里在后台对同国节点做**真实下载测速**，把结果落盘并切到最快的；
// 之后每隔一段时间（默认 10 分钟）重测一次，节点掉线或变慢就顺延。

// subPorts 是一次订阅出口会话的本地端口，测速与重测都靠它。
type subPorts struct {
	api   int
	mixed int
	group string
}

// subRankMu 保护下面的运行标记：定时重测是最多一个，换出口/断开时不要叠加。
var (
	subRankMu   sync.Mutex
	subRankStop chan struct{}
)

// rankSubExit 在后台按速度选最快并切过去（不阻塞 UI 的「已连接」）。
func (b *warpBackend) rankSubExit(country string, nodes []map[string]any) {
	b.mu.Lock()
	ports := b.subPorts
	b.mu.Unlock()
	if ports == nil {
		return
	}
	names := subNames(nodes)
	if len(names) == 0 {
		return
	}
	ranked, _ := subout.RankNodes(ports.api, ports.mixed, ports.group, names, 15*time.Second)
	if len(ranked) == 0 || ranked[0].Bps <= 0 {
		return
	}
	// 存盘：下次连接直接按这个顺序渲染，第一个就是最快。
	subout.SaveRank(country, ranked)
	_ = subout.SwitchGroup(ports.api, ports.group, ranked[0].Name)
}

// keepSubExitFresh 每隔 interval 重测一次，失效或明显变慢就切到更快的。
//
// 控制器不可达（用户断开 / 换出口）时自己退出，不会留下空转的 goroutine。
func (b *warpBackend) keepSubExitFresh(country string, nodes []map[string]any, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	names := subNames(nodes)
	if len(names) == 0 {
		return
	}

	subRankMu.Lock()
	if subRankStop != nil {
		close(subRankStop) // 旧会话的循环退出
	}
	stop := make(chan struct{})
	subRankStop = stop
	subRankMu.Unlock()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		b.mu.Lock()
		ports := b.subPorts
		b.mu.Unlock()
		if ports == nil || !subout.APIAvailable(ports.api) {
			return
		}
		ranked, _ := subout.RankNodes(ports.api, ports.mixed, ports.group, names, 15*time.Second)
		if len(ranked) == 0 || ranked[0].Bps <= 0 {
			continue
		}
		subout.SaveRank(country, ranked)
		_ = subout.SwitchGroup(ports.api, ports.group, ranked[0].Name)
	}
}

// subNames 取节点名（测速 API 用名字引用节点）。
func subNames(nodes []map[string]any) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if s, ok := n["name"].(string); ok {
			out = append(out, s)
		}
	}
	return out
}
