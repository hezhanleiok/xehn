package subout

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 订阅出口的「按速度选最快」+ 结果缓存。
//
// 为什么不能只用 mihomo 的 url-test：它只测**延迟**。公共订阅里
// 「延迟低但带宽只有几十 KB/s」的节点很常见（握手快、限速狠）。
// 所以分两层：并发 delay 筛死节点 → 对最好的一批做**真实下载**，按速度排序。
//
// 排序结果落盘（见 RankDir），下次连接直接按它渲染 —— 第二次不用再等测速。

// RankDir 是测速缓存的落盘目录，由 warpbackend 在启动时设成 App 私有目录。
var RankDir = ""

// rankMaxDelay 超过这个延迟的节点不进入下载测速（跨境 3 秒还没握上手，下载也不会快）。
const rankMaxDelay = 3000 * time.Millisecond

// rankTop 是进入下载测速的节点数上限：再多收益很小，时间却线性增长。
const rankTop = 6

// rankCacheTTL 是缓存有效期。公共订阅每小时刷新，排名能稳住半天左右。
const rankCacheTTL = 6 * time.Hour

// RankResult 是一个节点的测速结果。
type RankResult struct {
	Name  string        `json:"name"`
	Delay time.Duration `json:"delay"`
	Bps   int64         `json:"bps"`
}

// speedURLs 是下载测速源，**按顺序回退**。
//
// 只用 speed.cloudflare.com 不够：实测（2026-11-13）延迟都通的节点在那个地址上
// 全部下不动（TLS 被拦或限速），于是所有节点都被判 0。多源回退能让
// 「至少有一个源能出数据」的节点正常排上名次。
var speedURLs = []string{
	"http://cachefly.cachefly.net/10mb.test",
	"http://speedtest.tele2.net/10MB.zip",
	"https://speed.cloudflare.com/__down?bytes=20000000",
}

// RankNodes 对一组节点做「延迟初筛 + 真实下载测速」，返回按速度降序的结果。
//
// group 必须渲染成 select —— 只有 select 支持通过 controller API 手动切换。
// 返回的 note 非空表示「没测出速度」的原因（全失败 / 控制器不可达）。
func RankNodes(apiPort, mixedPort int, group string, names []string, timeout time.Duration) ([]RankResult, string) {
	if apiPort <= 0 || mixedPort <= 0 {
		return nil, "缺少 controller/mixed 端口"
	}
	if len(names) == 0 {
		return nil, "没有可测的节点"
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", apiPort)

	// 1) 并发 delay 筛一遍
	type delayed struct {
		name  string
		delay time.Duration
	}
	var (
		mu    sync.Mutex
		alive []delayed
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 16)
		cli   = &http.Client{Timeout: 6 * time.Second}
	)
	for _, n := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			u := fmt.Sprintf("%s/proxies/%s/delay?timeout=4000&url=%s",
				base, url.PathEscape(name),
				url.QueryEscape("http://www.gstatic.com/generate_204"))
			resp, err := cli.Get(u)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			var out struct {
				Delay int `json:"delay"`
			}
			if json.NewDecoder(resp.Body).Decode(&out) != nil || out.Delay <= 0 {
				return
			}
			d := time.Duration(out.Delay) * time.Millisecond
			if d > rankMaxDelay {
				return
			}
			mu.Lock()
			alive = append(alive, delayed{name: name, delay: d})
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	if len(alive) == 0 {
		return nil, "所有节点的延迟测试都失败（订阅里的节点当前都不可用）"
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].delay < alive[j].delay })
	if len(alive) > rankTop {
		alive = alive[:rankTop]
	}

	// 2) 逐个切组 + 真实下载
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	dl := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
	}
	out := make([]RankResult, 0, len(alive))
	for _, a := range alive {
		if err := SwitchGroup(apiPort, group, a.name); err != nil {
			out = append(out, RankResult{Name: a.name, Delay: a.delay})
			continue
		}
		out = append(out, RankResult{Name: a.name, Delay: a.delay, Bps: downloadBps(dl)})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bps > out[j].Bps })
	ok := 0
	for _, r := range out {
		if r.Bps > 0 {
			ok++
		}
	}
	if ok == 0 {
		return out, "延迟能通，但没有一个节点能下载数据（可能都被限速/拦截）"
	}
	return out, ""
}

// SwitchGroup 把 select 组切到指定节点。
func SwitchGroup(apiPort int, group, name string) error {
	body := strings.NewReader(fmt.Sprintf(`{"name":%q}`, name))
	req, err := http.NewRequest(http.MethodPut,
		fmt.Sprintf("http://127.0.0.1:%d/proxies/%s", apiPort, url.PathEscape(group)), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("切换节点返回 HTTP %d", resp.StatusCode)
	}
	return nil
}

// APIAvailable 探一下控制器还在不在（内核停了就返回 false）。
func APIAvailable(apiPort int) bool {
	if apiPort <= 0 {
		return false
	}
	cli := &http.Client{Timeout: 2 * time.Second}
	resp, err := cli.Get(fmt.Sprintf("http://127.0.0.1:%d/version", apiPort))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// downloadBps 经代理下载一段固定内容并算速率（字节/秒），多源回退。
func downloadBps(cli *http.Client) int64 {
	for _, u := range speedURLs {
		if bps := downloadBpsOne(cli, u); bps > 0 {
			return bps
		}
	}
	return 0
}

// downloadBpsOne 从单个地址读 1.5 秒（不等它下完，慢节点也能出数）。
func downloadBpsOne(cli *http.Client, u string) int64 {
	resp, err := cli.Get(u)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	buf := make([]byte, 64<<10)
	var total int64
	start := time.Now()
	for time.Now().Before(deadline) {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if rerr != nil {
			break
		}
	}
	el := time.Since(start)
	if total <= 0 || el <= 0 {
		return 0
	}
	return int64(float64(total) / el.Seconds())
}

// SortByRank 按测速结果给节点排序（最快在前）。
//
// select 组的默认节点就是 proxies 的第一个，所以「最快在前」等价于
// 「连上就用最快的」；ranked 里没有的节点（新拉的、上次没测到的）保持原序追加。
func SortByRank(nodes []map[string]any, ranked []RankResult) []map[string]any {
	if len(ranked) == 0 || len(nodes) == 0 {
		return nodes
	}
	byName := make(map[string]map[string]any, len(nodes))
	for _, n := range nodes {
		if name, ok := n["name"].(string); ok {
			byName[name] = n
		}
	}
	// 自己按速度降序，不信调用方给的顺序（缓存是 JSON，旧数据可能没排好）。
	ordered := make([]RankResult, len(ranked))
	copy(ordered, ranked)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Bps > ordered[j].Bps })

	out := make([]map[string]any, 0, len(nodes))
	used := make(map[string]bool, len(ranked))
	for _, r := range ordered {
		if r.Bps <= 0 {
			continue
		}
		if n, ok := byName[r.Name]; ok && !used[r.Name] {
			out = append(out, n)
			used[r.Name] = true
		}
	}
	for _, n := range nodes {
		if name, ok := n["name"].(string); ok && used[name] {
			continue
		}
		out = append(out, n)
	}
	return out
}

// rankCachePath 返回某个国家的测速缓存路径（RankDir 未设时返回空 = 不缓存）。
func rankCachePath(country string) string {
	dir := strings.TrimSpace(RankDir)
	if dir == "" {
		return ""
	}
	cc := strings.ToUpper(strings.TrimSpace(country))
	if cc == "" {
		cc = "DEFAULT"
	}
	return filepath.Join(dir, "subexit-rank-"+cc+".json")
}

type rankCache struct {
	Country string       `json:"country"`
	SavedAt time.Time    `json:"saved_at"`
	Ranked  []RankResult `json:"ranked"`
}

// LoadRank 读回该国的测速缓存（不存在 / 过期 / 损坏都返回 nil）。
func LoadRank(country string) []RankResult {
	p := rankCachePath(country)
	if p == "" {
		return nil
	}
	buf, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var c rankCache
	if json.Unmarshal(buf, &c) != nil {
		return nil
	}
	if time.Since(c.SavedAt) > rankCacheTTL {
		return nil
	}
	return c.Ranked
}

// SaveRank 写入测速结果（失败只影响下次速度，不报错）。
func SaveRank(country string, ranked []RankResult) bool {
	p := rankCachePath(country)
	if p == "" || len(ranked) == 0 {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false
	}
	buf, err := json.MarshalIndent(rankCache{
		Country: strings.ToUpper(strings.TrimSpace(country)),
		SavedAt: time.Now(),
		Ranked:  ranked,
	}, "", "  ")
	if err != nil {
		return false
	}
	return os.WriteFile(p, buf, 0o644) == nil
}
