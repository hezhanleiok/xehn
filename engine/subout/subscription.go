package subout

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// 内置订阅（按国家分片）。
//
// 来源：github.com/Au1rxx/free-vpn-subscriptions —— 每小时刷新一次，已按 GeoIP
// 分好国家，正好省掉我们自己归类。用分片而不是整包：选日本只拉 JP 那 394 条，
// 测速量和内存都可控。
const (
	subBase = "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/clash-"
	// DefaultCountry 是「自动」时用的分片（节点最多）。
	DefaultCountry = "US"
	// maxSubBytes 防止误拉到整包/异常文件把内存打满。
	maxSubBytes = 8 << 20
)

// supportedTypes 是 mihomo 能直接吃、且与本项目场景相关的协议。
// 不含 ssr（已废弃）、snell（少见）等，避免一个坏节点让整份配置解析失败。
var supportedTypes = map[string]bool{
	"vless":     true,
	"vmess":     true,
	"trojan":    true,
	"ss":        true,
	"hysteria2": true,
	"tuic":      true,
	"wireguard": true,
	"socks5":    true,
	"http":      true,
}

// CountryURL 返回某个国家码的分片订阅地址。
func CountryURL(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if cc == "" {
		cc = DefaultCountry
	}
	return subBase + cc + ".yaml"
}

// Fetch 拉一份订阅（走调用方给的 dialer —— 生产路径是经 WARP，避免 GitHub 被墙）。
func Fetch(ctx context.Context, url string, do func(ctx context.Context, url string) ([]byte, error)) ([]byte, error) {
	if do != nil {
		return do(ctx, url)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xehn-sub/1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("订阅返回 HTTP %d", resp.StatusCode)
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxSubBytes))
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// ParseClash 从 Clash YAML 里取出 proxies（字段原样保留，交给 mihomo 自己解释）。
//
// 只做三件事：过滤不支持的协议、丢掉缺字段的、名字去重（mihomo 用名字做组内引用，
// 重名会让整份配置解析失败）。
func ParseClash(buf []byte) ([]map[string]any, string, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(buf, &doc); err != nil {
		return nil, "", fmt.Errorf("订阅不是 Clash YAML: %w", err)
	}
	seen := map[string]int{}
	out := make([]map[string]any, 0, len(doc.Proxies))
	skipped := 0
	for _, p := range doc.Proxies {
		typ, _ := p["type"].(string)
		if !supportedTypes[strings.ToLower(typ)] {
			skipped++
			continue
		}
		server, _ := p["server"].(string)
		if strings.TrimSpace(server) == "" {
			skipped++
			continue
		}
		name, _ := p["name"].(string)
		if strings.TrimSpace(name) == "" {
			name = server
		}
		if n := seen[name]; n > 0 {
			name = fmt.Sprintf("%s #%d", name, n+1)
		}
		seen[name]++
		p["name"] = name
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("订阅里没有可用节点（跳过 %d 条）", skipped)
	}
	return out, fmt.Sprintf("共 %d 条，可用 %d 条", len(doc.Proxies), len(out)), nil
}
