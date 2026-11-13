package subout

import (
	"context"
	"fmt"
	"io"
	"net"
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

// ResolveNodeServers 把节点 `server` 里的域名换成 IP（宿主解析）。
//
// 为什么必须做（2026-11-13 真机日志）：
//
//	[mihomo] [TCP] dial 订阅出口 ... error: dns resolve failed:
//	  read udp 198.18.0.1:46493->1.1.1.1:53: i/o timeout
//
// mihomo 解析节点域名时会查 1.1.1.1，而它的查询走系统路由 → 进 tun → 又被自己
// 接住，全部超时 —— 表现就是 148 个节点 health check 一律 65535、所有连接
// `dns resolve failed`。换成 IP 之后内核不需要任何 DNS。
//
// TLS 的 SNI / WebSocket 的 Host 用原域名补回（如果订阅没显式配置），
// 否则证书校验和 CDN 路由都会错。解析不出来的节点直接丢掉：留着只会拖慢
// health check，反正也连不上。
func ResolveNodeServers(proxies []map[string]any) (kept []map[string]any, resolved, dropped, udpOnly int) {
	kept = make([]map[string]any, 0, len(proxies))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for _, p := range proxies {
		// 纯 UDP 协议先跳过：本地 SOCKS 桥只支持 TCP，hysteria2 / tuic / wireguard
		// 的出站报文发不出去（真机日志里全是 `quic: transport closed`）。
		// 留着它们只会让 url-test 白测一轮，还可能被选中导致「连上了没网」。
		switch strings.ToLower(fmt.Sprint(p["type"])) {
		case "hysteria2", "tuic", "wireguard":
			udpOnly++
			continue
		}
		server, _ := p["server"].(string)
		if strings.TrimSpace(server) == "" {
			dropped++
			continue
		}
		if net.ParseIP(server) != nil {
			kept = append(kept, p)
			continue
		}
		ips, err := net.DefaultResolver.LookupHost(ctx, server)
		if err != nil || len(ips) == 0 {
			dropped++
			continue
		}
		p["server"] = ips[0]
		patchTLSHost(p, server)
		kept = append(kept, p)
		resolved++
	}
	return kept, resolved, dropped, udpOnly
}

// patchTLSHost 把原域名补到 SNI / Host 字段（只在订阅没显式配置时）。
func patchTLSHost(p map[string]any, host string) {
	typ, _ := p["type"].(string)
	typ = strings.ToLower(typ)
	// sni / servername 二选一：不同协议/版本认的字段不同，两个都补最省事。
	if s, _ := p["servername"].(string); strings.TrimSpace(s) == "" {
		if s2, _ := p["sni"].(string); strings.TrimSpace(s2) == "" {
			switch typ {
			case "trojan", "hysteria2", "tuic":
				p["sni"] = host
			case "vless", "vmess":
				if on, _ := p["tls"].(bool); on {
					p["servername"] = host
				}
			}
		}
	}
	// WebSocket 的 Host 头：很多节点的域名绑定靠它。
	if ws, ok := p["ws-opts"].(map[string]any); ok {
		hdr, _ := ws["headers"].(map[string]any)
		if hdr == nil {
			hdr = map[string]any{}
		}
		if v, _ := hdr["Host"].(string); strings.TrimSpace(v) == "" {
			hdr["Host"] = host
			ws["headers"] = hdr
			p["ws-opts"] = ws
		}
	}
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
