package engine

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// 真实联网冒烟测试：默认跳过，WARP_LIVE=1 才跑。
//
//	$env:WARP_LIVE='1'; go test -run TestLiveDial -v .
//
// 它验证的是「搬进来的引擎能不能真的建隧道、真的出数据」：桌面版这一步由
// mihomo.exe 子进程承担，安卓上没有子进程可用，所以必须由 Go 自己跑通。
// 账号优先取 WARP_ACCOUNT_JSON，其次读桌面版已注册的那份，最后才现注册。
func TestLiveDial(t *testing.T) {
	if os.Getenv("WARP_LIVE") != "1" {
		t.Skip("设置 WARP_LIVE=1 才跑真实连接测试")
	}

	account := os.Getenv("WARP_ACCOUNT_JSON")
	if account == "" {
		for _, p := range []string{
			`d:\xhwarp\warp-client\warpscout-account.json`,
		} {
			if b, err := os.ReadFile(p); err == nil {
				account = string(b)
				t.Logf("使用桌面版账号文件作为输入: %s", p)
				break
			}
		}
	}

	proto := os.Getenv("WARP_LIVE_PROTO")
	if proto == "" {
		proto = "awg"
	}

	b := newWarpBackend(t.TempDir())
	if account != "" {
		b.SetAccountJSON(account)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	start := time.Now()
	res, err := b.Connect(ctx, Request{Proto: proto, MTU: 1280}, func(m string) { t.Logf("  | %s", m) })
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Logf("==> 连接成功 用时=%s exit=%s country=%s endpoint=%s socks=%s",
		time.Since(start).Round(time.Millisecond), res.ExitIP, res.Country, res.Endpoint, b.SocksAddr())

	if res.ExitIP == "" {
		t.Errorf("没有拿到出口 IP（数据面虽然通了，但 /meta 没给出 clientIp）")
	}
	if res.Country == "" {
		t.Errorf("没有拿到出口国家")
	}

	// 最硬的一条：不靠隧道内部的自证，而是像普通应用那样通过本地 SOCKS5
	// 真发一次请求，看公网看到的出口是不是隧道报的那个 IP。
	// 这正是桌面版定下的验收铁律：成功不是「端口打开了」，而是「真实流量
	// 经过它出去了，且出口对得上」。
	if socks := b.SocksAddr(); socks != "" {
		proxyURL, _ := url.Parse("socks5://" + socks)
		client := &http.Client{
			Timeout:   25 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		}
		resp, gerr := client.Get("https://api.ipify.org")
		if gerr != nil {
			t.Errorf("经本地 SOCKS 发请求失败: %v", gerr)
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			seen := strings.TrimSpace(string(body))
			t.Logf("==> 经 SOCKS5 实测出口 = %s (http=%d)", seen, resp.StatusCode)
			if seen != res.ExitIP {
				t.Errorf("经 SOCKS 看到的出口 %q 与隧道报告的 %q 不一致", seen, res.ExitIP)
			}
		}
	}

	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
