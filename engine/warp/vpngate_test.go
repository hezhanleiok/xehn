package warp

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"
)

// 一行真实的 VPN Gate CSV 形状（配置列是 base64 的 .ovpn）。
func vpnGateLine(host, ip, cc, operator, cfg string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(cfg))
	return fmt.Sprintf("%s,%s,0,12,189218132,Japan,%s,3,10,20,30,,%s,,%s", host, ip, cc, operator, b64)
}

func TestParseVPNGateCSV(t *testing.T) {
	line := vpnGateLine("public-vpn-153", "219.100.37.109", "JP",
		"Daiyuu Nobori_ Japan. Academic Use Only.", sampleVPNGateConfig)
	text := "*\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n" + line + "\n"

	nodes := ParseVPNGateCSV(text)
	if len(nodes) != 1 {
		t.Fatalf("解析出 %d 个节点，期望 1", len(nodes))
	}
	n := nodes[0]
	// 落地地址以 .ovpn 的 remote 为准（CSV 的 IP 列偶尔与配置不一致）。
	if n.IP != "60.103.240.103" || n.Port != 1855 {
		t.Fatalf("节点地址 = %s:%d，期望 60.103.240.103:1855", n.IP, n.Port)
	}
	if n.Proto != "tcp" || n.CC != "JP" || n.Country != "Japan" {
		t.Fatalf("基本字段错误: %+v", n)
	}
	if n.PingMS != 12 || n.SpeedBps != 189218132 {
		t.Fatalf("自报指标错误: ping=%d speed=%d", n.PingMS, n.SpeedBps)
	}
	// public-vpn-* 是 VPN Gate 作者自己的机房 VPS（电脑版 CFnew 也按这个前缀排除）。
	if n.Class != "datacenter" || n.ClassSource != "host" {
		t.Fatalf("分类 = %s/%s，期望 datacenter/host", n.Class, n.ClassSource)
	}
	if n.Config == "" {
		t.Fatal("配置原文没有保留（连接时要用）")
	}
}

func TestParseVPNGateCSVSkipsBrokenRows(t *testing.T) {
	text := "#HostName,IP\n" +
		"broken,1.2.3.4\n" + // 列数不足
		vpnGateLine("x", "1.2.3.4", "JP", "", "") + "\n" // 配置为空
	if got := ParseVPNGateCSV(text); len(got) != 0 {
		t.Fatalf("坏行不应产生节点，得到 %d 个", len(got))
	}
}

// 分类规则直接决定界面上「家宽/机房」的标记，锁住三种典型输入。
func TestEnrichClassify(t *testing.T) {
	cases := []struct {
		name string
		r    ipAPIResult
		want string
	}{
		{
			name: "KT 家宽",
			r:    ipAPIResult{Status: "success", ISP: "Korea Telecom", AS: "AS4766 Korea Telecom"},
			want: "residential",
		},
		{
			name: "Vultr 机房（硬 ASN）",
			r:    ipAPIResult{Status: "success", ISP: "Vultr Holdings", AS: "AS20473 Vultr", Hosting: true},
			want: "datacenter",
		},
		{
			name: "证据不足",
			r:    ipAPIResult{Status: "success", ISP: "Some LLC", AS: "AS64500 Some LLC"},
			want: "unknown",
		},
		{
			name: "机房与住宅冲突",
			r:    ipAPIResult{Status: "success", ISP: "SoftBank", AS: "AS17676 SoftBank", Hosting: true},
			want: "unknown",
		},
	}
	for _, c := range cases {
		n := VPNGateNode{}
		enrichClassify(&n, c.r)
		if n.Class != c.want {
			t.Errorf("%s: class = %q，期望 %q（isp=%s as=%s）", c.name, n.Class, c.want, n.ISP, n.AS)
		}
	}
}

// TestParseRealVPNGateSample 用一份真实的 iphone.txt 跑解析器。
//
// 默认跳过（仓库里不放 1.3 MB 的节点快照）；验证时：
//
//	$env:VPNGATE_SAMPLE='E:/XEHN/.research/vpngate/iphone.txt'; go test -run Real ./warp
func TestParseRealVPNGateSample(t *testing.T) {
	path := os.Getenv("VPNGATE_SAMPLE")
	if path == "" {
		t.Skip("未设置 VPNGATE_SAMPLE")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读样本失败: %v", err)
	}
	nodes := ParseVPNGateCSV(string(b))
	if len(nodes) < 20 {
		t.Fatalf("只解析出 %d 个节点，样本里应有几十个", len(nodes))
	}
	byClass := map[string]int{}
	byCC := map[string]int{}
	for _, n := range nodes {
		if n.Config == "" || n.IP == "" || n.Port == 0 {
			t.Fatalf("节点字段不完整: %+v", n)
		}
		// 配置必须能被连接路径再解析一次（否则抓下来的列表看着有、连不上）。
		if _, perr := ParseOpenVPNConfig(n.Config); perr != nil {
			t.Fatalf("节点 %s 的配置无法解析: %v", n.ID, perr)
		}
		byClass[n.Class]++
		byCC[n.CC]++
	}
	t.Logf("解析 %d 个节点，分类 %v，国家 %v", len(nodes), byClass, byCC)
}

func TestParseASN(t *testing.T) {
	for in, want := range map[string]int{
		"AS4766 Korea Telecom": 4766,
		"as20473 vultr":        20473,
		"Korea Telecom":        0,
		"AS":                   0,
	} {
		if got := parseASN(in); got != want {
			t.Errorf("parseASN(%q) = %d，期望 %d", in, got, want)
		}
	}
}
