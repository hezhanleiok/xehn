package warp

import (
	"net/netip"
	"testing"

	ovpn "github.com/xhwarp/android-engine/third_party/mihomo/openvpn"
)

// sampleVPNGateConfig 是 VPN Gate 的 .ovpn 形状（内联 ca/cert/key + tls-auth），
// 证书内容是占位符：解析只关心块的位置与字段，不校验 PEM（校验在 clientConfig
// 里，由 mihomo 的 Prepare 做）。
const sampleVPNGateConfig = `client
dev tun
proto tcp
remote 60.103.240.103 1855
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
auth SHA1
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUfake
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUfake
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIBfake
-----END PRIVATE KEY-----
</key>
key-direction 1
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
deadbeef
-----END OpenVPN Static key V1-----
</tls-auth>
`

func TestParseOpenVPNConfig(t *testing.T) {
	c, err := ParseOpenVPNConfig(sampleVPNGateConfig)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if c.RemoteHost != "60.103.240.103" || c.RemotePort != 1855 {
		t.Fatalf("remote 解析错误: %s:%d", c.RemoteHost, c.RemotePort)
	}
	if c.Proto != "tcp" {
		t.Fatalf("proto = %q，期望 tcp", c.Proto)
	}
	if c.Cipher != "AES-128-CBC" || c.Auth != "SHA1" {
		t.Fatalf("加密参数解析错误: cipher=%q auth=%q", c.Cipher, c.Auth)
	}
	if c.KeyDirection != "1" {
		t.Fatalf("key-direction = %q", c.KeyDirection)
	}
	if c.CA == "" || c.Cert == "" || c.Key == "" || c.TLSAuth == "" {
		t.Fatalf("内联块缺失: ca=%d cert=%d key=%d tls-auth=%d",
			len(c.CA), len(c.Cert), len(c.Key), len(c.TLSAuth))
	}
}

func TestParseOpenVPNConfigRejectsMissingRemote(t *testing.T) {
	if _, err := ParseOpenVPNConfig("client\ndev tun\n"); err == nil {
		t.Fatal("没有 remote 的配置应当报错")
	}
}

// openVPNTunFromPush 决定建 tun 用的地址。地址取错就是「握手成功但打不开」，
// 所以这里锁住 PushReply 里的第一个 IPv4 ifconfig。
func TestOpenVPNTunFromPush(t *testing.T) {
	p := &ovpn.PushReply{
		Prefixes: []netip.Prefix{
			netip.MustParsePrefix("10.211.1.6/24"),
			netip.MustParsePrefix("fd00::6/64"),
		},
		Routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")},
		DNS:    []netip.Addr{netip.MustParseAddr("10.211.1.1")},
	}
	tun := openVPNTunFromPush(p)
	if tun.Address != "10.211.1.6" || tun.PrefixLen != 24 {
		t.Fatalf("ifconfig = %s/%d，期望 10.211.1.6/24", tun.Address, tun.PrefixLen)
	}
	if len(tun.Routes) != 1 || tun.Routes[0] != "0.0.0.0/1" {
		t.Fatalf("routes = %v", tun.Routes)
	}
	if len(tun.DNS) != 1 || tun.DNS[0] != "10.211.1.1" {
		t.Fatalf("dns = %v", tun.DNS)
	}
	// 1160 不是随手写的：经 WARP 时外层 MSS 是 1240，一个内层包还要套 ~55 字节的
	// OpenVPN 头（长度 2 + opcode 1 + HMAC 20 + IV 16 + CBC 填充），1400 会被拆成
	// 两段，包量和加密次数接近翻倍。
	if tun.MTU != 1160 {
		t.Fatalf("MTU = %d，期望 1160（外层 MSS 1240 - OpenVPN 头 ~55）", tun.MTU)
	}
}
