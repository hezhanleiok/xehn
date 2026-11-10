package warp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// ---------------------------------------------------------------------------
// MASQUE：CONNECT-IP（RFC 9484），底层可以是 HTTP/3 或 HTTP/2
// ---------------------------------------------------------------------------
//
// 这段是从桌面版 warpscout/masque.go **整段搬过来的**（那一版已经在真机网络上
// 跑过、端点池也是实测出来的），只改了三处适配安卓：
//
//  1. 数据面：有 VpnService 的 tun fd 就用系统 tun（全机路由），没有才用
//     gVisor netstack（桌面/自测）。映射关系是「一个 IP 包 = 一个 CONNECT-IP
//     datagram」，两边都是裸 IP 包，所以直接换设备即可。
//  2. 凭据：桌面版从 warpscout 的 account 文件里取 masque 段；这里用一个
//     独立的 masque.json（原因见下）。
//  3. 拨号驱动：桌面版由扫描器驱动 handshake，这里由 dialMasque 驱动。
//
// 为什么 MASQUE 必须用**独立的一套账号**：登记（PATCH /reg/{id}）会把设备改成
// key_type=secp256r1 / tunnel_type=masque，同一个账号里原来的 curve25519 私钥
// 就再也对不上了 —— 拿 WG 的账号去做 MASQUE，会把 WG 模式弄坏。
//
// 关键事实（都来自桌面版的实测注释，不是猜的）：
//   - 客户端证书是本地自签的：Cloudflare 从不签发客户端证书，认证完全靠
//     「登记过的那把公钥」；反过来客户端 pin 的是服务端公钥（usque 的
//     PrepareTlsConfig 就是干这个）。
//   - QUIC 只从每个 /24 的 ::1/::2 提供；HTTP/2 覆盖整个 /24。
//   - 同一个端点同一时刻连得上、下一次超时，所以单次失败不说明问题。

// Values the official client uses, copied from Diniboy1123/usque (internal/, so
// not importable). The SNI never matches the endpoint address, which is why
// usque pins the peer's public key instead of verifying the certificate.
const (
	masqueConnectURI = "https://cloudflareaccess.com"
	masqueDefaultSNI = "consumer-masque.cloudflareclient.com"
	// 心跳 15s、静默 30s 算断。
	//
	// 这两个值原先抄成了 30s / **5s**，而 quic-go 的实际行为是
	//   idleTimeout = min(我们的 MaxIdleTimeout, 对端协商值)
	//   keepAliveInterval = min(KeepAlivePeriod, idleTimeout/2)
	// 于是心跳被夹到 2.5s（耗电），而链路只要静默 5 秒连接就被关掉 —— 手机上
	// 息屏、切基站、Wi-Fi 漫游都轻松超过 5s，表现就是「用一会儿就断，界面还显示
	// 已连接」。官方客户端的 idle 是 30s 量级、keepalive 15–25s，这里对齐。
	masqueKeepalive   = 15 * time.Second
	masqueIdleTimeout = 30 * time.Second
	// Cloudflare never signs the client certificate: it only carries the key
	// enrolled through the API, and that enrolment is the whole authentication.
	masqueCertLifetime = 24 * time.Hour
	// Headroom over the MTU so an oversized frame is read rather than truncated.
	masqueReadBuf = tunnelMTU + 256

	// MASQUE 的 tun MTU 上限。
	//
	// 2026-11-03 真机反馈：同一个手机、同一个网络，官方客户端下行 100+ Mb/s，
	// 这里只有十几兆。根因在「一个 IP 包 = 一个 QUIC DATAGRAM」这条链路上：
	//
	//	tun MTU 1280 的包 → +4 字节 contextID → QUIC DATAGRAM 帧 → QUIC 头
	//	→ UDP 8 → IPv6 40 / IPv4 20
	//
	// 外层走 IPv6 边缘（日志里就是 [2606:4700:103::1]:443，v6 路径 MTU 就是
	// 1280）时，1280 的内层包封装后约 1340 字节，**直接超过路径 MTU**。超限的
	// datagram 被 quic-go 以 DatagramTooLargeError 拒掉，而我们的泵把这个错误
	// （以及本该回写给内核的 ICMP）当成"这包算了"丢掉 —— 内层 TCP 只看到丢包，
	// 反复重传 + 拥塞窗口塌陷，实测就稳定在十几兆。
	//
	// 现在按**传输地址族**分开：
	//   v4 路径 MTU 1500 → tun 1300，wire ≈1368，留 130 字节余量；
	//   v6 路径 MTU 1280 → tun 1160，wire ≈1228，留 50 字节余量。
	// 比原来一律 1200 多 8%，更重要的是包数减少 8%（每包一次 syscall/加密）。
	// Aether（Rust + quiche）的对应取值是 1200…1350，和这里同一量级。
	masqueMaxTunMTU = 1350
	// v6 传输下的上限：1280 的路径 MTU 装不下更大的封装。
	masqueMaxTunMTUV6 = 1160

	// 上行并行的 CONNECT-IP 会话条数。
	//
	// 这是上行速度的关键：一条 QUIC 连接的上行受**它自己的拥塞窗口**限制，
	// 而手机网络的上行丢包率天生高于下行 —— Cubic 会把单连接卡在十几 Mb/s
	// （下行不受这个限制，因为我们是接收方，所以「下行满速、上行很慢」）。
	// 官方客户端同样是多条隧道并行。
	//
	// 必须**按流分发**（见 flowIndex）：同一条 TCP 流的所有包走同一条会话，
	// 否则同一条流会从不同出口出去，服务端看到源地址变化直接 RST。
	masqueUploadConns = 3

	// 每个 IP 包前要留出的空间：CONNECT-IP 的 context ID（0 编码为 1 字节）。
	// 这样写包时可以原地复用读缓冲，不必每包再 alloc + copy（见 pumpOut）。
	masqueCtxRoom = 8

	// 接收侧并发读的条数。单条 goroutine 在千兆下行（≈1 万包/秒）时，
	// 「一次 ReceiveDatagram + 一次 tun write」两处 syscall 就是上限。
	masquePumpReaders = 2
	// The same endpoint with the same SNI answers on one attempt and times out on
	// the next, so a single failure says nothing. Measured on a filtered network,
	// same endpoints and same SNI: one try scored 1-3 of 14 working, three tries
	// scored 11-13. Below this the scan reports mostly false negatives.
	masqueDefaultAttempts = 3

	// 并发拨号时同时尝试的端点数。
	//
	// 取 3 的理由：MASQUE 的失败大多是「这台边缘这次不答」，并发 3 个能在一轮
	// 超时（~3s）里覆盖三种不同边缘；再多只是白占 UDP 端口和蜂窝流量。
	masqueHedge = 3
)

// MASQUE is served from the ::1 and ::2 of each block, not from the WireGuard
// pools: measured, every other address in 162.159.198.0/24 and every wg pool
// address answers QUIC but rejects the TLS handshake outright. v6 has two such
// blocks and so four addresses - 16 random addresses sampled out of either /120
// answered nothing, while all four of these worked (20-21 of 28 ip:port pairs,
// the usual flap), reproduced on two hosts in different regions.
var (
	masquePoolsV4 = []netip.Prefix{
		netip.MustParsePrefix("162.159.198.1/32"),
		netip.MustParsePrefix("162.159.198.2/32"),
	}
	masquePoolsV6 = []netip.Prefix{
		netip.MustParsePrefix("2606:4700:103::1/128"),
		netip.MustParsePrefix("2606:4700:103::2/128"),
		netip.MustParsePrefix("2606:4700:104::1/128"),
		netip.MustParsePrefix("2606:4700:104::2/128"),
	}
)

// CONNECT-IP over TCP+TLS/HTTP2 is Cloudflare's own fallback transport, and the
// QUIC measurement above says nothing about it: usque defaults to 162.159.198.2
// and documents no v6 address at all
// (https://github.com/Diniboy1123/usque/wiki/HTTP-2-support). How much of these
// ranges answers over TCP is what this pool widens.
var (
	masqueH2PoolsV4 = []netip.Prefix{
		netip.MustParsePrefix("162.159.198.0/24"),
		netip.MustParsePrefix("162.159.199.0/24"),
	}
	// The v6 side is two whole /48s, not the /120 the QUIC addresses sit in: every
	// sampled ip:port pair worked across both, on two hosts in different regions.
	// The neighbouring blocks are dead on both - 101, 102 (Zero Trust), 105, 106
	// and the wg pools - so the range really is these two.
	masqueH2PoolsV6 = []netip.Prefix{
		netip.MustParsePrefix("2606:4700:103::/48"),
		netip.MustParsePrefix("2606:4700:104::/48"),
	}
)

// The API hands this list out per account, but it is the same everywhere and
// usque's own config.json has no port field at all, so it is a constant.
var masqueEndpointPorts = []int{443, 500, 1701, 4500, 4443, 8443, 8095}

// Set by loadMasqueAccount, like warpPrivateKey for the WireGuard family.
var masqueAcct *account

// 每次会话的 MASQUE 凭据文件路径，由 Config 注入（与 WG 账号分开存）。
var masqueCredsFile string

// EnsureMasqueAccount 确保 MASQUE 凭据就绪（必要时现注册），供「连接前预注册」用。
//
// 为什么必须在建系统 VPN **之前**做：VPN 一建立，系统 DNS 查询就被路由进一条
// 还没通的隧道，`api.cloudflareclient.com` 直接解析失败 —— 真机日志原文：
//
//	MASQUE 注册失败: Post "https://api.cloudflareclient.com/v0a4471/reg":
//	dial tcp: lookup api.cloudflareclient.com: no such host
//
// 这也是为什么 WG/AWG 能连（账号有缓存）、MASQUE 连不上（凭据丢了要重注册）。
func EnsureMasqueAccount(ctx context.Context, report func(string)) error {
	if masqueAcct != nil {
		return nil
	}
	a, err := ensureMasqueAccount(ctx, report)
	if err != nil {
		return err
	}
	masqueAcct = a
	return nil
}

// masqueMTU 与系统 tun 用同一个 MTU：Kotlin 的 VpnService.Builder 和引擎
// 必须是同一个值，否则内核会按错误尺寸切包。
//
// 上限按传输族分两档（v4 1300 / v6 1160）：超过这个值，封装成 CONNECT-IP
// DATAGRAM 后会超出路径 MTU 被静默丢弃 —— 那是"下行只有十几兆"的根因，见常量注释。
func masqueMTU(v6 bool) int {
	limit := masqueMaxTunMTU
	if v6 {
		limit = masqueMaxTunMTUV6
	}
	mtu := tunnelMTU
	if tunMTU > 0 {
		mtu = tunMTU
	}
	if mtu > limit {
		mtu = limit
	}
	return mtu
}

// -masque-sni overrides this. The endpoint never matches the SNI anyway and the
// peer is pinned by public key, so the name is free to be anything DPI lets
// through - the MASQUE equivalent of the AmneziaWG init packet.
var masqueSNI = masqueDefaultSNI

// The MASQUE flow lives on its own API version with its own client headers, and
// registers in two steps: POST /reg mints a device the same way the Android
// client does, PATCH /reg/{id} swaps its key for an ECDSA one and switches the
// tunnel type. Done through warpscout's own doJSON so -proxy, -interface and the
// tunnel fallback keep working.
const (
	masqueRegURL           = "https://api.cloudflareclient.com/v0a4471/reg"
	masqueClientVersion    = "a-6.35-4471"
	masqueUserAgent        = "WARP for Android"
	masqueKeyType          = "secp256r1"
	masqueTunnelType       = "masque"
	masqueRegKeyType       = "curve25519"
	masqueRegTunnelType    = "wireguard"
	masqueRegModel         = "PC"
	masqueRegLocale        = "en_US"
	masqueRegDeviceName    = "Xehn Android"
	masqueRegOSVersion     = "10"
	masqueRegSerialNumLen  = 8
	masqueRegPlaceholderKB = 32
)

type masqueRegResp struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func randomB64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// registerMasque 两步注册：先按 WireGuard 的样子开一台设备（key 只是占位，
// API 只看形状），再把它的 key 换成 ECDSA 并切到 masque。
func registerMasque(ctx context.Context, client *http.Client) (*account, error) {
	placeholder, err := randomB64(masqueRegPlaceholderKB)
	if err != nil {
		return nil, err
	}
	serial, err := randomB64(masqueRegSerialNumLen)
	if err != nil {
		return nil, err
	}
	body, err := doJSONAs(ctx, client, http.MethodPost, masqueRegURL, "",
		masqueUserAgent, masqueClientVersion, map[string]any{
			"key":           placeholder,
			"install_id":    "",
			"fcm_token":     "",
			"tos":           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			"model":         masqueRegModel,
			"serial_number": serial,
			"os_version":    masqueRegOSVersion,
			"key_type":      masqueRegKeyType,
			"tunnel_type":   masqueRegTunnelType,
			"locale":        masqueRegLocale,
		})
	if err != nil {
		return nil, fmt.Errorf("POST /reg: %w", err)
	}
	var first masqueRegResp
	if err := json.Unmarshal(body, &first); err != nil {
		return nil, fmt.Errorf("parse masque reg response: %w", err)
	}
	if first.ID == "" || first.Token == "" {
		return nil, fmt.Errorf("masque reg response missing id or token")
	}

	privDER, pubDER, err := genECKeyPair()
	if err != nil {
		return nil, err
	}
	body, err = doJSONAs(ctx, client, http.MethodPatch, masqueRegURL+"/"+first.ID, first.Token,
		masqueUserAgent, masqueClientVersion, map[string]string{
			"key":         base64.StdEncoding.EncodeToString(pubDER),
			"key_type":    masqueKeyType,
			"tunnel_type": masqueTunnelType,
			"name":        masqueRegDeviceName,
		})
	if err != nil {
		return nil, fmt.Errorf("PATCH /reg/%s: %w", first.ID, err)
	}
	var enrolled masqueRegResp
	if err := json.Unmarshal(body, &enrolled); err != nil {
		return nil, fmt.Errorf("parse masque enrol response: %w", err)
	}
	if len(enrolled.Config.Peers) == 0 || enrolled.Config.Peers[0].PublicKey == "" {
		return nil, fmt.Errorf("masque enrol response missing peer public key")
	}
	return &account{
		ID:            first.ID,
		Token:         first.Token,
		PrivateKey:    base64.StdEncoding.EncodeToString(privDER),
		PeerPublicKey: enrolled.Config.Peers[0].PublicKey,
		IPv4:          enrolled.Config.Interface.Addresses.V4,
		IPv6:          enrolled.Config.Interface.Addresses.V6,
	}, nil
}

// ensureMasqueAccount 拿到可用的 MASQUE 凭据：优先读缓存，否则现注册一套。
//
// 注册要联网，而系统 VPN 此时已经建立 —— 所以必须走 regTransport（它的
// Control 钩子里挂了 protect），否则这些请求会被自己的 tun 吞掉。
func ensureMasqueAccount(ctx context.Context, report func(string)) (*account, error) {
	if masqueCredsFile != "" {
		if a, err := loadAccount(masqueCredsFile); err == nil && a.PrivateKey != "" && a.PeerPublicKey != "" {
			report("复用已登记的 MASQUE 凭据")
			return &a, nil
		}
	}
	report("准备 MASQUE 账号（首次需要注册 + 登记 ECDSA 公钥）…")
	client := &http.Client{Timeout: 25 * time.Second, Transport: regTransport(nil)}
	a, err := registerMasque(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("MASQUE 注册失败: %w", err)
	}
	if masqueCredsFile != "" {
		if serr := saveAccount(masqueCredsFile, *a); serr != nil {
			report(fmt.Sprintf("警告：MASQUE 凭据保存失败（下次会重新登记）：%v", serr))
		}
	}
	report(fmt.Sprintf("MASQUE 登记完成：隧道地址 %s %s", a.IPv4, a.IPv6))
	return a, nil
}

func genECKeyPair() (privDER, pubDER []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if privDER, err = x509.MarshalECPrivateKey(priv); err != nil {
		return nil, nil, err
	}
	if pubDER, err = x509.MarshalPKIXPublicKey(&priv.PublicKey); err != nil {
		return nil, nil, err
	}
	return privDER, pubDER, nil
}

// selfSignedCert 造客户端证书。内容不参与校验，但 NotBefore 往前挪一小时：
// 手机时钟与服务器差几分钟是常态，卡在 notBefore 上就是握手直接失败。
func selfSignedCert(priv *ecdsa.PrivateKey) ([][]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(masqueCertLifetime),
	}, &x509.Certificate{}, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return [][]byte{der}, nil
}

func (a account) tlsConfig() (*tls.Config, error) {
	privDER, err := base64.StdEncoding.DecodeString(a.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("masque private key: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("masque private key: %w", err)
	}
	block, _ := pem.Decode([]byte(a.PeerPublicKey))
	if block == nil {
		return nil, fmt.Errorf("masque peer public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("masque peer public key: %w", err)
	}
	peerPub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("masque peer public key is not ECDSA")
	}
	cert, err := selfSignedCert(priv)
	if err != nil {
		return nil, err
	}
	cfg, err := api.PrepareTlsConfig(priv, peerPub, cert, masqueSNI, false)
	if err != nil {
		return nil, err
	}
	// TLS 1.3 会话票据复用：再连同一个 edge 时省掉一次完整握手（1-RTT 而不是 2-RTT）。
	// 官方客户端在原生层缓存 CID 与票据，我们这里只做票据这一半，成本一行。
	if cfg.ClientSessionCache == nil {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	}
	return cfg, nil
}

func (a account) localAddrs() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range []string{a.IPv4, a.IPv6} {
		if addr, err := netip.ParseAddr(s); err == nil {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("masque account carries no interface address")
	}
	return out, nil
}

// The netstack side outlives any single peer: handshake swaps the CONNECT-IP
// connection underneath it, exactly like IpcSet swaps the WireGuard peer.
type masqueTunnel struct {
	// ipStack 在 fd 模式下为 nil：系统 tun 就是数据面，不需要用户态协议栈。
	*ipStack
	dev     tun.Device
	counter tunCounter
	mtu     int
	tlsCfg  *tls.Config
	h2      bool
	report  func(string)

	// 超出外层可发送尺寸、只能回 ICMP 让内核降 MSS 的包数。用来在真机日志里
	// 直接看出「是不是 MTU 封装不下」——这一条以前是完全静默的。
	tooLarge atomic.Int64
	reported atomic.Bool

	// 上行并行：conns 是同时在跑的 CONNECT-IP 会话（第一条是握手时建的主会话，
	// 其余由 growConns 后台补齐）。所有会话共用同一个 tun 设备与同一个 netstack，
	// 上行包**按流**分发（见 flowIndex），下行各条会话各自写回 tun。
	mu         sync.Mutex
	conns      []*connectip.Conn
	dials      []*masqueDial
	pumpCtx    context.Context
	cancelPump context.CancelFunc
	closed     atomic.Bool
}

// quic-go and connect-ip-go write straight to the standard logger - a receive
// buffer warning, then a line per closed stream, and every endpoint swap closes
// one. Nothing here uses that logger, so the whole thing is muted rather than
// left to scribble over the app log.
var muteLibLog sync.Once

func newMasqueTunnel(h2 bool, mtu int, report func(string)) (*masqueTunnel, error) {
	muteLibLog.Do(func() { log.SetOutput(io.Discard) })
	if masqueAcct == nil {
		return nil, fmt.Errorf("no MASQUE device enrolled")
	}
	tlsCfg, err := masqueAcct.tlsConfig()
	if err != nil {
		return nil, err
	}

	var (
		dev     tun.Device
		stack   *ipStack
		counter tunCounter
	)
	if tunFD > 0 {
		// 安卓：VpnService 已经把 tun 建好了，我们只负责把包搬进 CONNECT-IP。
		dev, counter, err = newFdTunDevice(tunFD, mtu)
		if err != nil {
			return nil, err
		}
		report("MASQUE 数据面 = 系统 VPN")
	} else {
		// 桌面/自测：进程内 gVisor 协议栈，系统看不到这条隧道。
		local, lerr := masqueAcct.localAddrs()
		if lerr != nil {
			return nil, lerr
		}
		// 会话级缓冲：这条 netstack 可能承载整条带宽（MASQUE 作为 OpenVPN /
		// Psiphon 的上游时，外层连接就跑在它上面）。
		dev, stack, err = newIPStackBuffered(local, mtu, netstackSessionBufferMax)
		if err != nil {
			return nil, err
		}
		report("MASQUE 数据面 = 进程内 netstack")
	}

	t := &masqueTunnel{
		ipStack: stack, dev: dev, counter: counter, mtu: mtu,
		tlsCfg: tlsCfg, h2: h2, report: report,
	}
	go t.pumpOut()
	return t, nil
}

func (t *masqueTunnel) ports() []int    { return masqueEndpointPorts }
func (t *masqueTunnel) attempts() int   { return masqueDefaultAttempts }
func (t *masqueTunnel) stack() *ipStack { return t.ipStack }

func (t *masqueTunnel) counters() (uint64, uint64) {
	if t.counter == nil {
		return 0, 0
	}
	return t.counter.Counters()
}

func (t *masqueTunnel) Close() {
	t.closed.Store(true)
	t.dropPeer()
	if t.dev != nil {
		_ = t.dev.Close()
	}
}

func (t *masqueTunnel) dropPeer() {
	t.mu.Lock()
	cancel := t.cancelPump
	dials := t.dials
	t.cancelPump = nil
	t.pumpCtx = nil
	t.dials = nil
	t.conns = nil
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// 每条会话都有自己的 cancel（h3 的 CONNECT 请求活在它上面），必须逐条关。
	for _, d := range dials {
		d.close()
	}
}

// currentConns 返回当前可用会话的快照（调用方只读）。
func (t *masqueTunnel) currentConns() []*connectip.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.conns) == 0 {
		return nil
	}
	out := make([]*connectip.Conn, len(t.conns))
	copy(out, t.conns)
	return out
}

// One reader for the whole tunnel: the device is reused across peers, so a
// per-peer reader would be left blocked in dev.Read after a swap.
func (t *masqueTunnel) pumpOut() {
	// 前面留 masqueCtxRoom 字节：WritePacketBuffer 直接把 contextID 写在包前面，
	// 高包速时省掉每包一次 make+copy（quic-go 的 SendDatagram 自己还会再拷一次）。
	buf := make([]byte, masqueReadBuf+masqueCtxRoom)
	bufs := [][]byte{buf}
	sizes := []int{0}
	for {
		if _, err := t.dev.Read(bufs, sizes, masqueCtxRoom); err != nil {
			return
		}
		conns := t.currentConns()
		if len(conns) == 0 {
			continue
		}
		// 按流分发：同一条 TCP/UDP 流永远走同一条会话，出口地址才不会变。
		idx := flowIndex(buf[masqueCtxRoom:masqueCtxRoom+sizes[0]], len(conns))
		icmp, err := conns[idx].WritePacketBuffer(buf, masqueCtxRoom, sizes[0])
		if err != nil && len(conns) > 1 {
			// 这条会话刚坏（被 DPI 掐/迁移）：换一条重试一次。WritePacketBuffer
			// 每次都会重写 contextID，所以可以直接重入。
			icmp, err = conns[(idx+1)%len(conns)].WritePacketBuffer(buf, masqueCtxRoom, sizes[0])
		}
		if err != nil {
			continue
		}
		if len(icmp) > 0 {
			// CONNECT-IP 用 ICMP「包太大」告诉我们这个包封不下。**必须写回 tun**：
			// 内核收到才会把 MSS 调小重发；丢掉的话内层 TCP 只会一直重传同一个
			// 超限包，吞吐被死死压住（这就是下行只有十几兆的那一半原因）。
			if _, werr := t.dev.Write([][]byte{icmp}, 0); werr != nil {
				return
			}
			if t.tooLarge.Add(1) == 1 {
				// 第一次就写一行日志：这一版把 MTU 压到 1200 了，如果还能看到
				// 这条，说明外层路径比 1200 还窄，得继续往下调。
				t.reportOnce(fmt.Sprintf(
					"MASQUE：有包超出外层可发送尺寸，已回写 ICMP 让内核降 MSS（当前 tun MTU %d）", t.mtu))
			}
		}
	}
}

func (t *masqueTunnel) pumpIn(ctx context.Context, conn *connectip.Conn) {
	for ctx.Err() == nil {
		// 零拷贝：包直接引用接收缓冲，省掉每包一次 1280 字节的复制。
		// 生命周期到下一次 ReadPacketZeroCopy，而这里的 dev.Write 是同步的。
		pkt, err := conn.ReadPacketZeroCopy(true)
		if err != nil {
			return
		}
		if _, err := t.dev.Write([][]byte{pkt}, 0); err != nil {
			return
		}
	}
}

// reportOnce 让「只报一次」的日志不用在调用点写一堆 if。
func (t *masqueTunnel) reportOnce(msg string) {
	if t.reported.CompareAndSwap(false, true) && t.report != nil {
		t.report(msg)
	}
}

// dialConnectIP 建立一条 CONNECT-IP 连接，**套接字由我们自己开**。
//
// 为什么不用 usque 的 api.ConnectTunnel：它内部是裸的 net.ListenUDP / net.Dialer，
// 这些 socket 不在 VpnService.protect 的名单里。系统 VPN 一建立，它们的第一个包
// 就被我们自己的 tun 吞掉 —— 而 CONNECT-IP 还没建起来，包只会被丢，握手永远完不
// 成，界面上只看到「连不上」，还看不到原因。所以这里用带 protectControl 的
// ListenConfig / Dialer 重建同一套流程（quic-go + connect-ip-go 本来就是我们直接
// 依赖的，两边都是自己的代码路径，没有多引入任何东西）。
//
// HTTP/3：UDP + quic-go。HTTP/2：TCP + TLS + http2，两者都是 Cloudflare 的正式传输。
func dialConnectIP(ctx context.Context, tlsCfg *tls.Config, quicCfg *quic.Config, endpoint string, h2 bool) (net.PacketConn, *http3.Transport, *connectip.Conn, error) {
	template := uritemplate.MustNew(masqueConnectURI)
	headers := http.Header{"User-Agent": []string{""}}

	if h2 {
		hp := headers.Clone()
		hp.Set("cf-connect-proto", "cf-connect-ip")
		hp.Set("pq-enabled", "false")
		// RFC 9297 的胶囊协议声明。h3 由 connect-ip-go 自己加，h2 这条路径
		// 不会加 —— Aether 的 h3 请求头里也是显式带 `capsule-protocol: ?1`。
		hp.Set("capsule-protocol", "?1")

		// CONNECT 的 :authority 试两种：
		//   1. 端点自己的 ip:port —— Aether 走的就是这条（`connect_ip_request(authority=端点)`）；
		//   2. usque/connect-ip-go 默认的 cloudflareaccess.com。
		// 两种在 CF 的不同边缘上都见过，先端点、后通用名，谁通算谁。
		var lastErr error
		for _, uri := range []string{"https://" + endpoint, masqueConnectURI} {
			tmpl, terr := uritemplate.New(uri)
			if terr != nil {
				lastErr = terr
				continue
			}
			client, cerr := protectedHTTP2Client(tlsCfg, endpoint)
			if cerr != nil {
				return nil, nil, nil, cerr
			}
			ipConn, rsp, derr := connectip.DialH2(ctx, client, tmpl, hp)
			if derr == nil {
				if rsp != nil && rsp.Body != nil {
					// 成功时 body 就是隧道本身，绝不能关；这里只是把句柄留下。
					_ = rsp
				}
				return nil, nil, ipConn, nil
			}
			lastErr = fmt.Errorf("%s 被拒：%w%s", uri, derr, httpRespSnippet(rsp))
			client.CloseIdleConnections()
			if strings.Contains(derr.Error(), "tls: access denied") {
				return nil, nil, nil, fmt.Errorf(
					"MASQUE(h2) 登录被拒：本设备的凭据没有登记到 Cloudflare Access（%w）", derr)
			}
		}
		return nil, nil, nil, fmt.Errorf("MASQUE(h2) 建流失败：%w", lastErr)
	}

	remote, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, nil, nil, err
	}
	// 单层：主机上开一个被 protect 排除出系统 VPN 的 UDP socket。
	// 嵌套（MASQUEX2）：同一个 socket 开在**外层隧道的 netstack 里**，于是内层的
	// QUIC 包就成了外层隧道里的普通 UDP 传输（见 masque_nest.go）。
	udpConn, err := masqueUDPConn(ctx, remote)
	if err != nil {
		return nil, nil, nil, err
	}
	// ConnectionIDLength 不设时后端偶发 PROTOCOL_VIOLATION 并直接关连接。
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	conn, err := qtr.Dial(ctx, remote, tlsCfg, quicCfg)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, nil, err
	}
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// SETTINGS_H3_DATAGRAM_00：已废弃，但官方客户端仍然在发。
			0x276: 1,
		},
		DisableCompression: true,
	}
	ipConn, _, err := connectip.Dial(ctx, tr.NewClientConn(conn), template, "cf-connect-ip", headers, true)
	if err != nil {
		_ = tr.Close()
		_ = conn.CloseWithError(0, "connect-ip dial failed")
		_ = udpConn.Close()
		return nil, nil, nil, err
	}
	return udpConn, tr, ipConn, nil
}

// protectedUDPConn 开一个已被 VpnService.protect 排除出系统 VPN 的 UDP socket。
func protectedUDPConn(ctx context.Context, v6 bool) (*net.UDPConn, error) {
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	lc := net.ListenConfig{Control: protectControlFn}
	pc, err := lc.ListenPacket(ctx, network, ":0")
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("udp listen 返回了 %T", pc)
	}
	// 内核 UDP 缓冲：QUIC 在千兆级下行时每秒几百个包，默认 208 KB 的 rmem
	// 一满就丢包，丢了就触发拥塞退避 —— 这也是"下行上不去"的常见原因之一。
	// 非 root 只能设到 net.core.rmem_max，设不上就按系统上限跑，不报错。
	for _, sz := range []int{8 << 20, 4 << 20, 1 << 20} {
		if err := uc.SetReadBuffer(sz); err == nil {
			break
		}
	}
	_ = uc.SetWriteBuffer(4 << 20)
	return uc, nil
}

// masqueUDPConn 给这条 QUIC 连接开传输 socket。
//
// 默认在主机上开（单层 MASQUE）；masqueNest 非空时改开在**外层隧道的 netstack
// 里** —— 这就是 MASQUEX2 的全部机制：内层 QUIC 的 UDP 包进外层 CONNECT-IP 隧道。
func masqueUDPConn(ctx context.Context, remote *net.UDPAddr) (net.PacketConn, error) {
	if n := masqueNest.Load(); n != nil {
		return n.dialUDP(remote)
	}
	return protectedUDPConn(ctx, remote.IP.To4() == nil)
}

// protectedHTTP2Client 与 usque 的 newHTTP2Client 同构，区别只有一处：拨号用的是
// 带 protectControl 的 dialer（同样是为了不被自己的 tun 吞掉）。
func protectedHTTP2Client(base *tls.Config, endpoint string) (*http.Client, error) {
	cfg := base.Clone()
	cfg.NextProtos = []string{"h2"}
	dialer := &net.Dialer{Control: protectControlFn}
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, endpoint)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	return &http.Client{Transport: tr}, nil
}

// A successful dial is the MASQUE equivalent of the WireGuard handshake, but a
// weaker signal: measured on a filtered network, every endpoint dialled and only
// two passed data, so callers must still verify with /meta.
func (t *masqueTunnel) handshake(ctx context.Context, endpoint string, timeout time.Duration) bool {
	return t.handshakeErr(ctx, endpoint, timeout) == nil
}

// handshakeErr 与 handshake 相同，但把失败原因带出来。拨号失败必须能被说出来：
// 「42 个候选一个都没建起 CONNECT-IP」这种一句话日志没法定位是网络、凭据还是
// 版本问题。
func (t *masqueTunnel) handshakeErr(ctx context.Context, endpoint string, timeout time.Duration) error {
	t.dropPeer()

	// The deadline may only bound the dial: over HTTP/2 the CONNECT-IP stream is
	// one long-lived request carried by this very context, so a WithTimeout - or
	// the usual defer cancel() - kills the tunnel the moment the dial returns.
	dialCtx, cancelDial := context.WithCancel(ctx)
	dialDeadline := time.AfterFunc(timeout, cancelDial)
	// Both are set because a blocked endpoint stalls in two different places:
	// quic-go's own handshake, and the CONNECT-IP request that never answers.
	udpConn, tr, conn, err := dialConnectIP(dialCtx, t.tlsCfg, t.quicConfig(timeout), endpoint, t.h2)
	if err != nil {
		cancelDial()
		closeMasqueTransport(udpConn, tr, conn)
		return err
	}
	if !dialDeadline.Stop() {
		cancelDial()
		closeMasqueTransport(udpConn, tr, conn)
		return fmt.Errorf("拨号超时（%s）", timeout)
	}
	t.adoptDial(&masqueDial{endpoint: endpoint, udp: udpConn, tr: tr, conn: conn, cancel: cancelDial})
	return nil
}

// quicConfig 是每条 MASQUE 会话的 QUIC 参数。串行与竞速两条路共用，
// 免得「竞速拨出来的连接」和「串行拨出来的」行为不一致。
func (t *masqueTunnel) quicConfig(timeout time.Duration) *quic.Config {
	// InitialPacketSize 决定「一发出去就用多大的 UDP 载荷」。默认 1200 会让
	// quic-go 从 1200 起步、靠 DPLPMTUD 慢慢往上探（每升一档要一个 RTT），
	// 而我们要装的是 mtu 大小的内层 IP 包：太小会频繁撞 DatagramTooLarge。
	// 取 mtu+40：内层包 + contextID/帧头/QUIC 头/AEAD 的封装余量。
	initial := t.mtu + 40
	if initial < 1200 { // QUIC 规定客户端 Initial 不得小于 1200
		initial = 1200
	}
	if initial > 1452 {
		initial = 1452
	}
	return &quic.Config{
		EnableDatagrams:      true,
		InitialPacketSize:    uint16(initial),
		KeepAlivePeriod:      masqueKeepalive,
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       masqueIdleTimeout,
	}
}

// masqueDial 是一次成功的「QUIC/TLS + CONNECT-IP」拨号结果。
//
// cancel 关掉的是这次拨号的上下文：HTTP/2 下 CONNECT-IP 是挂在这个上下文上的
// 长请求，取消它等于断流，所以只能由 drop（或竞速的输家）来调。
type masqueDial struct {
	endpoint string
	// udp 是这条 QUIC 连接的传输 socket：单层是主机 UDP，嵌套时是外层隧道
	// netstack 里的 UDP（见 masqueUDPConn）。
	udp    net.PacketConn
	tr     *http3.Transport
	conn   *connectip.Conn
	cancel context.CancelFunc
}

func (d *masqueDial) close() {
	if d == nil {
		return
	}
	d.cancel()
	closeMasqueTransport(d.udp, d.tr, d.conn)
}

// adoptDial 把一次成功的拨号装进隧道：起读协程、记录关闭钩子。
// 串行与竞速两条路都走它，保证行为一致。
func (t *masqueTunnel) adoptDial(d *masqueDial) {
	pumpCtx, cancelPump := context.WithCancel(context.Background())
	t.mu.Lock()
	if t.closed.Load() {
		t.mu.Unlock()
		cancelPump()
		d.close()
		return
	}
	t.pumpCtx = pumpCtx
	t.cancelPump = cancelPump
	t.conns = append(t.conns, d.conn)
	t.dials = append(t.dials, d)
	t.mu.Unlock()
	// 接收侧开两条：一条 goroutine 每包一次 ReadPacket + 一次 tun 写 syscall，
	// 千兆下行时单条会成为瓶颈（quic-go 的接收队列是加锁的，多个读者安全；
	// 取出的包各自持有独立缓冲）。乱序交给内核的 TCP 处理，本来就是网络常态。
	for i := 0; i < masquePumpReaders; i++ {
		go t.pumpIn(pumpCtx, d.conn)
	}
}

// adoptExtra 追加一条上行并行会话（握手时那条之外的）。
func (t *masqueTunnel) adoptExtra(d *masqueDial) {
	t.mu.Lock()
	pumpCtx := t.pumpCtx
	if t.closed.Load() || pumpCtx == nil {
		t.mu.Unlock()
		d.close()
		return
	}
	t.conns = append(t.conns, d.conn)
	t.dials = append(t.dials, d)
	t.mu.Unlock()
	for i := 0; i < masquePumpReaders; i++ {
		go t.pumpIn(pumpCtx, d.conn)
	}
}

// growConns 在后台把上行并行会话补齐到 masqueUploadConns 条。
//
// 为什么不在握手时就一起建：那会把「连上」的时间翻几倍，用户等的是可用
// （第一条会话已经能跑），而不是完美。补齐过程中失败就停手 —— 少几条只是
// 上行没那么宽，不能因此把已经可用的会话弄坏。
//
// 只对 HTTP/3 做：h2 是一条 TCP 连接，并行只会让同一条 TCP 自己跟自己抢，
// 而且它的 CONNECT 请求活在 ctx 上，多一条就多一个长请求，没有收益。
func (t *masqueTunnel) growConns(endpoint string, timeout time.Duration, report func(string)) {
	if t.h2 || masqueUploadConns <= 1 {
		return
	}
	go func() {
		base := context.Background()
		for i := 1; i < masqueUploadConns; i++ {
			if t.closed.Load() {
				return
			}
			dialCtx, cancel := context.WithCancel(base)
			timer := time.AfterFunc(timeout, cancel)
			udp, tr, conn, err := dialConnectIP(dialCtx, t.tlsCfg, t.quicConfig(timeout), endpoint, t.h2)
			stopped := timer.Stop()
			if err != nil || !stopped {
				cancel()
				closeMasqueTransport(udp, tr, conn)
				if report != nil {
					report(fmt.Sprintf("上行并行：第 %d 条会话没建起来（%v），保持 %d 条", i+1, err, i))
				}
				return
			}
			t.adoptExtra(&masqueDial{endpoint: endpoint, udp: udp, tr: tr, conn: conn, cancel: cancel})
		}
		if report != nil {
			report(fmt.Sprintf("上行并行：%d 条 CONNECT-IP 会话就绪（按流分发）", masqueUploadConns))
		}
	}()
}

// flowIndex 按 IP 五元组把包固定分配到某条会话上。
//
// 不能简单轮询：同一条 TCP 流的上行包若分散到不同 CONNECT-IP 会话，会带来
// 严重的乱序，而且万一两条会话的出口地址不同，服务端看到源 IP 变了直接 RST。
// 五元组哈希保证同一条流始终同一条会话，不同的流才分散。
//
// （实测同一账号的各条隧道出口都是同一个 104.28.x.x，所以会话数变化时即使
// 映射变了也不会换源 IP；乱序由内核 TCP 处理。这也是敢用无状态哈希的前提。）
func flowIndex(pkt []byte, n int) int {
	if n <= 1 || len(pkt) < 20 {
		return 0
	}
	var proto byte
	var src, dst []byte
	var sport, dport int
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+4 {
			return 0
		}
		proto = pkt[9]
		src, dst = pkt[12:16], pkt[16:20]
		if proto == 6 || proto == 17 {
			sport = int(pkt[ihl])<<8 | int(pkt[ihl+1])
			dport = int(pkt[ihl+2])<<8 | int(pkt[ihl+3])
		}
	case 6:
		if len(pkt) < 44 {
			return 0
		}
		proto = pkt[6]
		src, dst = pkt[8:24], pkt[24:40]
		if proto == 6 || proto == 17 {
			sport = int(pkt[40])<<8 | int(pkt[41])
			dport = int(pkt[42])<<8 | int(pkt[43])
		}
	default:
		return 0
	}
	h := uint32(2166136261) // FNV-1a
	mix := func(b []byte) {
		for _, c := range b {
			h ^= uint32(c)
			h *= 16777619
		}
	}
	mix(src)
	mix(dst)
	h ^= uint32(proto)
	h *= 16777619
	h ^= uint32(sport)<<16 | uint32(dport)
	h *= 16777619
	return int(h % uint32(n))
}

// dialRace 并发拨一批端点：第一个成功者胜出，其余立刻取消。
//
// 为什么竞速只到「拨号」这一层、**不并发包装 tun 设备**：fd 模式下系统 tun 的
// fd 是唯一的，三个设备包同一个 fd，谁先 Close 谁就把系统 VPN 弄没了
// （见 newFdTunDevice 与 tunfd_owner.go 的所有权说明）。
func (t *masqueTunnel) dialRace(ctx context.Context, endpoints []string, timeout time.Duration) (*masqueDial, []error) {
	type res struct {
		d   *masqueDial
		err error
	}
	ch := make(chan res, len(endpoints))
	var mu sync.Mutex
	cancels := make(map[string]context.CancelFunc, len(endpoints))
	won := false

	for _, ep := range endpoints {
		dialCtx, cancel := context.WithCancel(ctx)
		mu.Lock()
		cancels[ep] = cancel
		mu.Unlock()
		go func(ep string, dialCtx context.Context, cancel context.CancelFunc) {
			timer := time.AfterFunc(timeout, cancel)
			udp, tr, conn, err := dialConnectIP(dialCtx, t.tlsCfg, t.quicConfig(timeout), ep, t.h2)
			timer.Stop()
			if err != nil {
				closeMasqueTransport(udp, tr, conn)
				cancel()
				ch <- res{err: err}
				return
			}
			mu.Lock()
			stopped := won
			mu.Unlock()
			if stopped {
				closeMasqueTransport(udp, tr, conn)
				cancel()
				ch <- res{err: fmt.Errorf("%s：已被更快的端点取代", ep)}
				return
			}
			ch <- res{d: &masqueDial{endpoint: ep, udp: udp, tr: tr, conn: conn, cancel: cancel}}
		}(ep, dialCtx, cancel)
	}

	var errs []error
	for i := 0; i < len(endpoints); i++ {
		r := <-ch
		if r.d == nil {
			if r.err != nil {
				errs = append(errs, r.err)
			}
			continue
		}
		// 赢家以外的全部取消：还在拨的会被唤醒，并自行关闭连接。
		mu.Lock()
		won = true
		for ep, c := range cancels {
			if ep != r.d.endpoint {
				c()
			}
		}
		mu.Unlock()
		// 剩下的结果没人要了：收掉并关闭，避免泄漏 UDP 端口。
		go func(remaining int) {
			for j := 0; j < remaining; j++ {
				if x := <-ch; x.d != nil {
					x.d.close()
				}
			}
		}(len(endpoints) - i - 1)
		return r.d, errs
	}
	return nil, errs
}

// httpRespSnippet 把被拒的 HTTP 响应压成一行日志：状态码 + 响应体前 160 字节。
// 没有它，「h2 连不上」在日志里只剩一句 goaway/tls 错误，看不出是 401、404
// 还是服务端根本不认这个 authority。
func httpRespSnippet(rsp *http.Response) string {
	if rsp == nil {
		return ""
	}
	if rsp.Body != nil {
		defer rsp.Body.Close()
	}
	body, _ := io.ReadAll(io.LimitReader(rsp.Body, 200))
	s := strings.TrimSpace(string(body))
	if s == "" {
		return fmt.Sprintf("（HTTP %d）", rsp.StatusCode)
	}
	return fmt.Sprintf("（HTTP %d：%s）", rsp.StatusCode, clipText(s, 160))
}

func closeMasqueTransport(udpConn net.PacketConn, tr *http3.Transport, conn *connectip.Conn) {
	if conn != nil {
		conn.Close()
	}
	if tr != nil {
		tr.Close()
	}
	if udpConn != nil {
		udpConn.Close()
	}
}

// masqueCandidateList 给出要按顺序试的 "ip:port"。
//
// 顺序是刻意排的：**先把 443 上的所有地址过一遍，再换端口**。MASQUE 的失败
// 绝大多数是「这台边缘这次没响应」，换地址比换端口有效得多；而 443 是唯一
// 在所有网络里都最可能放行的端口。
func masqueCandidateList(o Options, h2 bool) []string {
	if o.Endpoint != "" {
		host, port, err := net.SplitHostPort(o.Endpoint)
		if err != nil {
			return []string{o.Endpoint}
		}
		return []string{net.JoinHostPort(host, port)}
	}

	v4, v6 := masquePoolsV4, masquePoolsV6
	if h2 {
		v4, v6 = masqueH2PoolsV4, masqueH2PoolsV6
	}
	// 只出同一族：tun MTU 是按传输族定的（v4 1300 / v6 1160），混着试就会出现
	// 「v4 的 MTU 落到 v6 路径上」——封装 1368 字节 > 1280 的路径 MTU，握手能过、
	// 数据面全丢（2026-11-07 真机就是这样：8 轮外层探测全「数据面不通」）。
	var addrs []netip.Addr
	if o.IPv6 {
		addrs = append(addrs, prefixAddrs(v6, masqueSampleV6)...)
	} else {
		addrs = append(addrs, prefixAddrs(v4, masqueSampleV4)...)
	}

	ports := masqueEndpointPorts
	var out []string
	for i, port := range ports {
		// 第一轮只走 443；其余端口只在 443 全灭之后才试。
		if i > 0 && len(out) > 0 {
			break
		}
		_ = i
		for _, a := range addrs {
			out = append(out, net.JoinHostPort(a.String(), itoa(port)))
		}
	}
	if len(out) == 0 {
		return nil
	}
	// 443 单独排在最前，再排其余端口 × 地址。
	var rest []string
	for _, port := range ports[1:] {
		for _, a := range addrs {
			rest = append(rest, net.JoinHostPort(a.String(), itoa(port)))
		}
	}
	return append(out, rest...)
}

// 每个网段采样多少地址。/32 与 /128 就是它自己；/24 才有得挑。
const (
	masqueSampleV4 = 2
	masqueSampleV6 = 4
)

func prefixAddrs(pools []netip.Prefix, want int) []netip.Addr {
	var out []netip.Addr
	for _, p := range pools {
		if p.Bits() == p.Addr().BitLen() {
			out = append(out, p.Addr())
			continue
		}
		out = append(out, sampleInPrefix(p, want)...)
	}
	return out
}

// sampleInPrefix 在一个网段里随机取 n 个地址。整个 /24 有 256 个、/48 更是
// 天文数字，全扫既不现实也没意义。
func sampleInPrefix(p netip.Prefix, n int) []netip.Addr {
	base := p.Masked().Addr()
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits <= 0 {
		return []netip.Addr{base}
	}
	limit := 1 << min(hostBits, 16)
	out := make([]netip.Addr, 0, n)
	for i := 0; i < n; i++ {
		off := uint64(randInt(limit))
		out = append(out, addOffset(base, off))
	}
	return out
}

func itoa(v int) string { return fmt.Sprintf("%d", v) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// dialMasque 是 MASQUE 的拨号入口。流程与 WG 那条路一致 —— 逐个候选握手，
// 第一个「能握手且能过真实数据」的胜出 —— 只是候选来自 MASQUE 自己的实测池，
// 而且两端点之间要重换 CONNECT-IP 会话（桌面版的 handshake 已经处理了这件事）。
func dialMasque(ctx context.Context, o Options) (*Session, error) {
	// MASQUEX2（MASQUE H3 套 MASQUE H3）是「两条普通 MASQUE 串起来」，
	// 所以先在这里分派，下面的单层逻辑一行都不用改。
	if o.Proto == protoMASQUEX2 {
		return dialMasqueX2(ctx, o)
	}
	acct, err := ensureMasqueAccount(ctx, o.report)
	if err != nil {
		return nil, err
	}
	masqueAcct = acct

	mtu := masqueMTU(o.IPv6)
	if o.MTU > 0 {
		// 只有嵌套的外层会用到：外层必须装得下内层的 QUIC 初始包。
		mtu = o.MTU
	}
	h2 := o.Proto == protoMASQUEH2
	tn, err := newMasqueTunnel(h2, mtu, o.report)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			tn.Close()
		}
	}()

	// 提醒：系统 tun 的源地址是 Kotlin 写死的 172.16.0.2，而 MASQUE 分到的
	// 地址来自这套独立账号。两者不一致时包会被对端丢掉，必须说出来，
	// 而不是让人对着「已连接但打不开网页」猜。
	if tunFD > 0 && acct.IPv4 != "" && !hasPrefix(acct.IPv4, "172.16.0.2") {
		o.report(fmt.Sprintf("警告：MASQUE 分配的地址是 %s，与系统 tun 的 172.16.0.2 不一致，可能无法转发", acct.IPv4))
	}

	cands := masqueCandidateList(o, h2)
	if len(cands) == 0 {
		return nil, fmt.Errorf("MASQUE 没有候选端点")
	}
	transport := "HTTP/3"
	if h2 {
		transport = "HTTP/2"
	}
	o.report(fmt.Sprintf("MASQUE(%s) 候选端点 %d 个，预算 %s", transport, len(cands), o.Budget))

	deadline := time.Now().Add(o.Budget)
	var lastErr error
	// 最后一次**拨号**失败的原因。它和 lastErr（拨号成功但数据面不通）是两回事，
	// 分开留着，最终报错才能说清卡在哪一步。
	var lastDialErr error
	attempts := 0

	// 并发拨号（竞速）：只在「没钉死端点 + 不是 Psiphon 上游」时开。
	// 串行时一个候选要等满 3s 才有结论，20 个候选就是 60s；并发 3 个能把这段
	// 压到约 1/3，代价是同时多占两个 UDP 端口。
	hedge := !o.NoHedge && o.Endpoint == "" && len(cands) > 1
	if hedge {
		o.report(fmt.Sprintf("并发拨号：同时试 %d 个端点，先成功者胜出", masqueHedge))
	}

	for i := 0; i < len(cands); {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return nil, fmt.Errorf("MASQUE 在 %s 内没有可用端点（最后一次：%v）", o.Budget, lastErr)
			}
			if lastDialErr != nil {
				return nil, fmt.Errorf("MASQUE 在 %s 内没有可用端点（试了 %d 次，最后拨号错误：%v）", o.Budget, attempts, lastDialErr)
			}
			return nil, fmt.Errorf("MASQUE 在 %s 内没有可用端点（试了 %d 次）", o.Budget, attempts)
		}

		var endpoint string
		if hedge {
			batch := cands[i:min(i+masqueHedge, len(cands))]
			i += len(batch)
			attempts += len(batch)
			d, errs := tn.dialRace(ctx, batch, o.HandshakeTimeout)
			// 每个失败都要说话：MASQUE 的失败模式（UDP 被拦、凭据没登记、端点
			// 不答）只能靠错误文本区分，一句「42 次都没建起」等于没有信息。
			for _, e := range errs {
				o.report(fmt.Sprintf("拨号失败：%v", e))
			}
			if d == nil {
				if len(errs) > 0 {
					lastDialErr = errs[len(errs)-1]
				}
				continue
			}
			endpoint = d.endpoint
			// 上一轮的连接（数据面没验过）要先拆掉，否则 adopt 会把它覆盖成孤儿：
			// UDP 端口和 pumpIn 协程都还在，重试几次就积几个。
			tn.dropPeer()
			tn.adoptDial(d)
		} else {
			endpoint = cands[i]
			i++
			attempts++
			if dialErr := tn.handshakeErr(ctx, endpoint, o.HandshakeTimeout); dialErr != nil {
				lastDialErr = dialErr
				o.report(fmt.Sprintf("%s 拨号失败：%v", endpoint, dialErr))
				continue
			}
		}
		o.report(fmt.Sprintf("%s 已建立 CONNECT-IP，验证出口…", endpoint))
		start := time.Now()
		body, passed := egressProbe(ctx, tn, o.VerifyTimeout)
		if !passed {
			lastErr = fmt.Errorf("%s 连上但数据面不通", endpoint)
			o.report(fmt.Sprintf("%s 数据面不通，换下一个", endpoint))
			continue
		}
		s := &Session{tn: tn, Endpoint: endpoint, RTT: time.Since(start)}
		s.applyMeta(body)
		if s.ExitIP == "" && s.Country == "" {
			o.report("警告：出口信息解析为空（/meta 被拒），但数据面已验证")
		} else {
			// 带上 colo（实际接入的 Cloudflare 边缘机场代码）：出口 IP 是 CF 的共享
		// NAT 地址，同一个 IP 在不同地理库里会被标成不同城市（上海/郑州都出现过）。
		// 真正能区分线路的是 colo，不是 IP 归属地。
		if s.Colo != "" {
			o.report(fmt.Sprintf("出口 %s (%s, colo=%s)", s.ExitIP, s.Country, s.Colo))
		} else {
			o.report(fmt.Sprintf("出口 %s (%s)", s.ExitIP, s.Country))
		}
		}
		if o.SocksListen != "" && tn.stack() != nil {
			if !s.startSocks(ctx, o.SocksListen, o.report, o.Rules) && o.SocksRequired {
				return nil, fmt.Errorf("本地 SOCKS 端口 %s 起不来，而它这次是必需的（后续流程要连它）", o.SocksListen)
			}
		}
		// 上行并行：先把可用会话交给用户，其余几条在后台补齐（补失败不影响连接）。
		if !o.NoHedge && !o.NoParallelUplink {
			tn.growConns(endpoint, 6*time.Second, o.report)
		}
		ok = true
		return s, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("MASQUE 没有可用端点（%d 次尝试，最后一个错误：%v）", attempts, lastErr)
	}
	if lastDialErr != nil {
		return nil, fmt.Errorf("MASQUE 没有可用端点：%d 次尝试都没建起 CONNECT-IP（最后拨号错误：%v）", attempts, lastDialErr)
	}
	return nil, fmt.Errorf("MASQUE 没有可用端点：%d 次尝试都没建起 CONNECT-IP", attempts)
}

// hasPrefix 判断地址字符串是否落在给定前缀里（这里用于比对 172.16.0.2）。
func hasPrefix(addr, want string) bool {
	if addr == want {
		return true
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return ip.String() == want
}

func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// addOffset 在地址上加上一个主机位偏移。
func addOffset(base netip.Addr, off uint64) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v += uint32(off)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := base.As16()
	var v [16]byte
	copy(v[:], b[:])
	for i := 15; i >= 0 && off > 0; i-- {
		sum := uint64(v[i]) + (off & 0xff)
		v[i] = byte(sum)
		off >>= 8
		if sum <= 0xff {
			break
		}
	}
	return netip.AddrFrom16(v)
}
