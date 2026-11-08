package warp

// OpenVPN 出口（VPN Gate）。
//
// 形态与 Psiphon 出口一致，都是「基础协议打底 + 另一种隧道做最终出口」：
//
//	系统 tun fd ──▶ 本文件的包泵 ──▶ OpenVPN 客户端 ──▶ 节点 ──▶ 互联网
//	                     ▲
//	                     └── 外层连接跑在基础协议（WARP）的 netstack 里
//
// 与 Psiphon 的**关键区别**：Psiphon 自带 packet tunnel，把 fd 交给它就行；
// OpenVPN 协议本身只负责加解密 IP 包，fd 的读写必须我们自己做。而且 OpenVPN
// 是**路由式**隧道：服务端按它 PUSH_REPLY 下发的 ifconfig 地址回程。若 tun 上
// 还是 WARP 的 172.16.0.2，服务端内核会把回程包发到 172.16.0.2、根本到不了我们，
// 表现就是「握手成功、什么都打不开」。所以建 VPN 必须分两步：
//
//	① 先起 WARP netstack（tunFD=0，不建系统 VPN）→ 经它拨节点 → OpenVPN 握手
//	② 拿到 PushReply 里的 ifconfig/route/dns → 回调上层建系统 VPN → 拿 fd → 起泵
//
// 客户端实现直接引用 mihomo 的 transport/openvpn（纯 Go、GPL-3.0）：
// 电脑版 1.19.32 的 `type: openvpn` 出站就是它，VPN Gate 的 AES-128-CBC/SHA1、
// 内联 ca/cert/key、tcp/udp、tls-auth/tls-crypt 都由它处理。重协商依赖
// github.com/metacubex/tls（标准库客户端不支持自由重协商，满一小时必断）。

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ovpn "github.com/xhwarp/android-engine/third_party/mihomo/openvpn"
)

// openvpnTunWait 是「握手完成后等上层建好系统 VPN」的上限。建 tun 只是一次
// VpnService.Builder.establish()，正常在几十毫秒内；给 30s 是为了覆盖用户在
// 系统弹窗上点「允许」的慢路径。
const openvpnTunWait = 30 * time.Second

// openvpnKeepalive 是空闲多久发一次 ping。NAT 会丢弃长时间没有反向流量的映射，
// 而 OpenVPN 的 ping 就是协议自带的保活包（mihomo 也按配置里的 ping 做同一件事）。
const openvpnKeepalive = 10 * time.Second

// OpenVPNConfig 是从 .ovpn 文本里解析出来的连接参数。
//
// 字段与 mihomo 的 ClientConfig 对齐：VPN Gate 的配置就是 hwdsl2/openvpn-install
// 生成的子集（dev tun / proto tcp|udp / cipher / auth / 内联证书）。
type OpenVPNConfig struct {
	RemoteHost string
	RemotePort int
	Proto      string
	Cipher     string
	Auth       string
	Dev        string
	CompLZO    string

	CA       string
	Cert     string
	Key      string
	TLSAuth  string
	TLSCrypt string

	KeyDirection string
	Username     string
	Password     string
	Ping         int
	PingRestart  int
}

// ParseOpenVPNConfig 解析 .ovpn 文本。
//
// 只认 VPN Gate 实际会用到的指令；未知指令一律忽略（OpenVPN 配置里大量
// `resolv-retry infinite` / `nobind` / `verb 3` 之类与数据面无关）。
// 内联块（<ca>…</ca>）必须原样保留 PEM，因为证书校验要它。
func ParseOpenVPNConfig(text string) (OpenVPNConfig, error) {
	var c OpenVPNConfig
	c.Proto = ovpn.ProtoUDP
	c.Dev = "tun"

	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var block string // 当前正在收集的内联块名
	var buf []string // 内联块内容
	flush := func() {
		if block == "" {
			return
		}
		body := strings.Join(buf, "\n")
		switch block {
		case "ca":
			c.CA = body
		case "cert":
			c.Cert = body
		case "key":
			c.Key = body
		case "tls-auth":
			c.TLSAuth = body
		case "tls-crypt":
			c.TLSCrypt = body
		}
		block, buf = "", nil
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if block != "" {
			if strings.EqualFold(line, "</"+block+">") {
				flush()
				continue
			}
			buf = append(buf, raw)
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			name := strings.ToLower(strings.Trim(line, "<>"))
			switch name {
			case "ca", "cert", "key", "tls-auth", "tls-crypt":
				block, buf = name, nil
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		arg := func(i int) string {
			if i < len(fields) {
				return fields[i]
			}
			return ""
		}
		switch key {
		case "remote":
			// 只取第一条：VPN Gate 的配置里通常只有一条，remote-random 只是打乱。
			if c.RemoteHost == "" {
				c.RemoteHost = arg(1)
				if p, err := strconv.Atoi(arg(2)); err == nil && p > 0 {
					c.RemotePort = p
				}
			}
		case "proto":
			c.Proto = strings.ToLower(arg(1))
		case "cipher":
			c.Cipher = arg(1)
		case "auth":
			c.Auth = arg(1)
		case "dev":
			c.Dev = strings.ToLower(arg(1))
		case "comp-lzo":
			c.CompLZO = arg(1)
			if c.CompLZO == "" {
				c.CompLZO = "yes"
			}
		case "key-direction":
			c.KeyDirection = arg(1)
		case "auth-user-pass":
			// VPN Gate 用证书认证；这里只记录，凭据由调用方另给。
			c.Username = "vpn"
			c.Password = "vpn"
		case "ping":
			if n, err := strconv.Atoi(arg(1)); err == nil {
				c.Ping = n
			}
		case "ping-restart":
			if n, err := strconv.Atoi(arg(1)); err == nil {
				c.PingRestart = n
			}
		}
	}
	flush()

	if c.RemoteHost == "" || c.RemotePort == 0 {
		return c, errors.New("ovpn 配置里没有可用的 remote host/port")
	}
	if strings.TrimSpace(c.CA) == "" {
		return c, errors.New("ovpn 配置里没有内联 <ca>（VPN Gate 的配置都带，缺了无法校验证书）")
	}
	return c, nil
}

// clientConfig 把解析结果转成 mihomo 的 ClientConfig。
func (c OpenVPNConfig) clientConfig() (*ovpn.ClientConfig, error) {
	cfg := &ovpn.ClientConfig{
		RemoteHost:   c.RemoteHost,
		RemotePort:   uint16(c.RemotePort),
		Proto:        c.Proto,
		Dev:          c.Dev,
		Cipher:       c.Cipher,
		Auth:         c.Auth,
		CompLZO:      c.CompLZO,
		CA:           []byte(c.CA),
		Cert:         []byte(c.Cert),
		Key:          []byte(c.Key),
		TLSAuth:      []byte(c.TLSAuth),
		TLSCrypt:     []byte(c.TLSCrypt),
		KeyDirection: c.KeyDirection,
		Username:     c.Username,
		Password:     c.Password,
		PingInterval: time.Duration(c.Ping) * time.Second,
		PingRestart:  time.Duration(c.PingRestart) * time.Second,
	}
	if err := cfg.Prepare(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// OpenVPNTun 是服务器下发的、建系统 VPN 必须用的参数。
//
// Address 就是 PushReply 的 ifconfig 地址 —— 服务端按它回程，改成别的值必然丢包。
type OpenVPNTun struct {
	Address   string
	PrefixLen int
	Routes    []string
	DNS       []string
	MTU       int
}

// OpenVPNOptions 是一次「基础协议 + OpenVPN 节点」会话的参数。
type OpenVPNOptions struct {
	// Config 是 .ovpn 原文（含内联证书）。
	Config string
	// Label 只用于日志（节点名/国家）。
	Label string

	UnderlayProto    string
	UnderlayEndpoint string
	UnderlayPrefer   string
	IPv6             bool

	HandshakeTimeout time.Duration
	VerifyTimeout    time.Duration
	Budget           time.Duration

	// PrepareTun 在握手成功后调用：上层用这些参数建系统 VPN 并返回 fd。
	// 这是本流程唯一需要回调 Android 的地方（VpnService.Builder 只能在 Java 侧调）。
	PrepareTun func(OpenVPNTun) (int, error)

	Report func(string)
}

func (o *OpenVPNOptions) report(msg string) {
	if o.Report != nil {
		o.Report(msg)
	}
}

// packetStream 是 tun 侧的最小读写接口。
//
// 真实连接用 packetFile（借用 VpnService 的 fd，不拥有、不关闭）；
// 「测延迟时顺便测速」用 gVisor netstack 设备（tunDeviceStream），这样不必为
// 测一个节点的速度而去建系统 VPN（那会把用户正在用的连接踢掉）。
type packetStream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// tunDeviceStream 把 amneziawg-go 的 tun.Device（这里是 gVisor netstack）适配成
// packetStream：设备的 Read/Write 是「批量 + offset」形状，这里退化成单包。
type tunDeviceStream struct {
	dev interface {
		Read([][]byte, []int, int) (int, error)
		Write([][]byte, int) (int, error)
	}
}

func (t *tunDeviceStream) Read(p []byte) (int, error) {
	bufs := [][]byte{p}
	sizes := []int{0}
	if _, err := t.dev.Read(bufs, sizes, 0); err != nil {
		return 0, err
	}
	return sizes[0], nil
}

func (t *tunDeviceStream) Write(p []byte) (int, error) {
	return t.dev.Write([][]byte{p}, 0)
}

// Close 什么都不做：netstack 设备由调用方关闭。
func (t *tunDeviceStream) Close() error { return nil }

// openvpnExit 是一条已经跑起来的 OpenVPN 数据面。
type openvpnExit struct {
	client *ovpn.Client
	// file 只借用 tun fd，不拥有、不关闭（关闭权在 Kotlin 的 ParcelFileDescriptor）。
	file   packetStream
	cancel context.CancelFunc
	once   sync.Once

	txBytes atomic.Uint64 // 写进 tun 的字节 = 从节点收下来的
	rxBytes atomic.Uint64 // 从 tun 读出的字节 = 发往节点的
}

func (e *openvpnExit) counters() (tx, rx uint64) {
	return e.txBytes.Load(), e.rxBytes.Load()
}

func (e *openvpnExit) close() {
	if e == nil {
		return
	}
	e.once.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}
		if e.client != nil {
			_ = e.client.Close()
		}
		if e.file != nil {
			_ = e.file.Close()
		}
	})
}

// startPump 在 tun fd 与 OpenVPN 客户端之间双向搬运 IP 包。
//
// ctx 用**会话级**的 background context，不能用这次 Connect 的 ctx：Connect
// 成功后引擎会把那个 ctx cancel 掉，泵会立刻退出（表现是「连上就断」）。
func (e *openvpnExit) startPump(ctx context.Context) {
	pumpCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	go func() {
		defer e.close()
		buf := make([]byte, 65535)
		for {
			n, err := e.file.Read(buf)
			if n > 0 {
				e.rxBytes.Add(uint64(n))
				if werr := e.client.WriteIPPacket(pumpCtx, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
			if pumpCtx.Err() != nil {
				return
			}
		}
	}()

	go func() {
		defer e.close()
		for {
			pkt, err := e.client.ReadIPPacket(pumpCtx)
			if err != nil {
				return
			}
			if _, werr := e.file.Write(pkt); werr != nil {
				return
			}
			e.txBytes.Add(uint64(len(pkt)))
		}
	}()

	// 保活：空闲超过 openvpnKeepalive 就发一个 ping。服务端也会发，但我们这边
	// 的 NAT 映射是「发出去」才刷新的，只靠收包不够。
	go func() {
		defer e.close()
		t := time.NewTicker(openvpnKeepalive)
		defer t.Stop()
		for {
			select {
			case <-pumpCtx.Done():
				return
			case <-t.C:
				if e.client.SinceSend() >= openvpnKeepalive {
					if err := e.client.WritePing(pumpCtx); err != nil {
						return
					}
				}
			}
		}
	}()
}

// DialOpenVPN 建「基础协议（WARP）→ OpenVPN 节点」的出口。
//
// 返回的 Session 已经把系统 tun fd 接管（Session.Close 会关掉它，系统 VPN 随之消失）。
func DialOpenVPN(ctx context.Context, o OpenVPNOptions) (*Session, error) {
	if strings.TrimSpace(o.Config) == "" {
		return nil, errors.New("缺少 OpenVPN 节点配置")
	}
	if o.PrepareTun == nil {
		return nil, errors.New("缺少建 tun 的回调（Android 侧必须先装好 TunProvider）")
	}
	if o.UnderlayProto == "" {
		o.UnderlayProto = protoAWG
	}
	if o.Budget <= 0 {
		o.Budget = 60 * time.Second
	}

	cfgText, err := ParseOpenVPNConfig(o.Config)
	if err != nil {
		return nil, err
	}
	clientCfg, err := cfgText.clientConfig()
	if err != nil {
		return nil, fmt.Errorf("ovpn 配置不受支持: %w", err)
	}
	nodeAddr := net.JoinHostPort(cfgText.RemoteHost, strconv.Itoa(cfgText.RemotePort))
	o.report(fmt.Sprintf("OpenVPN 节点 %s（%s/%s）", nodeAddr, cfgText.Proto, firstNonEmpty(cfgText.Cipher, "默认加密")))

	// ①② 上游只有一条：先进 WARP，再从隧道里拨节点。
	//
	// 曾经有过「宿主 socket 直连节点」的模式（理论上更快，因为它省掉了 WARP 和
	// gVisor 用户态 TCP），但 2026-10-22 真机实测：这条网络里直连节点的 TCP
	// 全部 i/o timeout，连接失败**全部**由它引入，而直连成功的那几个也过不了数据。
	// 所以整条直连分支（含设置里的「连节点方式」）在 0.2.3 移除，不再作为选项。
	under, client, push, err := dialOpenVPNUpstream(ctx, o, cfgText, clientCfg, nodeAddr)
	if err != nil {
		// 同一节点重试一次：VPN Gate 的 TCP 握手会抖（真机日志里 98 个节点有 36 个
		// 是 `hard reset response` / `EOF` 这类瞬时失败，同一个节点下一次就过）。
		// 用户看到的却是「固定节点连不上」——重试一次能救回相当一部分。
		o.report(fmt.Sprintf("节点 %s 第一次握手失败（%v），重试一次…", nodeAddr, err))
		under, client, push, err = dialOpenVPNUpstream(ctx, o, cfgText, clientCfg, nodeAddr)
		if err != nil {
			return nil, fmt.Errorf("连接 OpenVPN 节点 %s 失败：%w", nodeAddr, err)
		}
	}
	// ok 只在真正把会话交出去之后置位；中途任何 return 都要把上游隧道关掉，
	// 否则一条 netstack 隧道会留在后台空转（系统看不到，日志里也看不出来）。
	ok := false
	defer func() {
		if !ok && under != nil {
			under.Close()
		}
	}()

	// ③ 建系统 VPN：地址必须用服务器下发的那个。
	tun := openVPNTunFromPush(push)
	o.report(fmt.Sprintf("OpenVPN 已握手，下发地址 %s/%d（peer-id %d），建立系统 VPN…",
		tun.Address, tun.PrefixLen, push.PeerID))
	tunCtx, tunCancel := context.WithTimeout(ctx, openvpnTunWait)
	fdCh := make(chan struct {
		fd  int
		err error
	}, 1)
	go func() {
		fd, perr := o.PrepareTun(tun)
		fdCh <- struct {
			fd  int
			err error
		}{fd, perr}
	}()
	var fd int
	select {
	case r := <-fdCh:
		fd, err = r.fd, r.err
	case <-tunCtx.Done():
		err = fmt.Errorf("建系统 VPN 超时（%s）", openvpnTunWait)
	}
	tunCancel()
	if err != nil || fd <= 0 {
		_ = client.Close()
		if err == nil {
			err = fmt.Errorf("建系统 VPN 失败（fd=%d）", fd)
		}
		return nil, err
	}

	// ④ 起泵。
	//
	// fd 归 Kotlin 的 ParcelFileDescriptor 所有，这里只借用（见 pktfile_android.go
	// 的 fdsan 记录）。以前是 os.NewFile + file.Close，Go 关一次、Java 侧对象还
	// 认为自己是 owner —— 换点几次后必然撞上 fdsan abort（真机 SIGABRT 闪退）。
	f := newPacketFile(fd)
	ex := &openvpnExit{client: client, file: f}
	ex.startPump(context.Background())

	sess := under
	sess.ovpn = ex
	sess.tunFD = fd

	// ⑤ 出口验证：此时 App 自己的流量已经被系统路由进新的 tun，所以一次普通
	//    HTTPS 请求就是端到端验证（握手成功 ≠ 能过数据）。
	//
	//    这里必须多端点 + 重试：单端点（只看 1.1.1.1）单次请求会在两种情况下误判 ——
	//    ① 某些网络里 1.1.1.1 直连被拦、经隧道才通，刚 establish 那一两秒正是飘的；
	//    ② 个别节点只拦 Cloudflare 的 trace 端点本身。真机实测就是被这个窗口判死的。
	//
	//    预算不能照搬「单个端点握手超时」那档：这里要付的是
	//    TCP(OpenVPN over WARP netstack) + TLS 到 1.1.1.1 的完整往返。真机日志
	//    （2026-11-07）里 8s 预算只够跑 2 轮、两轮都超时，而节点其实能用（用户
	//    实测有下载）。20s 是同一批节点里最慢那档的实际握手时长量级。
	verify := o.VerifyTimeout
	if verify < 20*time.Second {
		verify = 20 * time.Second
	}
	ip, country, passed := probeExitViaTun(ctx, verify, o.Report)
	if !passed {
		ex.close()
		sess.ovpn = nil
		sess.tunFD = 0
		// ok 保持 false：让 defer 把上游隧道也关掉，不留后台空转的 netstack。
		return nil, fmt.Errorf("OpenVPN 已连接但出口验证失败（节点 %s 没有真正转发流量）", nodeAddr)
	}
	sess.ExitIP, sess.Country = ip, country
	o.report(fmt.Sprintf("OpenVPN 出口 %s (%s)", ip, country))
	ok = true
	return sess, nil
}

// OpenUnderlay 起一条「只当外层载体」的 WARP 隧道（系统 tun fd 不参与）。
//
// 单独抽出来是因为「真延迟测试」要复用同一条上游去握手几十个节点：
// 每测一个节点就重拨一次 WARP（28 个端点 × 60s 预算）既慢又没必要 ——
// 一条上游本来就是纯用户态 netstack，谁都能往上拨。
//
// 调用方负责 Close 返回的 Session。
func OpenUnderlay(ctx context.Context, o OpenVPNOptions) (*Session, error) {
	if o.UnderlayProto == "" {
		o.UnderlayProto = protoAWG
	}
	savedTunFD := tunFD
	tunFD = 0
	sess, err := Dial(ctx, Options{
		Proto:            o.UnderlayProto,
		Endpoint:         o.UnderlayEndpoint,
		Prefer:           o.UnderlayPrefer,
		IPv6:             o.IPv6,
		Sample:           2,
		HandshakeTimeout: o.HandshakeTimeout,
		VerifyTimeout:    o.VerifyTimeout,
		Budget:           o.Budget,
		NoHedge:          true,
		Report:           o.Report,
	})
	tunFD = savedTunFD
	if err != nil {
		return nil, fmt.Errorf("WARP 上游（%s）建立失败: %w", o.UnderlayProto, err)
	}
	if sess.tn.stack() == nil {
		sess.Close()
		return nil, errors.New("上游没有 netstack，OpenVPN 外层连接无处可拨（内部错误）")
	}
	o.report(fmt.Sprintf("上游就绪（%s 出口 %s），经 WARP 拨节点…", o.UnderlayProto, sess.ExitIP))
	return sess, nil
}

// ProbeOpenVPNHandshake 只做「经已有上游拨节点 + OpenVPN 握手」，返回握手耗时。
//
// 与 DialOpenVPN 的区别只有一个：**握手成功后立刻关掉，不建系统 tun、不验证数据面**。
// 这正是「延迟」两个字的正确含义 —— 列表里原来那个延迟是同域名 TCP 连接时间，
// 跟这个节点能不能握手、握手多久几乎没有关系（2026-11-01 实测：显示 193~214ms 的
// 美国节点三个全死）。
//
// 注意它证明不了「能转发流量」：握手成功但一个字节都不转的节点在 VPN Gate 上很常见，
// 所以这只是**筛掉死的**，真正能不能用还得靠连接时的出口验证。
func ProbeOpenVPNHandshake(ctx context.Context, under *Session, configText string, timeout time.Duration) (time.Duration, error) {
	client, _, elapsed, err := probeOpenVPNHandshake(ctx, under, configText, timeout)
	if client != nil {
		_ = client.Close()
	}
	return elapsed, err
}

// ProbeOpenVPNSpeed 在握手之后，经**同一个节点**真下载一小段，返回
// (握手耗时, 字节/秒, error)。
//
// bps == 0 且 err == nil 表示「握手成功但测不出速度」（节点慢、测速端点不可达）：
// 这种情况**不要判节点失败** —— 没有证据说明它不能用，界面显示「握手成功 ·
// 速度未测」即可，和连接时 measureExitBps 的取舍一致。
//
// 数据面用进程内 gVisor netstack 当 tun：OpenVPN 的包泵往它写，HTTPS 从它拨。
// 这样测速不需要建系统 VPN，也就不会把用户正在用的连接踢掉。
func ProbeOpenVPNSpeed(
	ctx context.Context, under *Session, configText string,
	timeout, budget time.Duration,
) (time.Duration, int64, string, error) {
	client, push, elapsed, err := probeOpenVPNHandshake(ctx, under, configText, timeout)
	if err != nil {
		if client != nil {
			_ = client.Close()
		}
		return elapsed, 0, "", err
	}
	closed := false
	defer func() {
		if !closed {
			_ = client.Close()
		}
	}()
	bps, stage := measureThroughOpenVPN(client, push, budget)
	closed = true
	return elapsed, bps, stage, nil
}

// probeOpenVPNHandshake 拨号并完成握手，把可用的 client 交给调用方关闭。
func probeOpenVPNHandshake(
	ctx context.Context, under *Session, configText string, timeout time.Duration,
) (*ovpn.Client, *ovpn.PushReply, time.Duration, error) {
	if under == nil {
		return nil, nil, 0, errors.New("没有上游隧道")
	}
	stack := under.tn.stack()
	if stack == nil {
		return nil, nil, 0, errors.New("上游没有 netstack（内部错误）")
	}
	cfgText, err := ParseOpenVPNConfig(configText)
	if err != nil {
		return nil, nil, 0, err
	}
	clientCfg, err := cfgText.clientConfig()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ovpn 配置不受支持: %w", err)
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	nodeAddr := net.JoinHostPort(cfgText.RemoteHost, strconv.Itoa(cfgText.RemotePort))
	conn, err := dialThroughStack(ctx, stack, cfgText.Proto, nodeAddr, timeout)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("经 WARP 连接节点失败: %w", err)
	}
	packetIO := ovpn.NewDatagramPacketIO(conn)
	if cfgText.Proto == ovpn.ProtoTCP {
		packetIO = ovpn.NewTCPPacketIO(conn)
	}
	client, err := ovpn.NewClient(clientCfg, packetIO)
	if err != nil {
		_ = conn.Close()
		return nil, nil, 0, fmt.Errorf("OpenVPN 客户端初始化失败: %w", err)
	}

	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	push, err := client.Handshake(hsCtx)
	elapsed := time.Since(start)
	if err != nil {
		_ = client.Close()
		return nil, nil, elapsed, fmt.Errorf("OpenVPN 握手失败: %w", err)
	}
	if push == nil || len(push.Prefixes) == 0 {
		_ = client.Close()
		return nil, nil, elapsed, errors.New("握手成功但服务器没有下发 ifconfig 地址")
	}
	return client, push, elapsed, nil
}

// probeSpeedSlots 限制「同时做测速」的节点数。
//
// 每一个测速都要起一个完整的 gVisor netstack（TCP/IP 栈 + goroutine 池）再叠
// 一条 OpenVPN 数据通道。握手探测本身很轻（一个控制通道），但测速很重：
// 真机现象是「测到第 8 个就再也不动了」—— 8 个并发 netstack 把手机 CPU/内存
// 压满，后面的节点永远等不到 worker。握手仍然并发 8，只把**测速**限到 3。
var probeSpeedSlots = make(chan struct{}, 3)

// measureThroughOpenVPN 用 gVisor netstack 当 tun，把 OpenVPN 的包泵接上去，
// 然后做一次真实下载。0 = 测不出来。
func measureThroughOpenVPN(client *ovpn.Client, push *ovpn.PushReply, budget time.Duration) (int64, string) {
	if budget <= 0 {
		budget = 6 * time.Second
	}
	// 等一个测速槽位。
	//
	// 这里**不能**只等 budget：8 个握手 worker 里只有 3 个能同时测速，其余 5 个
	// 若 6 秒就放弃，界面会有一大半节点「速度未测」（用户明确不接受）。正常排队
	// 最多 3×6=18 秒，所以给 30 秒的等待上限：足够排队，又不会把 worker 永久占住。
	select {
	case probeSpeedSlots <- struct{}{}:
		defer func() { <-probeSpeedSlots }()
	case <-time.After(30 * time.Second):
		return 0, "测速队列等待超时"
	}

	tun := openVPNTunFromPush(push)
	addr, err := netip.ParseAddr(tun.Address)
	if err != nil || !addr.Is4() {
		return 0, "节点没有下发 IPv4 地址"
	}
	dev, stack, err := newIPStack([]netip.Addr{addr}, tun.MTU)
	if err != nil {
		return 0, "建测速网络栈失败"
	}
	ex := &openvpnExit{client: client, file: &tunDeviceStream{dev: dev}}
	// 硬超时 + 关闭顺序都必须是「先关 dev、再关 client」：
	//   dev.Close() 让包泵里卡在 Read/Write 的 goroutine 立刻返回，
	//   之后 client.Close() 才不会等一个永远不返回的读循环。
	// 没有这层保护时，某个节点一旦卡在泵里，这个 worker 就永久丢失 ——
	// 8 个 worker 全部卡住 = 探测停在 8/N 再也不动（真机现场）。
	var once sync.Once
	forceClose := func() {
		once.Do(func() {
			_ = dev.Close()
			ex.close()
		})
	}
	timer := time.AfterFunc(budget+3*time.Second, forceClose)
	ex.startPump(context.Background())
	defer func() {
		timer.Stop()
		forceClose()
	}()
	return probeDownloadBps(stack, budget)
}

// probeSpeedHost / probeSpeedURL 是探测用的测速端点：1 MiB 足够看出量级，
// 又不至于让一个节点占住探测通道太久（正式出口测速另有 speedURL）。
const (
	probeSpeedHost = "speed.cloudflare.com"
	probeSpeedURL  = "https://" + probeSpeedHost + "/__down?bytes=1048576"
)

// probeSpeedIP 缓存测速端点的 IPv4 解析结果。
var probeSpeedIP atomic.Value

// lookupProbeSpeedIP 用**主机** DNS 解析测速端点。
//
// 为什么不用隧道里的解析：探测阶段系统 VPN 还没建立，主机 DNS 一定可用；而经节点
// 的 DNS 经常不通（VPN Gate 节点普遍不转发 UDP 53）。那会让测速「6 秒一个字节都
// 收不到」，表现就是握手成功、速度永远显示「未测」—— 真机里澳大利亚节点就是这样。
func lookupProbeSpeedIP() string {
	if v, ok := probeSpeedIP.Load().(string); ok && v != "" {
		return v
	}
	ips, err := net.LookupIP(probeSpeedHost)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			probeSpeedIP.Store(v4.String())
			return v4.String()
		}
	}
	return ""
}

// probeDownloadBps 经 netstack 下载一小段并算出字节/秒。
//
// 第二个返回值是「为什么没测出来」，由调用方写进日志 —— 只写「速度未测」的话，
// 下次还是分不清是 DNS 不通、TLS 失败，还是节点真的没带宽。
func probeDownloadBps(stack *ipStack, budget time.Duration) (int64, string) {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	tr := &http.Transport{DisableKeepAlives: true}
	if ip := lookupProbeSpeedIP(); ip != "" {
		// 直接拨 IP + 固定 SNI：绕过隧道内 DNS，这一步救回了大量「握手成功但
		// 测速 0 字节」的节点。
		tr.DialTLSContext = func(dctx context.Context, network, addr string) (net.Conn, error) {
			c, err := stack.tnet.DialContext(dctx, "tcp", net.JoinHostPort(ip, "443"))
			if err != nil {
				return nil, fmt.Errorf("tcp: %w", err)
			}
			tc := tls.Client(c, &tls.Config{
				ServerName: probeSpeedHost,
				NextProtos: []string{"http/1.1"},
			})
			if err := tc.HandshakeContext(dctx); err != nil {
				_ = c.Close()
				return nil, fmt.Errorf("tls: %w", err)
			}
			return tc, nil
		}
	} else {
		tr.DialContext = func(dctx context.Context, network, addr string) (net.Conn, error) {
			return stack.tnet.DialContext(dctx, network, addr)
		}
	}

	client := &http.Client{Timeout: budget, Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeSpeedURL, nil)
	if err != nil {
		return 0, "构造请求失败"
	}
	// client.Do 包含 TCP + TLS + 首字节：经「WARP → 节点 → CF」链路，光握手就要
	// 好几秒，所以计时**从首字节之后开始**。
	resp, err := client.Do(req)
	if err != nil {
		return 0, shortErr(err)
	}
	defer resp.Body.Close()

	start := time.Now()
	window := 2 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rest := time.Until(dl); rest < window {
			window = rest
		}
	}
	var got int64
	buf := make([]byte, 32<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		got += int64(n)
		if rerr != nil || time.Since(start) >= window {
			break
		}
	}
	d := time.Since(start).Seconds()
	// 样本太短（<0.3s）就不可信：可能是首包刚好卡在窗口边缘。
	if got <= 0 {
		return 0, "已连上但 2 秒内没有收到数据"
	}
	if d < 0.3 {
		return 0, "样本太短"
	}
	return int64(float64(got) / d), ""
}

// dialOpenVPNUpstream 起 WARP 上游 → 经它拨节点 → 完成 OpenVPN 握手。
//
// 上游**只有这一条**：不进 WARP 的「直连节点」模式在 0.2.3 被删掉了 ——
// 真机实测那条路在本网络里全是 i/o timeout（连接失败全部由它引入），
// 偶尔握手成功也过不了数据，留着只是给用户多一个失败面。
//
// 失败时自己清理：conn / 上游隧道 / 客户端都不留给调用方，避免残留一条
// netstack 隧道（这种残留系统看不到，只能靠内存涨和日志里少一行察觉）。
func dialOpenVPNUpstream(
	ctx context.Context,
	o OpenVPNOptions,
	cfg OpenVPNConfig,
	clientCfg *ovpn.ClientConfig,
	nodeAddr string,
) (under *Session, client *ovpn.Client, push *ovpn.PushReply, err error) {
	// 系统 tun fd 这一轮归 OpenVPN 的包泵，基础协议退成 netstack。
	under, err = OpenUnderlay(ctx, o)
	if err != nil {
		return nil, nil, nil, err
	}
	stack := under.tn.stack()
	if stack == nil {
		under.Close()
		return nil, nil, nil, errors.New("上游没有 netstack，OpenVPN 外层连接无处可拨（内部错误）")
	}

	// TCP/UDP 都走 gVisor，系统的路由表完全不参与，所以这一步在系统 VPN
	// 建起来之前就能完成。
	conn, err := dialThroughStack(ctx, stack, cfg.Proto, nodeAddr, o.HandshakeTimeout)
	if err != nil {
		under.Close()
		return nil, nil, nil, fmt.Errorf("经 WARP 连接节点失败: %w", err)
	}

	packetIO := ovpn.NewDatagramPacketIO(conn)
	if cfg.Proto == ovpn.ProtoTCP {
		packetIO = ovpn.NewTCPPacketIO(conn)
	}
	client, err = ovpn.NewClient(clientCfg, packetIO)
	if err != nil {
		_ = conn.Close()
		under.Close()
		return nil, nil, nil, fmt.Errorf("OpenVPN 客户端初始化失败: %w", err)
	}

	hsCtx, hsCancel := context.WithTimeout(ctx, handshakeWindow(o.HandshakeTimeout))
	push, err = client.Handshake(hsCtx)
	hsCancel()
	if err != nil {
		_ = client.Close()
		under.Close()
		return nil, nil, nil, fmt.Errorf("OpenVPN 握手失败: %w", err)
	}
	if push == nil || len(push.Prefixes) == 0 {
		_ = client.Close()
		under.Close()
		return nil, nil, nil, errors.New("OpenVPN 握手成功但服务器没有下发 ifconfig 地址")
	}
	return under, client, push, nil
}

// dialThroughStack 在隧道 netstack 里拨一个 TCP/UDP 连接。
func dialThroughStack(ctx context.Context, stack *ipStack, proto, addr string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch proto {
	case ovpn.ProtoTCP:
		return stack.tnet.DialContext(dialCtx, "tcp", addr)
	case ovpn.ProtoUDP:
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		// 域名在隧道内解析：宿主解析器给出的地址可能只有隧道外才路由得到。
		var ip netip.Addr
		if a, perr := netip.ParseAddr(host); perr == nil {
			ip = a
		} else {
			ips, lerr := stack.tnet.LookupContextHost(dialCtx, host)
			if lerr != nil || len(ips) == 0 {
				return nil, fmt.Errorf("隧道内解析 %s 失败: %v", host, lerr)
			}
			ip, err = netip.ParseAddr(preferV4(ips))
			if err != nil {
				return nil, err
			}
		}
		return stack.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(ip, uint16(port)))
	default:
		return nil, fmt.Errorf("不支持的 OpenVPN 传输协议 %q", proto)
	}
}

// handshakeWindow 给单次 OpenVPN 握手一个上限。VPN Gate 节点的握手实测
// 4.8–12.5s，给 25s 既不会把慢节点误杀，也不会让界面无休止转。
func handshakeWindow(d time.Duration) time.Duration {
	if d <= 0 {
		return 25 * time.Second
	}
	if d < 10*time.Second {
		return 10 * time.Second
	}
	return d * 2
}

// openVPNTunFromPush 把 PUSH_REPLY 转成 VpnService 需要的参数。
func openVPNTunFromPush(p *ovpn.PushReply) OpenVPNTun {
	// 1160 是算出来的，不是拍的：
	//   经 WARP 时外层 netstack MTU 1280 → MSS 1240；
	//   一个内层 IP 包要再套 OpenVPN 头（2 字节长度 + 1 字节 opcode + 20 HMAC
	//   + 16 IV + ≤16 的 CBC 填充 ≈ 55），所以内层最多 1240-55 ≈ 1185。
	// 原来写 1400，每个包都被外层拆成 1240+160 两段，包量和加密次数接近翻倍。
	t := OpenVPNTun{MTU: 1160}
	for _, pfx := range p.Prefixes {
		if pfx.Addr().Is4() {
			t.Address = pfx.Addr().String()
			t.PrefixLen = pfx.Bits()
			break
		}
	}
	for _, r := range p.Routes {
		if r.Addr().Is4() {
			t.Routes = append(t.Routes, r.String())
		}
	}
	for _, d := range p.DNS {
		if d.Is4() {
			t.DNS = append(t.DNS, d.String())
		}
	}
	return t
}

// exitProbeEndpoints 是出口验证用的端点，按尝试顺序排列。
//
// 两个都是 IP 字面量：系统 VPN 刚 establish 时隧道内的 DNS 是最不可靠的一环，
// 而这里要回答的问题只是「节点有没有在转发 IP 包」。
var exitProbeEndpoints = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"https://1.0.0.1/cdn-cgi/trace",
}

// exitProbeAttempt 是单次请求的上限。整轮验证的预算由 timeout 控制，
// 这个值只防止一个卡住的端点把整轮预算吃光。
const exitProbeAttempt = 4 * time.Second

// exitProbeRetryGap 是两轮之间的间隔。
//
// 实测（真机 2026-10-22）：VpnService.establish() 返回后路由/接口还会飘 1–2 秒，
// 期间同一个 URL 可能立刻失败、也可能超时；而 curl 在同一块 tun0 上晚几秒就 200。
// 所以「一次失败就判节点死刑」会把大量本来能用的节点丢掉 —— 必须在预算内重试。
const exitProbeRetryGap = 700 * time.Millisecond

// probeExitViaTun 验证隧道是否真的在转发流量，并顺手取出口 IP。
//
// 判定标准是「拿到一份带 ip= 的 trace」，而不是「TCP 能握手」：VPN Gate 上存在
// 握手成功、控制通道正常、但数据面被节点自己丢掉的情况，只有端到端请求能分清。
func probeExitViaTun(ctx context.Context, timeout time.Duration, report func(string)) (string, string, bool) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	deadline := time.Now().Add(timeout)
	lastErr := "预算内一次都没发出去"
	round := 0

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			lastErr = ctx.Err().Error()
			break
		}
		round++
		for _, ep := range exitProbeEndpoints {
			remain := time.Until(deadline)
			if remain < 300*time.Millisecond {
				break
			}
			attempt := remain
			if attempt > exitProbeAttempt {
				attempt = exitProbeAttempt
			}
			reqCtx, cancel := context.WithTimeout(ctx, attempt)
			body, err := fetchMetaErr(reqCtx, &http.Client{Timeout: attempt}, ep)
			cancel()
			if err != nil {
				lastErr = shortErr(err)
				continue
			}
			ip := traceValue(body, "ip")
			if ip == "" {
				lastErr = "端点有响应但没有 ip 字段"
				continue
			}
			if round > 1 && report != nil {
				report(fmt.Sprintf("出口验证第 %d 轮通过（%s）", round, ip))
			}
			return ip, traceValue(body, "loc"), true
		}
		select {
		case <-ctx.Done():
			lastErr = ctx.Err().Error()
		case <-time.After(exitProbeRetryGap):
		}
	}

	if report != nil {
		report(fmt.Sprintf("出口验证未通过（%d 轮：%s）", round, lastErr))
	}
	return "", "", false
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
