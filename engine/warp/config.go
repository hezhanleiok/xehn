package warp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// 这个包是从 warpscout 的 CLI 搬过来的：它按「一个进程只跑一次扫描/一条隧道」
// 的假设把配置和账号存成了包级变量。安卓 App 也是单会话，所以保留这个形状，
// 但要**显式**地在会话开始前 Configure、结束后 Reset，否则 metaAddr / trap 这类
// 运行时缓教会把上一次会话的出口带进下一次。
//
// 协议家族都搬进来了：WG / AWG（tunnel.go）、MASQUE / MASQUE-H2（masque.go）、
// WARP-in-WARP（nest.go）。分派入口统一在 session.go 的 Dial。

// Config 是每次会话的输入（原本来自命令行 flag）。
type Config struct {
	// 端口列表；空则用 Cloudflare 的主端口集 {2408,500,1701,4500}。
	Ports []int
	// AmneziaWG 的混淆参数；为 0 表示用库里的默认值。
	AWGJc, AWGJmin, AWGJmax int
	AWGI1                   string
	// 只在 v6 池里挑端点（默认 v4）。
	IPv6 bool
	// TunFD > 0 表示走系统 VPN：这是 VpnService 建好的 tun 设备 fd，
	// 数据面交给操作系统，隧道只负责加解密。为 0 则退回 gVisor netstack
	// （进程内隧道，系统看不到，仅用于自测）。
	TunFD int
	// 设备 MTU；为 0 用 tunnelMTU(1280)。必须与 VpnService.Builder 的
	// setMtu 一致，否则大包会被内核按错误尺寸切分。
	MTU int
	// MASQUE 专用凭据的存放路径。必须与 WG 账号分开：登记会把设备改成
	// secp256r1/masque，同一账号里原来的 curve25519 私钥就作废了。
	MasqueCredsPath string
	// WARP-in-WARP 外层设备的凭据存放路径。同样要分开存：外层是**另一台**
	// WARP 设备（Cloudflare 会丢掉「同一设备嵌套自己」的流量）。
	OuterCredsPath string
}

// 每次会话的设备输入。VpnService 交上来的 tun fd 必须随会话重置：上一个
// 会话的 fd 早就随隧道关闭失效了，复用指针等于把设备的读写接进一个死文件。
var (
	tunFD  int
	tunMTU int
)

// Apply 把配置写进包的全局状态，并清掉上一次会话残留的运行时缓存。
func Apply(c Config) {
	tunFD = c.TunFD
	tunMTU = c.MTU
	masqueCredsFile = c.MasqueCredsPath
	outerCredsFile = c.OuterCredsPath

	// 每个会话都必须重置的东西。
	// metaAddr / pingAddr 是包级 atomic 缓存，跨会话不清会把上一次的出口元数据
	// 带进下一次（桌面版踩过：换了账号却复用了旧出口）。
	metaAddr.Store(nil)
	pingAddr.Store(nil)
	scanInterface = ""
	scanSourceIP = netip.Addr{}
	// 上一次会话的嵌套状态同样不能留：outer 非 nil 会被 newWGTunnel 当成
	// 「这条是内层隧道」，把普通会话的 UDP 塞进早已关闭的 netstack。
	outer = nil
	outerAcct = nil
	// 新一次连接拿到的是新的 tun fd，接管标记必须归零：否则上一次的
	// 「已被接管」会让这次的失败路径不敢关 fd，系统 VPN 又挂住。见 tunfd.go。
	tunFDAdopted.Store(false)

	if len(c.Ports) > 0 {
		warpPorts = c.Ports
	} else {
		warpPorts = primaryWarpPorts
	}
	if c.AWGJc > 0 {
		awgJc = c.AWGJc
	}
	if c.AWGJmin > 0 {
		awgJmin = c.AWGJmin
	}
	if c.AWGJmax > 0 {
		awgJmax = c.AWGJmax
	}
	if c.AWGI1 != "" {
		awgI1 = c.AWGI1
	}
	if c.IPv6 {
		pools = poolsV6
	} else {
		pools = poolsV4
	}
}

// ApplyAccountJSON 把一份账号 JSON 灌进全局（对应原来 applyAccount 的作用）。
// 安卓侧可以用它直接喂一份在电脑上生成好的账号，绕开注册那一步。
func ApplyAccountJSON(raw string) error {
	var a account
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return fmt.Errorf("账号 JSON 解析失败: %w", err)
	}
	if a.PrivateKey == "" || a.PeerPublicKey == "" {
		return errors.New("账号 JSON 里缺 private_key / peer_public_key")
	}
	applyAccount(a)
	return nil
}

// LoadOrRegisterAccount 按「supplied JSON → 本地文件 → 现注册」的顺序取账号，
// 并把它应用到全局，返回账号 JSON（调用方可以存起来复用）。
//
// 为什么要允许外部喂 JSON：在部分网络里 api.cloudflareclient.com 连不上，
// 现注册必然失败；这时在电脑上跑一次 warpscout register，把生成的
// account.json 导进 App 就能用。
func LoadOrRegisterAccount(ctx context.Context, accountPath, accountJSON string) (string, error) {
	if accountJSON != "" {
		if err := ApplyAccountJSON(accountJSON); err != nil {
			return "", err
		}
		return accountJSON, nil
	}

	if accountPath != "" {
		a, err := loadAccount(accountPath)
		switch {
		case err == nil:
			applyAccount(a)
			raw, _ := json.Marshal(a)
			return string(raw), nil
		case errors.Is(err, os.ErrNotExist):
			// 没缓存，往下走注册。
		default:
			return "", err
		}
	}

	client := &http.Client{Timeout: registerTimeout, Transport: regTransport(nil)}
	a, err := registerWARP(ctx, client)
	if err != nil {
		return "", fmt.Errorf("注册 WARP 账号失败（%v）；可在电脑上跑 warpscout register 生成 account.json 后导入", err)
	}
	if accountPath != "" {
		_ = os.MkdirAll(filepath.Dir(accountPath), 0o755)
		_ = saveAccount(accountPath, a)
	}
	applyAccount(a)
	raw, _ := json.Marshal(a)
	return string(raw), nil
}

// SplitEmbeddedAccounts 把一份「复合账号 JSON」里内嵌的 `masque` / `outer` 子账号
// 落成各自的凭据文件（masque.json / outer.json）。
//
// 它们本来就是**另外两台** WARP 设备：MASQUE 登记会把设备改成 secp256r1/masque，
// 外层设备是 Cloudflare 允许「嵌套 WARP」的前提（同一设备嵌套自己会被丢掉）。
// 随包账号里带上它们，就能在 api.cloudflareclient.com 不可达的网络里直接用，
// 而不必现注册。没有子对象、或子对象不完整时是空操作 —— 主账号照常可用，
// 缺的那条协议到运行时会自己去注册。
func SplitEmbeddedAccounts(workDir, raw string) {
	if raw == "" {
		return
	}
	var holder struct {
		Masque json.RawMessage `json:"masque"`
		Outer  json.RawMessage `json:"outer"`
	}
	if err := json.Unmarshal([]byte(raw), &holder); err != nil {
		return
	}
	for _, part := range []struct {
		data json.RawMessage
		file string
	}{
		{holder.Masque, filepath.Join(workDir, "masque.json")},
		{holder.Outer, filepath.Join(workDir, "outer.json")},
	} {
		if len(part.data) == 0 {
			continue
		}
		var a account
		if err := json.Unmarshal(part.data, &a); err != nil || a.PrivateKey == "" || a.PeerPublicKey == "" {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(part.file), 0o755)
		_ = saveAccount(part.file, a)
	}
}

// registerThroughTunnel 是「直连注册不通时，先握手一条隧道再从隧道里注册」的兜底。
// 原本在 register.go 的 obtainAccount 里，那一段依赖 CLI 的进度条与终端配色，
// 所以搬库时删掉了；这里保留能力、去掉终端耦合。
func registerThroughTunnel(ctx context.Context, run protoRun, ips []netip.Addr, timeout time.Duration, existing account) (account, error) {
	tn, err := newTunnel(run)
	if err != nil {
		return account{}, err
	}
	defer tn.Close()

	for _, ip := range ips {
		if ctx.Err() != nil {
			return account{}, ctx.Err()
		}
		if !tunnelConnect(ctx, tn, ip, timeout) {
			continue
		}
		client, err := tunnelClient(tn.stack().tnet)
		if err != nil {
			return account{}, err
		}
		return mintWGAccount(ctx, client, existing)
	}
	return account{}, errors.New("隧道内注册失败：没有可用端点")
}
