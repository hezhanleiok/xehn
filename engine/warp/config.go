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
	// MASQUEX2 外层 MASQUE 设备的凭据路径。和 WARP-in-WARP 的外层一样，这里也
	// 需要**另一套**设备：Cloudflare 会丢掉「同一设备嵌套自己」的流量。
	// 为空则不缓存（每次现登记一台，费一次注册请求但功能正常）。
	MasqueOuterCredsPath string
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
// SetCredsPaths 只设置凭据文件路径，不碰任何会话状态。
//
// 给「连接前预注册账号」用：那里只需要知道 masque.json 在哪，之前却调了
// 完整的 Apply(Config{})，顺手把 metaAddr / outer / masqueNest 全清了。清掉
// metaAddr 的后果是出口验证必须重新做一次 DNS 解析，而解析在 WARP 刚起来时
// 经常失败 —— 于是一条好隧道被判定成「数据面不通」。
func SetCredsPaths(masque, masqueOuter, outer string) {
	masqueCredsFile = masque
	masqueOuterCredsFile = masqueOuter
	outerCredsFile = outer
}

// ResetTransient 只清「跨会话的临时状态」，不动 tunFD / MTU / 凭据路径。
//
// 用途：某些流程（「更新地区列表」跑一次 Psiphon、之前的探测会话）会留下
// outer / masqueNest / metaAddr 这些指针。下一次连接如果复用了它们，上游的 UDP
// 会被塞进一条已经关闭的 netstack —— 表现就是「握手成功、数据面全不通」。
func ResetTransient() {
	metaAddr.Store(nil)
	pingAddr.Store(nil)
	masqueNest.Store(nil)
	outer = nil
	outerAcct = nil
}

func Apply(c Config) {
	tunFD = c.TunFD
	tunMTU = c.MTU
	masqueCredsFile = c.MasqueCredsPath
	masqueOuterCredsFile = c.MasqueOuterCredsPath
	outerCredsFile = c.OuterCredsPath
	// 上一次会话如果死在嵌套拨号里，hook 可能还指着一条已经关掉的 netstack：
	// 留着它会让下一次单层 MASQUE 把 socket 开进一个死隧道。
	masqueNest.Store(nil)

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
	// 系统 tun fd 的所有权已经统一交给 Kotlin 的 ParcelFileDescriptor（见
	// tunfd_owner.go）：引擎不再持有「谁该关这个 fd」的状态，也就不需要在这里
	// 重置任何标记。

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

// accountMaxAge 是本地账号缓存的有效期。
//
// 为什么要过期：Cloudflare 会注销长期不用/被风控的设备，之后用这份凭据握手
// 会一直失败，而失败看起来和「网络不通」一模一样。设备首次使用自动注册，
// 缓存到期自动换一台新设备 —— 用户不用知道有「账号」这回事。
const accountMaxAge = 14 * 24 * time.Hour

// LoadOrRegisterAccount 按「supplied JSON → 本地文件 → 现注册」的顺序取账号，
// 并把它应用到全局，返回账号 JSON（调用方可以存起来复用）。
//
// 现在 APK **不再内置账号**：每台设备首次连接时自己注册，凭据落在本地缓存，
// 过期（[accountMaxAge]）或本地文件损坏就重新注册。
func LoadOrRegisterAccount(ctx context.Context, accountPath, accountJSON string) (string, error) {
	if accountJSON != "" {
		if err := ApplyAccountJSON(accountJSON); err != nil {
			return "", err
		}
		return accountJSON, nil
	}

	if accountPath != "" {
		st, serr := os.Stat(accountPath)
		fresh := serr == nil && time.Since(st.ModTime()) < accountMaxAge
		if fresh {
			a, err := loadAccount(accountPath)
			switch {
			case err == nil:
				applyAccount(a)
				raw, _ := json.Marshal(a)
				return string(raw), nil
			case errors.Is(err, os.ErrNotExist):
				// 没缓存，往下走注册。
			default:
				// 文件坏了：删掉重注册，不要卡在一条读不出来的缓存上。
				_ = os.Remove(accountPath)
			}
		} else if serr == nil {
			// 过期：删掉，走重新注册。
			_ = os.Remove(accountPath)
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
