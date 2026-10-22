package warp

import "sync/atomic"

// VpnService 交出来的 tun fd 的**所有权记账**。
//
// 为什么需要它：VpnService 建出来的接口是「只要还有任何一个 fd 打开就一直挂着」。
// 隧道建立成功时 fd 会交给某个接管者（fd 模式的 tun 设备、或 Psiphon 的 packet
// tunnel），由它们在自己的 Close 里关掉；但**连接失败时可能谁都还没接管** ——
// 例如带 Psiphon 时上游跑在 netstack 里、还没轮到 Psiphon 就失败了，或者账号 /
// 候选端点阶段就报错。这时没人关 fd，系统 VPN 就会一直亮着，而隧道已经没了：
// 手机全部流量都被送进一个没人读的 tun。用户实测到的正是这个 —— 连接失败后
// 系统 VPN 持续开着，只有退出 App（进程消失、fd 被系统回收）才恢复。
//
// 接管点只有两个：
//   - newFdTunDevice（fd 模式的 tun 设备，Close 会 file.Close）
//   - startPsiphon（Psiphon 的 packet tunnel，Stop 时会 device.Close）
var tunFDAdopted atomic.Bool

// ClaimTunFD 标记 tun fd 已被接管；此后由接管者负责关闭。
func ClaimTunFD() { tunFDAdopted.Store(true) }

// ReleaseTunFD 在**没有任何接管者**的前提下关闭 tun fd，返回是否真的关了。
//
// 为什么要区分「有没有人接管」：fd 一旦被 os.File 包走并由设备 Close，这个 fd
// 号随时可能被系统复用给另一个 socket —— 那时再关一次就会关掉无关的连接。
// 所以只在无人接管时动手。
func ReleaseTunFD(fd int) bool {
	if fd <= 0 || tunFDAdopted.Load() {
		return false
	}
	return closeFD(fd) == nil
}
