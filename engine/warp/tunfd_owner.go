package warp

// VpnService 交出来的 tun fd 的所有权，2026-11-03 改成了「只归创建者」：
//
//   - fd 由 Kotlin 的 `ParcelFileDescriptor` 创建并持有，也**只由它关闭**
//     （WarpVpnService.closeTun）；
//   - 引擎这边（tun 设备、OpenVPN 泵、Psiphon packet tunnel）全部只借用，
//     Close 时不会碰 fd。
//
// 为什么不再让引擎关：真机日志里稳定复现的 fdsan abort 就是两边各记了一份
// 所有权 —— Java 的 ParcelFileDescriptor 带 fdsan tag，Go 用裸 fd 关掉之后，
// 同一 fd 号被内核复用给别人的 fd，下一次 ParcelFileDescriptor 操作就撞上
// "fd 已有主" → SIGABRT（Java 抓不到，直接闪退）。
//
// 下面两个函数保留成 no-op，只是为了让旧调用点不必同时改：引擎永远不会关闭
// 系统 tun fd。
func ClaimTunFD() {}

func ReleaseTunFD(int) bool { return false }
