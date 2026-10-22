# 安卓移植可行性分析（只读分析，未改动 `d:\xhwarp`）

分析对象：`d:\xhwarp\warp-client`（Windows 客户端）、`d:\xhwarp\warpscout`（纯 Go 引擎）。
结论先行：**引擎可 90% 直接复用，Windows 编排层必须整体替换。**

---

## 0. 一句话结论

| 层 | 内容 | 处置 |
|---|---|---|
| `warpscout` 引擎 | WG/AWG/MASQUE 隧道、账号注册、端点扫描、QUIC 指纹、SOCKS5 | **直接复用**（纯 Go，用户态 gVisor，不需要 TUN 设备、不需要 root） |
| `warp-client` Windows 编排 | 注册表系统代理、lxn/walk GUI、子进程管理、mihomo/psiphon sidecar、state.json + pid 租约 | **整体替换** |

已验证的硬证据：`GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build` 在 `warpscout` 与
`warp-client` 两个目录里**都已经退出码 0**。也就是说引擎在 Android 上编译不是问题，
问题全在「谁来做数据面、谁来管会话、谁来画界面」。

---

## 1. 代码结构：两个完全不同的东西

```
d:\xhwarp\
├── warpscout\        纯 Go 引擎（≈35 个 .go）
│   ├── tunnel.go     tunnel 接口、wgTunnel.handshake、netstack.CreateNetTUN、tunnelProbe
│   ├── warp.go       WARP 常量/端口、baseUAPI/peerUAPI、AWG 参数
│   ├── masque.go     MASQUE H3/H2（connect-ip-go + usque + quic-go/http3）
│   ├── quic.go       QUIC Initial 指纹生成（纯 crypto）
│   ├── register.go   账号注册/轮换（curve25519 + api.cloudflareclient.com）
│   ├── discovery.go  端口可达探测、fetchMeta
│   ├── pools.go      端点池      i1gen.go / findjunk.go / findsni.go  参数搜索
│   ├── socks.go      手写 SOCKS5 服务（CONNECT-only，无认证）
│   └── nest.go       WARP-in-WARP
└── warp-client\      编排层（≈65 个 .go，其中 20 个 *_windows.go）
    ├── connect.go            连接生命周期（runConnectCmd / runConnectPsiphon / startAndVerify）
    ├── client.go             clientState、state.json、renderClientConfig（生成 mihomo config.yaml）
    ├── wgconf.go             renderMihomoConf / mihomoProxies / renderConf（UAPI .conf）
    ├── settings.go           settings.json（主题、端口、分流、Psiphon 开关…）
    ├── health.go             **跨进程**健康守护（spawn 自己当 guard + health-owner pid 租约）
    ├── psiphon_health.go     Psiphon 专属修复（重启 Psiphon / 重建 underlay）
    ├── psiphon.go            起 psiphon.exe 子进程，解析它的 notice
    ├── internal/core\        mihomo 子进程管理、注册表代理、TerminateProcess
    └── gui_*_windows.go      lxn/walk 自绘 UI（≈110KB 源码）
```

关键点：**真正的数据面在 Windows 版里不是 Go，而是外挂的 `mihomo.exe` 子进程**
（`internal/core/core.go` 起进程 + 写 `config.yaml` + 走 REST `/proxies` `/traffic`）。
`warp-client/go.mod` 里**没有** mihomo —— 它只是 sidecar。所以 Android 上要么换掉这个
sidecar，要么干脆不用它，直接跑 warpscout 自己的隧道。

---

## 2. 必须整体替换的清单

### (a) 注册表 / 系统代理
`internal/core/proxy_windows.go` 全文件：`SetSystemProxy` / `SetSystemProxyVerified` /
`UnsetSystemProxy` / `ClearSystemProxy` / `applyProxyValues` / `writeProxyRegistry` /
`setProxyViaWininet` / `setProxyViaRegExe` / `DetectProxyBlocker` / `notifyProxyChange` /
`IsElevated` / `runSelfElevated` / `startHelperDaemon` / `SetSystemProxyElevated`。
调用点：`connect.go`（连接成功后写代理 + UAC 提权兜底）、`watchdog.go`、`health.go` 的守护判定。

**Android 对应物：不存在。** 系统代理是 Windows/WinINET 概念，Android 靠 `VpnService`
全网路由。`clientState` 里的 `ProxySnap` / `ProxyWarn` / `NoProxy` 三个字段在 Android 版
直接删掉（新引擎里已经没有它们）。

### (b) Win32 GUI（lxn/walk）
`gui_native_windows.go`(45KB)、`gui_draw_windows.go`(19KB)、`gui_i18n_windows.go`(16KB)、
`gui_actions_windows.go`、`gui_dialogs_windows.go`、`gui_page_{home,nodes,rules,settings,logs}_windows.go`、
`gui_shell_windows.go`、`gui_theme_windows.go` —— 全部 `//go:build windows` + `import "github.com/lxn/walk"`。

**Android 对应物：Compose 重写。** 好消息是 `natModel`（`gui_native_windows.go:40`）
和 `settings.go` 的字段与 UI 元素一一对应，可以直接当 Kotlin 的 ViewModel 参照物；
本工程已经按这个对应关系写了 `EngineBridge.VpnState` 与 `ui/HomeScreen.kt`。

### (c) 进程管理 / 杀进程
`internal/core/core.go`（`exec.CommandContext` 起 mihomo）、`internal/core/stop_windows.go`
（`spawnWatchdog` 再 spawn 自己、`KillByPID` = `TerminateProcess` + 校验映像路径）、
`guard_windows.go`（`OpenProcess` + `WaitForSingleObject`）、`health.go:spawnHealthGuard`
（`exec.Command(os.Executable(), "guard", ...)`）、`psiphon.go:Start`、`capability.go`（跑 `mihomo -t` 探测）。

**Android 对应物：全删。** apk 内部没有可执行文件，`os.Executable()` 指向的路径不能执行，
任何 `spawn 自己` 的做法在 Android 上都会静默失败 —— 这是移植时最容易漏的一个坑。
替代方案就是本工程的做法：**前台 `VpnService` 持有唯一一个 `Engine`**。

### (d) 控制台 / TUI
`console_windows.go`（`SetConsoleMode` + `ENABLE_VIRTUAL_TERMINAL_PROCESSING`）、
`cli.go/flags.go/main.go/tui.go/ui.go`（bubbletea 全屏 TUI）、`report.go` 的表格输出。
**Android 对应物：删除。** 顺带甩掉 `bubbletea`/`bubbles`/`lipgloss`/`termenv` 一串依赖。

### (e) 其它 Windows 专有
- `internal/core/download.go` 的 `ostuple()`：`default: osPart = runtime.GOOS` → Android 会去
  找 `mihomo-android-arm64-*.zip`（不存在）。整段作废。
- `bind_linux.go`（`SO_BINDTODEVICE`，需要 `CAP_NET_RAW`）：Android 只能走 `bind_other.go` 分支。
- `pack.ps1` / `rsrc_windows_amd64.syso` / `app.manifest` / `-H windowsgui`：作废。
- `argv_android.go` / `dns_android.go`：为 **Termux** 写的（剥 `linker64` 参数、读
  `$PREFIX/etc/resolv.conf`）。App 内不需要，且 `$PREFIX` 在 App 里根本不存在 —— 别照抄。

---

## 3. 可直接复用的清单

纯 Go、无 cgo、无平台 syscall，可直接搬进 Android 引擎包：

```
warpscout\warp.go        warpscout\register.go    warpscout\tunnel.go
warpscout\masque.go      warpscout\quic.go        warpscout\nest.go
warpscout\pools.go       warpscout\discovery.go   warpscout\i1gen.go
warpscout\findjunk.go    warpscout\findsni.go     warpscout\meta.go
warpscout\geo.go         warpscout\socks.go       warpscout\bind.go + bind_other.go
warp-client\wgconf.go    （配置/UAPI 渲染）        warp-client\settings.go（纯数据模型）
warp-client\internal\cache\store.go（TTL JSON 缓存，完全平台无关）
warp-client\client.go 的 renderClientConfig（只保留字符串渲染部分）
```

运行时依赖的库也都支持 Android：`net/netip`、`golang.org/x/crypto/curve25519`、
`golang.org/x/net/{icmp,ipv4,ipv6}`、`quic-go`、`connect-ip-go`、`usque`、
`amneziawg-go`（`conn`/`device`/`tun/netstack`）、transitive 的 `gvisor.dev/gvisor`。

---

## 4. Android 特有的运行期坑（真正的风险点）

1. **`amneziawg-go/tun` 没有 `tun_android.go`**（只有 darwin/freebsd/linux/openbsd/windows）。
   - 纯用户态路径（`netstack.CreateNetTUN`）**不需要任何平台 TUN 文件**，所以
     `register` / `scan` / 本地 `socks` 在 Android 上零改动可用。
   - 要做**全机 VPN**，必须自己写一个 `tun.Device`：把 `VpnService.Builder.establish()`
     返回的 `ParcelFileDescriptor` 的 fd 包进去（wireguard-android 的
     `tun.CreateTUNFromFile` 是同一思路，约 200~300 行）。本工程已经把接缝留好：
     `Engine.SetTunFD(fd)`。
   - **不要**依赖 `songgao/water` 或 `vishvananda/netlink`：Android 上没有 `/dev/net/tun` 权限，
     netlink 也受限。

2. **`VpnService.protect()`**：引擎自己往 WARP/MASQUE 服务器发的 UDP/TCP 必须 `protect()`
   过的 socket，否则那些包会被自己的 VPN 路由抓回来，形成死循环（尤其是 MASQUE 的 QUIC）。
   这是移植 MASQUE 时唯一的真运行期坑。

3. **内存**：`cli.go` 里 `SetMemoryLimit(32<<20)` 是桌面假设；gVisor 每包分配，
   移动端要重新评估（建议先在真机上量 `Scan` 的峰值）。

4. **前台服务类型**：Android 14+ 起 `startForeground` 必须声明类型，VPN 用
   `specialUse`（上架需要在 Play 后台说明用途）。漏了会直接抛异常。

5. **VpnService 的 `establish()` 必须最后做**：`addRoute("0.0.0.0", 0)` + `establish()`
   意味着全部流量进隧道。**引擎还没接管 fd 之前绝不能 establish**，否则设备直接断网。
   本工程用 `WarpVpnService.ENGINE_CAN_ROUTE = false` 挡着，P1 完成后再打开。

---

## 5. 会话/状态模型：从「多进程 + 状态文件」改成「单进程 + 一把锁」

Windows 版的模型是：

| 机制 | 位置 | Android 上 |
|---|---|---|
| `state.json` 作为跨进程唯一真相源 | `client.go:76-137` | 删；改成内存单例 + `StateFlow`（`EngineBridge`） |
| detached `guard` 子进程 | `health.go:spawnHealthGuard` | 删；改成 Service 生命周期 |
| `health-owner` pid 租约（谁有资格修复） | `health.go:69-120` | 删；只有一个进程，没有竞争 |
| GUI 2 秒 status loop 抢 claim | `gui_native_windows.go` 状态循环 | 保留「轮询」形式，去掉 claim |
| `spawnWatchdog` 保证 core 随客户端死亡 | `internal/core/stop_windows.go:43` | 删；Service `onDestroy` 清理 |
| `TUN`/`NoProxy`/`ProxyWarn` 三分支 | `health.go:602-608` | 删；只有 VpnService 一条路 |

已经在新引擎里落地的对应物（`engine/session.go`）：
`idle → connecting → connected / stopping / error` 的状态机 + 日志环形缓冲，
并且**把「连接中取消」当成一等公民**（`connecting → stopping → idle`），
因为桌面 GUI 最糟的体验恰恰是连接中点击被吞掉、只能干等失败。

---

## 6. gomobile 化的重构点（这是唯一有实际工作量的部分）

`warpscout` 是 `package main`，且有**大量包级可变全局状态**，gomobile 只能绑定
可导出的类型/函数、**不能绑定 `package main`**。所以必须先把引擎收进一个 struct：

需要收拢的全局（`warpscout/warp.go` 等）：
`scanInterface` / `scanSourceIP`、`warpPrivateKey` / `warpPublicKey` / `warpAddress` / `warpAddressV6`、
`awgJc` / `awgJmin` / `awgJmax` / `awgI1`、`warpPorts`、`masqueAcct`、`metaAddr`、
`pingTarget` / `pingAddr`、`outer`、`pools`。

改造顺序（机械但必须一次做完一个协议族）：

1. 新建 `engine` 包（本工程 `engine/`），把上面这些变量收进 `type Engine struct` + `Config`，加 `sync.Mutex`。
2. 先搬「无依赖」的：`quic.go`、`meta.go`、`geo.go`（已在本工程以纯函数形式落了 `uapi.go`）。
3. 再搬 `warp.go` + `register.go` + `discovery.go`（注册与扫描，验证 `Scan` 在真机可用）。
4. 再搬 `tunnel.go` + `masque.go` + `socks.go`（起本地 SOCKS，此时 App 已经能用「手动代理」模式）。
5. 最后写 `tun_android.go` + 接 `SetTunFD`，打开 `ENGINE_CAN_ROUTE`（全机 VPN）。
6. `psiphon.go` 若保留：把 `exec.CommandContext` 换成 `psiphon-tunnel-core` 的 gomobile 绑定
   （上游有 MobileLibrary 目标），`handleNotice` 的 notice 解析可原样复用。

---

## 7. 依赖风险表（`warp-client/go.mod`）

| 依赖 | Android 评估 |
|---|---|
| `amnezia-vpn/amneziawg-go` | ✅ 纯 Go；⚠️ 无 `tun_android.go`，全机 VPN 需自写 `tun.Device` |
| `gvisor.dev/gvisor` | ✅ 纯 Go；⚠️ 体积大，最终 .aar 会明显变大 |
| `quic-go/quic-go`、`qpack` | ✅ 需 UDP + `VpnService.protect()` |
| `Diniboy1123/connect-ip-go`、`usque` | ✅ 纯 Go |
| `golang.org/x/{crypto,net,text}` | ✅ |
| `lxn/walk`、`lxn/win` | ❌ Win32 GUI（已 build tag 隔离，不进 Android 构建） |
| `golang.zx2c4.com/wintun` | ❌ Windows TUN 驱动（indirect，tag 隔离） |
| `songgao/water`、`vishvananda/netlink` | ⚠️ Android 权限受限，别用 |
| `charmbracelet/*`、`muesli/termenv` | ❌ App 里无意义，建议移除 |
| `golang.org/x/mobile` | ➕ **需要新增**（gomobile 的运行时依赖） |

`warp-client` 里**没有** cgo 强制依赖 —— 这点很关键，意味着可以用
`CGO_ENABLED=0` 纯 Go 交叉编译（已实测通过）。

---

## 8. 落地路线

| 阶段 | 内容 | 验收 |
|---|---|---|
| **P0（已完成）** | 工程骨架：`engine`（gomobile API + 状态机 + UAPI 渲染 + 单测）、Kotlin/Compose 首页、`WarpVpnService`（含 `ENGINE_CAN_ROUTE` 安全开关）、环境检查与打包脚本 | `engine` 的 `go test` / `go vet` / `android/arm64` 交叉编译全绿 |
| **P1（已完成，2026-10-09）** | warpscout 的 WG/AWG 引擎搬进 `engine/warp`（`warp.go`/`tunnel.go`/`register.go`/`pools.go`/`socks.go`/`discovery.go`/`bind*.go`，砍掉 CLI 层与 MASQUE/nest 分支），新增 `config.go`（Configure/账号）与 `session.go`（拨号+验证+SOCKS），后端 `warpbackend.go` 接进 Engine | 实测：`WARP_LIVE=1 go test -run TestLiveDial` 真的建隧道（awg，端点 8.6.112.217:2408），出口 `104.28.245.200 (CN)`，**经本地 SOCKS5 实测出口与隧道报告完全一致** |
| **P2** | 写 `tun_android.go`，接 `SetTunFD`，打开 `ENGINE_CAN_ROUTE`，全机 VPN | 真机：全局路由，出口 IP = WARP 出口；`protect()` 无回环 |
| **P3** | 迁移 UI（节点列表 / 规则 / 设置 4 个页面）、导出 mihomo/WireGuard 配置给别人用 | 与桌面版功能对齐 |
| **P4（可选）** | Psiphon 出口（改库调用） | 出口 = Psiphon，`session=AWG-Psiphon` 语义一致 |

### 为什么不选 Flutter / 纯 Go Activity

- **Flutter**：多一层 Dart↔FFI，Android 侧照样要写 `VpnService` 平台代码，没有收益。
- **纯 Go 单 Activity**（`golang.org/x/mobile/app`）：该包事实上已停止维护、只给 OpenGL ES
  裸画布，等于用 Go 重写 `gui_native_windows.go` 那 110KB UI，工作量最大、风险最高。

结论：**Kotlin + Compose + gomobile 绑定 Go 引擎**是唯一合理路径，也是本工程采用的结构。
