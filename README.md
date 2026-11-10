# xiaohe VPN · 安卓版（xhwarp-android）

把桌面版 `xhwarp` 的 **WARP / Psiphon / VPN Gate 节点** 能力做成一个完整的 Android 客户端：
系统级 VPN（VpnService）、真握手测速、节点选择、DNS 防泄漏、本地代理与局域网共享。

- 仓库：<https://github.com/hezhanleiok/xehn/tree/xehn-android>
- 分支：`xehn-android`
- 当前版本：**0.2.37**（versionCode 39）
- 最低系统：Android 8.0（API 24），支持 arm64-v8a / armeabi-v7a

> 本项目只做网络转发实验，不提供任何账号或订阅。使用前请自行确认当地法律法规。

---

## 一、能做什么

| 能力 | 说明 |
|---|---|
| 三种出口 | **WARP 直连**、**Psiphon 出口（可指定地区）**、**VPN Gate OpenVPN 节点**（自动或固定节点） |
| 五种传输 | WG、AWG、MASQUE(HTTP/3)、MASQUE(HTTP/2)、MASQUEX2，可热切换 |
| 系统 VPN | 真正的 VpnService 全局接管；出口建立成功后才建 tun，失败不留残留 |
| 真握手测速 | 对节点做**真实 OpenVPN 握手 + 4 路并发下载**（不建 VPN、可中断），按实测速度排序 |
| 节点列表 | 经 WARP 抓取 VPN Gate，分类家宽/机房，支持国家筛选与固定节点 |
| DNS 防泄漏 | 剔除国内解析器、解析器强制走隧道、IPv6 fail-closed |
| 本地代理 | SOCKS5 监听，可仅本机或局域网共享；出口跟随当前隧道 |
| 分流 | 全局 / 绕过大陆 / 黑名单三档，支持分应用白黑名单 |

---

## 二、安装

从 Releases 或构建产物安装 `xehn-<版本>.apk`（debug 签名，可直接覆盖安装）。

首次启动会在本机注册一个 WARP 设备身份并缓存到 `filesDir/engine/account.json`
（14 天过期，或确认账号失效时才重新注册）。

**不用数据线装到手机**：`powershell -ExecutionPolicy Bypass -File .\tools\serve-apk.ps1`，
按提示用手机浏览器打开局域网地址即可。

---

## 三、从源码构建

```powershell
# 1) Go 引擎 → app\libs\engine.aar
powershell -ExecutionPolicy Bypass -File .\tools\build-engine.ps1 -SkipTest -SkipInit

# 2) 打 APK → app\build\outputs\apk\debug\xehn-<版本号>.apk
powershell -ExecutionPolicy Bypass -File .\tools\build-apk.ps1
```

只验引擎（不需要 Android 工具链）：

```powershell
cd engine
go build ./... ; go vet ./...
```

### 环境

| 组件 | 版本 / 位置 |
|---|---|
| Go | 1.27.x（`D:\soft\go`），`GOPATH=D:\soft\gopath` |
| 引擎工具链 | 由 `GOTOOLCHAIN` 固定为 1.26.10（PSIPHON 依赖要求） |
| JDK | Microsoft OpenJDK 17 |
| Android SDK | `D:\soft\Android\Sdk`（platform 35 / build-tools 35 / platform-tools） |
| NDK | 30.0.16248370 |
| Gradle | 8.9（Wrapper，走腾讯镜像；依赖走阿里云） |

一键体检：`powershell -ExecutionPolicy Bypass -File .\tools\check-env.ps1`

### 两个常见坑

- **`gomobile init` 需要联网**，离线环境会失败 → 用 `-SkipInit`（`gomobile bind` 本身不需要 init）。
- **`go test ./warp` 可能被 Windows 应用控制策略拦测试 exe**（报 `Application Control policy blocked`），
  这不是代码错误；此时以 `go build` / `go vet` 为准。

---

## 四、目录结构

```
xehn-android/
├── engine/                 Go 引擎（gomobile bind 目标，进程内运行）
│   ├── engine.go           对外 API：Connect / Disconnect / StatusJSON / SetTunFD / 节点测速 …
│   ├── warpbackend.go      出口编排：WARP / Psiphon / OpenVPN 三条路 + 节点缓存 + 失败记忆
│   ├── session.go          会话状态机（idle → connecting → connected → stopping）
│   └── warp/               数据面
│       ├── tunnel.go       WG/AWG 隧道与 netstack 装配
│       ├── masque.go       MASQUE(HTTP/3、HTTP/2) 与嵌套
│       ├── psiphon.go      Psiphon 出口（tunnel-core 直连集成）
│       ├── psiphon_region.go  地区并发测速（每地区独立 controller）
│       ├── openvpn.go      OpenVPN 出口（握手 → 建 tun → 包泵）
│       ├── iprewrite.go    tun↔节点地址替换（一对一 NAT）
│       ├── speedprobe.go   统一测速口径（多流 + 稳态中位数）
│       ├── vpngate.go      节点抓取 / 分类 / 延迟
│       └── netstackx/      gVisor netstack 适配（窗口与批处理调优）
├── app/                    Android（Kotlin + Compose）
│   ├── libs/engine.aar     gomobile 产物（不入库）
│   └── src/main/java/com/xiaohe/vpn/
│       ├── EngineBridge.kt     引擎单例 + StateFlow + 节点缓存
│       ├── WarpVpnService.kt   前台服务：建 tun、分流、DNS、分应用
│       └── ui/                 首页 / 设置 / 节点选择器 / 日志
├── docs/                   文档（见下）
├── tools/                  构建、体检、局域网分发脚本
└── gradle/                 Wrapper
```

---

## 五、文档

| 文档 | 内容 |
|---|---|
| [`docs/kb-index.md`](docs/kb-index.md) | **知识库入口**：三条判据 + 主题索引 + 改数据面前的检查清单 |
| [`docs/pitfalls.md`](docs/pitfalls.md) | 踩坑全记录（按版本分节，含根因、判据、日志样例） |
| [`docs/connection-modes-and-rules.md`](docs/connection-modes-and-rules.md) | 连接模式、分流规则、分应用语义 |
| [`docs/desktop-optimization.md`](docs/desktop-optimization.md) | 与桌面版的架构对比、能否复用、桌面优化清单 |
| [`docs/porting-analysis.md`](docs/porting-analysis.md) | 早期可移植性分析（历史参考） |
| [`CHANGELOG.md`](CHANGELOG.md) | 版本变更一览 |

---

## 六、已知限制

- **WARP 直连**时出口 IP 常被判成中国、Cloudflare 解析器被判成美国，泄漏检测会报
  「国家不一致」—— 那是归属地判定，查询本身在隧道内。
- **OpenVPN 出口**受「单条长连接 + 高 RTT」限制，与桌面版（内核 TCP + 批处理）仍有差距，
  下一轮方向是外层批处理 / GSO。
- 连接后界面上的「出口实测速度」是 512 KB × 4 的**短测**（含慢启动），
  只用于判断「有没有数据在流」，不代表稳定带宽。
- VPN Gate 节点由志愿者提供，掉线、限速、AUTH_FAILED 都是常态。

---

## 七、许可与第三方

安卓版**在进程内链接了** `psiphon-tunnel-core`（GPL-3.0）——APK 里没有子进程可起，
桌面版那套「独立进程 + 本地端口」搬不过来，这是 Psiphon 出口在 Android 上唯一可行的形态。
因此**本项目的分发需遵循 GPL-3.0**，源码随仓库提供。

第三方组件与许可证声明：

| 组件 | 许可证 | 位置 |
|---|---|---|
| psiphon-tunnel-core | GPL-3.0 | Go 依赖（见 `engine/go.mod`） |
| amneziawg-go / wireguard-go | MIT | Go 依赖 |
| gVisor | Apache-2.0 | Go 依赖 |
| mihomo（openvpn 客户端等） | GPL-3.0 | `engine/third_party/mihomo/`（本地副本，README 说明改动） |
| qpack | MIT | `engine/third_party/qpack/`（含 LICENSE.md） |
| tailscale-netlink | BSD-3-Clause | `engine/third_party/tailscale-netlink/`（含 LICENSE） |

`engine/third_party/` 下每份本地源码副本都带有说明其改动原因的 README，随源码一同分发。
