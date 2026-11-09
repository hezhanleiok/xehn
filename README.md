# xhwarp-android — xiaohe VPN 安卓版

把 `d:\xhwarp`（Windows 版）的 WARP/Psiphon 能力做成安卓 App。
**本目录只读参考 `d:\xhwarp`，不修改它。**

- 仓库：<https://github.com/hezhanleiok/xehn/tree/xehn-android>
- 当前版本：**v0.2.23**（versionCode 25）

详细代码分析见 [`docs/porting-analysis.md`](docs/porting-analysis.md)。

---

## 1. 现在能跑到哪一步（已实测）

| 部分 | 状态 |
|---|---|
| `engine/` Go 引擎（gomobile 打成 `.aar`） | ✅ `go test` / `go vet` 全过，`android/arm64` 交叉编译通过 |
| `app/libs/engine.aar` | ✅ 已生成（17.8 MB，含 arm64 + arm 的 `libgojni.so`） |
| `app/` Kotlin + Compose 界面骨架 | ✅ 编译通过 |
| **`xehn-<版本号>.apk`** | ✅ **已构建成功（`xehn-0.2.20.apk`，65.7 MB）**，含 arm64 + arm 两个 ABI 的原生库（引擎里已带 Psiphon/QUIC/gVisor，aar 本身 17.9 MB）。产物名由 `app/build.gradle.kts` 的 `androidComponents` 统一改成 `xehn-<versionName>.apk` |
| `WarpVpnService` | ✅ 前台服务 + 通知 + tun fd 接缝（**路由默认关闭**，见下） |
| 环境（JDK/SDK/NDK/gomobile/Gradle） | ✅ `check-env.ps1` **12 项就绪 / 0 缺失** |
| **真正建立隧道（P1，已接入）** | ✅ warpscout 引擎搬进 `engine/warp`，能建 WG/AWG 隧道并拿到真实出口 IP |
| **系统 VPN / 全机路由（P2，已接入）** | ✅ `VpnService.establish()` 的 fd 交给引擎当数据面（自写 `tun_android.go` 的等价物），出口验证走真实系统网络；`VpnService.protect` 已接，避免隧道抓自己的包 |
| **UI 重做 + 设置页（P3，已接入）** | ✅ 浅色主题；首页显示本机 IP / 出口 IP / 国旗 / 国家 / 延迟 / 上下行速率，协议改为下拉；Psiphon 开关与电脑版设置搬进设置页 |
| **四种传输全接通（2026-10-10）** | ✅ `Dial` 统一分派：WG / AWG、MASQUE（HTTP/3 与 HTTP/2）、WARP-in-WARP（`wwarp`，`nest.go`）都有实现，设置页五种协议全部可选（真机待验） |
| **MASQUEX2 + 失败收尾（0.2.11）** | ✅ MASQUE(HTTP/3) 套 MASQUE(HTTP/3)（`masque-x2`，`masque_nest.go`）；连接失败/看门狗放弃时关 tun + 停服务；Psiphon 上游改临时端口 + 自动退 AWG；WG/AWG 隧道 UDP 收发缓冲拉到 8 MB |
| **0.2.12：h2 / OpenVPN / X2 / 上行** | ✅ MASQUE(HTTP/2) 两种 authority + 失败回退 H3；OpenVPN 出口验证 20s + 同节点重试 + 只为「实测更快」的候选换点；MASQUEX2 外层改 v4-only、MTU 1300；MASQUE 上行 3 条会话按流并行、MTU 按 v4/v6 分档（1300/1160） |
| **0.2.13：测速 / 分类 / 设置重构** | ✅ 「测延迟」改成「握手 + 真下载测速」（引擎用 gVisor netstack 当 tun，不建系统 VPN）；节点分类加 ipwho.is 第二数据源交叉验证，「未知」改「未分类」；设置页删除假开关与重复的关于信息，新增「本地代理（VPN 模式可用）」「局域网共享」页、「语言」「健康守护」 |
| **0.2.14：热切换 / 入口去重 / 文案** | ✅ 已连接时换协议 = 热切换（服务不退出，只换引擎会话）；「局域网共享」收进设置页，抽屉不再重复；删除设置里「电脑版有、安卓没搬」整节与大量解释性文案；VPN 模式的 `direct,网段` 规则真正生效（API 33+ 用 excludeRoute，旧版用补集路由） |
| **0.2.15：本机 IP / 账号 / 测速范围** | ✅ 首页「本机 IP」改回**局域网地址**（192.168.x.x，不再显示公网出口）；**移除内置 WARP 账号**，设备首次连接自动注册，缓存 14 天过期或连续 2 次失败自动重置重注册；测延迟支持「只测当前节点 / 只测当前国家 / 全部」；MASQUE 日志带 `colo`（区分 CF 边缘，替代不准的 IP 归属地） |
| **0.2.16：连接前预注册 / VPN Gate 只走 WARP** | ✅ **修 MASQUE「注册失败 no such host」**：账号改在建 tun 之前注册（VPN 一建立 DNS 就进未通的隧道）；VPN Gate 节点抓取取消直连，只走 WARP 前置（超时 20s→40s） |
| **0.2.17：分类二值化 / 测速真正出数** | ✅ 节点分类改为**只看家宽/机房**：ip-api + ipwho.is 对所有 IP 交叉验证，无强证据时按云厂商 ASN 启发式二分，不再出现「未分类」；测延迟的测速预算 2s→8s 且**从首字节开始计时**（原来 2s 连 TLS 都没完成，全部「速度未测」）；节点行改为「名称 ｜ 速度 ｜ 握手延迟」三列 |
| **0.2.18：全量测速卡死修复** | ✅ 「测到第 8 个就不动」= 8 个 worker 全卡在测速（每节点一个 gVisor netstack + OpenVPN 包泵）；测速改为**并发上限 3**、每节点**硬超时**、关闭顺序改为「先关 dev 再关 client」、探测总预算 6→10 分钟、日志带单节点耗时 |
| **0.2.19：测速绕过隧道 DNS** | ✅ 「握手成功但速度未测」的根因是测速端点在隧道内解析（VPN Gate 节点不转发 DNS）；改为**主机 DNS 解析 + 直连 IP + 固定 SNI**，并把失败原因（tcp/tls/没数据）写进日志 |
| **0.2.20：首次启动注册 / 赛风修复 / 地区更新** | ✅ 首次启动即注册本机账号（之后才缓存，有日志）；**赛风改成「先建上游、再建 tun」**（提前建 tun 导致上游 14 个端点全「数据面不通」）；重试 3 次/150s → 2 次/90s（连接更快）；出口地区新增「更新列表」（WARP 前置跑一次 Psiphon 只取地区，首次为空自动拉一次） |
| 装机运行 | ⏳ 需要一台开了 USB 调试的手机或模拟器（当前 `adb devices` 为空） |

> P2 的意义：在这之前只有进程内的 gVisor 隧道，系统 VPN 根本没起来 ——
> 界面显示「已连接」而状态栏没有 VPN 钥匙，手机上其它应用一个字节都不走它。
> 现在顺序是：装 protect → `establish()` → fd 交给引擎 → OS tun 做数据面 →
> 走真实系统网络验证出口。任何一步失败都直接报错收摊，不留假成功。

### 已接入 vs 尚未搬运（设置页里也照实标注）

| 电脑版功能 | 安卓版 |
|---|---|
| 协议选择、IPv6、MTU、自定义 DNS、不下发 DNS、连接超时、启动后自动连接 | ✅ 已接入并生效 |
| 分应用（仅代理所选 / 所选直连） | ✅ 用 VpnService 原生白黑名单，内核层生效 |
| 主题（浅色/深色/跟随系统）、日志自动滚动 | ✅ |
| Psiphon 出口 | ✅ 进程内跑官方 `psiphon-tunnel-core`（用户确认接受 GPL-3.0）：tun fd 交给它的 packet tunnel，基础协议（wg/awg）退成 netstack 只作上游；出口 IP/国家按 Psiphon 的 SOCKS 实测，所以显示的就是 Psiphon 的出口 |
| Psiphon 出口地区 | ✅ 设置页可选（默认自动）：列表来自 Psiphon 上报的 `AvailableEgressRegions`，选它不去的地区会立刻失败并给出可选值 |
| 直连/代理域名、地区分流、规则模式 | ❌ VpnService 只能按应用与 IP 分流，域名级规则要另做引擎 |
| 导出配置（.conf / mihomo YAML） | ❌ 需要另做分享入口 |
| 界面中英切换、健康守护自动修复 | ❌ 未做 |
| 开机自启、系统代理、混合/API 端口、外部内核路径 | — 桌面专有，安卓无对应物 |

### P1 验收证据（本机实测，2026-10-09）

`engine/live_test.go` 是真实联网测试（默认跳过，`WARP_LIVE=1` 才跑）：

```powershell
cd engine; $env:WARP_LIVE='1'; go test -run TestLiveDial -v .
```

```
| 候选端点 28 个 × 端口 [2408 500 1701 4500]（awg），预算 1m0s
| 8.6.112.217:2408 握手成功，验证出口（隧道内 HTTPS）…
| 出口 104.28.245.200 (CN)
| 本地 SOCKS5 已监听 127.0.0.1:1080
==> 连接成功 用时=9.25s exit=104.28.245.200 country=CN endpoint=8.6.112.217:2408
==> 经 SOCKS5 实测出口 = 104.28.245.200 (http=200)
```

最后一行是关键：**像普通应用那样通过本地 SOCKS5 真发一次请求，公网看到的出口
与隧道报告的一致** —— 这是「真的通了」，不是「端口打开了」。

### P1 阶段的可用性说明（重要）

P1 只做到「建立隧道 + 真实出口」。**手机上其它 App 还不会自动走这条隧道**：
隧道对外提供的是 `127.0.0.1:1080` 的本地 SOCKS5，要先用支持 SOCKS 的应用
（例如 Firefox 的网络设置里填 SOCKS5 `127.0.0.1:1080`）验证。
让全局流量走隧道需要 P2（`VpnService` 的 tun fd 交给引擎）。

**安全开关**：`WarpVpnService.ENGINE_CAN_ROUTE = false`。在引擎真正读写 tun fd 之前
**不要**打开它 —— 一旦 `addRoute("0.0.0.0", 0)` + `establish()` 而没人读那个 fd，
设备会直接断网。

---

## 2. 目录结构

```
d:\xhwarp-android\
├── engine\                    Go 引擎（gomobile bind 的目标）
│   ├── engine.go              Engine: Connect / Disconnect / StatusJSON / SetTunFD / LogSink
│   ├── session.go             会话状态机（取代桌面版的 state.json + pid 租约）
│   ├── uapi.go                WireGuard / AmneziaWG 的 UAPI 渲染
│   └── engine_test.go         状态机 / 取消 / UAPI / StatusJSON 契约
├── app\                       Android 应用
│   ├── build.gradle.kts       namespace com.xiaohe.vpn, minSdk 24
│   ├── libs\engine.aar        gomobile 产物（不入库）
│   └── src\main\
│       ├── AndroidManifest.xml
│       ├── res\drawable\ic_vpn_notification.xml
│       ├── res\values\{strings,themes}.xml
│       └── java\com\xiaohe\vpn\
│           ├── MainActivity.kt    申请 VPN 授权 + 转发点击到 Service
│           ├── EngineBridge.kt    进程内唯一引擎持有者 + StateFlow（替代 state.json）
│           ├── WarpVpnService.kt  前台服务，会话真正的主人
│           ├── CountryNames.kt    国旗 emoji + 系统 ICU 国名
│           └── ui\HomeScreen.kt   首页 UI（与桌面版首页同构）
├── docs\porting-analysis.md   ★ 代码分析 + 可移植/必须替换清单 + 路线
├── tools\
│   ├── check-env.ps1          ★ 环境体检（读注册表，旧终端也不误报）
│   ├── build-engine.ps1       生成 engine.aar（并剖开 aar 核对方法真的生成了）
│   ├── build-apk.ps1          构建 APK（自动补齐 JAVA_HOME 等）
│   └── syntax-check.ps1       解析检查 tools 下的 ps1
├── gradlew / gradlew.bat / gradle\wrapper\    Gradle Wrapper（8.9，走腾讯镜像）
├── settings.gradle.kts / build.gradle.kts / gradle.properties
└── README.md
```

---

## 3. 环境（已装好，2026-11-01 全部更新到最新稳定版）

一键复核：

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\check-env.ps1
```

**安装位置规则：所有开发软件一律装在 `D:\soft` 下**（不装 C 盘、不装 `C:\Program Files`）。

| 组件 | 版本 / 位置 |
|---|---|
| Go | **1.27.3**（最新稳定版）→ `D:\soft\go`；`GOPATH`/`GOBIN` = `D:\soft\gopath`（含 `bin`） |
| Go（打引擎用的工具链） | **1.26.10** —— 由 `GOTOOLCHAIN` 自动下载到 `D:\soft\gopath\pkg\mod\golang.org\toolchain@*`，见下方注意点 |
| JDK | Microsoft Build of OpenJDK **17.0.20.1** → `C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot`（`JAVA_HOME` 已设） |
| Android SDK | `D:\soft\Android\Sdk`（`ANDROID_HOME` 已设） |
| — platform-tools | 37.0.1（含 adb） |
| — platforms | android-35 |
| — build-tools | 35.0.0（AGP 后来自己又补装了 34.0.0） |
| — NDK | **30.0.16248370**（最新稳定版）→ `D:\soft\Android\Sdk\ndk\30.0.16248370`（`ANDROID_NDK_HOME` 已设） |
| Gradle | 8.9（Wrapper）；缓存 `GRADLE_USER_HOME=D:\soft\gradle-cache`，发行包走 `mirrors.cloud.tencent.com` |
| gomobile / gobind | `golang.org/x/mobile` 最新（`v0.0.0-20261011…`）→ `D:\soft\gopath\bin` |
| Android Studio | 未装（非必须） |

**NDK 30 的安装方式**：`cmdline-tools` 里的 `sdkmanager` 已废弃，被新的 Android CLI 接管，
不再认 `ndk;<版本>` 这种写法（会报 `Package ndk not found`）。所以直接下官方包
`https://dl.google.com/android/repository/android-ndk-r30-windows.zip`（694 MB），
解压到 `D:\soft\Android\Sdk\ndk\` 后把目录名改成版本号即可 —— `source.properties` 里有
`Pkg.Revision = 30.0.16248370`，AGP / gomobile 都按这个路径识别。

**打包体积**：`build-engine.ps1` 给 `gomobile bind` 加了 `-ldflags=-w`（去 DWARF、保符号表）。
不加时每个 ABI 的 `libgojni.so` 是 43 MB，而 APK 里的 `.so` 是不压缩存放的 ——
实测 APK 会到 **145 MB**；加上 `-w` 后 25 MB / 24 MB，APK 回落到 **109 MB**。

**这台机器的网络注意点**（都已处理并写进配置）：
- `github.com` / `services.gradle.org` / `proxy.golang.org` 连不上 → Gradle 发行包走腾讯镜像，
  依赖走阿里云镜像（`settings.gradle.kts`），`GOPROXY` 已固化为 `https://goproxy.cn,direct`。
- winget 下 JDK 会报 `0x80072f78` → 改用 `curl` 直接拉 MSI 再 `msiexec /qn` 装（已装好）。

---

## 4. 构建

```powershell
# 1) Go 引擎 → app\libs\engine.aar
powershell -ExecutionPolicy Bypass -File .\tools\build-engine.ps1

# 2) 打 APK（产物 app\build\outputs\apk\debug\xehn-<版本号>.apk）
powershell -ExecutionPolicy Bypass -File .\tools\build-apk.ps1
powershell -ExecutionPolicy Bypass -File .\tools\build-apk.ps1 -Install   # 直接装到设备
```

不需要 Android 工具链也能跑的部分：

```powershell
cd engine
go test ./...     # 状态机 / 取消 / UAPI / StatusJSON 契约
go vet ./...
```

### 不用数据线装到手机（三种）

**A. 局域网直传（推荐，最省事）**

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\serve-apk.ps1
```

脚本会打印形如 `http://192.168.5.8:8765/` 的地址（并复制到剪贴板），
**手机连同一个 Wi-Fi，浏览器打开这个地址，点"下载并安装"即可**。按 Ctrl+C 结束。

- 手机首次装会要求「允许安装未知应用」，跟着系统提示走。
- debug APK 用 debug keystore 签名，任何手机都能直接装，不需要先卸载什么。
- 脚本会自动确认一条防火墙规则（`xhwarp-android APK server (8765)`，仅专用网络 + 仅 TCP 8765）；
  不用了删掉：`Remove-NetFirewallRule -DisplayName "xhwarp-android APK server (8765)"`
- 为什么不直接拖进微信：微信会拦 `.apk`。QQ 的「我的电脑」可以直接发。

**B. adb 无线调试（Android 11+，之后能一直无线连）**

手机：开发者选项 → 无线调试 → 使用配对码配对设备，屏幕上会给出 `IP:端口` 和配对码。

```powershell
$adb = "$env:ANDROID_HOME\platform-tools\adb.exe"
& $adb pair 192.168.5.20:37419      # 换成手机显示的地址，然后输入配对码
& $adb connect 192.168.5.20:5555    # 换成手机上显示的"IP 地址和端口"
& $adb devices
powershell -ExecutionPolicy Bypass -File .\tools\build-apk.ps1 -Install   # 之后无线装机
```

**C. U 盘 / 网盘**：把 `xehn-<版本号>.apk` 拷出去，手机上点开安装。最慢，但最不需要配置。

---

## 4.1 账号（为什么包里带了一个）

`app/src/main/assets/account.json` 是内置的 WARP 账号，App 启动就喂给引擎
（`EngineBridge` 调 `setAccountJSON`），`api.cloudflareclient.com` 连不通时也能用。

**它不在仓库里**：这个文件带真私钥，`app/src/main/assets/psiphon/client.config`
（Psiphon 的 `SponsorId`）同理，两个都写在 `.gitignore` 里。克隆下来先按
[`docs/credentials/README.md`](docs/credentials/README.md) 把它们补上再构建 ——
不补也能装、能用，只是首次连接要现注册、开 Psiphon 会直接报错。

- 想换成自己的：在电脑上跑 `warpscout register`（或用桌面客户端的
  `warpscout-account.json`），把文件覆盖到 `app/src/main/assets/account.json`，重新打包。
- 注意它跟着 APK 走：把 APK 发给别人等于把这份 WARP 身份一起给了。
- 引擎内部还会把它缓存在 `filesDir/engine/account.json`，注册成功时也会写那里。

## 5. 踩过的坑（都已经写进脚本/文档，别改回去）

1. **`javac` 必须在 PATH 里。** gomobile 最后一步直接 `exec javac`，不看 `JAVA_HOME`。
   装完 JDK 请**新开一个终端**（旧的 `$env:PATH` 里没有）。
2. **Go 1.24+ 的 gomobile 要求 `golang.org/x/mobile` 在模块依赖图里**，否则拒绝：
   `go get -tool golang.org/x/mobile/cmd/gobind`（`build-engine.ps1` 自动补）。
3. **`-javapkg` 要传 `com.xiaohe`，不是 `com.xiaohe.engine`。** gomobile 会把 Go 包名当子包
   追加：`com.xiaohe` + `package engine` = `com.xiaohe.engine`。
4. **gobind 会静默跳过「参数/返回值是结构体（按值）」的方法**，退出码仍是 0，
   到 Kotlin 才报 `Unresolved reference`。所以导出 API 只用基础类型，
   快照走 `StatusJSON() string`（Kotlin 用系统自带 `org.json` 解析）。
   `build-engine.ps1` 会在绑定后剖开 aar 核对方法存在。
5. **`sdkmanager --licenses` 的 stdin 管道**：PowerShell 的 `|` 喂不进 `.bat`，
   要用 `cmd /c "... < yes.txt"`。
6. **Windows PowerShell 5.1 会把 `-target=$Target` 原样传给原生 exe**（变量不展开），
   必须写成参数数组再 `@` 展开。
7. `.ps1` 带中文必须存成 **UTF-8 with BOM**，否则 PowerShell 5.1 按 GBK 解码会语法报错。
8. **`gomobile bind` 里的 javac 会把 Go 的 doc 注释抄进生成的 Java，而中文 Windows 上
   javac 默认按 GBK 解码源码** —— 注释里任何非 ASCII 字节都会以
   `unmappable character (0x8E) for encoding GBK` 打挂整次 bind，而且报错被 gomobile
   吞掉、只剩一句 `javac ... failed`。`build-engine.ps1` 已经设
   `JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8` 解决；同时被绑定符号的注释保持英文。
9. **`serve-apk.ps1` 必须每次请求重新取 APK 大小。** 之前把大小缓存在启动那一刻，
   重新构建后响应头的 Content-Length 还是旧值，手机只下载前一半 →
   装的时候报「解析包时出现问题」。
10. **`VpnService.protect` 必须在 `establish()` 之前装好。** VPN 一建立，隧道自己
    发往 Cloudflare 的 UDP 就会被自己的 VPN 抓回去，握手包出不去 —— 表现是
    「VPN 钥匙出来了、界面已连接、网页打不开」。挂在 `ListenConfig.Control` 上
    （socket 创建那一刻），而不是事后补救。
11. **tun fd 要用 `ParcelFileDescriptor.detachFd()` 交出所有权。** 用 `pfd.fd`
    的话 Java 侧对象被回收时会关掉同一个 fd，隧道会在毫无征兆的情况下断掉。
12. **`START_NOT_STICKY`，并且只认显式指令。** 系统重建服务时会送来 null Intent，
    不能因为「服务被叫起来过」就擅自建立 VPN。
13. **gomobile 把 Go 的 `int` 绑成 Java 的 `long`** —— Kotlin 侧传 Int 变量要
    `.toLong()`（字面量可以自动推断，变量不行）。
14. **amneziawg-go 与上游 wireguard 都没有 `tun_android.go`**（已核实）：
    `engine/warp/tun_android.go` 是自己写的，只做数据面读写，不做任何 ioctl ——
    接口地址、路由、DNS 全部由 `VpnService.Builder` 决定。
15. **`targetSdk 35` 起 edge-to-edge 是强制的，界面必须自己让开 insets。**
    状态栏是透明浮层，顶栏那排图标会落进系统状态栏窗口里 —— 表现就是
    「图标看得见但点不动」，而且整排的纵向比例看着也不对。
    修法：`statusBarsPadding()` / `navigationBarsPadding()` 加在
    `verticalScroll` **之前**，让滚动视口本身就在安全区内。
16. **自适应图标靠遮罩吃掉白角。** 原始 logo 是「圆角方形卡片 + 四角纯白」，
    直接当图标用会露出四个白角。做法：先把纯白边框裁掉，再把卡片按画布 90%
    摆放 —— 卡片自身的圆角落在启动器遮罩之外被裁掉，而底部的 XEHN 字样
    仍留在遮罩内（按 108dp 画布 / 54dp 半径算过）。工具：`tools/make-icons.ps1`。
    同时生成 legacy 方形/圆形图标，照顾忽略自适应图标的启动器。
17. **PowerShell 的 `Graphics.SetClip(GraphicsPath)` 重载解析会挑错重载**，
    报一个看不懂的 `GraphicsPath → Rectangle` 转换错误；换成逐像素抠圆更稳，
    顺便能做 1px 边缘抗锯齿。
18. **gomobile 把 Go 的 `int` 绑成 Java 的 `long`** —— Kotlin 侧传 Int 变量要
   `.toLong()`（字面量能自动推断，变量不行）。`Protector.protect(long)` 同理。
19. **引擎必须用 Go 1.26 构建，不能用本机的 1.27。** Psiphon 的 `psiphon-tls` 在
   `init` 里用反射逐字段校验 `crypto/tls.ConnectionState` 的布局，Go 1.27 给它加了
   一个字段 —— 直接以 1.27 构建出来的包一 import 就 panic
   （`struct field count mismatch: 18 vs 17`），而且是**启动即崩**。
   `engine/go.mod` 的 go 指令写成 `1.26.3`（依赖里最高的那一个），
   `tools/build-engine.ps1` 再把 `GOTOOLCHAIN` 钉成 `go1.26.10`（1.26 系列最新补丁，
   本机没有会自动下载）。
   手动跑引擎命令时记得带：`$env:GOTOOLCHAIN='go1.26.10'`。
   **装最新版 Go 不受影响**：PATH 上的是 go1.27.3，只有引擎这一步临时切到 1.26.10。
20. **Psiphon 与 MASQUE 各用一个 quic-go fork，而它们的 qpack API 不兼容。**
   官方 quic-go（MASQUE 走它）要 qpack v0.6 的 `NewDecoder()` + `Decode`；Psiphon 的
   fork 要 qpack v0.5 的 `NewDecoder(cb)` + `DecodeFull`。同一个模块路径只能有一个版本，
   所以 `engine/third_party/qpack` 是一份把两套 API 合并的本地副本
   （`NewDecoder` 改可变参数 + 补回 `DecodeFull`），见该目录 README。
21. **Psiphon 的 packet tunnel 会 import `github.com/tailscale/netlink`（2021 年的
   vishvananda 分叉），它跟新版 vishvananda/netlink 有 6 处类型不兼容。**
   同样是本地副本：`engine/third_party/tailscale-netlink`，只改了 6 行类型转换。
22. **走 Psiphon 出口时系统 tun 的 MTU 要用 1500**（tunnel-core 的 `DEFAULT_MTU`）。
   Psiphon 会往 tun 写最多 1500 字节的包，接口 MTU 设 1280 会被内核丢掉 ——
   表现是「连上了、小请求通、稍大一点就断」。基础隧道在 netstack 里，不受影响。

---

## 6. 与桌面版的对应关系（改动要点）

| 桌面版 | 安卓版 | 原因 |
|---|---|---|
| `mihomo.exe` 外挂进程做数据面 | 引擎自己跑 warpscout 的 WG/AWG/MASQUE | apk 里没有可执行文件；也不需要 |
| 注册表系统代理 | `VpnService` 全网路由 | Android 没有系统代理概念 |
| `state.json` + `health-owner` pid 租约 | 单例 `Engine` + `StateFlow` | 只有一个进程，不需要跨进程协调 |
| detached `guard` 子进程守护 | 前台 Service 生命周期 | `os.Executable()` 在 apk 内不可执行，spawn 自己必然失败 |
| lxn/walk 自绘 UI（110KB） | Compose | 平台必须换 |
| 用画布拼国旗（圆盘旗会被拉成椭圆） | 国旗 emoji | Android 原生渲染国旗，无变形问题 |
| 连接中点击被吞、只能干等 | 连接中点击 = 取消 | 桌面版最糟的体验，安卓版从一开始就修掉 |

---

## 7. 下一步

1. **P1**：把 `warpscout` 搬进 `engine` 包（收拢包级全局 → `Engine` struct），先做
   `Register` + `Scan` + 本地 SOCKS，不碰 `VpnService`。这一步能立刻在真机验证编译链与内存。
2. **P2**：写 `tun_android.go`（`VpnService` 的 fd → `tun.Device`），接 `SetTunFD`，
   打开 `ENGINE_CAN_ROUTE`，再加 `protect()` 防回环。
   **已核实**：`amneziawg-go/tun` 与上游 `golang.zx2c4.com/wireguard/tun` 都只有
   darwin/freebsd/linux/openbsd(仅 amnezia 还有 windows)，**没有 `tun_android.go`**，
   所以这个包装必须自己写（约 200 行，参考 wireguard-android 的
   `tun.CreateTUNFromFile`：VpnService 已经建好接口，只需把 fd 当设备读写）。
3. **P3**：节点 / 规则 / 设置页面；导出 mihomo / WireGuard 配置。
4. ~~**P4**：Psiphon 出口改成库调用~~ ✅ 已完成（2026-10-10）：`engine/warp/psiphon.go`
   用 `MobileLibrary/psi` 在进程内跑 tunnel-core，`PacketTunnelTunFileDescriptor` 直接用
   系统 tun fd；上游是基础协议的本地 SOCKS（`UpstreamProxyURL`）。

## 8. 待确认

- 包名 / 应用名：现在 `com.xiaohe.vpn` + `xiaohe VPN`（跟桌面版标题栏走），要改说一声。
- `minSdk`：现在 24（与 gomobile 默认 `-androidapi 24` 对齐）。
- 装机验证：需要一台开 USB 调试的安卓设备；`adb devices` 现在是空的。

## 9. 许可

安卓版**在进程内链接了** `psiphon-tunnel-core`（GPL-3.0）—— 这是 Psiphon 出口在
Android 上唯一可行的形态：APK 里没有子进程可起，桌面版那套「独立 `psiphon.exe` +
本地端口」搬不过来（`docs/porting-analysis.md` 的 P4 记录了这次取舍）。完整许可证
文本在 [`third_party/GPL-3.0.txt`](third_party/GPL-3.0.txt)。`engine/third_party/`
下的两份本地源码副本（`qpack`、`tailscale-netlink`）各有 README 说明改动原因，
同样随源码分发。
