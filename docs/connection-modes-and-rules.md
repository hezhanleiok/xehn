# 连接模式与分流规则（设计稿，2026-10-21）

> 结论先说：**只有两种模式**（VPN 模式 / 仅代理），**分应用只在 VPN 模式生效**，
> 规则要按模式分开设计——VPN 模式只能到 IP 级，域名级规则只有「仅代理」能做。

## 1. 为什么是两种模式，不是三种

你列的三种里，「VPN 模式」和「TUN 模式」在 Android 上是**同一件事**：
`VpnService.Builder.establish()` 给出来的就是一个 tun 文件描述符，系统把路由表
指到它上面。没有第二种「tun 设备」可以做（`/dev/net/tun` 普通 App 打不开，
那是 root/系统权限的事）。桌面版之所以区分，是因为它有 wintun（独立虚拟网卡）
和 mihomo（用户态 tun），两套东西；Android 上没有这个二分。

| 模式 | 怎么接管流量 | 适用 |
|---|---|---|
| **VPN 模式** | `Builder.establish()` → tun fd 交给引擎当数据面；全机（或分应用名单）流量进隧道 | 默认；要「打开就全网走」 |
| **仅代理** | 不建 VPN；引擎跑 netstack + 本地 SOCKS5（`127.0.0.1:端口`，可选 `0.0.0.0` 允许局域网） | 只想给浏览器/某个应用用；不想弹 VPN 授权 |

第三种「系统全局 HTTP 代理」需要 `WRITE_SECURE_SETTINGS`（要 adb 授权），
装完不能直接用，所以不做。

## 2. 分应用：只在 VPN 模式生效

`addAllowedApplication` / `addDisallowedApplication` 是 `VpnService.Builder` 的能力。
「仅代理」模式没有任何东西被接管，谈不上「哪些应用走隧道」—— 设置里这一项按模式
置灰（已实现）。

## 3. 规则：两种模式的能力不一样，必须分开设计

| 规则依据 | VPN 模式 | 仅代理模式 |
|---|---|---|
| IP / CIDR | ✅ 路由层直接决定走不走隧道 | ✅ 每条连接自己决定 direct / proxy |
| 域名 | ❌ 只能看到 IP（除非做 TLS SNI 嗅探，HTTP/3 还嗅不到） | ✅ SOCKS5 握手就带域名 |
| 应用包名 | ✅ 系统级白/黑名单 | ❌ |

### 3.1 VPN 模式：用「加哪些路由」表达策略

VpnService 的语义很简单：**只把加了路由的网段抓进 tun，没加的照旧走物理网卡**
（也就是直连）。所以三种内置策略就是三份「路由集合」：

| 策略 | 路由集合 |
|---|---|
| **全局** | `0.0.0.0/0` + `::/0`（现状） |
| **绕过大陆** | 全局 减去 CN 段（CN 直连，其余走隧道） |
| **黑名单** | 只加黑名单里的段（列表内走隧道，其余直连） |

「减去 CN 段」怎么减：

- **Android 13+（API 33）**：`Builder.excludeRoute(IpPrefix)` —— 官方就是为这个加的。
- **API 24–32**：没有 excludeRoute，只能算出「CN 段之外」的前缀**补集**再
  `addRoute` 逐条加。CN CIDR 约 8k 条，补集反而更少（几百条），开销可接受。
- 数据来源：内置一份 CN CIDR 快照（100–200 KB，随 App 版本更新，不联网拉取）。

**自定义规则（VPN 模式）**：只支持 `IP/CIDR → direct|proxy`，等价于在路由集合里
增删网段。写「域名」在这里是**做不到的**，UI 上要明确说，否则就是骗人。

### 3.2 仅代理模式：请求级判定（这才是「规则模式」的正确形态）

本地 SOCKS5 收到请求时就知道目标（域名或 IP + 端口），可以逐条判定：

```
请求 → 匹配自定义规则（按顺序，首个命中生效）
     → 匹配内置规则（黑名单 / CN 段 / 地区）
     → 都没命中 → 用策略默认（全局=proxy，绕过大陆=proxy，黑名单=direct）
   proxy → 经隧道 netstack 拨号（域名在出口侧解析，不泄漏）
   direct → 用 App 自己的 socket 直接拨（protect 过，不走隧道）
```

只有这条路能真正实现「某域名直连、其余走代理」。

### 3.3 规则优先级与兜底

1. **自定义规则**（用户写的，按顺序，首个命中即停）
2. **内置规则**（黑名单表 → 大陆 CIDR → 地区表）
3. **策略默认**（proxied / direct）
4. 规则写错（匹配不到、解析失败）一律**不阻断连接**，只记一行日志并按默认走

## 4. 实现顺序

1. ✅ 连接模式（VPN / 仅代理）+ 本地端口 + 允许局域网
2. ✅ 规则引擎 + **仅代理模式**的域名级判定：
   - `engine/warp/rules.go`：`policy`（global / bypass-cn / blacklist）+ 自定义规则
     `direct|proxy,域名或CIDR`，首个命中即停；写错的行会计数并写日志
   - `engine/warp/socks.go`：命中 direct 的连接用本机网络直接拨（不进隧道），
     proxy 的仍在隧道内解析并连接
   - 设置页「分流规则」：规则模式三选一 + 多行自定义规则（VPN 模式下置灰）
   - 单元测试 `engine/warp/rules_test.go`：策略默认、子域匹配、首条命中、坏行计数
   - **内置表目前是骨架**：`.cn` 后缀 + 约 55 个常见 CN 域名；完整 geosite:cn 与
     CN CIDR 随第 3 步一起换
3. ✅ VPN 模式的 CN 路由表 + 黑名单（**运行时拉取**，不占包体）：
   - `engine/cnroutes.go`：按序试两个数据源（17mon/china_ip_list → ispip.clang.cn），
     只留合法 IPv4 CIDR；缓存 `filesDir/engine/cn-cidrs.txt`（mtime 即拉取时间，
     7 天算过期）。拉不到就保留旧缓存，绝不影响连接
   - 拉取时机 = **隧道建好之后**：fd 模式下这个 HTTP 会被路由进 tun，所以
     「被墙的网络里用当前隧道拉」是可行的；仅代理模式下走本机网络
   - `WarpVpnService.applyRoutePolicy`：
     `global` → `0.0.0.0/0`；`bypass-cn` → `0/0` 减 CN（API 33+ 用 `excludeRoute`，
     API 24–32 合并区间后生成**补集前缀**）；`blacklist` → 只加规则里的 `proxy` 网段
   - 设置页显示「N 条 · 较新/已过期 · 时间」+「立即更新路由表」按钮
4. 自定义规则 UI 增强（逐条增删、拖动排序、导入导出）

## 5. 已知限制（必须写进 UI 或文档）

- **VPN 模式按域名分流做不到**（除非在 App 里做用户态 TCP 终止 —— 那等于重写一个
  mihomo，QUIC/UDP 无解）。这也是桌面版离不开 mihomo 的原因。
- **局域网代理没有认证**：同一 Wi-Fi 下谁都能用，公共网络不要开。
- CN CIDR 是快照，会过期；要随版本更新，或以后加「在线更新规则」。
- 仅代理模式下「连接成功」只代表本地端口在监听且出口可用，**不代表**其它应用真的
  在用 —— 界面文案要区分。

---

## 6. OpenVPN 出口（VPN Gate，2026-10-22）

### 6.1 为什么不用整块 mihomo

电脑版的 OpenVPN 出口来自 `core/mihomo.exe` 的 `type: openvpn` 出站，而它的实现是
**纯 Go 包** `transport/openvpn`（AES-128-CBC/SHA1、inline ca/cert/key、tcp/udp、
tls-auth/tls-crypt 都支持）。手机版已经有等价的数据面（WARP + gVisor netstack +
tun 所有权 + 出口实测），缺的只有这一个包，所以只把它复制进
`engine/third_party/mihomo/`（与 `qpack`、`tailscale-netlink` 同一种做法），
**不引入 mihomo 模块本身**：那个模块的 `require` 会把 x/net、x/crypto 等一起
MVS 升级，可能打乱 quic-go / psiphon 的固定版本。

两个不能省的点：

- `github.com/metacubex/tls`：OpenVPN 靠 TLS 重协商做 rekey，Go 标准库的客户端
  不支持自由重协商（`RenegotiateFreelyAsClient`），省掉它 = 连接满一小时必断。
- `github.com/rasky/go-lzo`：`comp-lzo` 解压。

### 6.2 链路与「两阶段建 tun」

```
系统 tun fd ──▶ warp/openvpn.go 的包泵 ──▶ OpenVPN 客户端 ──▶ 节点 ──▶ 互联网
                    ▲
                    └── 外层 TCP/UDP 走基础协议（WARP）的 netstack
```

OpenVPN 是**路由式**隧道：服务端按 `PUSH_REPLY` 里 `ifconfig` 下发的地址回程。
如果用 WARP 的 `172.16.0.2` 建 tun，回程包会被服务端丢在自己的路由表里，表现是
「握手成功、什么都打不开」。地址只有握手后才知道，而 `VpnService.Builder` 必须先于
fd 存在，所以顺序必须是：

1. 基础隧道以 netstack 起来（`tunFD=0`，不建系统 VPN）；
2. 经 netstack 拨节点 → `Handshake` → 拿到 ifconfig/route/dns/peer-id；
3. 引擎回调 Kotlin（`TunProvider.EstablishTun`）用这些参数 establish，拿 fd；
4. 起「tun ⇄ OpenVPN 包」双向泵 + 10s 空闲 ping；
5. 用一次 `https://1.1.1.1/cdn-cgi/trace`（IP 字面量，不依赖 DNS）验证出口。

`TunProvider` 与 `Protector`/`LogSink` 同一种跨语言回调，注释保持 ASCII
（gomobile 会把注释抄进 Java，javac 可能按 GBK 读）。

### 6.3 节点池与分类

- 数据源：`https://www.vpngate.net/api/iphone/`（15 列 CSV，最后一列是 base64 的
  .ovpn）。直连 8s 超时后**自动起一条临时 WARP tunnel 再抓**，抓完即关；
- 落地地址以 .ovpn 的 `remote` 为准（CSV 的 IP 列偶尔与配置不一致）；
- 分类：`public-vpn-*` 直接判机房（电脑版 CFnew 也用它排除）；其余经 `ip-api.com/batch`
  （100 IP/次）拿 isp/org/as/mobile/proxy/hosting，规则移植自电脑版
  `stageJ/classify.js`（25 个硬机房 ASN + 住宅品牌表）；
- **与电脑版 26 个已判样本对拍：一致 22，机房→家宽 0，家宽→机房 0**
  （`warp/vpngate_pc_compare_test.go`）。剩下 4 个都是「住宅 vs 未知」的保守差异。
  手机端没有 PTR/PeeringDB，所以 access-type 关键词（telecom/communications）**不作为**
  住宅证据 —— 否则 Cogent/NTT Communications/FPT Telecom 会被误标成家宽；
- 延迟是**实测 TCP 握手 RTT**；UDP 节点或探测失败显示自报 ping 并标「自报」。

### 6.4 真机实测修正（2026-10-22，Xiaomi Mi 11 Ultra / MIUI）

第一次真机跑通这一整套时，暴露了两个只能靠真机发现的问题，已修，记在这里免得回退：

1. **出口验证不能单端点、不能只试一次**。原来只请求 `https://1.1.1.1/cdn-cgi/trace` 一次，
   真机上连续 5 个候选全被判「没有真正转发流量」，但实际上同一块 `tun0` 上手机侧
   `curl https://1.1.1.1/cdn-cgi/trace` 是 200、出口 `122.36.8.16 (KR)`：
   - `1.1.1.1` 在这些线路里**直连被拦、经隧道才通**，而 `establish()` 返回后路由/接口
     还会飘 1–2 秒，那一瞬间的请求注定失败；
   - 现在的做法（`warp/probeExitViaTun`）：两个 IP 字面量端点 + 在预算内每 700ms 重试
     一轮，单次请求上限 4s，任一轮拿到 `ip=` 就算通过，并把「第 N 轮通过」写进日志。
2. **`.ovpn` 原文必须落盘**。`VPNGateNode.Config` 是 `json:"-"`（列表要小，不能把
   1 MB 证书塞给 UI），结果进程一重启就只剩元数据 → 每个节点都「配置不在缓存里」，
   而且旧逻辑会**静默退回普通 WARP 隧道**并显示「已连接」（出口 104.28.x，不是节点）。
   现在：
   - 配置原文单独存 `files/engine/vpn-gate-configs.json`（与列表同目录、原子写），
     `LoadVPNGateCache` 读列表时顺手挂回去；
   - `warpBackend.openvpnWanted` 与 `openvpnIDs` 分开记：用户要了 OpenVPN 出口但一个
     可用配置都没有时，`Connect` 直接报错，绝不再退回普通隧道。

验证方式（不需要电脑版）：`adb shell curl -4 https://1.1.1.1/cdn-cgi/trace` 看 `ip=`/`loc=`
是否等于界面上的「出口 IP」，以及 `/proc/net/dev` 里 `tun0` 的收发计数在涨。

### 6.5 已知限制


- 电脑版实测 VPN Gate 只有 **37.5%** 的节点能完成握手，且 6/6 家宽出口被标
  PacketStream 共享代理。所以「能用都保留」：不按层级过滤，只做排序与标记，
  连接时按顺序最多试 5 个候选；
- 单节点吞吐与稳定性都不如直连 WARP；节点抖动时靠 `needRecover` 看门狗重连；
- 与 Psiphon 互斥（两者都要求独占最终出口），UI 与引擎都会拦；
- 系统 tun MTU 用 **1160**（服务端 tun-mtu 1500，但外层还要经 WARP 封装一次；
  1400 会被拆成 1240+160 两段，包量与加密次数接近翻倍，见 §2.3 的踩坑记录）。

### 6.6 出口速度优化（2026-11-01，移植自电脑版）

电脑版 `warp-client` 早就把「选节点」从「挑延迟最低的」改成「挑实测吞吐最高的」，
手机端原先只看 TCP 握手延迟 + 分类（家宽/机房），所以会出现「连上了、每个网页都在爬」。
这次把能搬的都搬过来了（电脑版：`connect.go` 的 `openvpnSpeedProbe*` / `openvpnMinBps`
/ `openvpnSpeedRetries`，`vpngate.go` 的 `vpngate-speeds.json` 与 `vpnGateSpeedTier`）：

| 电脑版机制 | 手机端对应 | 状态 |
|---|---|---|
| 实测吞吐记忆 `vpngate-speeds.json`，TTL 6h | `NodeSpeedStore`（SharedPreferences，TTL 6h） | ✅ |
| 排序分档 快 → 未测 → 慢（`vpnGateSpeedTier`） | `pickOpenVPNCandidates` 的块内排序 | ✅ |
| 连接时用 **512 KiB** 真下载量吞吐（通用门槛 128 KiB 会被慢启动主导） | `measureExitBps`：512 KiB，**8s 预算** | ✅（见下） |
| 速度地板 **150 KB/s**，低于就换中继 | `OPENVPN_MIN_BPS` + `connectLoop` 换点 | ✅ |
| 连续 2 个慢中继后接受当前连接（慢总比没有强） | `OPENVPN_SPEED_RETRIES = 2` | ✅ |
| 手动钉死的节点不因速度换掉 | `connectLoop` 里比对 `openvpnNodeId` | ✅ |
| 握手预热窗口（mihomo 把握手从 inbound dial 上摘掉，首个请求必失败） | — | ❌ 不适用：我们的引擎在 `DialOpenVPN` 里同步 `Handshake`，建 tun 之前握手已经完成 |
| TCP 节点优先（UDP 节点最容易被限速） | — | ✅ 间接覆盖：只有 TCP 节点有实测延迟，UDP 节点自然排在后面 |
| 把 `MeasuredBps` 写进 `state.json` 给界面用 | 只写日志 | ⚠ 见下 |

**为什么测速在 Kotlin 侧、不在 `engine/warp/openvpn.go`**：改引擎要重跑 gomobile
重新打 `app/libs/engine.aar`（那台机器需要 Go 1.26 + gomobile + NDK），而候选排序本来
就在 Kotlin（`pickOpenVPNCandidates`），换点又必须重新 `VpnService.Builder.establish()`
（只能在 Java 侧做）。等引擎下次重建时，`NodeSpeedStore` + 分档规则应该整体搬进
`engine/warp/vpngate.go`，界面再按 `MeasuredBps` 显示速度。

**和电脑版的两处刻意差异**：

1. 测速**不要求下满**：电脑版 `probeThroughput` 要求 12s 内下满 512 KiB，没下满就
   算数据面失败（进失败记忆）。手机端改成「预算 8s，按已收到字节算速度」——
   14 KB/s 的节点下满要 36s，为了证明它慢让用户等半分钟不划算；而且「有一点点
   流量但很慢」正是要判成慢、而不是判成坏的那种情况。
2. 测速 0 字节（DNS 关了、或 `speed.cloudflare.com` 不可达）**不换点**：
   没证据说明它慢，就不该把能用的节点丢掉。电脑版没有这一档，因为它经 mihomo
   的 DNS 一定可用。

**实际代价**：一次 OpenVPN 连接多 0.3–8s（512 KiB / 实测速度）。测速端点与电脑版
同一个：`https://speed.cloudflare.com/__down?bytes=524288`，走系统 VPN 出去。
