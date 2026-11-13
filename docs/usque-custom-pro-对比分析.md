# usque-custom-pro 与本项目「改变 WARP 出口」对比分析（只读）

- 分析对象：`KJGX66F/usque-custom-pro`（v6.27，浅克隆快照，分析后已删除）
- 访问方式：本机 v2rayN 的 mixed 入站 `http://127.0.0.1:10808`
- 范围：只读检查，未修改 `e:/xehn-android` 任何代码；下文所有速度的对比都是架构与既有实测记录的推论，不是本次重新跑分。

---

## 一、结论速览

1. **它不是 VPN 客户端，也不是数据面。** 这是一个跑在 Cloudflare Pages / Workers 上的「WARP / MASQUE 注册 + 配置生成 + 多客户端转换」面板，加一个本地 Python 选路脚本。真正的转发由用户自己电脑上的 `mihomo / sing-box / usque` 完成；仓库里的 Worker 只是把注册请求转发给 `api.cloudflareclient.com`。
2. **它所谓「改变 WARP 出口」其实是四种不同机制，只有两种真正改变最终出口 IP**：
   - 换 MASQUE 入口（`endpoint / port / SNI / H3↔H2`）→ 改的是**如何进入 Cloudflare**，README 自己写明「不能保证把最终 WARP 出口强制切换成某国家」；
   - 出口检测 / 地区优选 → 从**已经出现的真实出口里挑一个**，不创造新出口；
   - **链式出口**（Clash `dialer-proxy: "WARP中转"` + 自备 HTTP/SOCKS5 二级代理）→ 真正改变最终出口；
   - 免费落地节点（`proxy-provider`，vless/vmess/trojan/ss）→ 也是真正换出口，可带 WARP 前置也可不带。
3. **我们项目是「WARP 前置 + 一整套 IP 层 VPN 隧道」**：系统 `tun fd` 交给 Psiphon packet tunnel，或交给自写包泵 + mihomo OpenVPN 客户端；外层承载连接必须走同一会话的 gVisor netstack。出口地区是真能指定的（`EgressRegion` / VPN Gate 国家），代价是双层加密、用户态 TCP、每包 syscall / NAT / 校验和重算。
4. **他快的主因不是「改出口的算法更好」，而是他多数时候根本没有第二层隧道**：单层 MASQUE + 最快入口优选 + 大量 `DIRECT` 分流；即使开链式出口，二级代理也只是**应用层字节流（HTTP CONNECT / SOCKS5）**，交给成熟 mihomo 内核处理，没有 `tun`、没有 IP 包重组、没有一对一 NAT、没有 TCP-over-TCP 的完整 VPN 嵌套。
5. **对比口径有坑**：我们 App 里的「出口实测速度」是 512 KiB × 4 的短测，含 TCP 慢启动，`docs/pitfalls.md:1458-1460` 明确说不要当最终速度；而他的面板用 lazy `url-test` / 客户端 speedtest 看稳态。拿两者直接比会系统性低估我们。

---

## 二、他的原理

### 2.1 注册与配置生成（无数据面）

- `workers/src/worker.js:10-18`：常量 `API_ORIGIN = https://api.cloudflareclient.com`，伪造 `WARP for Android` 头；API 只有 `/api/health`、`/api/warp/register`、`/api/warp/enroll`、`/api/sub`。
- `README.md:421-479`：浏览器 WebCrypto 本地生成 P-256 私钥 → Worker 转发注册 / enroll 公钥 → 浏览器把 `private_key / endpoint_* / endpoint_pub_key / license / ipv4 / ipv6` 拼成原生 `usque-config.json`。
- `README.md:1657-1662`：作者自己声明「本项目是配置与客户端转换工具，不是 VPN 服务提供商」「VLESS 输出属于本地桥接，不是把 MASQUE 直接转换成远程 VLESS 服务器」。

### 2.2 多节点 = 同一份凭据 × 不同入口

- `README.md:483-522`：13/32/64/100/500 个节点**不是** 500 个账号，是「同一套 Usque 凭据 + 不同 Endpoint + 不同 Port」的候选连接；用途是测速、自动选择、找更稳的入口。
- `endpoints.json`：`162.159.198.1/.2`、`162.159.199.2`、IPv6 `2606:4700:103::/104::`、`masque*.bestcf.eu.cc`，端口 443/500/4500/8095，H2 扩展池从 `162.159.198.* / 162.159.199.*` 生成最多 508 个地址。
- `pages/app.js:532-553`：生成 `type: masque` 节点，字段只有 `server / port / private-key / public-key / ip / ipv6 / mtu / udp / sni / network / ip-stack.mode / congestion-controller / handshake-timeout`；即**只改连接参数**。
- `pages/index.html:432-456` + `pages/app.js:1314-1318`：默认 `ip-stack: auto`、`congestion-controller: cubic`，可选 `mips / gvisor` 与 `bbr / bbr3`；MTU 稳定 1280 / 速度 1400。
- `README.md:326-334`（v6.27）：这一版做的全是**延迟与测速调优**——默认入口 `162.159.198.2:443`、SNI 用 `speed.cloudflare.com`、默认 48 节点、lazy 测速 / 300s 间隔 / 3s 超时 / 50ms 容差、按入口 IP 分小组 url-test、H2 随机抽样。**没有任何数据面代码**。

### 2.3 出口检测与「地区优选」

- `pages/warp-egress-selector.py:3-18`：脚本开头就写死边界——「It DOES NOT force Cloudflare WARP to egress from a requested country. It only selects among the real egress locations observed from your existing nodes.」
- 机制（`:44-74, :107-135, :156-189, :204-215`）：连 mihomo 控制口 `127.0.0.1:9090` → 枚举 `type: masque` 节点 → 逐个把隐藏组「出口检测」切到该节点 → 经本地 mixed proxy `127.0.0.1:7890` 打 `cdn-cgi/trace` + `ipinfo.io` 取 `ip/loc/colo` → 测 `chatgpt.com` 可达性 → 按 `存活 → 国家偏好 → ChatGPT → 延迟` 排序 → 回写「地区优选 / PROXY / AI」等策略组。
- `README.md:526-562, :1297-1366, :1455-1466`：「WARP 入口与出口不是一回事」「不同入口可以最终使用相同或相近的 WARP 出口」。所以这里的「改出口」= **择优切换节点**，不是构造新出口。

### 2.4 真正改变最终出口的两种办法

| 机制 | 实现 | 证据 |
|---|---|---|
| 链式出口 | 生成 `type: http` 或 `socks5` 的「⛓ 链式出口」节点，带 `dialer-proxy: "WARP中转"`；流量先过 WARP 再从二级代理落地（典型：自备 Opera 代理） | `README.md:306-313`；`pages/app.js:1092-1097`（生成节点）、`:1621-1627`（只收 `host/port/user/pass/type`） |
| 免费落地 | mihomo `proxy-providers` 从公共订阅拉 vless/vmess/trojan/ss 节点，`url-test` 竞速；开 `freeUseWarp` 时给 provider 加 `proxy: / dialer-proxy: "WARP中转"` | `pages/app.js:588-625, :682-700, :765-883`；`README_EN.md:19,26`；`README.md:261-279` |

两种都是**应用层代理协议**：一次 CONNECT / SOCKS5 握手后是字节流透传，由 mihomo 出站处理；没有第二个 `tun`、没有 IP 包、没有二次 IP 层加密。

### 2.5 本机桥接（说明为什么 v2rayN 也能用）

`pages/app.js:1137-1142, :1144-1190`：`usque.exe socks 127.0.0.1:1080` → `sing-box` 本地 VLESS `127.0.0.1:2081`（`encryption=none`）→ v2rayN 导入。整条是**本机环回**，不额外加密、不过 tun，开销接近零。

### 2.6 一个容易误判为「出口快」的策略

`README.md:206-216` 与 `pages/app.js:1319`：默认 `ChatGPT / OpenAI → DIRECT`，其它国外流量才走 WARP；配置里还有「🎯 全球直连」组和国内规则 `DIRECT`（`pages/app.js:884-885, :990-993`）、`url-test` 自动选最快节点。所以用户体感速度有相当一部分来自**根本没走隧道 / 自动挑了最快入口**，而不是「链式出口本身更快」。

---

## 三、我们项目的数据路径（对照）

### Psiphon 出口

```text
App → 系统 tun fd(1500, 172.16.0.2) → Psiphon packet tunnel（tunnel-core 独占 fd）
    → Psiphon 协议封装/混淆（OSSH / meek / TLS / QUIC）
    → 本地 SOCKS 链（127.0.0.1:0 上游 SOCKS → gVisor netstack）
    → WG/AWG（WARP 前置）→ 物理网卡
```

- `engine/warp/psiphon.go:21-38`：注释明确「协议层的叠加」「tun fd 归 Psiphon 所有，基础 WARP 隧道退到 netstack 模式只当上游载体」。
- `docs/pitfalls.md:885-905`：Psiphon 整个上游走本地 SOCKS，原 32 KB 缓冲 + Nagle 曾压低吞吐，改成 128 KB + `TCP_NODELAY`；并记录了「tun 1500 / 上游 1280 导致二次分片、约 10% 效率损失，尚未改」。
- `docs/pitfalls.md:865-866`（既有结论）：tun fd 直接交给 Psiphon，引擎统计不到流量。

### OpenVPN 出口

```text
App → 系统 tun fd(MTU 1160, 192.0.2.111) → 自写双向包泵（每包 syscall + 地址 NAT + 校验和重算）
    → mihomo OpenVPN 客户端（数据通道加密；TCP 模式带 2 字节长度前缀）
    → gVisor netstack TCP/UDP（stack.tnet.DialContext）
    → WG/AWG（WARP 前置）→ 物理网卡
```

- `engine/warp/openvpn.go:961-1025`：`stack := under.tn.stack()`，TCP 走 `stack.tnet.DialContext` 并 `SetNoDelay(true)`；注释写明「TCP/UDP 都走 gVisor，系统的路由表完全不参与」。
- `docs/connection-modes-and-rules.md:133-148`：两阶段建 tun，外层 TCP/UDP 走基础协议 WARP 的 netstack；`:190-199`：单节点吞吐/稳定性不如直连 WARP，MTU 只能 1160。
- `docs/connection-modes-and-rules.md:261-264`：**始终 WARP 前置，没有任何直连分支**；`:286-291`：VPN Gate 公共节点普遍「握手不转发 / AUTH_FAILED」，桌面版握手成功率仅 37.5%。
- `engine/warp/netstackx/tun.go:89-108` + `docs/pitfalls.md:1431-1443` + `CHANGELOG.md:29-39`：0.2.37 关掉 gVisor `ModerateRecvBuf` 自适应、固定 4/8 MiB 窗口，加 `WriteNotify` 排空 + scratch 复用后，固定韩国节点从几兆回到 ≈80 Mbps，赛风同步提升。
- `docs/pitfalls.md:1361-1373, :1462-1468`：桌面版同链路（`wintun(内核 TCP) + mihomo 出站 + dialer-proxy(WARP)`）约 100 Mbps；手机外层是用户态 gVisor TCP，且仍无 BBR、无 GSO / 批处理。

> 关键结构差异：桌面版 mihomo 的 `type: openvpn` 是**出站代理**（字节流），Psiphon 是**子进程 SOCKS**；手机端为了不引入 mihomo 主模块，只搬了 `transport/openvpn` 包，自己写了 L3 数据面（tun 包泵 + gVisor netstack）。同样的出口协议，形态从「出站」变成了「第二层 VPN」。

---

## 四、逐项对照

| 维度 | usque-custom-pro | 本项目（赛风 / OpenVPN 出口） |
|---|---|---|
| 项目形态 | 网页/Workers 配置生成器 + Python 选路脚本，零数据面 | Android App + Go 引擎，自研完整 L3 数据面 |
| 「改出口」语义 | 主要改**入口**；真正换 IP 靠 SOCKS5/HTTP 链式出口或免费落地节点 | 真把最终出口换成 Psiphon 服务器 / VPN Gate 节点 |
| 出口地区可控性 | 不能强制，只能从已观测出口里挑；`README.md:1659` | 可指定 `EgressRegion` / 钉国家、钉节点 |
| 链路层数 | 单层 MASQUE(QUIC/H3 或 H2)；链式出口时多一层**字节流**代理 | 两层 IP 隧道：Psiphon/OpenVPN + WARP 前置，双重加密 |
| tun 设备 | 无（mihomo / sing-box 进程内出站或 PC wintun） | 有，且 `tun fd` 独占交给 Psiphon 或自写包泵 |
| 承载 TCP 栈 | mihomo 可选 `auto / mips / gvisor`，可开 `bbr / bbr3`；PC 上多为内核栈 | 只能是本工程的 gVisor netstack，CUBIC/RENO，无 BBR/GSO |
| 每包开销 | mihomo 内核内部处理，无 NAT、无校验和重算 | syscall 读写 + `192.0.2.111` ↔ 节点地址 NAT + 校验和重算 + OpenVPN 长度前缀/加密 + Psiphon 本地 SOCKS 链 |
| MTU | 稳定 1280 / 速度 1400，单层 | Psiphon 1500→1280 二次分片；OpenVPN 1160 |
| 节点来源 | 同一账号的 Cloudflare 入口池 + 自备高质量代理 + 多源订阅 health-check | Psiphon 官方地区服务器（抗封锁优先）、VPN Gate 公共节点（共享/限速/易死） |
| 选路策略 | lazy url-test、按入口分组竞速、300s 测速间隔、失败容差、失败节点不拖累 | 地区测速串行、握手探测、`512 KiB` 真下载 + 150 KB/s 地板换点、无 DIRECT 分支 |
| 平台 | PC / 桌面客户端，内核 TCP + 批量读写 | Android `VpnService`，每包一次 syscall |
| 分流 | 国内 / ChatGPT 可 `DIRECT`，只把需要的流量送进隧道 | 全部流量强制经 WARP + 出口 |

---

## 五、为什么他的「改出口」访问速度更快

按贡献排序（架构必然 → 节点/策略 → 测量口径）：

1. **多数情况他根本没加第二层隧道。** 换 endpoint / 端口 / SNI / H3↔H2 只是给同一条 MASQUE 连接挑更近、更通的入口；v6.27 的全部工作都是「延迟与测速参数调优」。我们这边只要选了赛风 / OpenVPN，就必定是「WARP → 第二条 IP 隧道」两次封装。
2. **链式出口是字节流代理，不是 VPN。** `http / socks5` 出站只在建连时一次握手，之后 mihomo 直接转发字节流；没有 `VpnService` tun、没有 IP 包泵、没有一对一 NAT、没有第二套 TCP/IP 栈。我们的 OpenVPN over TCP 是典型的 **TCP 套 TCP**：内层拥塞控制跑在外层 gVisor 用户态 TCP 上，丢包/高 RTT 时两层重传互相放大（`docs/pitfalls.md:1455` 也把它列为出口实测偏低的首因）。
3. **外层协议栈代差。** 他的 MASQUE 由 mihomo 承担，可选 `system/auto` 栈 + `bbr/bbr3`，PC 上是内核 TCP + 批处理；我们外层永远是 gVisor，虽然 0.2.37 修好了「自适应窗口把单流钉在几十 KB」的致命问题（≈80 Mbps），但仍缺 BBR、GSO、批处理（`docs/pitfalls.md:1464-1468`）。桌面版同结构能到 100 Mbps，说明差距主要在这层，不在节点。
4. **每包固定成本不同。** OpenVPN 出口每包两次 syscall、地址替换 + 校验和重算、数据通道加密、TCP 2 字节长度前缀；赛风还有一层本地 SOCKS 链（虽已优化到 128 KB + `TCP_NODELAY`）和 1500/1280 二次分片。这些在他那边都不存在。
5. **节点质量与选路。** Psiphon 的 OSSH/meek/多跳是为抗封锁设计，天然高开销；VPN Gate 节点共享、限流、握手成功率低（`docs/connection-modes-and-rules.md:286-291`）。他那边要么是 Cloudflare 自家边缘入口，要么是用户自备的 SOCKS5/HTTP 代理或多源订阅里 health-check 竞速出的健康节点，并且自动切到最快的一条。
6. **分流与直连。** 他默认 ChatGPT → `DIRECT`、国内规则 → `DIRECT`；我们「始终 WARP 前置，没有任何直连分支」，所有流量都要过两层隧道。用户感受到的「快」有相当比例来自流量没进隧道。
7. **测量口径。** 我们的「出口实测速度」是 512 KiB × 4 短测（含慢启动，实测同节点短测 854 KB/s 而稳态 80 Mbps）；他看的是 lazy url-test / speedtest 稳态。两者不可直接相减。

> 因此更准确的说法是：**「他的场景链路更短、协议栈更接近内核、节点更健康、还能直连」，而不是「他改变 WARP 出口的技术比我们的赛风/OpenVPN 更快」。** 如果我们只连基础 WARP/MASQUE（不叠出口），链路与他默认场景基本一致；差距出现在叠加第二层出口之后。

---

## 六、若要缩小差距，可验证的方向（仅建议，未改代码）

1. **A/B 先定性**：同一时段、同一目标、4 流稳态下载，分别测「只连 WARP」「WARP + 出口」，并按 `docs/pitfalls.md:1447-1460` 的 `[diag] 上游 1 流 / 4 流` 顺序定位是上游、单流窗口还是出口层。先确认测试包已含 0.2.37 的固定窗口修复。
2. **把二级出口从「IP 层 VPN」降为「应用层出站链」**：mihomo 式 `dialer-proxy` + SOCKS5/HTTP，只做字节流，避免 tun 包泵、NAT、二次 IP 加密；代价是失去 `EgressRegion` / 全局 tun 语义，需要评估。
3. **让外层尽量交给系统内核**：`docs/desktop-optimization.md:64-80` 的 P0（`stack: gvisor → system`、MTU 1160–1240 对齐、出站优先带批处理/GSO + BBR 的 MASQUE）在桌面侧已验证是最大收益项；手机侧受 `VpnService` 限制，至少可先补多流稳态测速与节点吞吐缓存。
4. **选路策略**：把「握手延迟」换成真实吞吐排序 + 6h 记忆（项目已有 `NodeSpeedStore` / 150 KB/s 地板），再引入按入口分组竞速、lazy 测速、失败节点不反复齐测——这三条正是对方 v6.27 的主要调优，属于纯策略，成本最低。
5. **允许部分流量 DIRECT**：当前「没有任何直连分支」是硬约束，若产品允许，分流比换内核更能改善体感。
6. **MTU 分层**：Psiphon 1500 → 1280 的二次分片（约 10% 损失）与 OpenVPN 1160 值得做一次真机 A/B。

---

## 七、证据索引

**克隆快照（分析后已删除，路径为仓库内相对路径）**

- `README.md:5-7, :206-216, :306-334, :421-562, :1297-1366, :1455-1466, :1657-1662`
- `README_EN.md:5-27`、`endpoints.json`、`pages/README.md:64-77`
- `pages/app.js:532-553`（masque 节点字段）、`:588-625, :682-700`（免费落地 + WARP 前置）、`:1092-1097, :1621-1627`（链式出口）、`:1137-1142, :1144-1190`（本地 VLESS 桥）、`:1314-1319`（默认策略）
- `pages/index.html:432-456`（IP 栈 / BBR 选项）
- `pages/warp-egress-selector.py:3-18, :44-74, :107-135, :156-189, :204-215`
- `workers/src/worker.js:1-18`

**本项目（只读检查，未改动）**

- `engine/warp/psiphon.go:21-51`、`engine/warp/openvpn.go:961-1025`
- `engine/warp/netstackx/tun.go:89-108`
- `docs/connection-modes-and-rules.md:113-148, :190-237, :261-291`
- `docs/pitfalls.md:885-905, :1361-1373, :1431-1476`
- `docs/desktop-optimization.md:60-119`、`CHANGELOG.md:29-39`

---

## 八、执行记录

- 通过 v2rayN（`http://127.0.0.1:10808`）浅克隆 `KJGX66F/usque-custom-pro` 到 `e:/xehn-android/_tmp_usque_review`；
- 完成只读分析后已删除该临时目录（含 `.git`）；
- 未修改 `e:/xehn-android` 下任何代码（本报告为新增文档）。

---

## 九、补充：对桌面版（`D:\work\xhwarp`）有没有用

### 9.1 路径确认

`D:\work\xhwarp`（已只读核实存在）主要组成：

| 路径 | 作用 |
|---|---|
| `D:\work\xhwarp\warp-client` | Go 编排层 + Win32 GUI，`renderClientConfig` 生成 mihomo `config.yaml` |
| `D:\work\xhwarp\warp-client\internal\core` | 起 `mihomo.exe` 子进程、写 `config.yaml`、走 REST `external-controller` |
| `D:\work\xhwarp\warpscout` | 端点扫描引擎（WG/AWG/MASQUE 真实握手验证） |
| `D:\work\xhwarp\XEHN-dev\core\config.yaml` | 便携发布目录里实际生成的配置实例（当前是 Psiphon V1：wireguard + 本地 socks5） |
| `D:\work\xhwarp\XEHN_ISSUE_AUDIT_AND_PLAN_2026-11-08.md` | 现状审计，`:172-180` 自己列了配置层短板 |

桌面版 README 写「embedded Clash (mihomo) core」，实际是**外置 sidecar 子进程**：`internal/core/core.go:184` 用 `exec.CommandContext(..., "-d", WorkDir)` 启动，`config.yaml` 由 `WriteConfig` 原子落盘。

### 9.2 结论：有用，但只在「配置/策略层」；数据面不要动

**桌面版早就具备 usque-custom-pro 的大部分能力**，包括它最招牌的「链式出口」：

- `client.go:449-476`：OpenVPN V2 用 mihomo 原生 `type: openvpn` 出站 + `dialer-proxy: <WARP 底座>`，`connect.go:704-708` 明确「不需要外部 OpenVPN 二进制、不需要 sidecar SOCKS 端口」；
- `subconfig.go:17-20, :77-85`：订阅模式（Mode B）把导入节点当第一跳，OpenVPN / SOCKS5 二级出口通过 `dialer-proxy` 挂在上面；`warp.go:195-198`、`connect.go:229-237` 还有 WARP-in-WARP / MASQUE-in-MASQUE；
- `wgconf.go:649-679`：MASQUE H3/H2、`sni`、`congestion-controller: bbr`、`ip-stack: gvisor`；`pools.go:10-51`、`masque.go:84-100`、`warp.go:93-101`、`findsni.go:46-97` 有端点池 / 端口池 / SNI 扫描；
- `client.go:868-899`、`subgeo.go:16-27`：出口 IP / colo / country 检测；`client.go:654-746`：私网、`GEOSITE,cn,DIRECT`、`GEOIP,CN,DIRECT` 分流；`health.go`、`connect.go:1576-1580`：失败节点记忆与健康换点；`probe_openvpn.go:21-25`：真握手 + 真下载探测。

所以 `pages/app.js:1092-1097` 那个 `dialer-proxy: "WARP中转"` 对桌面版不是新东西，是已有形态。

### 9.3 真正值得抄的四条（都是纯渲染/策略级，不动数据面）

1. **把「单条最佳端点」展开成候选节点池 + 分组自动优选**（收益最大）。桌面版现在只把扫描出的一个最佳端点渲染成一条 outbound（`client.go:421-476`），`auto` 的 `url-test` 组只有 1 个成员（`client.go:624-625`），等于没优选。端点/端口/SNI 数据全都有，照 `pages/app.js:532-553` 把「同一账号 × 多 endpoint/port/SNI」渲染成多条 `masque` proxies，再按入口 IP 分小组 `url-test`（`README.md:332`）→ 只改 `client.go` / `subconfig.go` 的 `proxies` / `proxy-groups` 渲染。
2. **测速口径从「延迟」换成「吞吐 + lazy」**。桌面版连接默认按 `betterEndpoint` 比 `Loss → Ping`（`client.go:1335-1355`），审计文档 `:172` 自己写的方向是「top-4 并行短下载按吞吐排序并写回缓存」；这与 usque v6.27 的 lazy / 300s / 3s / 50ms（`README.md:331`）以及 `docs/desktop-optimization.md:82-92` 的 P1-2、P1-3 完全一致。现成件已具备：`probeThroughput`（`client.go:1241-1275`）、`ProxyDelay/ProxyGroupDelay/SelectProxy`（`internal/core/core.go:324-410`）。
3. **参数选项化**：`bbr3`、`ip-stack auto/mips/gvisor`、SNI 候选池轮换。桌面版是硬编码 `bbr + gvisor`（`wgconf.go:668-679`），设置层零开关；可加 `options` 字段并同步扩展 `capability.go` 的内核能力探测，避免渲染出当前内核不认的配置。另可参照 `docs/desktop-optimization.md:64-68` 做 `stack: gvisor → system` 的 A/B——这一条是 usque 那边没有的。
4. **「出口检测 → REST 热切换节点」**：`warp-egress-selector.py` 用 `PUT /proxies/{group}` 逐个切节点测 `cdn-cgi/trace`。桌面版有 API（`core.go:389-410`）但只用于测速归因，真正换点是 health guard 重渲染 + 重启核心（`health.go:573-578`）。做成按 colo/loc 热选是纯策略增强；注意桌面版「出口地区」是 Psiphon/OpenVPN 的用户偏好（`flags.go:116-127`），与 WARP colo 自动优选是两件事，别混。

另外 `proxy-providers` 免费落地（`pages/app.js:588-625`）在桌面版全仓库 0 命中，可借鉴作为订阅来源层；但必须保留 `subscribe.go:122-126` 对 `dialer-proxy / interface-name / routing-mark` 的强制剔除，不能原样吞外部 YAML。

### 9.4 不适用 / 不要做

- **不要用它替换数据面**：桌面版是 mihomo tun（可选 Windows 内核 `stack: system`）+ 批处理/GSO + BBR，且 `warpscout` 有两阶段真实隧道验证、内核能力门、隔离探测器；usque-custom-pro 只是浏览器配置生成器。这与 `docs/desktop-optimization.md:26-36` 的既有结论一致。
- **不要照搬它的注册面板 / 本地 VLESS 桥**：桌面版已自己注册并做真实握手扫描，桥接在 Windows 上没有收益。
- **手机端无法直接吃这套配置**：Android 只有一个 `VpnService` tun fd + 自研 gVisor netstack，没有 mihomo 去消费 `type: masque` / `url-test` / `proxy-providers`；桌上能「改 YAML 就生效」的事，在手机上要动 Go 数据面。所以手机端仍只移植三条经验：多流稳态测速、握手≠可用、失败分层。

### 9.5 证据索引（桌面版，只读）

- `warp-client/client.go:421-476, :615-625, :868-899, :1241-1275, :1335-1355, :654-746`
- `warp-client/wgconf.go:649-679`、`warp-client/subconfig.go:17-85`、`warp-client/connect.go:704-708, :1576-1580`
- `warp-client/internal/core/core.go:124-139, :184, :324-410`
- `warp-client/pools.go:10-51`、`masque.go:84-100`、`warp.go:93-101`、`findsni.go:46-97`、`flags.go:116-127, :206-213`
- `warp-client/psiphon.go:40-46, :135-140`、`probe_openvpn.go:21-25`、`subscribe.go:122-126`、`subdelay.go:17-35`、`subgeo.go:16-27`
- `XEHN-dev/core/config.yaml:1-8, :23-40, :42-70`、`XEHN_ISSUE_AUDIT_AND_PLAN_2026-11-08.md:172-180`
