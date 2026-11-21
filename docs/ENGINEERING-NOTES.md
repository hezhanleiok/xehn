# 工程笔记：内存、DNS、订阅解析与代理生命周期

> 面向手机端（Android / iOS）复用这套协议与配置逻辑时的参考。
> 所有数字来自 Windows 客户端的实测，方法在每节末尾，可在手机上照做。
>
> 对应版本：1.1.35（2026-11-21）

---

## 0. 为什么要有这份文档

1.1.22 ~ 1.1.35 这十几个版本里，反复出现的故障几乎都不是"协议写错了"，
而是**四类系统性问题**：

1. **资源没复用**（每 2 秒泄漏一个连接池）
2. **DNS 解析器选错**（国内 DNS 在并发查询里永远赢）
3. **订阅字段没折叠**（mihomo 只认 `ws-opts`，顶层 `path`/`host` 被静默忽略）
4. **超时预算互相打架**（改了预检没改总预算）

手机端内存和 fd 更紧张，这四类问题会更早暴露。下面逐条给出**症状 → 根因 → 修法 → 测量**。

---

## 1. 内存与句柄（最重要）

### 1.1 症状

- 连接状态下内存缓慢上涨：4 分钟 +10 MB，不收敛
- 句柄数持续增长：4 分钟 +204
- 长时间运行（几小时）后界面卡顿、切换页面掉帧

**注意**：GDI/USER 对象数一直稳定（85 / 47），所以不是绘制泄漏——是网络层。

### 1.2 根因

`internal/core/httputil.go` 的 `httpClient(timeout)` **每次调用都新建一个 `http.Transport`**：

```go
// 错误写法
func httpClient(timeout time.Duration) *http.Client {
    return &http.Client{
        Timeout:   timeout,
        Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: timeout}).DialContext},
    }
}
```

而连接状态下有两处**每 2 秒**调一次：

| 调用点 | 用途 |
|---|---|
| `shareLoop` → `core.Connections(apiPort)` | 首页实时流量统计 |
| `statusLoop` → `fetchSessionProbe()` → `fetchExitProbe()` | 出口 IP 刷新 |

每个 `http.Transport` 自带**连接池 + 后台读协程**，`Transport` 没人引用后
它的 idle 连接和 goroutine **不会立刻回收**。每 2 秒一个 → 每分钟 30 个 →
4 分钟 120~200 个，正好对上实测的 +204 句柄。

同类问题还有两处：

- `localProbeClients()`（本地 IP 探测，12 秒一次）
- `fetchExitProbe()`（出口探测，2 秒一次）

### 1.3 修法

**A. 共享 Transport（最有效）**

```go
var (
    apiTransportOnce sync.Once
    apiTransport     *http.Transport
)

func httpClient(timeout time.Duration) *http.Client {
    apiTransportOnce.Do(func() {
        apiTransport = &http.Transport{
            DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
            MaxIdleConns:        16,
            MaxIdleConnsPerHost: 8,
            IdleConnTimeout:     90 * time.Second,
        }
    })
    // 每次仍返回独立 client（各自 timeout），但 Transport 共享 → 连接池复用
    return &http.Client{Timeout: timeout, Transport: apiTransport}
}
```

要点：
- `http.Client` 结构体很轻（几十字节），复制它不复制 Transport
- **每次调用只换 Timeout，不换 Transport**
- `IdleConnTimeout` 设 90s，让 keep-alive 连接活过两轮轮询

**B. 按 key 缓存 client（多端口场景）**

```go
var (
    exitProbeMu      sync.Mutex
    exitProbeClients = map[int]*http.Client{}
)

func exitProbeClient(mixedPort int) *http.Client {
    exitProbeMu.Lock()
    defer exitProbeMu.Unlock()
    if c, ok := exitProbeClients[mixedPort]; ok {
        return c
    }
    c := &http.Client{ /* ... */ }
    exitProbeClients[mixedPort] = c
    return c
}
```

**C. 探测 client 按代理 URL 缓存**（`probeClientFor(proxyURL)` 同理）

### 1.4 测量方法（可在手机上照做）

**Windows**：

```powershell
Add-Type -Namespace Win32 -Name Gui4 -MemberDefinition '
[DllImport("user32.dll")] public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);'

$p = Get-Process -Name xehn | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
$p.Refresh()
[Win32.Gui4]::GetGuiResources($p.Handle, 0)   # GDI
[Win32.Gui4]::GetGuiResources($p.Handle, 1)   # USER
$p.HandleCount                                 # 内核句柄
$p.WorkingSet64 / 1MB                          # 工作集 MB
```

**Android**：

```bash
# fd 数（对应 Windows 句柄）
ls /proc/<pid>/fd | wc -l
# 内存（PSS 比 RSS 更准）
adb shell dumpsys meminfo <package> | grep -E "TOTAL PSS|Java Heap|Native Heap"
# goroutine 数（如果开了 pprof）
curl http://127.0.0.1:<pprof-port>/debug/pprof/goroutine?debug=1 | head -1
```

**采样节奏**：连接后每 20 秒一次，至少跑 4 分钟。
**判据**：看**是否收敛**——涨 10 MB 后稳住不算泄漏；线性增长才是。

### 1.5 实测数字

| 指标 | 修复前（4 分钟） | 修复后（4 分钟） |
|---|---|---|
| Handles | 775 → 979（**+204**） | 696 → 680（**-16**） |
| WorkingSet | 56.3 → 66.6 MB（**+10.3**） | 52.1 → 51.4 MB（**-0.7**） |
| GDI | 85（稳定） | 85（稳定） |
| USER | 48（稳定） | 48（稳定） |

**副作用是好的**：连接复用后吞吐从 0.66–1.1 MB/s 提升到 1.43–1.74 MB/s。

### 1.6 手机端特别注意

| 项 | Windows | Android/iOS |
|---|---|---|
| 资源单位 | 内核句柄 | **fd**（`/proc/self/fd`） |
| 泄漏后果 | 卡顿 | **OOM 被杀 / fd 耗尽** |
| 常驻方式 | 托盘 | **前台服务**（跑几小时） |
| 轮询耗电 | 不敏感 | **很敏感** |

建议：
1. **轮询间隔从 2s 放宽到 5–10s**（手机上 2s 一次的网络请求显著耗电）
2. **任何轮询路径里禁止 `new http.Client{}` / `&http.Transport{}`**
3. 给 `Transport` 设 `MaxIdleConnsPerHost`（默认 2 太小，会频繁建连）
4. 前后台切换时**暂停轮询**，回前台再恢复

---

## 2. DNS

### 2.1 最反直觉的一条：nameserver 顺序不重要

mihomo 的 `dns.nameserver` 是**并发查询所有条目、取最快返回的**。

所以：

```yaml
# 这样写没用 —— 国内 DNS 靠 RTT 永远赢
nameserver:
  - 1.1.1.1
  - 223.5.5.5
```

**国内 DNS 必须从列表里删掉**，而不是往后排。

### 2.2 正确的配置

```yaml
dns:
  enable: true
  respect-rules: true            # DNS 请求的出站遵守 rules
  nameserver:                    # 用户查询
    - 8.8.8.8
    - 1.1.1.1
  proxy-server-nameserver:       # 解析节点域名，不走 rules
    - 8.8.8.8
    - 1.1.1.1

rules:
  - IP-CIDR,8.8.8.8/32,<出口组>   # 把解析器地址钉到隧道
  - IP-CIDR,1.1.1.1/32,<出口组>
  - ...
  - MATCH,<出口组>
```

三条缺一不可：

| 项 | 作用 | 缺失后果 |
|---|---|---|
| `respect-rules: true` | DNS 查询走规则 | 查询从本机直发 |
| `IP-CIDR,...,<出口>` | 解析器地址本身走隧道 | 匹配不到 → 回落到 MATCH（可能是 DIRECT） |
| `proxy-server-nameserver` | 解析节点域名 | 用系统 DNS，CDN 域名解析错 |

### 2.3 为什么 `proxy-server-nameserver` 必须不走 rules

它用来把**节点域名**解析成 IP。如果它也走隧道，就变成：
「要连节点 → 先解析节点域名 → 解析要走节点 → 死循环」。

所以 mihomo 让它**永远直连**。这是设计，不是 bug。

**推论**：日志里 `mihomo --> 1.1.1.1:53 doesn't match any rule using DIRECT`
**大概率是这一路**，不是用户查询泄漏。

### 2.4 CDN 前端域名的陷阱

国内 DNS 对套 CDN 的域名（Fastly / Cloudflare 前置）经常返回一个
**能完成 TCP 握手、但 TLS 不认这个 SNI** 的边缘 IP。

实测同一域名：

```
119.29.29.29  →  146.75.113.242        TCP 通，TLS 失败 → 502
223.5.5.5     →  146.75.113.242        同上
1.1.1.1       →  151.101.x.x           正常，1349ms
8.8.8.8       →  151.101.x.x           正常
```

表现就是：节点列表全超时，或者连上后每个请求都 `502 Bad Gateway`。

### 2.5 假泄露 vs 真泄露

| 检测结果特征 | 判定 | 能否消除 |
|---|---|---|
| 解析器全是 Cloudflare / Google，且出口也在同一网内 | **假泄露**（anycast 地理标注差异） | 换非 Cloudflare 的 DoH 可缓解，但无法保证 |
| 解析器出现 `China Telecom` / `China Unicom` / 地方运营商 IP | **真泄露** | 按 2.2 配置即可修 |

**快速自检**：

```bash
curl --proxy http://127.0.0.1:7890 https://www.cloudflare.com/cdn-cgi/trace
```

输出里 `ip=` 是你的出口、`warp=on/off` 是 WARP 状态。
如果整段结果里**没有任何本地 ISP 的痕迹**，就是假泄露。

---

## 3. 订阅解析

### 3.1 WebSocket 参数必须折叠

分享链接：

```
vless://uuid@cdn.example.com:443?type=ws&path=/ws&host=cdn.example.com&security=tls&fp=chrome
```

解析后**必须**生成：

```yaml
network: ws
ws-opts:
  path: /ws
  headers:
    Host: cdn.example.com
```

而不是：

```yaml
network: ws
path: /ws          # ← mihomo 忽略
host: cdn.example.com   # ← mihomo 忽略
```

**mihomo 的 VLESS 结构里只有 `ws-opts`**，顶层 `path`/`host` 会被静默丢弃。
后果：TCP 通、TLS 通、**WebSocket 升级发不出去** → `502 Bad Gateway` 或超时。

同样的折叠规则适用于：

| 传输 | 目标结构 |
|---|---|
| `ws` | `ws-opts.path` + `ws-opts.headers.Host` |
| `grpc` | `grpc-opts.grpc-service-name` |
| `h2` / `http` | `h2-opts.path` + `h2-opts.host[]` |

**这是"同一个订阅在 v2rayN/FlClash 正常、在我们这全超时"的最常见原因**——
那些客户端在解析阶段就做了这层折叠。

### 3.2 字段白名单

只保留 mihomo 认识的字段。未知字段会让**整个配置解析失败**（核心起不来），
而不是被忽略。

### 3.3 解析后自检

```go
// 折叠后必须没有顶层 path/host
if _, ok := fields["path"]; ok { /* bug */ }
if _, ok := fields["host"]; ok { /* bug */ }
opts, ok := fields["ws-opts"].(map[string]any)
if !ok || opts["path"] == nil { /* bug */ }
```

---

## 4. 系统代理的生命周期

> 这一节是 Windows 特有的（WinINET），但**思路对 Android 的 VpnService 同样适用**。

### 4.1 四道防线

| 时机 | 动作 |
|---|---|
| 连接前 | 读当前代理值存**快照** |
| 断开时 | 还原快照；**还原后仍指向我们**则强制清空 |
| 进程退出 | **无条件**再清一次（幂等，只清自己的端口） |
| 启动时 | 自愈：代理指向我们但端口没监听 → 清掉 |

### 4.2 为什么"还原快照"不够

最常见的死循环：

```
上次退出没清干净 → 代理仍指向 127.0.0.1:7890（死端口）
这次连接 → 快照记录的就是这个死端口
断开时"还原" → 又还原成死端口
```

所以还原后必须**再检查一次**：

```go
if core.SystemProxyEnabledAt(port) {
    // 快照本身就是死代理，强制清空而不是"还原"
    _ = core.UnsetSystemProxy(&core.ProxySnapshot{})
}
```

### 4.3 被其它客户端抢占

v2rayN / FlClash 会按自己的节奏重写 WinINET。检测到后：

1. **尝试夺回**（最多 2 次，避免无限打架）
2. 夺不回 → **结束会话**（`giveUp`：还原代理 + 停核心 + `connected=false`）
3. 界面显示「直连中」，**不能继续显示「已连接」**

**关键**：区分两种状态

| 状态 | 含义 | 动作 |
|---|---|---|
| `ProxyEnable=1` 但服务器是别人 | 被抢占 | 结束会话 |
| `ProxyEnable=0` | 用户自己关的 | 只告警，保留会话 |

### 4.4 Android 的对应问题

Android 没有"系统代理"，但有类似残留：

- `VpnService.establish()` 后进程被杀 → **VPN 接口残留**，系统设置里一直显示已连接
- 必须用 `onRevoke()` / 前台服务保活 / 启动时检查 `VpnService.prepare()`

---

## 5. 测速参数

| 参数 | 值 | 依据 |
|---|---|---|
| 端口预检超时 | **6s** | 跨国 TCP 建连实测 3–5s；2s 会误杀大量可用节点 |
| 单节点总预算 | **42s** | 6（预检）+ 30（握手窗口）+ 4（下载）+ 2（余量） |
| 握手窗口 | 30s | OpenVPN 家宽中继实测 5–20s |
| 下载采样窗口 | 4s | 够算速率，又不至于让慢节点超时 |
| 并发 | **10** | 握手期间不占带宽，并发只影响总时长 |
| 判定"可用" | 握手成功 + 收到 ≥8 KiB | 8 KiB 只过滤噪声，不是速度门槛 |

**预算必须联动**：预检从 2s 改到 6s，总预算就要从 35s 改到 42s，
否则预检放过的节点会在握手第 29 秒被掐断——**换个地方误杀**。

---

## 6. 踩坑清单（按踩到的顺序）

1. **每次新建 `http.Transport`** → 每 2 秒泄漏一个连接池
2. **国内 DNS 留在 `nameserver` 里** → 并发查询靠 RTT 必胜，删掉而不是后置
3. **顶层 `path`/`host`** → mihomo 只读 `ws-opts`，静默丢弃
4. **端口预检 2s** → 跨国节点在握手前就被判死
5. **预检加长了但总预算没加** → 误杀从"端口不可达"变成"握手超时"
6. **防火墙 `program=` 没加引号** → 路径含空格（`C:\Program Files\...`）时规则静默失败
7. **`proxy-server-nameserver:` 以 `nameserver:` 结尾** → 子串检查误判（写测试时踩到）
8. **`mode: direct` 下用 `/proxies/{name}/delay`** → 仍然能测（API 显式指定代理，不受 mode 影响），但 `MATCH,DIRECT` 会让真实流量直连

---

## 7. 验证清单（每次改完跑一遍）

```bash
go vet ./...            # 期望：只有 2 处标准 Win32 unsafe 警告
go test ./...           # 期望：全绿
gofmt -l .              # 期望：无输出
```

然后真机跑：

1. 连接 → 每 20 秒采样 4 分钟 → **句柄和内存必须收敛**
2. 断开 → 检查系统代理**是否已还原**
3. 强杀进程 → 重启 → 检查代理**是否被自愈**
4. 订阅测速 → 看日志里 `probe group ok: N/M` 和每个失败节点的原因
5. DNS 检测站 → 对照 2.5 判断真假泄露
