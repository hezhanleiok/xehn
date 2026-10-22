# 踩坑记录 · Pitfalls

> 用途：把已经踩过的坑固定下来，避免同一个问题反复出现。
> 用法：出问题先按第 1–4 节的「症状」查找；每轮改代码前先看第 5 节的基线与版本纪律。
> 维护规则：**修一个坑就补一条**，写清「症状 → 根因 → 正确做法」，并标注是哪次真机实测踩到的。

---

## 1. 出口验证类：把能用的判成不能用

这一类最坑，因为它和「节点真的坏了」在日志里长得一模一样。

### 1.1 单端点 + 只试一次（OpenVPN 节点）

- **症状**：`OpenVPN 已连接但出口验证失败（节点 X 没有真正转发流量）`，但同一节点改天/换个前置能连；界面「出口 IP」空白。
- **根因**（2026-10-22 真机）：
  1. 只请求 `https://1.1.1.1/cdn-cgi/trace` 一次；
  2. `VpnService.establish()` 返回后路由/接口还会飘 1–2 秒，那一瞬的请求必然失败；
  3. 部分线路 `1.1.1.1` 直连被拦、经隧道才通。
- **正确做法**（`engine/warp/openvpn.go` → `probeExitViaTun`）：
  - 两个 **IP 字面量**端点轮流打（`1.1.1.1` / `1.0.0.1`）；
  - 在 `VerifyTimeout` 预算内每 700ms 重试一轮，单次请求上限 4s；
  - 任一轮拿到 `ip=` 即通过，日志写「出口验证第 N 轮通过」，失败写「出口验证未通过（N 轮：原因）」。

### 1.2 WARP 端点验证依赖 DNS

- **症状**：`<endpoint> 数据面不通`，但隧道其实是通的（换个客户端/换时段就通）。
- **根因**：验证用的两档（`speed.cloudflare.com/meta`、`www.cloudflare.com/cdn-cgi/trace`）**都要解析域名**；DNS 一挂就返回 `false`，被当成「隧道死了」。
- **正确做法**：
  - `engine/warp/probe.go` 增加 `traceIPURLs`（`https://1.1.1.1/cdn-cgi/trace`、`1.0.0.1`）作为第三档，不依赖 DNS；
  - netstack 侧（`ipStack.fetchReason` / `fetchLiteral`）同样要有一档 IP 字面量；
  - 失败必须带原因：`（隧道内请求超时）` vs `（DNS 或被出口拒绝）`，否则永远分不清。

---

## 2. 数据面类

### 2.1 `VpnService.protect()` 在 establish 之前可能无效

- **症状**：直连节点「握手成功 → 建 tun → 出口验证零流量」，看起来节点不转发数据。
- **根因**：`protect()` 在 VPN 还没建立时可能拿不到 fwmark 直接返回 false。节点连接是握手前建的 socket，等 tun 起来后它就被自己的隧道抓回去。
- **正确做法**（`engine/warp/openvpn.go` → `reProtect`）：建 tun 成功之后，对同一个 fd **再 protect 一次**；日志会写 `节点连接已补打 protect（系统 VPN 建好后）`。打不上要显式警告。

### 2.2 gVisor TCP 缓冲上限 8MB 会让数据面卡死 ⚠

- **症状**：握手成功、tun 建好（`MTU=1160`）、出口验证失败；关掉后**一次就连上**。
- **根因**（2026-10-22 深夜，真机二分确认）：给外层 netstack 设 `TCPReceive/SendBufferSizeRangeOption{Max: 8MB}` 之后数据面不通。为什么坏还没深挖（疑似窗口/拥塞状态异常）。
- **正确做法**：`engine/warp/tunnel.go` 的 `netstackTCPBufferMax = 0`（= 用上游默认）。要重开必须从 **2MB** 起步、每次真机验证；别一步上 8MB。
- **注**：`engine/warp/netstackx/` 是为此 fork 的 netstack（唯一改动是新增 `CreateNetTUNBuffered`），留着方便以后调参，默认传 0 即与上游等价。

### 2.3 内层 MTU 要和外层对齐（但这项**不是**故障源）

- 经 WARP 时外层 netstack MTU 1280 → MSS 1240；一个内层 IP 包还要套 ~55 字节 OpenVPN 头（长度 2 + opcode 1 + HMAC 20 + IV 16 + CBC 填充 ≤16）。
- 内层 1400 会被拆成 1240+160 两段（包量、加密次数接近翻倍）；现在用 **1160** 正好 1:1。
- 记录这一点是为了避免误会：`MTU=1160` 的构建跑到过 17.4 Mbps，**它不是“数据面不通”的原因**。

### 2.4 受限网络「放握手、掐数据」

- **症状 A**：`dial tcp <ip>:<port>: i/o timeout`（拨号阶段就死）。
- **症状 B**：握手成功、无数据（DPI 只放行握手）。
- **做法**：上游 `auto` = 先直连（单节点上限 12s）→ 失败转 WARP；直连拨号失败记 10 分钟（`markDirectBlocked`），后续候选直接走 WARP，避免 5 个候选各白等 12 秒。

---

## 3. 配置与状态类

### 3.1 `.ovpn` 原文必须落盘（sidecar）

- **症状**：进程重启后每个节点都「配置不在缓存里」，连接直接失败。
- **根因**：`VPNGateNode.Config` 是 `json:"-"`（列表要保持小、能整份搬给 UI），结果只存了元数据。
- **正确做法**：配置原文单独存 `files/engine/vpn-gate-configs.json`（原子写），`LoadVPNGateCache` 读列表时挂回去。

### 3.2 绝不能静默降级成普通隧道

- **症状**：界面显示「已连接」，出口却是 `104.28.x`（WARP），用户以为在走节点。
- **根因**：`enabled` 用 `len(ids)>0` 推导，节点配置全丢时被当成「关闭 OpenVPN」。
- **正确做法**：`openvpnWanted`（用户意图）与 `openvpnIDs`（可用配置）分开记；没有可用配置时 `Connect` 直接报错。

### 3.3 节点失效必须能自动切

- 候选阶梯：手动节点 → 同国同类（延迟升序）→ 同国其他类 → 他国同类 → 他国其他类，最多 24 个；
- 引擎侧失败记忆 10 分钟（`freshOpenVPNIDs`），下一轮自然落到更后面的节点；
- 服务侧最多 3 轮（`OPENVPN_CONNECT_ROUNDS`）。

---

## 4. 真机调试类（省时间用）

### 4.1 MIUI 装包

- `adb install` 会报 `INSTALL_FAILED_USER_RESTRICTED`；改用 `adb push apk /data/local/tmp/x.apk` + `pm install -r /data/local/tmp/x.apk`。
- **装机时屏幕必须点亮且解锁**，否则返回 `Failure [INSTALL_FAILED_USER_RESTRICTED: Install canceled by user]`；严重时应用会被**连数据一起清掉**（设置、节点缓存全丢，需重新刷新节点）。

### 4.2 点亮屏幕

- `KEYCODE_WAKEUP` 有时无效（设备停在 Dozing）；用 `input keyevent 26`（电源）切一次，再 `wm dismiss-keyguard`。
- `input tap` **不会**唤醒睡眠屏，别以为点没生效是坐标问题。
- 测试前 `settings put system screen_off_timeout 600000`，结束时恢复 `30000`。

### 4.3 抓屏与坐标

- 设备可能报“Multiple displays”，`screencap` 默认抓第一个 display（可能是 AOD，截出来全黑/锁屏）。
- `uiautomator dump` 的 `bounds` 是真实坐标（1440×3200），截图显示尺寸是缩放的，按截图量坐标要乘缩放比。

### 4.4 改设置的最快路径

```powershell
adb shell am force-stop com.xiaohe.vpn
adb shell run-as com.xiaohe.vpn cat shared_prefs/xiaohe-settings.xml > prefs.xml
# 本地改 XML
adb push prefs.xml /data/local/tmp/p.xml
adb shell run-as com.xiaohe.vpn cp /data/local/tmp/p.xml shared_prefs/xiaohe-settings.xml
```

- 首次安装后 `shared_prefs/xiaohe-settings.xml` 可能**不存在**（要 UI 写过一次才有）。
- 注意别用 `sed 's/auto/warp/'` 这种模糊替换（`autoConnect` 会被误伤）。

### 4.5 判断设备上装的是哪一版

- REA 的后端在这台机器都没配（Ghidra 未安装 / Hopper 只支持 macOS / IDA、Kuna 未配置），`open_binary` 能开但任何字符串查询都返回 `provider_unavailable`。
- 可行办法：从 APK 抽 `lib/arm64-v8a/libgojni.so` 和 `classes*.dex`，按字节查特征串，见第 6 节。

---

## 5. 基线与版本纪律（每轮必做）

1. **改代码之前先建基线**：

   ```powershell
   .\tools\baseline.ps1 -Name r3 -Message "改什么/为什么"
   ```

   它会：`git add -A` → 提交 → 打标签 `baseline-<日期>-<Name>` → 把源码快照 zip 到 `E:\备份`。**不会 push**（本仓库没有 remote，也不允许 push）。

2. **每次必须递增版本号**：改 `app/build.gradle.kts` 的 `versionCode`（+1）和 `versionName`。
   启动器按「包名 + versionCode」缓存图标，不递增会继续显示旧图标；也方便对照「设备上装的是哪版」。

3. **回滚**：

   ```powershell
   git diff baseline-<tag> -- engine app       # 先看差了什么
   git checkout baseline-<tag> -- engine app   # 只回滚这两棵子树
   git checkout baseline-<tag>                 # 或整树回到某个基线
   ```

4. **每一轮真机验证都要留结论**：什么构建、什么网络、跑了哪条路径、数字是多少。没有数字的“感觉快了/慢了”不算结论。

---

## 6. 版本特征表（用来定位设备上装的是哪版）

| 特征串（在 `.so` 或 `.dex` 里） | 说明 |
|---|---|
| `出口验证第`、`1.1.1.1/cdn-cgi/trace`、`1.0.0.1/cdn-cgi/trace` | 出口验证双端点 + 重试（2026-10-22 16:35 之后） |
| `家宽` 且 **没有** `🏠 家宽` | 节点列表改成 `JP家宽01` 命名、行内删掉 IP 的那版 |
| `个最近失败过的节点`、`自动换下一批` | 节点失败记忆 + 多轮重试 |
| `直连节点`、`dialHostNode`、`reProtect`、`SetOpenVPNUpstream` | 直连优先 / 上游三选（19:50 之后） |
| `CreateNetTUNBuffered`、`netstackx` | gVisor 缓冲实验版 —— **数据面会坏，别拿这版当基线** |
| `数据面不通（` | 验证失败会带原因的输出 |

> 查法：解压 APK 取 `libgojni.so` / `classes*.dex`，转 Latin1 后按 UTF-8 字节做 `IndexOf`（PowerShell 一行即可），比逐个装上试快得多。
