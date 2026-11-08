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

### 2.4 直连节点（已移除，别再捡回来）

- **症状**：`dial tcp <ip>:<port>: i/o timeout`；偶尔握手成功但过不了数据。
- **历史**：0.2.2 曾提供「直连 / 经 WARP / 自动」三档，指望直连能拿到桌面版那种几十 Mbps。
- **实测结论**（2026-10-22 晚，真机）：这条网络里**直连节点的 TCP 全部 i/o timeout**，当次连接的失败**全部**由直连分支引入；偶尔握手成功的也过不了数据（DPI 只放握手、掐数据）。而经 WARP 的同节点能达到 17.4 Mbps。
- **处理**：0.2.3 起删除直连分支（`dialHostNode` / `reProtect` / `直接上游` / 设置里的「连节点方式」全部移除），上游只剩「先进 WARP 再从隧道里拨节点」。
- **教训**：**先证伪再实现**。这条路只有在网络允许直连 VPN Gate 时才有意义，而实测一次都没成功过，却贡献了整晚的失败日志。

### 2.5 MASQUE 下行只有十几兆：包封不下，不是带宽不够（2026-11-03）

- **症状**：同一手机、同一网络，官方客户端下行 100+ Mb/s，本 App 的 MASQUE 只有
  十几兆；不是断，就是慢。
- **根因**：MASQUE 走 CONNECT-IP，**一个 IP 包 = 一个 QUIC DATAGRAM**。系统 tun
  MTU 是 1280，封装后 = 1280 + contextID 4 + DATAGRAM 帧头 + QUIC 头 + UDP 8 +
  IPv6 40 ≈ **1340 字节**；而日志里选中的边缘是 `[2606:4700:103::1]:443`，
  **v6 路径 MTU 就是 1280**。超限的 datagram 被 quic-go 以 `DatagramTooLargeError`
  拒掉，而我们的泵把这个错误（以及本该回写给内核的 ICMP「包太大」）直接丢弃 ——
  内层 TCP 只看到丢包，反复重传、拥塞窗口塌陷，实测就稳定在十几兆。
- **修法（0.2.9）**：
  1. MASQUE 的 tun MTU 压到 **1200**（`MASQUE_TUN_MTU` / `masqueMaxTunMTU`，两边
     必须同值），留给外层 ~80 字节封装余量；
  2. `WritePacket` 返回的 ICMP 必须**写回 tun**，让内核自己把 MSS 调小；
  3. 第一次触发时记一行日志（`tooLarge` 计数），下次真机上还慢就能直接看出是不是
     这个原因，不用再猜；
  4. 顺带：UDP 读写缓冲提到 4–8 MB（默认 208 KB，高带宽下会丢包）、接收侧用零拷贝
     `ReadPacketZeroCopy`、发送侧用 `WritePacketBuffer` 原地封装、接收侧两条
     goroutine 并发读。
- **教训**：这类"能用但慢"的问题，先看**封装后尺寸 vs 路径 MTU**，再看带宽。
  把"静默丢弃"改成"计数 + 回写 ICMP"，比继续调参数有用。

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

### 3.4 `e.connect()` 是异步的，`try/catch` 包不住连接失败（2026-11-01）

- **症状**：OpenVPN 出口候选全失败时，日志里只有引擎自己的 5 次尝试，
  `OPENVPN_CONNECT_ROUNDS` 那 3 轮「自动换下一批」一次都没出现；连接失败也从不进
  Kotlin 的 catch。
- **根因**：`Engine.Connect` 只把活儿丢进 goroutine 就 `return nil`。所以
  `try { e.connect(…) } catch { }` 里永远不会抛，`while` 第一轮就 `break` 了。
- **正确做法**（`WarpVpnService.connectLoop`）：发起 → 轮询 `statusJSON` 等
  `connected / error / idle` → 再决定「保留、换一批、还是收手」。顺带两个约束：
  - 换点前必须 `e.disconnect()` 并**等回 idle**，状态机不允许从 `stopping` 直接连；
  - 结果要认「哪个节点通的」：引擎一次试 5 个，成功的不一定是首位那个；
    引擎没把节点 id 报上来（aar 接口），所以用出口 IP 反查节点。

### 3.5 侧滑返回直接退出 App（2026-11-01）

- **症状**：在设置/关于/隐私等子页面里，从屏幕边缘划一下返回，App 直接退到桌面，
  而不是回到上一页。
- **根因**：页面只是同一个 Compose 树里的分支（`current == null` 才是首页），
  系统并不知道「还有上一页」；而全程没有任何 `BackHandler`，没人消费返回事件，
  系统就按「Activity 到底了」处理 → finish()。
- **正确做法**（`MainActivity`）：按「进来得越晚越先退」装一个 `BackHandler`：
  分应用选择 → 抽屉 → 子页面 → 首页；只有首页时 `enabled=false`，才让它退出。
  弹窗（节点/地区选择）在独立 Dialog 窗口里，自己消费返回，不需要在这里判。

### 3.6 闪退之后日志一起消失（2026-11-01）

- **症状**：点连接后 App 直接闪退；重新打开，日志面板是空的 —— 现场没了，
  只剩用户手快复制出来的一段。
- **根因**：日志只活在 `EngineBridge._state`（内存 StateFlow）里。进程一死，
  缓冲跟着消失；而且没有任何未捕获异常兜底，Java 层崩溃连堆栈都不留。
- **正确做法**（`VpnLog` / `CrashGuard`）：
  - 每一行**立刻 append + flush** 到 `filesDir/logs/vpn.log`，进程启动时读回界面；
  - **不做任何自动清理**（退出、重启、重连都不删），只有设置页「清空日志」删；
  - `Thread.setDefaultUncaughtExceptionHandler` 把堆栈写进同一份日志 + `crash.log`；
  - 每次启动写 `[app] 启动 x.y.z(code)`，若上一行没有 `[app] 正常退出` 就明确写
    「上次进程没有正常结束（崩溃或被系统杀掉）」——闪退自己不会说话，得让它留痕。
  - 边界：Go 侧原生崩溃（SIGSEGV/abort）不会被这个处理器抓到，只能靠最后一行的位置定位。
- **同批加的定位点**：OpenVPN 建 tun 前写「第 N 次 establish（地址/MTU/分流）」。
  真机上第 5 次 establish 之后就没了进程，因此 `N` 本身是关键证据。

### 3.7 一次连接里连建 3~5 次系统 VPN，进程就没了（2026-11-01）

- **症状**：`0.2.4` 在本次连接第 5 次 `establish()` 之后、`0.2.5` 在第 4 次和第 3 次
  之后，进程直接消失；日志最后一行都是「OpenVPN 系统 VPN 已启用」。同一批日志里
  韩国节点连上后一切正常（实测 83 KB/s），说明数据面本身没坏。
- **当时的触发条件**：引擎一次 connect 会按候选列表连试 5 个节点，每个节点握手成功
  就 `Builder.establish()` 一次系统 VPN；失败后关闭 tun fd，再试下一个。
- **处理**：
  1. 一次 connect 只给引擎 **1 个节点**，Kotlin 侧循环换点，单次点击上限 3 个
     （`OPENVPN_MAX_TRIES`）——先把「反复 establish」这个变量摘掉；
  2. 启动时读 `ApplicationExitInfo`（`getHistoricalProcessExitReasons(包名, 0, 5)`），
     把上次退出原因写进日志：LMK / Java 崩溃 / **原生崩溃 + tombstone 摘要** / ANR。
     方法名很容易记错（没有 `getHistoricalProcessExitInfos`，只有 `...ExitReasons`）。
- **仍未定论**：到底是反复 establish、还是内存被 LMK、还是引擎里原生崩溃，要看
  0.2.6 那行「上次退出原因」。如果是原生崩溃，就必须改引擎（§6.1 的 aar 重建）。

### 3.8 §3.7 结案：tun fd 被两边各关一次 → fdsan SIGABRT（2026-11-03）

- **证据**（0.2.8 真机日志，`ApplicationExitInfo` 抓到的 tombstone 摘要）：

  ```
  signal SIGABRT (SI_QUEUE)
  fdsan: failed to exchange ownership of file descriptor: fd 193 is owned by
  unique_fd 0x7ad8acf33c, was expected to be unowned
  ```

  两次崩溃报的都是**上一次 establish 的 fd 号**（193、211），而崩溃前最后一行是
  「OpenVPN 系统 VPN 已启用（fd=220）」—— 说明新的 tun 刚建好，旧的 fd 号被内核
  复用，然后某个 ParcelFileDescriptor 操作发现这个号"已经有主了"。
- **根因**：tun fd 的**所有权被记了两份**。Kotlin 侧 `pfd.detachFd()` 把裸 fd 的
  fdsan tag 清成 unowned 交给 Go，Go 用 `os.NewFile` 包起来、Close 时 `syscall.Close`；
  而 Java 的 `ParcelFileDescriptor`（带 fdsan tag）还活在这个进程里。换点几次之后
  就一定撞上「fd 号已复用 + tag 不一致」→ `__libc_fatal` → SIGABRT。
  **Java 层 try/catch 抓不到**，所以只能从所有权上根治。
- **修法（0.2.9）**：所有权只留一份 —— **`ParcelFileDescriptor` 持有并关闭**
  （`WarpVpnService.closeTun()`），引擎侧全部改成"只借用、绝不 close"
  （`engine/warp/pktfile_android.go`，用裸 `syscall.Read/Write`，Close 只置标志）。
  `ClaimTunFD` / `ReleaseTunFD` 退役成 no-op。
- **另一条同类闪退**（同一次日志里还有一条 Java 崩溃）：
  `go.Universe$proxyerror: session: 状态 connecting 不能转到 connecting` ——
  `scope.launch` 跑在 `Dispatchers.Main.immediate` 上，引擎状态机拒绝重复 connect
  时抛的 RuntimeException 直接冒到 main 线程。修法：`connectSafely()` 先等 idle
  再调、并接住异常；整个 `connectLoop` 外面再包一层 catch。

### 3.9 速度地板不能照搬电脑版（2026-11-03）

- **症状**：OpenVPN 出口「连接成功立刻就断开」，反复闪一下「已连接」。
- **原因**：`OPENVPN_MIN_BPS` 沿用电脑版的 150 KB/s，而真机实测的 KR 家宽节点是
  94 / 79 / 72 KB/s —— **每一个都低于地板**，于是每连上一个就立刻断开换下一个，
  每次换点又 establish 一次系统 VPN（正好踩在 §3.8 的崩溃路径上）。
- **修法**：地板与排序分档线统一到 `NodeSpeedStore.MIN_BPS` = **100 KB/s**
  （0.2.9 先降到 40 只是止血；40 太低，58 KB/s 的节点会被当成"够快"留下来，
  用户看到的就是 0.x 兆）。

### 3.10 「自动选最快」不能只按握手延迟猜（2026-11-03）

- **症状**：用户选「日本自动」，连上的节点只有 0.x 兆；换一个还是 0.x 兆。
- **原因**（0.2.9 的排序顺序）：`家宽 → 握手 → **吞吐档** → 延迟`。因为地板
  150 KB/s 谁都过不了，**所有实测过的节点都进「慢」档**，于是「没测过」的节点
  永远排在它们前面 —— 自动模式一路去赌没测过的节点，而赌的结果只有 58 KB/s。
  日志证据：`JP家宽01（254ms，实测 未测）` 被选中，测速 58 KB/s。
- **修法（0.2.10）**：
  1. 排序改成 `家宽 → 能握手 → 吞吐档 → **实测速度降序** → 握手耗时 → 延迟`：
     测过的快的排最前，没测过的排它后面，最后才是测过但慢的；
  2. 分档线与换点地板同源（都是 100 KB/s），不会出现"排序说它慢、连接却留着"；
  3. 测速改成 **4 条并发流**：单流在 200ms RTT 的线路上被慢启动压到几十 KB/s，
     读数只有真实能力的一小部分，按那个读数挑节点等于瞎挑；
  4. 节点列表行里直接显示实测速度（`握手 254ms · ≈58 KB/s`），用户能看出到底
     测没测、测出来多少。

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
| `直连节点`、`dialHostNode`、`reProtect`、`SetOpenVPNUpstream` | 直连优先 / 上游三选（0.2.2 才有，**0.2.3 已移除**；见到这些串说明是旧包） |
| `CreateNetTUNBuffered`、`netstackx` | gVisor 缓冲实验版 —— **数据面会坏，别拿这版当基线** |
| `数据面不通（` | 验证失败会带原因的输出 |
| `出口实测速度`、`中继速度记忆`、`node-speeds` | **0.2.4**：OpenVPN 出口实测吞吐记忆 + 150 KB/s 速度地板换点（移植电脑版） |
| `关闭系统 VPN（失败不留残留）`、`收掉系统 VPN` | **0.2.11**：连接失败/看门狗放弃时关 tun + 停服务（失败不再留残余 VPN） |
| `改用 amneziawg 再试`、`本地 SOCKS %s` | **0.2.11**：Psiphon 上游临时端口 + 失败自动换协议 |
| `masque-x2`、`MASQUEX2`、`masque-outer.json` | **0.2.11**：MASQUE(HTTP/3) 套 MASQUE(HTTP/3) |
| `改用 HTTP/3 再试一轮`、`按流分发`、`上行并行` | **0.2.12**：h2 回退 h3 + MASQUE 上行三条会话并行 |
| `ipwho.is`、`未分类`、`握手 + 测速完成`、`局域网共享` | **0.2.13**：双数据源分类 + 探测测速 + 设置重构 |
| `协议热切换`、`direct 网段`、`补集路由` | **0.2.14**：热切换 + VPN 模式 direct 规则 + 文案精简 |

---

## 7. 0.2.11：三个真机现场

### 7.1 连接失败，系统 VPN 一直连着

现象：日志最后是 `[session] connecting -> error`，之后没有一行收尾，状态栏的 VPN 钥匙
一直亮着，只能杀进程。

根因：VPN 模式（wg / awg / masque / wwarp / psiphon）的系统 VPN 是在 `connect()` **之前**
由 `VpnService.Builder.establish()` 建好的；引擎失败时只把会话状态打成 `error`，而
`Session.Close()` 刻意**不关** tun fd（fd 归 Kotlin 的 `ParcelFileDescriptor`，见
`engine/warp/tunfd_owner.go` —— 引擎关它会触发 fdsan abort）。于是谁都不关：
`warpbackend.Connect` 里的 `releaseLeftoverTunFD` 自 2026-11-03 起是 no-op，
Kotlin 侧原来也只在用户点「断开」时才 `closeTun()`。

修法：`WarpVpnService.teardownAfterFailure()`（断开引擎 → `closeTun()` → 停前台服务），
在以下位置调用：非 OpenVPN 分支等不到 `connected`、OpenVPN 分支的三种终止失败、
看门狗放弃自动重连、连接协程抛异常。

> 判别：`grep 关闭系统 VPN` 命中就是修好的包。

### 7.2 赛风（Psiphon）反复连不上

两个独立原因，都在「上游」这一层：

1. **本地 SOCKS 端口钉死 1081**。上一个监听没收拾干净（或别的进程占着）时，bind 失败
   只写一行日志就继续，Psiphon 的 `UpstreamProxyURL` 于是指向一个没人监听（或指向别人）
   的端口，tunnel-core 一遍遍拨它、一遍遍失败，日志里只剩 meek/TLS 错误。
   改成 `127.0.0.1:0`（内核分配）+ `Options.SocksRequired`：bind 失败直接让这次尝试失败，
   下一次是全新端口。
2. **上游选了 wg，而 wg 在这张网里只有握手能过**。日志证据：
   `8.6.112.74:2408 握手成功，验证出口…` → `数据面不通（隧道内请求超时）`，连续 6 个端点
   一样，最后 `在 1m0s 内没有找到可用端点`。同一时刻 awg 是通的。
   改成 `underlayProtos()`：用户选的协议先试，建不起来自动退到 AmneziaWG 再试一轮；
   每次尝试的 budget 按剩余预算收敛，总预算仍是 150s。

### 7.3 WG/AWG 吞吐与 MASQUEX2

- WG/AWG：`deviceBind.Open` 里把隧道 UDP socket 的收发缓冲拉到 8 MB/4 MB
  （`tuneUDPBuffers`）。默认 rmem 只有 200 KB 量级，手机下行突发几百毫秒就能灌满，
  满了就是内核丢包 → wireguard-go 重传 → 拥塞退避，表现为「速度上不去还抖」。
- MASQUEX2（`masque-x2`）：外层一条普通 MASQUE(HTTP/3)（**第二套设备**，`masque-outer.json`），
  内层 QUIC 的 UDP socket 开在外层隧道的 netstack 里（`netstackPacketConn`）。
  外层 MTU 取 1300（0.2.12 修正）：QUIC 规定客户端 Initial 包至少 1200 字节，内层写进
  外层的 IP 包约 1228 字节，所以外层不能是 1200；但也不能太大 —— 0.2.11 用的 1400
  封装后约 1460，已经压到很多移动网络的 1400 路径 MTU 之上，真机 8 个外层候选全部
  「已建立 CONNECT-IP、数据面不通」。1300 两头都留了余量（Aether 用 1350）。

---

## 8. 0.2.12：h2 / OpenVPN / X2 / 上行四件事

### 8.1 MASQUE(HTTP/2) 连不上

日志里 h2 从来没有成功记录，只有一句 `拨号失败：...`。修了三处：

1. **CONNECT 的 `:authority` 试两种**：先端点自己（`https://<ip>:<port>`，Aether 的
   `connect_ip_request(authority=端点)` 就是这条），再退 `cloudflareaccess.com`
   （usque / connect-ip-go 的默认）。两条在 CF 的不同边缘上都出现过。
2. **补 `capsule-protocol: ?1`**（RFC 9297 声明）。h3 由 connect-ip-go 自己加，h2 这条路
   不加，边缘可能直接拒。
3. **h2 全灭自动回退 h3**：`Dial` 里在 h2 失败后改协议再试 30s。用户要的是能上网，
   不是协议执念。
4. 失败时把 HTTP 状态码 + 响应体前 160 字节写进日志（`httpRespSnippet`），下次能直接
   看出是 401/404 还是 GOAWAY。

### 8.2 OpenVPN「连上马上断」

三个独立原因叠在一起：

1. **出口验证预算 8s 太短**。日志：`出口验证未通过（2 轮：Get "https://1.1.1.1/cdn-cgi/trace": context deadline exceeded）`
   —— 8s 只够跑 2 轮，而这个节点其实能用（用户实测有下载）。这里要付的是
   TCP(OpenVPN over WARP netstack) + TLS 的完整往返，改成至少 20s。
2. **同节点不重试**。98 个节点里 36 个是 `hard reset response` / `EOF` 这类瞬时失败，
   同一个节点下一次就过。现在握手失败会重试一次。
3. **为速度换点换到「没测过」的节点**。日志：65 KB/s 的节点被换掉 → 117 KB/s → 第三个
   直接握手失败。改成只换「**有实测记录、且比当前快 1.5 倍**」的候选，没有就留着
   （慢总比连不上强）。固定节点仍然不因速度换。

### 8.3 MASQUEX2 连不上

日志证据：外层 8 轮全是 `[2606:4700:103::1]:443 已建立 CONNECT-IP` → `数据面不通`。

- 外层候选里混进了 **v6 边缘**：v6 路径 MTU 1280，装不下「内层 1228 的 IP 包 + 外层
  封装」。现在外层 `IPv6=false`（只 v4），预算也只给一半。
- 外层 MTU 1400 → 1300（见 7.3）。

### 8.4 MASQUE 上行只有十几 Mb/s（下行正常）

机理：**一条 QUIC 连接的上行受它自己的拥塞窗口限制**。我们是发送方，Cubic 在手机网络
的上行丢包率下会把单连接卡在十几 Mb/s；下行不受这个限制（我们是接收方，只有对端的
cwnd 在管），所以「下行满速、上行很慢」是必然的不对称。WG/AWG 没有拥塞控制，所以
上行也是满的 —— 这和观测完全一致。

Aether（Rust + quiche）同样是 Cubic、同样没有 BBR，它的优势不在拥塞控制。

0.2.12 做两件事：

1. **上行 3 条 CONNECT-IP 会话并行**（`masqueUploadConns`）：第一条握手时建，其余在
   后台补齐（`growConns`，不拖慢「连上」）。上行按 **IP 五元组哈希** 分发
   （`flowIndex`）—— 同一条流固定走同一条会话，不同的流才分散。实测同一账号所有
   隧道出口都是同一个 104.28.x.x，所以即便会话数变化也不会换源 IP。
2. **MTU 按传输族分档**：v4 → 1300，v6 → 1160（原来一律 1200）。包数少 8%，
   配合 `quic.Config.InitialPacketSize` 直接按该尺寸起步，省掉 DPLPMTUD 的爬坡。

> 验证点：日志里应出现 `上行并行：3 条 CONNECT-IP 会话就绪（按流分发）`。

---

## 9. 0.2.13：测速、分类与设置页审计

### 9.1 「测延迟」改成「握手 + 真下载」

只测握手看不出「能握手但只有几 KB/s」的节点 —— 而那正是最该筛掉的（用户在
2026-11-07 的日志里就碰到：65 KB/s 的节点连上后立刻被换掉）。

做法：`ProbeOpenVPNSpeed` 在握手成功后，用 **gVisor netstack 当 tun** 把 OpenVPN
的包泵接上，再经它下载 1 MiB 测吞吐。这样测速**不需要建系统 VPN**，不会把用户
正在用的连接踢掉；代价是每个节点多 4 秒。

结果同时写进速度记忆（`NodeSpeedStore`）：列表里的 `握手 3341ms · ≈94 KB/s`
和下次排序、自动选点用的是同一份数据。

### 9.2 家宽识别：两个数据源 + 「未分类」

原来只查 ip-api，判不出来就写 `unknown`，界面显示成 `US未知01` —— 用户以为程序坏了。

现在：

1. ip-api（批量）先判；
2. **只对仍然是 unknown 的 IP** 再查 ipwho.is（免费、无需 key），看它的顶层
   `type`（isp / hosting / business）与 `security.hosting`；
3. 两个源都给不出证据时写「**未分类**」—— 这是中性结论，不是错误。

判定口径没有放宽：`business` / `education` 这类既不是托管也不确定是居民宽带的，
仍然保持未分类。宁可少说，也不把机房说成家宽。

### 9.3 设置页清理（含「有没有真的生效」审计）

删除：

| 项 | 原因 |
|---|---|
| 启动后自动连接 / 开机自启 | 安卓没有开机自启；「打开 App 就自动连」在未授权时会弹授权框，容易误解 |
| 不下发 DNS | 与「自定义 DNS」互相打脸；要跟随系统就把自定义 DNS 留空 |
| 连接前重新扫描端点 | 置灰的假开关（安卓每次连接本来就会重新抽样） |
| 设置页的「关于」节 | 版本/引擎/账号/目录/日志路径与侧边栏「关于」完全重复 —— 全部收进关于页 |
| 顶部品牌块的版本号 | 同上 |
| 「尚未搬运」里的语言、健康守护 | 这一版真做出来了，不能再挂在未实现表里 |

新增：

- **本地代理**（VPN 模式也能开）＋ 侧边栏 **局域网共享** 页：手机这条隧道借给
  同一 Wi-Fi 的电脑，地址/端口/监听状态都写在一页里。
- **语言**：中 / 英 / 跟随系统。**诚实说明**：英文覆盖抽屉、页面标题、设置分区与
  主要按钮，大段说明文字仍是中文（副标题里写着）。
- **健康守护**：关掉后出口异常只记录、不自动重连（按流量计费/要绝对稳定时用）。

审计结论（设置的每一项到底有没有生效）：

| 设置项 | 生效点 |
|---|---|
| 连接模式 vpn/proxy | `WarpVpnService.startConnect` 分支 |
| 连接超时 | `e.setTimeout()` → 引擎单端点握手预算 |
| Psiphon / 出口地区 | `setPsiphonRegion` / `PsiphonOptions.EgressRegion` |
| OpenVPN / 地区 / 节点 | `setOpenVPNExit` + 引擎候选 |
| 分应用 | `VpnService.Builder.addAllowed/DisallowedApplication` |
| 本地代理 / 端口 / 局域网 | `setSocksListen`（VPN 模式按 `localProxy`） |
| IPv6 / MTU / 自定义 DNS | `Builder.addRoute` / `setMtu` / `addDnsServer` |
| 主题 / 日志自动滚动 | `XiaoheTheme` / `HomeScreen` 冻结日志 |
| 语言 | 抽屉与页面标题、设置分区 |
| 健康守护 | `startWatchdog()` |
| 分流规则 | 仅「仅代理」的本地 SOCKS 执行（VPN 模式只有 IP 级路由表） |
| 清空日志 | `EngineBridge.clearLogs()` |

---

## 10. 0.2.14：热切换、入口去重、VPN 模式的 direct 规则

### 10.1 协议热切换

安卓没有「换隧道而系统 VPN 不动」的接口：协议变了，tun 的 MTU/地址就得跟着变
（MASQUE 1300、Psiphon 1500、其它 1280），只能重建 tun。

所以「热」的定义是：**服务不退出、通知不重建、用户不用先点断开**。
`ACTION_SWITCH_PROTO` → `switchProto()`：断开引擎会话 → 等状态机回 idle（最多 3 秒）
→ `startConnect()` 用新协议重建。全过程约 1–3 秒，首页协议下拉在已连接时也可点，
右侧提示改成「切换会重连」。

### 10.2 入口去重

「局域网共享」不再占抽屉入口，改为 **设置 → 本地代理 → 局域网共享**。两处入口会
让人以为这是两个功能。

### 10.3 删除「电脑版有、安卓没搬」与解释性文案

设置页里那整节「尚未搬运」已删除（`NotYet` 组件一并删掉），各设置项的副标题压到
一句话。详细说明改在文档与回复里，不塞进 App。

### 10.4 VPN 模式的 `direct,网段` 之前没生效

`applyRoutePolicy` 原来只处理 `proxy,`：全局模式下 `direct,1.2.3.0/24` 被忽略。
现在：

- **API 33+**：`addRoute(0/0)` + `excludeRoute(该网段)`；
- **API 24–32**：算 `0/0 减去 direct` 的补集，逐条 `addRoute`（`complementV4`）。

域名形式的 direct 在 VPN 模式仍然无效 —— 内核按 IP 路由，看不到域名，这是
平台限制，不是漏做。

### 10.5 产物命名：`xehn-<版本号>.apk`

在 `app/build.gradle.kts` 里用 `androidComponents { onVariants { ... } }` 把
`VariantOutputImpl.outputFileName` 改成 `xehn-$buildVersionName.apk`。

注意两件事：

- **不能用老的 `applicationVariants.all`**：AGP 8 已废弃，而且它改的是「输出对象」
  的旧实现；`androidComponents` 是官方路径。
- **`Variant.versionName` 不存在**（只有 `applicationVariants` 的
  `mergedFlavor.versionName`）。这里从 `android.defaultConfig.versionName` 读，
  一处定义、两处使用（APK 名和 `BuildConfig.VERSION_NAME`）。

---

## 11. 0.2.15：本机 IP、账号、测速范围、出口归属地

### 11.1 「本机 IP」显示局域网地址

原来首页那一栏调 `probeLocalJSON` 显示**公网出口 IP** —— 它和「出口 IP」几乎相同，
用户既没法用它确认自己在哪个局域网，也没法据此给别的设备填局域网共享地址。
现在直接读系统网卡的 IPv4（`LocalNetwork.ipv4`），不发请求、立刻返回。

### 11.2 不再内置 WARP 账号

删掉 `assets/account.json`。每台设备首次连接自己注册，凭据落在
`filesDir/engine/account.json`，两条失效兜底：

- **14 天过期**（`accountMaxAge`）：到期删除并重新注册 —— CF 会注销长期不用的设备，
  之后握手一直失败，表象和「网络不通」完全一样；
- **连续 2 次整体失败**：`accountFailStreak` 达到 2 就删缓存，下次连接重新注册。

### 11.3 测速范围

「测延迟+速度」按当前选择决定范围：钉了节点 → 只测它；选了国家 → 只测该国；
都没选 → 全部。并发 8、测速预算 2s，98 个最坏约 2.5 分钟。

### 11.4 MASQUE 出口「上海变郑州」

出口 IP `104.28.245.200` 是 Cloudflare 的共享 NAT 地址，与 WG/AWG **相同是正常的**
（同一个 CF 出口）。不同地理库对同一 IP 会给出不同城市（上海/郑州都出现过），
这不是协议问题。

真正能区分线路的是 `/cdn-cgi/trace` 里的 `colo`（接入的边缘机场代码），现在连接
日志会写：`出口 104.28.245.200 (CN, colo=HKG)`。

---

## 12. 0.2.16：MASQUE 注册失败的真正原因

真机日志（2026-11-08 16:29）：

```
[tunnel] 准备 MASQUE 账号（首次需要注册 + 登记 ECDSA 公钥）…
[engine] 连接失败: MASQUE 注册失败: POST /reg:
         dial tcp: lookup api.cloudflareclient.com: no such host
```

**因果链**：`WarpVpnService.startConnect()` 先 `establish()` 建系统 VPN，再
`connect()`；账号注册发生在 connect 内部。此时系统 DNS 已经被路由进 tun，
而隧道还没通 —— 域名解析直接失败。WG/AWG 之所以能连，是因为它们的账号早就有
缓存，根本不需要联网注册。

修法：把账号准备**提到建 tun 之前**。

- 引擎新增 `Engine.PrepareAccounts(proto)` → `warpBackend.PrepareAccounts`
  → `warp.EnsureMasqueAccount`（MASQUE 时）；
- `WarpVpnService` 的 `ACTION_CONNECT` 改成协程：先在 IO 线程预注册，
  再 `startConnect()`。首次会慢几秒（注册 + ECDSA 登记），之后走缓存。

顺带把 VPN Gate 抓取改成**只走 WARP**（原先是 8s 直连超时后再走 WARP，纯白等），
超时从 20s 提到 40s（经 WARP 到日本回源经常 20s 以上）。

> 对照：官方 Cloudflare One Client 的 `conf.json` 里也是**匿名免费账号**
> （`account_type: free` + `license`，无登录），`tunnel_key_data` 为
> `secp256r1/masque`，MASQUE 端点只有 `162.159.198.2`（7 个端口），
> 并且用 `always_exclude` 把 `162.159.197.3` 永久排除出隧道 —— 正是为了避免
> 「建隧道后连不上控制面」这类死锁。

---

## 13. 0.2.17：分类只剩两类、测速真正出数

### 13.1 「未分类」必须消失

用户要求节点只有**家宽 / 机房**两类。原来两源都给不出强证据就写 `unknown`，
界面显示成 `JP未分类01`。

现在：

1. **两个源对所有 IP 都查**（ip-api 批量 + ipwho.is 逐个），不再只补 unknown；
2. 判定顺序：任一源说 hosting → 机房；ipwho 说 `type=isp` → 家宽；
   冲突（一个说 hosting、一个说 isp）→ 判**机房**（误标家宽的代价更大）；
3. 仍然没有强证据 → `heuristicClass()`：命中硬机房 ASN / 机房关键词判机房，
   否则判家宽（VPN Gate 节点绝大多数是住宅/小 ISP 接入）；
4. 最后再兜一遍，保证 `Class` 不会是 `unknown`。

### 13.2 测速全是「速度未测」的原因

真机日志（2026-11-08 16:48）里 33 个握手成功的节点**全部**「速度未测」：

```
[probe] 握手测试 1/49：jp-60.73.70.60-1941 握手成功 3037ms · 速度未测
```

原因不是网络，是**预算**：`probeDownloadBps` 原来只有 2 秒，而这条链路光
OpenVPN 握手就要 3–7 秒（日志里 3037ms、4983ms、7535ms），2 秒连 TLS 都没
完成；而且计时从 `client.Do` **之前**开始，握手时间被算进了「下载速度」。

改成：

- 总预算 8 秒（DNS + TCP + TLS + 首字节 + 2 秒下载窗口）；
- `start` 移到 `client.Do` 之后，**只统计真正在收数据的 2 秒**；
- 样本短于 0.3 秒判为不可信（返回 0，界面显示「—」）。

### 13.3 节点行布局

`名称 ｜ 速度 ｜ 握手延迟`：速度单独一列夹在中间（用户指定位置），
`JP家宽01` 的宽度从 84dp 放到 100dp 并加 ellipsis，避免「JP未分类」被截掉数字。

---

## 14. 0.2.18：全量测速停在 8/N

真机日志（2026-11-08 21:14）最后一行是 `握手测试 8/97`，之后再无输出、App 也没崩。

根因：探测有 **8 个 worker**，而每个「握手成功」的节点都会走 `measureThroughOpenVPN`
—— 它要起一个**完整的 gVisor netstack**（TCP/IP 栈 + goroutine）+ 一条 OpenVPN
数据通道。8 个并发 netstack 把手机 CPU/内存压满，worker 卡在泵里出不来（`dev.Read`
阻塞，`client.Close()` 又在等读循环），于是 8 个 worker 全部丢失，队里剩下 89 个
永远等不到 worker。

四处修法：

1. **测速限流**：`probeSpeedSlots` 容量 3 —— 握手仍并发 8（很轻），只有测速受限；
   等槽位最多 30 秒（正常排队 3×6=18s 足够），超时才放弃。
2. **硬超时**：`time.AfterFunc(budget+3s, forceClose)`，到点强制收掉，任何一步卡住
   都不会拖死 worker。
3. **关闭顺序**：`dev.Close()` → `ex.close()`。先关 dev 让泵里卡在 Read/Write 的
   goroutine 立刻返回，`client.Close()` 才不会等一个永远不返回的读循环。
4. **探测预算 6→10 分钟**，日志每行带单节点耗时（`… 握手成功 3767ms · ≈152 KB/s（7.2s）`），
   下次再出问题能直接看出是某个节点拖住、还是整体停摆。

> 查法：解压 APK 取 `libgojni.so` / `classes*.dex`，转 Latin1 后按 UTF-8 字节做 `IndexOf`（PowerShell 一行即可），比逐个装上试快得多。
