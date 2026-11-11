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

---

## 15. 0.2.19：握手成功但没有速度

真机日志（2026-11-08 21:49）：

```
[probe] 握手测试 95/97：au-112.213.191.252-53956 握手成功 2430ms · 速度未测（8.4s）
[probe] 握手测试完成：97 个节点里 58 个能握手
[ui]   握手 + 测速完成：58/97 个能握手，50 个测到了速度
```

8.4 秒 = 握手 2.4 秒 + **测速 6 秒一个字节都没收到**。

原因：`probeDownloadBps` 原来把域名交给 netstack 解析（`stack.tnet.DialContext`），
而 **VPN Gate 节点普遍不转发 UDP 53** —— 6 秒全花在 DNS 上，TCP 都没开始。

修法：测速端点改用**主机 DNS 解析一次（缓存）+ 直连 IP + 固定 SNI**
（`DialTLSContext` 里 `tls.Config{ServerName: "speed.cloudflare.com"}`），
彻底绕开隧道内 DNS；失败原因（`tcp:` / `tls:` / `已连上但 2 秒内没有收到数据`）
写进 `OpenVPNProbe.Note`，日志会显示 `速度未测（tcp: i/o timeout）`。

> **为什么连上之后又有速度**：那是另一条链路。探测走「WARP 上游 → 节点 → CF」的
> 临时 netstack（6 秒预算），连接后走的是真实数据面（`measureExitBps`，20 秒 +
> 1 MiB 预热），后者当然能测出数。两者互不矛盾，**连接后的结果会写回本节点的
> 速度记忆**，所以再打开出口地区就能看到。

---

## 16. 0.2.20：赛风连不上（提前建 tun）与地区列表

### 16.1 赛风 14 个端点全「数据面不通」

真机日志（2026-11-09 12:37）：Psiphon 的上游连续 14 个端点
`握手成功，验证出口…` → `数据面不通（隧道内请求超时）`，最后 60 秒失败；
**同一时刻 OpenVPN 出口用同一条 awg 上游却是通的**（`上游就绪，出口 104.28.245.200`）。

两者唯一的差别是**建 tun 的时机**：

- OpenVPN 分支：`e.setTunFD(0)` → 引擎先建上游 → 回调 `TunProvider` 建 tun；
- Psiphon 分支：Kotlin **先** `establish()` 建 tun（整机路由立刻被接管），再建上游。

系统 VPN 一建立，即使 socket 被 `protect`，在「VPN 刚起来」的窗口里这条上游的
UDP 仍会被丢。修法是把顺序反过来：`psiphonTunProvider`（`warp/psiphon.go` 的
`psiphonTunProvider` + `SetPsiphonTunProvider`），上游就绪后才向 Android 要 fd。

顺带把重试从 3 次 / 150 秒收紧到 **2 次 / 90 秒** —— 根因修了，不必再用 150 秒
去赌第三个端点（用户明确要求连接时间短）。

### 16.2 出口地区列表首次为空

Psiphon 的可用地区是 tunnel-core 运行时上报的，没有独立 API：没连过就一定是空的。

新增 `RefreshPsiphonRegions()`（引擎）：

1. 起一条 WARP 上游（netstack）；
2. 以 `PsiphonOptions.RegionsOnly` 启动 Psiphon —— 不建 tun、不接管流量、不做
   出口测速，只在拿到 `AvailableEgressRegions` 后立即返回；
3. 落盘 `psiphon-regions.json`（`savePsiphonRegions`），下次启动直接预置。

UI：出口地区弹窗右上角「更新列表」；**首次打开且列表为空时自动拉一次**（只自动
尝试一次，失败后等用户手动点，避免每次弹窗都白等 30 秒）。

### 16.3 首次启动就注册账号

`MainActivity.onCreate` 起一个后台线程调 `EngineBridge.prepareAccountsOnFirstLaunch`
——只在本地没有 `account.json` / `masque.json` 时才联网注册，之后走缓存。日志有
`[ui] 首次启动：正在注册本机 WARP 账号…`，注册过程引擎会写 `[acct] …`。

> APK 内**不打包任何账号或节点**：`assets/` 只有 `psiphon/client.config`（官方
> Psiphon 客户端配置，必需且不含身份）。账号、节点、大陆路由表全部是运行时生成
> 并缓存在 `filesDir/engine/`。

---

## 17. 0.2.21：赛风「握手成功、数据面全不通」的残留状态

真机日志（2026-11-09 14:03）里有一段几乎是实验对照：

```
[psiphon] 8.6.112.92:2408  握手成功，验证出口… 出口 104.28.245.200 (CN)   ← 更新地区列表时，通
[tunnel]  8.6.112.172:2408 握手成功，验证出口… 数据面不通（隧道内请求超时）← 紧接着连接，14 个端点全死
```

两次相隔不到一分钟、同为 awg、同一个账号。差别只有两个：

1. 前者**没有系统 VPN**（`tun fd = 0`，RegionsOnly 模式）；
2. 后者紧跟在一次 Psiphon 会话之后。

三处修复：

- **`warp.ResetTransient()`**：连接前清掉 `outer` / `outerAcct` / `masqueNest` /
  `metaAddr` / `pingAddr`。这些是跨会话的指针，指向上一条已关闭的 netstack 时，
  新上游的 UDP 会被塞进死隧道 —— 表现正是「握手过、数据全丢」。
- **`newIPStack` 的 MTU 兜底**：`mtu < 576` 一律用 1280。gVisor 在 MTU=0 时连一个
  包都发不出去，而调用方完全看不出原因（`warp.Apply(Config{})` 会把 `tunMTU`
  置 0，这类空 Config 调用很容易踩到）。
- **诊断日志**：`Psiphon 上游：netstack 数据面（全局 tunFD %d→0, tunMTU %d）`。
  下次再失败，这一行就能确认是不是 MTU / tunFD 的锅。

> 建议的验证顺序：**先直接连接（不要先点「更新列表」）**。如果这样能连、而
> 「先更新再连接」连不上，就说明残留状态那一层还没清干净，把新日志里
> `netstack 数据面（… tunMTU …）` 那行发过来即可定位。

---

## 18. 0.2.22：赛风直连优先 + 上游 MTU 固定 1280

日志里那行诊断直接给出了答案：

```
[tunnel] Psiphon 上游：netstack 数据面（全局 tunFD 0→0, tunMTU 1500）
[tunnel] 8.6.112.156:2408 握手成功，验证出口… 数据面不通（隧道内请求超时）
```

**`tunMTU 1500`**：WARP 的 MTU 是 1280，而 gVisor netstack 被设成 Psiphon 自己
tun 的 1500 —— 每个包都超出 WARP 能承载的大小，握手（小包）能过，数据（大包）
一个字节也发不出去。对照 Aether 的日志：它根本不做这层上游
（`starting psiphon with no tunnel underneath it`），2 秒拿到地区、6 秒就绪。

两处改动（A+B）：

- **A：直连优先**。`DialPsiphon` 先跑 `dialPsiphonDirect`（不建上游，45 秒上限），
  失败才退到原有的「WARP 前置」。直连路径与 Aether 完全一致 —— Psiphon 本就是
  抗审查隧道，直连是它的设计用法。
- **B：上游 netstack 固定 1280**。`dialPsiphonOnce` 里 `tunMTU = 1280`（defer 还原），
  不再让 Psiphon 的 1500 泄漏到上游。

预期日志：

```
[psiphon] Psiphon 直连（不建上游隧道），等就绪上限 3m0s…
[psiphon] Psiphon can leave from: AT AU BE …        ← 约 2 秒
[psiphon] Psiphon 隧道已建立（1 条）
[psiphon] Psiphon 出口 … (…)
```

---

## 19. 0.2.23：出口验证误判（真正的原因）

0.2.22 的直连日志证明：**隧道其实是通的，是验证把它判死了。**

```
[tunnel] Psiphon 隧道已建立（1 条）
[tunnel] Psiphon[ConnectedServerRegion] {"serverRegion":"FR"}
[tunnel] Psiphon[TotalBytesTransferred] {"received":62,"sent":20693}
[tunnel] Psiphon 直连没成功（出口验证失败（SOCKS 127.0.0.1:41029））
```

### 19.1 `newIPStack` 的 DialContext 丢掉了请求地址

```go
DialContext: func(ctx, network, _ string) (net.Conn, error) {
    return tnet.DialContext(ctx, "tcp", metaDialAddr())
}
```

第三个参数（请求自己的地址）被丢弃，一律用全局 `metaDialAddr()`。当 `metaAddr`
为空时它返回 **空串** → `Dial("tcp", "")` 必失败 → 连
`https://1.1.1.1/cdn-cgi/trace` 这种 **IP 字面量**也拨不出去 → `verifyEgress`
三档全灭 → 报「数据面不通」。

### 19.2 谁把 metaAddr 清空的：`PrepareAccounts`

0.2.16 加的「连接前预注册账号」里调了完整的 `warp.Apply(Config{})`，它会
`metaAddr.Store(nil)`。于是**每次连接前**缓存必被清 → 必须重新解析 → WARP 刚
起来时解析经常失败 → 必误判。

这解释了两个场景的差别：

- 「更新地区列表」不经过 `PrepareAccounts` → metaAddr 还是上次的 → 通过；
- 连接必经过 `PrepareAccounts` → metaAddr 被清 → 全灭。

### 19.3 与基线的对比

```powershell
git show 3e9caba:engine/warp/tunnel.go | Select-String metaDialAddr
```

基线（`3e9caba`，2026-10-22 可运行状态）里 `DialContext` 也是 `metaDialAddr()`，
但**基线能连** —— 因为那时没有 `PrepareAccounts`，`metaAddr` 从上次会话一直
保留着。所以问题不是基线写法，而是 0.2.16 引入的「连接前 Apply」。

### 19.4 本版修复

1. **删除赛风直连**（按要求，只走 WARP 前置）；
2. `DialContext` 尊重传入地址：`metaAddr` 为空时用它 → IP 字面量档恢复可用；
3. `probeViaSocks` 加第三档 IP 字面量（`https://1.1.1.1/cdn-cgi/trace`）；
4. `PrepareAccounts` 改用 `warp.SetCredsPaths()`，只设凭据路径，**不再清 metaAddr**；
5. 保留上游 netstack MTU 固定 1280。

---

## 20. 0.2.24：赛风连上了，但界面说「系统 VPN 未启用」

### 20.1 状态没回填（不是隧道的问题）

0.2.20 把 Psiphon 改成「先上游、后 tun」之后，tun 是在 `psiphonTunProvider`
里建的，而 `startConnect` 里那段「建完 tun 回填 `setTunFD` / `setVPNState(true)`」
**根本没机会执行**。于是：

- 隧道真的通（能上网、出口 IP 是 Psiphon 的 45.33.64.181）；
- 引擎快照里 `vpn=false` → 首页显示「系统 VPN 未启用（流量不会走隧道）」；
- 出口看门狗（`needRecover`）也不工作。

修法：`psiphonTunProvider` 建完 tun 立即回填 `setTunFD` / `setVPNState(true)` 并
`refresh`。

> 顺带一句：首页的 ↑↓ 速率与总量在 Psiphon 模式下恒为 0 是正常的 —— tun fd 直接
> 交给了 Psiphon 的 packet tunnel，引擎不经过任何数据包，统计不到。

### 20.2 速度慢：netstack TCP 缓冲一直是 0

`netstackTCPBufferMax = 0` 意味着 gVisor TCP 用上游默认缓冲（1MB 量级）。
`tunnel.go` 里自己的注释写着：**「实测把 WARP→节点 这条链锁在 17 Mbps」** —— 和
用户反馈的「能连但慢」完全吻合。

当时关成 0 的理由是「开到 8MB 后出现握手成功但数据面不通」，而那件事的真正原因
是出口验证的 DialContext 丢地址（第 19 节）。现在按注释里给自己留的建议：

```go
const netstackTCPBufferMax = 2 << 20   // 2MB ⇒ RTT 250ms 时约 64 Mbps
```

> 再往上（4/8MB）要真机对照，不要一次跳上去。

---

## 21. 0.2.25：赛风地区测速 + SOCKS 转发优化

### 21.1 出口地区「测速」

新增 `Engine.ProbePsiphonRegions(regionsCSV)`：逐个国家走一遍 **WARP 前置 + Psiphon**
（`RegionsOnly`，不建 tun、不接管流量），拿到该地区的 SOCKS 后用
`warp.ProbeSpeedViaSocks` 下载 512 KB 计算速度；`ms` 是「开始拨号 → Psiphon 就绪」
的耗时。

UI：出口地区弹窗右上角 **「测速」**，结果直接写在每个国家行上
（`320ms · ≈1.2 MB/s`）。慢：每个国家 8–15 秒。

### 21.2 SOCKS 转发：128 KB 缓冲 + TCP_NODELAY

`serveSOCKS` / `dialDirect` 原来是裸 `io.Copy`（32 KB 缓冲、不碰 Nagle）。
Psiphon 的整个上游都走这个 SOCKS，32 KB 的小缓冲 + Nagle 会把高 RTT 链路的吞吐
压得很低。改成 `pipeBoth()`：两边 `SetNoDelay(true)`，`io.CopyBuffer` 用 128 KB。

> 观察到但**没有改**的一点：Psiphon 的 tun MTU 是 1500，而它的上游 WARP 只有
> 1280。内层 1500 的包在外层会被切成两段，理论上有约 10% 的效率损失。要不要
> 降到 1280 需要真机对照（改小会让终端的 MSS 变小，可能反而更慢），先看测速数据。

---

## 22. 0.2.26：地区测速把资源耗光，导致随后连不上赛风

真机日志（2026-11-09 15:22）的顺序很清楚：先测了 27 个地区，然后连接失败。

**测速侧完全正常**（每个地区都有值）：

```
[psiphon] 地区测速 AT：≈99 KB/s
[psiphon] 地区测速 AU：≈84 KB/s
[psiphon] 地区测速 BE：≈274 KB/s
[psiphon] 地区测速 CA：≈6 KB/s
[psiphon] 地区测速 BR：失败  Psiphon 本次不提供 BR 地区的出口
```

**紧接着的连接失败**：

```
[tunnel] Psiphon[RemoteServerListResourceDownloadedBytes] {"bytes":0,...}
[tunnel] Psiphon[CandidateServers] {"count":13,"initialCount":0,...}
[engine] 连接失败: Psiphon 在 1m29.999s 内没有建立隧道
```

`bytes:0` = 远程服务器列表没下载到；候选只剩 13 个（正常是 20+）。根因是
`ProbePsiphonRegions` 对**每个地区**都 `DialPsiphon` 一次 —— 27 次「建 WARP 上游
+ 启动/停止 Psiphon」，把 socket / netstack / tunnel-core 的进程内全局状态全耗光。

三条修法：

1. **一条上游复用给所有地区**：`warp.OpenUnderlay` 只建一次，每个地区改用
   `warp.ProbePsiphonRegion(ctx, …, upSocks, region, …)`（同一上游 SOCKS 上起停
   Psiphon）。27 条上游 → 1 条。
2. **测速结束后冷却 2 秒**再放行正式连接（`psi` 是进程内单例，刚 `Stop` 完立刻
   `Start` 拿不到服务器列表）。
3. **测速进行中拒绝连接**（`probingRegions`）：两者共用同一个 `psi`，同时跑只会
   互相破坏，明确报错比静默失败好。

UI 也加了进度：`测速中… 3/27`（从引擎日志里取），27 个地区要 5 分钟以上，没有
进度看起来就是卡死。

---

## 23. 0.2.27：测速「全部失败」是我用错了上游函数

真机日志（2026-11-09 15:49）：

```
[psiphon] 地区测速：先建一条 WARP 上游（各地区共用）…
[psiphon] 8.35.211.16:2408  握手成功，验证出口… 数据面不通（隧道内请求超时）
[psiphon] 8.35.211.157:2408 握手成功，验证出口… 数据面不通（隧道内请求超时）
```

0.2.26 为了「一条上游复用」调了 `warp.OpenUnderlay` —— 但那个函数是给**「经
WARP 拨 OpenVPN 节点」**用的，它的 `Dial` 参数里**没有 `SocksListen`**。也就是说
这条上游根本没有本地 SOCKS，Psiphon 无处挂载，紧接着的验证自然全灭。

修法：新增 `warp.OpenPsiphonUnderlay`（`Dial` + `SocksListen: 127.0.0.1:0` +
`SocksRequired: true`），和单国测速 `dialPsiphonOnce` 走的是同一条路径。

另外两点：

- **每国上限 45s → 15s**。成功的地区实测 6–10s 就绪；拖满 45s 的地区基本就是要
  失败，白等只会让 25 个国家变成十分钟。
- **边测边显示**：新增 `RegionProbeSink` 接口，引擎每测完一个国家回调一次
  （`OnRegionProbe(region, ms, bps, ok, err)`），Kotlin 切主线程更新那一行。以前是
  等全部跑完才一次性刷新，看起来就是「一直转圈，最后冒出一片失败」。

---

## 24. 0.2.28：国家数 27 vs 25、测速偏慢

### 24.1 刷新列表 27 个，测速时只有 25 个

真机日志同一份里就同时存在：

```
[psiphon] Psiphon 上报可用地区 27 个                    ← 刷新列表那次会话
[psiphon] Psiphon 可用出口地区 25 个：AT AU BE CA … US  ← 测速时每次会话
```

这不是我们的 bug：**Psiphon 每次会话连到的服务器集合不同，能落地的地区就不同**。
27 是上一次的、25 是这一次的，差的是 BR 这类「本轮没有服务器」的地区。

改进：测速跑完**第一个国家**后就把本次会话的上报列表记下来（`known`），
后续不在列表里的地区直接标「本次会话不提供该地区」并跳过 —— 以前 BR 要白等
十几秒才失败。

### 24.2 测速只有 200–350 KB/s

`ProbeSpeedViaSocks` 原来一上来就计时：前 512 KB 基本全在 **TCP 慢启动**里，
测出来只有稳态的几分之一。正式出口测速（`measureExitBps`）一直是「1 MiB 预热
+ 3 秒采样」，探测这边漏了预热。

现在先丢 **256 KB** 不计数，再计时读 512 KB。同一条链路测出来的数字会明显更接近
真实值（也更能区分「真的慢」和「还没起来」）。

---

## 25. 0.2.29：测速压到 2 分钟，并修「共用上游后更慢」

### 25.1 为什么 2 分钟内测不完 25 个国家

Psiphon 的 `psi` 是**进程内单例**，两个国家不能同时跑（`psi.Start` 会直接拒绝）。
一个国家最少要「启动隧道 5–8s + 测速 1.5s」，25 × 7s ≈ 3 分钟 —— 这是物理下限，
不是实现问题。

所以改成**硬预算 110 秒**：到点就停，已测的照常显示，剩下标「超时未测（2 分钟
预算用尽）」。同时把每国上限 15s → **8s**，采样 512KB → **256KB**（预热 128KB），
测速超时 8s → 6s。

### 25.2 共用上游之后变慢：`psi` 没停稳

两份日志对比很清楚：

| 版本 | 上游 | 结果 |
|---|---|---|
| 16:09 | 每国独立 | AT 276、AU 356、BE 232、DE 264 KB/s |
| 16:26 | 共用一条 | AT 失败、AU 70、BE 失败、DE 73、DK 46 KB/s |

共用上游省掉了 24 次建隧道的时间，但每国 `Stop → 立刻 Start`，Psiphon 内部
还没收拾完就被重新拉起，于是「8–15s 内没有建立隧道」或者「连上了但测不出速度」，
成功的那些也只剩几十 KB/s。

修法：每国之间等 **500ms** 再进下一个。仍然共用一条上游（省时间），但给 `psi`
一个停稳的窗口。

> 查法：解压 APK 取 `libgojni.so` / `classes*.dex`，转 Latin1 后按 UTF-8 字节做 `IndexOf`（PowerShell 一行即可），比逐个装上试快得多。

---

## 26. 0.2.30：测速口径、节点行排版、OpenVPN 下行、赛风地区全测

四个问题来自同一份真机日志（2026-11-09 17:03）。前三个是「数字不可信」，
第四个是「只测了一部分」。

### 26.1 单流测速与 speedtest 差 25 倍（必须多流）

日志：`jp-219.75.197.22-1596 握手成功 3434ms · ≈79 KB/s`，而同一节点用 speedtest
实测下行 **17 Mbps**（≈2 MB/s）。差的不是节点，是测法：

- 单流在「手机 → WARP → 跨境节点」这条 200–400ms RTT 的链路上会同时被三件事拖死：
  慢启动（2 秒窗口基本全在爬坡）、丢一个包 cwnd 腰斩、以及「窗口/RTT」的物理上限；
- speedtest 用的是 4–8 条并发流，它给出的是**线路能给多少**，不是**一条流能给多少**。

修法：`engine/warp/speedprobe.go` 的 `speedProbeVia`——**4 条并发 HTTP 流 +
预热 800ms + 稳态窗口 2s**，取窗口内所有流的总字节数。节点测速、赛风地区测速、
串行兜底路径全部走它，保证「同一个数字」的口径一致。

> 判据：日志里同一节点从「≈79 KB/s」变成与 speedtest 同量级（MB/s 级）。

### 26.2 节点行排版：成功不再出现「握手」两个字

旧文案是 `握手 3341ms` + 单独一列速度，两个数字来自**不同的存储**（握手来自
`NodeProbeStore`、速度来自 `NodeSpeedStore`，后者是「上次连上它时」的出口速度，
6 小时有效）。于是出现「握手成功、只有延迟、速度是别人的」这种行 —— 用户明确
不接受。

现在的排版（`SettingsScreen.kt` 的 `OpenVpnNodeRow`）：左边节点名，右边一列：

| 状态 | 显示 |
|---|---|
| 握手成功且有速度 | `≈2.0 MB/s · 3214ms`（**不出现「握手」**） |
| 握手成功但一个字节都下不来 | `测速失败`（标红，不再伪装成成功） |
| 握手失败 | `握手失败`（标红） |
| 没测过 | `未测`（有历史实测速度时会带上） |

配套：`NodeProbeStore.Probe` 增加 `bps` 字段（`ms|ok|bps|at`，3 段旧格式按 bps=0
兼容读取），`VpnGateNode.probeBps` 只代表**这一次探测**测到速度。

### 26.3 OpenVPN 出口下行只剩几兆：三处叠加

用户反馈「以前有 100 兆，现在几兆，好的十几兆」。逐个查下来是三处：

1. **gVisor 的接收缓冲自适应默认是关的**（最致命）。`tcpip.TCPReceiveBufferSizeRangeOption`
   的 `Max` 只在自适应打开时才有意义 —— `endpoint.go` 的 `ModerateRecvBuf` 第一句就是
   `if e.RcvAutoParams.Disabled { return }`。所以 0.2.24 把 Max 从 0 调到 2 MiB 根本没生效，
   窗口永远停在 `Default`（1 MiB）：1 MiB / 400ms ≈ **20 Mbps 封顶**，正是「几兆到十几兆」。
   修法：`netstackx/tun.go` 里显式 `TCPModerateReceiveBufferOption(true)`，并把正式会话的
   Max 提到 **8 MiB**（8 MiB / 0.3s ≈ 213 Mbps），测速用的临时栈 4 MiB。
2. **OpenVPN over TCP 没关 Nagle**。协议是「一个 IP 包一次 Write」，1217 字节 < MSS 1240，
   在 Nagle 眼里是「小段」，高 RTT 下要等 ACK 才发下一段。修法：`dialThroughStack`
   里对 TCP 连接 `SetNoDelay(true)`。
3. **每包 64 KB 分配**。`datagramPacketIO.ReadPacket` 每读一个包就 `make([]byte, 64*1024)`：
   1160 字节的包、每秒 1 万包 = 每秒 640 MB 垃圾，GC 直接把吞吐压在几兆。
   修法：复用 64 KB scratch 缓冲，只按实际长度拷一份（垃圾降到 1/55）。
   另外把 `netstackx` 的 `incomingPacket` 从无缓冲改成 64 缓冲，突发时不再逐包阻塞。

### 26.4 赛风地区：串行只能测前 10 个 → 每个地区一条 controller

`MobileLibrary/psi` 的 `controller` 是**进程内全局变量**，串行 27 个地区（每个 8–10 秒）
在 110 秒预算里只够跑前 10 个，剩下的只能标「超时未测」。

修法：`engine/warp/psiphon_region.go` 直接用 tunnel-core 的 `psiphon` 包 ——
`NewController` 是实例级的，`OpenDataStore`/`CloseDataStore` 是**引用计数**的
（`psiphon/dataStore.go` 明确支持嵌套打开），所以 4 个地区可以并行。
27 个地区 4 路并发 ≈ 1 分钟跑完，**全部地区都有结果**。

三个边界：

- 建 controller 的准备工作（Commit / OpenDataStore / NewController）用
  `psiphonSetupMu` 串起来 —— `Commit` 里那段 `if !FileExists { os.Mkdir }` 并发会撞车；
- notice writer 是进程级的，测速期间 `MutePsiphonNotices()` 静音，正式连接时
  `psi.Start` 会重新装上自己的 writer；
- 所有地区都是「基础设施起不来」时，自动回退到原来的串行实现（慢，但不会整块失效）。

---

## 27. 0.2.31：本地代理 / 局域网共享在 VPN 模式下「开了也没用」

用户反馈两件事：局域网共享连不上、VPN 模式下 DNS 泄露。第一个不是配置问题，
是四处**互不相干的门槛**把功能整条掐断了。

### 27.1 四个门槛（任何一个都足以让端口不存在）

1. **`session.go` 里的 `tn.stack() != nil`**。fd 模式（系统 VPN）的隧道根本没有
   netstack（`newWGTunnel` 在 `tunFD > 0` 时 stack 是 nil），于是
   `startSocks` 永远不执行 —— 设置里开关是开的、日志里一行也不写、端口不存在。
   MASQUE 路径（`masque.go`）有同一句，一起删掉。
2. **Kotlin 侧把地址清空了**。Psiphon / OpenVPN 两个分支里写着
   `e.setSocksListen("")`，等于「这两种出口下永远不要本地代理」。现在改成按设置
   传 `proxyListenAddr()`。
3. **界面拿不到真实地址**。`VpnState.socks` 这个字段一直存在，但 `merge()` 从来
   没从引擎状态里读过它 —— 界面永远显示设置里那个「预期地址」，端口没起来也照显。
   现在引擎 `StatusJSON` 回填 `socks`（真实监听地址，端口可能是内核临时给的），
   断开时清空。
4. **Psiphon 的 SOCKS 只绑 127.0.0.1**。就算前三条都修好，局域网电脑也只能连到
   一个回环监听。所以给 Psiphon 会话单独开一个面向用户的监听，**链式经
   Psiphon 的 SOCKS** 出去（`Session.userLn` 与内部 `ln` 分开存）；OpenVPN 会话
   同样在 `DialOpenVPN` 结束后开一个。

拨号路径（`engine/warp/socks.go` 的 `socksPath`）按会话种类分三支，这一支必须
分对，否则「能连上但出口不对」：

| 会话 | 拨号 |
|---|---|
| Psiphon | 链式经 psiphon 自己的本地 SOCKS |
| OpenVPN 节点 | 宿主 dial（会被系统路由进 tun → 走节点）；**不能**用上游 netstack，那是 WARP 的出口 |
| 仅代理（netstack） | netstack dial，域名在隧道内解析 |
| 其它 fd 模式 | 宿主 dial（同样靠系统路由进 tun） |

> 关键点：fd 模式下这些 socket **不要** protect。protect 之后流量会绕开隧道
> 直接从物理网卡出去 —— 用户以为在用代理，实际是直连。

### 27.2 DNS 泄露：默认列表里就有一个「国内解析器」

leak 测试（ipleak / dnsleaktest）判的是「最终是谁替你解析的」。三处叠加：

1. 默认 DNS 是 `1.1.1.1, 223.5.5.5`。查询哪怕走了隧道，落地解析器仍是阿里 DNS，
   测试站点直接判泄露；
2. **「绕过大陆」分流会把 CN 网段从 tun 里排除**，223.5.5.5 正在 CN 网段里 ——
   查询根本不进隧道，从物理网卡直发。这是**真泄露**，不是显示问题；
3. **「黑名单」分流**只抓规则里写 proxy 的网段，默认路由不加，DNS 一样直连；
4. 没开 IPv6 时不加 `::/0`，v6 里的解析器查询也绕过隧道。

修法（设置 → 网络 → DNS 防泄漏，默认开）：

- 默认列表改成只有 `1.1.1.1`；开启防泄漏时，从候选里**剔除已知的国内公共解析器**
  （`LEAKY_RESOLVERS`，阿里 / 114 / DNSPod / 百度 / CNNIC / 字节 / 各地电信），
  顺序是「服务器 push 的 > 用户列表（已过滤）> 1.1.1.1」；
- 给每个下发的解析器加 **/32（/128）主机路由**：黑名单模式下也强制进隧道；
- 防泄漏开启且没开 IPv6 时，仍然抓 `::/0`（fail closed）。不抓的话，v6 流量
  （含 v6 解析器查询）走物理网卡，是「明明开了 VPN 还泄露」的常见原因；
- 永不下发空列表 —— 空列表时系统会退回物理网络的 DNS，等于没开 VPN。

日志里能直接核对：`[dns] 防泄漏：下发 1.1.1.1（1 条主机路由强制走隧道），已剔除国内解析器 223.5.5.5`。

---

## 28. 0.2.32/0.2.33：固定节点「Cannot set address」、十几兆的假高速、DNS 告警到底在说什么

### 28.1 固定节点全失败：`Cannot set address`

真机日志（2026-11-10 12:10）四次固定节点全部停在同一句：

```
[tunnel] OpenVPN 已握手，下发地址 10.211.1.9/32 …
[vpn] 第 1 次 establish（10.211.1.9/32, MTU=1160, 分流=global）…
[vpn] OpenVPN 建 tun 失败: Cannot set address
```

这不是节点坏了，是**系统拒绝把 10.211.1.x 配到 tun 上**。0.2.32 加了「换前缀」
（/32→/24→/16），真机日志证明**三个前缀全被拒** —— 所以不是前缀问题，是这个地址
本身在系统眼里不可用（10.0.0.0/8 同时是家用宽带与运营商 CGNAT 的常用网段）：

```
[vpn] establish 失败（IllegalArgumentException: Cannot set address / Remote stack trace:
    at com.android.server.connectivity.Vpn.jniSetAddresses(Native Method)
    at com.android.server.Vpn.establish(Vpn.java:1860)
），换前缀 /24 再试
```

0.2.33 改成**地址替换（一对一 NAT）**，这才是正解：

- 系统 tun 上放 `192.0.2.111/32` —— 192.0.2.0/24 是 RFC 5737 的 TEST-NET-1（保留给
  文档），任何真实网络都不会分配，**永远不会冲突**；
- 节点认的仍是它下发的地址，所以由引擎在包泵里替换
  （`engine/warp/iprewrite.go`）：出去的包把**源**地址换成节点下发的，回来的包把
  **目的**地址换回来；
- 替换只改地址（IPv4 头 + TCP/UDP 校验和一起重算），不改端口/序列号，对节点和
  应用都透明。

```
[vpn] 第 1 次 establish（tun=192.0.2.111/32，节点下发=10.211.1.145/32, MTU=1160, 分流=global）…
[tunnel] 数据面地址替换：tun 192.0.2.111 ↔ 节点 10.211.1.145（节点侧看到的仍是它分配的地址）
[vpn] OpenVPN 系统 VPN 已启用（tun=192.0.2.111/32 ← 节点 10.211.1.145, tun fd=203, MTU=1160）
```

> 判据：固定节点能连上并出数据；`ipinfo.io` 显示节点所在国；DNS 走
> `10.211.254.254`（节点侧解析器）。
>
> 为什么不能用「换个地址但不做替换」：节点按 ifconfig 做回程 NAT，源地址不是它
> 分配的那个，回程包就找不到我们 —— 表现是「连上了、什么都打不开」。

### 28.2 「十几兆/秒」是缓冲排空造成的假高速

0.2.30 的测速是「窗口内总字节 ÷ 窗口时长」，但**窗口开始前**每条流在本端（gVisor /
内核）的接收缓冲里已经攒了几 MB（测速栈缓冲上限 4 MiB × 4 流 = 十几 MB）。这些字节
是预热阶段收到的，却会在窗口前半段被飞快读出来并计入窗口 —— 一条 2 MB/s 的链路能
报出 17 MB/s。

现在改成**逐区间采样（250ms）× 中位数**：丢掉前两个区间（排空缓冲 + 慢启动尾巴），
其余区间的速率取中位数。中位数对「某条流提前读完」这种掉速也免疫。

> 判据：同一节点在 speedtest 与这里的数字应在同一量级；真正的日本 10G 家宽仍可能
> 报 10 MB/s 以上 —— 那是真的，不是算错。

### 28.3 DNS 告警：它判的是「国家不一致」，不是「查询出了隧道」

用户截图里的三条解析器是 `162.158.185.202/.203/.28` —— 全是 **Cloudflare**，
说明查询确实走了隧道并在 Cloudflare 解析（没有落到运营商）。告警文案是
「解析器在 US，出口在 CN，不一致」，而出口 `104.28.245.200` 是 Cloudflare WARP
的出口 IP，只是它的**注册地**是 CN。

所以：

- 查询路径没问题（`/32` 主机路由把它钉在 tun 里）；
- 不一致来自「WARP 出口 IP 注册地 = CN」而「Cloudflare 递归出口注册地 = US」。

能真正对齐的只有一条路：**用出口那台机器自己的解析器**（它一定和出口同国）。
0.2.32 起，服务器下发的 DNS 里只要有私有地址（10/8、100.64/10 等），就只保留它、
丢掉 `8.8.8.8` 这类公共解析器 —— 于是「JP 节点 + JP 节点自己的解析器」，
测试显示的国家就一致了：

```
[dns] 防泄漏：下发 10.211.254.254（来源：服务器下发，1 条主机路由强制走隧道）
```

反过来，**不要**为了这个分数改用运营商 DNS：它的递归查询本身在墙内，被污染的
域名会拿到错误 IP —— 那是拿「能不能上网」换一个测试分数。

---

## 29. 0.2.34：刷新节点拉不到列表（WARP 上游起不来）

真机日志（2026-11-10 16:06）两连败，形态很典型：

```
[vpngate] 候选端点 28 个 × 端口 [2408 500 1701 4500]（awg），预算 1m0s
[engine] 刷新节点失败: … 在 1m0s 内没有找到可用端点（试了 20 次）
--- 再点一次 ---
[vpngate] 8.35.211.155:2408 握手成功，验证出口…
[vpngate] 8.35.211.155:2408 数据面不通（隧道内请求超时），换下一个
```

「20 个端点一个都握不上」= 这条网络在拦 UDP；「握手成功、数据面不通」= 小包能过、
数据大包被掐。刷新节点是**整条功能的第一步**，卡在这里等于什么都用不了，所以不能
只试一种传输：

1. **协议回退**（`dialFetchUnderlay`）：用户选的协议 → `awg` → `wg` → `masque`
   （H3/UDP）→ `masque-h2`（**TCP/443**，运营商整段封 UDP 时它是唯一的活路）。
   首个协议 30s、其余 15s，总上限 75s，不会把「换条路」拖成几分钟。
2. **账号兜底**（`RefreshVPNGateNodes`）：全部协议都失败时，删掉本地 WARP 账号、
   重新注册，再抓一次。被 Cloudflare 注销/限速的设备，握手照样成功、数据一个字节
   都不给 —— 表象和「网络不通」完全一样，靠换协议救不回来，只能换设备身份。

> 判据：日志里出现 `awg 上游失败：… → 换 wg 再试一次上游… → wg 上游成功` 或
> `重置账号后刷新成功`，节点列表正常刷出。
>
> 记住一条：**测速能测出几十/几百 KB/s、连接却失败**，多半不是节点问题，而是
> 「握手路径」和「数据路径」被分开对待了（DNS/DPI/地址冲突都可能）。看日志里失败
> 停在哪一步，再决定是换协议、换地址还是换账号。

---

## 30. 0.2.35：建 tun 被拒的第二种形态、反复注册账号、刷新进度

### 30.1 连 192.0.2.111 也被拒 → 地址不能写死

0.2.33 把 tun 地址换成保留地址后，真机日志（16:40）**还是同一句**：

```
[vpn] 第 1 次 establish（tun=192.0.2.111/32, 节点下发=10.211.1.1/32 …）…
[vpn] OpenVPN 建 tun 失败（IllegalArgumentException: Cannot set address /
    at Vpn.jniSetAddresses(Native Method) … at Vpn.establish(Vpn.java:1860)）
```

说明撞的不是「网段被占用」，而是**上一个 tun 接口还没回收时残留的同一个地址**
（`fd00:1:fd00:1:fd00:1:fd00:1/128` 每次都一样，最容易撞）。所以地址不能写死：

| # | tun 地址 | 带 v6 | 用途 |
|---|---|---|---|
| ① | 192.0.2.111 | 是 | 正常情况，v6 也抓（防泄漏） |
| ② | 192.0.2.111 | 否 | 排除「v6 地址残留」 |
| ③ | 192.0.2.x（随机） | 否 | 排除「v4 地址残留」 |
| ④ | 198.18.0.x（随机） | 否 | 整个网段都被系统记着 |

成功的那组地址会通过 `Engine.SetOpenVPNLocalAddr` 回填给引擎，包泵按它做
源/目的替换 —— 所以走哪一组都不影响连通性，日志里会看到：

```
[vpn] 第 1 次 establish（2/4 保留地址，不带 v6：tun=192.0.2.111/32 …）…
[vpn] OpenVPN 系统 VPN 已启用（tun=192.0.2.111/32 ← 节点 10.211.1.1, tun fd=203 …，本轮未抓 v6）
```

### 30.2 「每次启动都在重新注册 WARP 账号」

根因是**错误包装用了 `%v`**：`试了 N 个 OpenVPN 节点都失败（最后一个错误：%v）`
把 `errTunEstablish` 这条链切断了，于是 0.2.34 里那句「建 tun 失败不算账号问题」的
豁免从来没生效 —— 两次失败就把 `account.json` 删掉，下次启动重新注册一台设备。
用户看到的就是「每次都在注册」。

修法三条：
1. 改成 `%w`，`errors.Is(err, errTunEstablish)` 才能真正命中；
2. 只有「基础 WARP 隧道自己的失败」才计入 streak —— 节点出口（OpenVPN/Psiphon）
   连不上是节点/网络的事；
3. **刷新节点失败不再重置账号**（0.2.34 加的那条已删）：换协议已经在
   `dialFetchUnderlay` 做了，账号是启动时注册好的，不该因为一次抓取失败就换设备。

### 30.3 刷新节点没有进度说明

刷新走的是引擎日志（`[vpngate] 候选端点… → 握手成功… → 换 wg 再试…`），但选择器
对话框里只写了「刷新中…」。现在把最近一条 `[vpngate]` 日志同步显示在对话框里，
和「测延迟」的进度条同一套做法。

### 30.4 关于 CFNEW（byjoey/cfnew）能不能直接借鉴

读它的 README 后可以确认两件事：

1. **CFNEW 本身不是 mihomo 核心**，它是跑在 Cloudflare Workers 上的 JS 脚本
   （edgetunnel 改造）：入站 VLESS/Trojan、在 Worker 里生成各客户端订阅。
   「家宽链式」靠的是**客户端** mihomo（≥1.19.25）的 `type: openvpn` +
   `dialer-proxy` —— 也就是 mihomo 负责 OpenVPN 出站和 tun 数据面。
2. **它的延迟测试不是 OpenVPN 握手**：测的是 Cloudflare 优选 IP 的 TCP/TLS 延迟
   （并发 1–50、自动扣掉 DNS+TLS 时间）。所以「几秒测上百个」和「节点能不能连」
   本来就是两个问题。

我们这边 `engine/third_party/mihomo` 只 vendored 了 `openvpn`（客户端）和 `common`，
**没有** adapter / tunnel / listener(sing-tun) —— 要照搬「OpenVPN 作为 mihomo 出站、
tun 由内核建」这套，等于把大半个 mihomo 内核引进来（数万行 + 依赖）。这是可选项，
不是这一轮能顺手做完的事；本轮先把「建 tun 被系统拒绝」这条硬伤解决掉。

---

## 31. 0.2.36：先量清楚「慢在哪一层」

用户固定韩国节点，手机下行只有几兆，而**同一节点桌面版（mihomo 内核 + WARP 前置）
能跑到 100 Mbps**。两边链路结构其实一样：

```
桌面：应用 → wintun(内核 TCP) → mihomo 出站 → openvpn 客户端 → dialer-proxy(WARP) → UDP
手机：应用 → 系统 tun(内核 TCP) → 包泵 → openvpn 客户端 → netstack(WARP) → UDP
```

差异在「外层」：桌面 Windows 上 WARP 前端常是内核 WireGuard（或带批处理的
sing-wireguard），我们外层是**用户态 gVisor TCP**。所以手机上限天然低一截 ——
但 10 Mbps 对 100 Mbps 差了十倍，不能只用「手机 CPU 慢」解释。

**不能靠猜。** 0.2.36 在每次进程内第一次连 OpenVPN 出口时，先用**同一条 WARP 上游**
量一次它自己的下载吞吐（4 流，600ms 预热 + 1500ms 窗口），日志里一行：

```
[diag] WARP 上游自身吞吐 ≈ 8200 KB/s（4 流）
```

判据：

| 这一行的值 | 说明 | 下一步 |
|---|---|---|
| 几百 KB/s | 上游本身就被限速（国内直连 WARP 很常见） | 换端点/协议，或加中转，优化节点没用 |
| 几 MB/s，节点只有几百 KB/s | 瓶颈在 OpenVPN 传输层（用户态 TCP 窗口/丢包） | 做批处理/GSO（sing-tun 那套），或换 UDP 外层 |
| 十几 MB/s 以上，节点也慢 | 节点上传有限（VPN Gate 是志愿者家宽） | 换节点，不用改代码 |

同时做了两处**与诊断无关、但确定有益**的改动：

1. `netstackx` 的 `WriteNotify` 从「一次通知只取一个包」改成**把队列排空**，
   并把 `incomingPacket` 从 64 加深到 256 —— 上游 wireguard-go 的写法在高 pps
   下会把通知开销放大，突发时队列越积越多；
2. 保持 4 流测速口径不变，避免又出现「数字变了但没人知道为什么」。

### 31.1 诊断结果与它的含义（0.2.37）

真机（17:48）第一次量出来：

```
[tunnel] 诊断：WARP 上游自身吞吐 ≈ 36719 KB/s（4 流）     ← 294 Mbps
[tunnel] OpenVPN 出口 218.48.52.240 (KR)（节点路径 583 KB/s）
[vpn]    出口实测速度 ≈854 KB/s（KR家宽01）
```

**WARP 层完全不是瓶颈**（用户自己用 WireGuard 单层测也是 200–700 Mbps）。
但 18 个不同韩国节点（不同 ISP）全都落在 300–600 KB/s —— 这么整齐，不像节点上传，
更像「一条长连接被窗口钉住」：单条 gVisor TCP、RTT 60–80ms、窗口若只有 64–90 KB，
上限就是 1–1.4 MB/s，正好对上。

所以 0.2.37 把 gVisor 的**接收缓冲自适应关掉，改回固定大窗口**
（`Default = Max = 4/8 MiB`）：

- `ModerateRecvBuf` 是「本轮拷给用户的字节比上一轮多才抬窗口」的正反馈，
  窗口小 → 拷得少 → 不再增长。低 RTT 的短连接看不出问题，高 RTT 的长连接就被压住；
- 固定大窗口会在握手时协商窗口缩放（>64 KiB 才开），BDP 一次给足；
- 缓冲按实际到达的数据分配段，不是一上来就吃掉 4/8 MiB。

同时把诊断升级成**单流 + 四流**两档：

```
[diag] WARP 上游 1 流 ≈ 9000 KB/s，4 流 ≈ 36000 KB/s
```

- 单流就不低、节点仍低 → 问题在节点/跨境那一段；
- 单流很低、四流高 → 每条流的窗口/拥塞控制仍是瓶颈（继续优化传输层）。

---

## 32. 0.2.37 定论：速度问题解决了，以后按这张表判断

真机复测（2026-11-10 傍晚，0.2.37）：固定韩国节点 **下行 ≈ 80 Mbps**（此前同节点只有几兆），
赛风出口的速度同步提升。结论：**这轮踩的不是节点、不是测速算法，而是「用户态 TCP 的窗口」**。

### 32.1 四个决定性改动（按贡献排序）

| 序 | 改动 | 为什么是它 |
|---|---|---|
| ① | **关掉 gVisor 接收缓冲自适应，改固定大窗口（4/8 MiB）** | `ModerateRecvBuf` 是正反馈（本轮拷得少就不涨窗口），高 RTT 长连接被钉在几十 KB；固定窗口在握手时协商缩放，BDP 一次给足 |
| ② | netstack `WriteNotify` **一次排空队列** + 待发队列 64→256 | 上游 wireguard-go 一次通知只取一个包，高 pps 下通知开销把下行摊薄 |
| ③ | `ReadPacket` **复用 64 KB scratch**，不再每包 `make(64KB)` | 1 万包/秒 = 每秒 640 MB 垃圾，GC 直接压吞吐 |
| ④ | tun 地址替换（192.0.2.111 ↔ 节点地址）+ 四组候选地址 | 先让「连得上」成立：系统会拒绝 10.211.x.x，v6 地址还会被残留接口占用 |

### 32.2 判定「慢在哪一层」的顺序（照这个顺序看日志）

```
1) [diag] WARP 上游 1 流 ≈ A，4 流 ≈ B
      A、B 都很低（几百 KB/s）        → 上游/运营商限速，换节点没用
      A 低、B 高                      → 单流窗口/拥塞控制问题（本轮的 ①）
2) [probe] 节点测速（4 流）
      和 B 同量级                     → 正常，节点能跑满
      只有几百 KB/s                   → 节点上传 or 跨境路径
3) [vpn] 出口实测速度（连上后 512 KB × 4 短测）
      明显低于 2)                     → 多半是「TCP 套 TCP」+ 短测只覆盖启动段
```

> 第 3 条要特别注意：`出口实测速度` 是**512 KB × 4 的短测**，包含 TCP 慢启动，
> 天生偏低（实测同节点短测 854 KB/s，speedtest 稳定值 80 Mbps）。**不要拿它当最终速度**，
> 只当「有没有数据在流」的检查。

### 32.3 与桌面版仍存的差距（下一轮方向）

| 层 | 桌面（mihomo 内核） | 手机（本项目） | 差距原因 |
|---|---|---|---|
| 应用侧 tun | wintun（内核设备）+ 批量读写 | 系统 tun（内核）+ 每包一次 syscall | 手机 tun 无 VNET_HDR 批量接口，影响有限 |
| 外层传输 | gVisor + 批处理/GSO（QUIC 段还有 BBR） | gVisor + 单包通知 | 批处理/GSO 是下一步 |
| 拥塞控制 | QUIC 侧可开 BBR | 只有 CUBIC/RENO（gVisor 无 BBR） | 高丢包长链路上 BBR 优势明显 |

### 32.4 改网络栈前的检查清单（防重复踩坑）

1. 先量上游（`[diag]` 两档），再改任何参数；
2. 改缓冲前确认「自适应开关」的真实状态 —— gVisor 里 `Disabled` 时 `Max` 完全不生效；
3. 任何「一次只处理一个包」的循环都要问：突发时谁来吸收？（信道缓冲 + 排空循环）
4. 高频路径禁止按包分配大块内存，改成 scratch + 按实际长度拷；
5. 短测 ≠ 稳态：报告用户速度前，先确认采样窗口已经越过慢启动。

---

## 33. 0.2.38：masque 系列反复 `establish 异常: Cannot set address`

用户日志（2026-11-11 00:02，从 0.2.8 直接升到 0.2.36）形态非常整齐：

```
[vpn] 本次连接：协议=masque …
[dns] 防泄漏：下发 1.1.1.1（来源：用户设置，1 条主机路由强制走隧道），已剔除国内解析器 223.5.5.5
[vpn] establish 异常: Cannot set address
[vpn] 系统 VPN 建立失败（未授权或被系统拒绝），已中止连接
```

规律：

| 协议 | 结果 |
|---|---|
| masque / masque-h2 / masque-x2 | **全部** `Cannot set address` |
| wg / awg | 正常（`tun fd = 148 / 130 / 154`） |
| wwarp | `外层隧道没有可用端点`（另一个问题，见下） |
| 0.2.8 时代的 masque | 能连（`tun fd = 150`、`已建立 CONNECT-IP`） |

**根因不是协议，是地址。** 同一个 `establishTun` 里，v4 固定 `172.16.0.2/32`、
v6 固定 `fd00:1:.../128`；只要上一个 tun 接口还没被系统回收，新接口再配同一组
地址就会被 `Vpn.jniSetAddresses` 拒掉。触发场景在日志里都能对上：

- **协议热切换**：`[vpn] 协议热切换 → masque` → `connected -> stopping` → 立刻
  `establish`，旧接口还在关闭路上；
- **进程被杀后重启**：0.2.8 最后状态是 masque「已连接」，升级到 0.2.36 重启后
  第一次 establish 就撞上残留接口；
- v6 地址每次都一样，所以它是最容易撞的那一个。

0.2.37 只在 **OpenVPN 出口**（`establishOpenVpnTun`）加了四组候选地址，
WARP / MASQUE / Psiphon 共用的 `establishTun` 那条路径**漏了**。

**修法（0.2.38）**：`establishTun` 也按候选梯子建，失败换下一组：

| 序 | 地址 | 带 v6 | 用途 |
|---|---|---|---|
| 1 | 172.16.0.2/32 | 是 | 正常情况（v6 也抓，防泄漏） |
| 2 | 172.16.0.2/32 | 否 | 排除「v6 地址被残留接口占着」 |
| 3 | 172.16.0.2/32 | 否 | 先等 400ms 让系统回收旧接口，再试一次 |

> **v4 地址不能换**：引擎 netstack 的设备地址固定是 `172.16.0.2`，tun 上换成别的
> 之后，回程包在内核里没有归属，表现是「连上了、什么都打不开」。
> 与 OpenVPN 出口不同 —— 那条路有包泵做地址替换，所以能随便换。

日志判据：

```
[vpn] establish 失败（1/3 默认地址 + v6）：IllegalArgumentException: Cannot set address，换下一组再试
[vpn] 系统 VPN 已启用（tun fd=203, MTU=1280，第 2 组：不带 v6）
```

顺带记录两个**尚未修**的现象（同一份日志）：

1. `wwarp` 协议报 `外层隧道没有可用端点` —— 它需要一条外层 WARP，而当时端点池
   只剩 5 个候选（失败记忆把大部分端点标记掉了），随后 `复用已登记的外层设备`
   也没救回来；
2. 后期 `候选端点 5 个`（早期 28/29 个）—— 端点失败记忆的有效期偏长，网络恢复
   后需要等它过期；点「刷新节点」或重启 App 可立刻重置。

---

## 34. 0.2.39：我们有没有「误杀慢节点」？（有，但不是字节门槛）

用户问的是电脑版那个坑：**4 秒窗口内收满 64 KB 才算成功（=16 KB/s 下限）**，
`us-142.254.51.93` 收了 46480 字节就被判失败，其实能用。

### 34.1 我们没有字节门槛

`engine/warp/speedprobe.go` 的判定只有四条，**全都不是速度门槛**：

| 判定 | 含义 |
|---|---|
| `total == 0`（等首字节超时后） | 一个字节都没收到 |
| `len(rates) < 2` | 采样区间不足（窗口被提前截断） |
| `median(rates) <= 0` | 预热后没有任何新数据 |
| 其余 | **按实测速率报数**，哪怕只有几 KB/s |

`speedProbeBytes = 64 MiB` 只是「每条流申请下载多少」，不是成功门槛；
采样是 250ms 一档、丢掉前两档后取中位数。所以桌面那种「收了 46 KB 判失败」
在我们这里会显示 `≈11 KB/s`，不会标红。

### 34.2 但有一处**时间型**误杀（已修）

4 条流**各自**都要在 5 秒内完成「穿透节点建 TCP + TLS」：

```go
dctx, dcancel := context.WithTimeout(runCtx, connectTO)  // 默认 5s
```

慢节点（尤其 TCP-over-userspace 的出口）经常只来得及立起 1–2 条流，另外两三条
直接 `context deadline exceeded`；只要总量还是 0，整节点就被标成「测速失败」。
真机日志（2026-11-10）里的原话：

```
jp-219.100.37.62-443 握手成功 1381ms · 速度未测（没有收到数据（连接: context deadline exceeded））
kr-... 握手成功 · 速度未测（没有收到数据（TLS: context deadline exceeded））
```

握手只花 1.4 秒，说明节点是活的 —— 这就是误杀。

**修法（0.2.39）**：4 流失败后加一次**单流兜底**：

| 轮次 | 流数 | 建连超时 | 预热/采样 | 预算 |
|---|---|---|---|---|
| 第一次 | 4 | 5s | 800ms / 2s | 12s |
| 兜底 | **1** | **8s** | 1s / 2s | 15s |

单流对慢节点的建连压力小得多；只要兜底能拿到数据，就按实测速率报数
（单流数值偏低，但它只用于「能不能用」的判断，不改变 4 流的主口径）。
硬超时上限同步从 `budget+12s` 调到 `budget+16s`，避免兜底跑到一半被关。

### 34.3 仍然存在的边界（记录在案，不算误杀）

| 场景 | 表现 | 说明 |
|---|---|---|
| 握手 > 10s | `OpenVPN 握手失败: context deadline exceeded` | 控制通道都建不起来，判失败合理 |
| 首字节 > 建连超时+2s | `首字节超时（等待 8s+2s）` | 文案已改成带具体秒数，不再写「1 秒」 |
| 单流兜底也只有几 KB/s | 正常报 `≈N KB/s`，排序靠后 | 可用但慢，不标红 |
| 节点只转发特定端口 | 测速端点不通、浏览正常 | 测速端点固定 `speed.cloudflare.com`，属于口径限制 |

> 一句话：**判失败只看「有没有数据」，不看「数据够不够多」**。速度只影响排序，
> 不影响可用性判定 —— 这是 0.2.30 起就定下的口径，0.2.39 补上了「慢节点也要
> 有机会把第一个字节吐出来」这条时限。
