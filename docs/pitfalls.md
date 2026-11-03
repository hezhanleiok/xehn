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

> 查法：解压 APK 取 `libgojni.so` / `classes*.dex`，转 Latin1 后按 UTF-8 字节做 `IndexOf`（PowerShell 一行即可），比逐个装上试快得多。
