package com.xiaohe.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.content.pm.ServiceInfo
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 常驻服务：系统 VPN 与会话的主人。
 *
 * 桌面版把「守护」做成 detach 的子进程（health.go 的 spawnHealthGuard 再 spawn
 * 自己）。Android 上 os.Executable() 指向 apk 内部不可执行的路径，那套方案必须
 * 整体丢掉 —— 换成「前台 Service 持有 Engine + VpnService 建 tun」。
 *
 * 这一版的核心变化：**连接 = 真的建立系统 VPN**。之前只有进程内的 gVisor 隧道，
 * 系统 VPN 根本没起来，手机上其它应用一个字节都不走它 —— 界面显示「已连接」而
 * 状态栏没有 VPN 钥匙，就是那个状态。现在顺序是：
 *
 *   装 socket protector → VpnService.Builder.establish() → 把 fd 交给引擎
 *   → 引擎用 OS tun 做数据面 → 隧道内验证出口
 *
 * 任何一步失败都直接报错收摊，绝不留下「显示已连接但没路由」的假成功。
 */
class WarpVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.xiaohe.vpn.action.CONNECT"
        const val ACTION_DISCONNECT = "com.xiaohe.vpn.action.DISCONNECT"
        /** 已连接时换协议：不退出前台服务，只把引擎会话换成新协议重连。 */
        const val ACTION_SWITCH_PROTO = "com.xiaohe.vpn.action.SWITCH_PROTO"
        const val EXTRA_PROTO = "proto"
        const val EXTRA_ENDPOINT = "endpoint"
        const val EXTRA_PSIPHON = "psiphon"
        const val EXTRA_OPENVPN = "openvpn"

        private const val NOTIF_ID = 1001
        private const val CHANNEL_ID = "vpn-state"

        /** 隧道里用的设备地址（Cloudflare WARP 会给设备一个 172.16.0.2/32）。 */
        private const val TUN_ADDR_V4 = "172.16.0.2"
        private const val TUN_ADDR_V6 = "fd00:1:fd00:1:fd00:1:fd00:1"

        /**
         * 已知会被 leak 测试判成「DNS 泄露」的国内公共解析器。
         *
         * 不按网段判断（大陆网段表可能还没下载、而且会误伤用户自己搭的解析器），
         * 只列这些「一定会把查询落到国内」的公共地址。用户如果确实想用它们，把
         * 设置里的「DNS 防泄漏」关掉即可 —— 那时候列表原样下发。
         */
        private val LEAKY_RESOLVERS = setOf(
            "223.5.5.5", "223.6.6.6",           // 阿里
            "114.114.114.114", "114.114.115.115", // 114DNS
            "119.29.29.29", "182.254.116.116", "182.254.116.117", // DNSPod
            "180.76.76.76",                    // 百度
            "1.2.4.8", "210.2.4.8",            // 世纪互联/CNNIC
            "117.50.10.10", "117.50.11.11",    // 下一代
            "52.80.66.66", "101.226.4.6", "123.125.81.6", // 电信/联通/百度
            "180.184.1.1", "180.184.2.2",      // 字节
            "218.30.118.6", "202.96.128.86", "202.96.134.133", // 各地电信
        )

        /**
         * Psiphon packet tunnel 的 MTU（tunnel-core 的 DEFAULT_MTU）。
         *
         * Psiphon 会往 tun 写最多 1500 字节的包，而内核会按接口 MTU 丢弃过大的包 ——
         * 接口 MTU 设 1280 时表现为「连上了、小请求通、稍微一大就断」。所以走
         * Psiphon 出口时，系统 tun 必须用它的 MTU；基础隧道在 netstack 里，
         * 不受这个值影响。
         */
        private const val PSIPHON_TUN_MTU = 1500

        /**
         * MASQUE（CONNECT-IP）的系统 tun MTU，按**传输地址族**分开。
         *
         * 每个 IP 包封装成一个 QUIC DATAGRAM：内层包 + contextID + DATAGRAM 帧头 +
         * QUIC 头 + UDP + IP。路径 MTU 决定了上限：
         *
         *   v4 路径 MTU 1500 → tun 1300，封装后约 1368，留 130 字节余量；
         *   v6 路径 MTU 1280 → tun 1160，封装后约 1228，留 50 字节余量。
         *
         * 以前一律 1200（按 v6 的最坏情况取），白白丢掉 8% 载荷 —— 在「一个包
         * 一次 syscall + 一次加密」的链路上，包数少 8% 就是实打实的 8%。Aether
         * （Rust + quiche）对应的取值是 1200…1350，同一量级。
         *
         * 引擎侧 masqueMTU() 的上限是同一组数（masqueMaxTunMTU / masqueMaxTunMTUV6），
         * 两边必须一致：内核按 Builder 的 MTU 切包，引擎按自己的 MTU 封装。
         */
        private const val MASQUE_TUN_MTU_V4 = 1300
        private const val MASQUE_TUN_MTU_V6 = 1160

        /** 当前设置下 MASQUE 该用哪个 tun MTU（v6 传输要留出 1280 的路径 MTU）。 */
        private fun masqueTunMtu(s: AppSettings): Int =
            if (s.ipv6) MASQUE_TUN_MTU_V6 else MASQUE_TUN_MTU_V4

        /**
         * OpenVPN 出口的系统 tun MTU。
         *
         * 服务端 tun-mtu 通常是 1500，但经 WARP 时外层 netstack MTU 只有 1280
         * （MSS 1240），一个内层包要再套 OpenVPN 头（长度 2 + opcode 1 + HMAC 20
         * + IV 16 + CBC 填充 ≤16 ≈ 55），所以内层最多 ~1185。
         *
         * 原来用 1400，每个包都被外层拆成 1240+160 两段 —— 包量和加密次数接近翻倍。
         * 现在取 1160，1 个包正好 1 个外层段。直连模式下这也是个稳妥值。
         */
        private const val OPENVPN_TUN_MTU = 1160

        /**
         * OpenVPN 出口时系统 tun 上用的**本机地址**（不是节点下发的那个）。
         *
         * 192.0.2.0/24 是 RFC 5737 的 TEST-NET-1（保留给文档），任何真实网络都不会
         * 分配，所以永远不会和物理网卡/运营商网段冲突。节点下发的 10.211.x.x 在
         * 引擎的包泵里做一对一替换（出去换源、回来换目的），对节点完全透明。
         *
         * 必须与 `engine/warp/openvpn.go` 的 `openVPNLocalSurrogate` 一致。
         */
        private const val OPENVPN_TUN_LOCAL = "192.0.2.111"

        /**
         * 订阅出口时系统 tun 的地址。
         *
         * 现在 tun 由**我们自己的 gVisor 栈**读写（tun2socks），本地地址就是它
         * 认的 172.16.0.2 —— 与普通 WARP 模式一致。mihomo 不再碰 tun
         * （它自带的 tun 在非 root Android 上必然失败）。
         */
        private const val SUB_TUN_V4 = "172.16.0.2"

        /** 看门狗多久看一次快照。 */
        private const val WATCHDOG_TICK_MS = 5_000L
        /** 自动重连的统计窗口与上限：5 分钟内最多 3 次。 */
        private const val RECOVER_WINDOW_MS = 5 * 60_000L
        private const val RECOVER_MAX = 3

        /**
         * 一次连接最多交多少个候选给引擎。
         *
         * 引擎单轮只试 5 个，但会跳过 10 分钟内失败过的节点，所以给足 24 个才能覆盖
         * 「同国同类全挂 → 同国其他类 → 别的国家」这条阶梯，而不至于卡在同一批。
         */
        private const val OPENVPN_CANDIDATE_CAP = 24

        /**
         * 一次点击最多试几个节点（每个节点一次 connect、一次 establish）。
         *
         * 原来是「一次 connect 里引擎连试 5 个」，真机日志显示进程总是在同一次连接
         * 的第 3~5 次建立系统 VPN 之后直接消失（0.2.4 第 5 次、0.2.5 第 4 次/第 3 次）。
         * 改成一次只建一次系统 VPN，并把单次点击的上限压到 3，先把「反复 establish」
         * 这个变量摘掉；失败记忆还在（引擎侧 10 分钟），下次点击自然会换别的节点。
         */
        private const val OPENVPN_MAX_TRIES = 3

        /**
         * 出口测速要下载的字节数 —— 与电脑版 `openvpnSpeedProbeBytes` 一致（512 KiB）。
         *
         * 电脑版的注释写得很清楚：通用验证那档 128 KiB 会被 TCP 慢启动主导，
         * 分不出「真的快」和「只是没卡住」。同一个下载顺带喂速度排序。
         */
        private const val OPENVPN_SPEED_PROBE_BYTES = 512 * 1024

        /**
         * 测速的整体预算。超过就按「已经收到的字节 ÷ 实际耗时」算 ——
         * 100 KB/s 的节点跑完 512 KiB 要 5s，而 14 KB/s 的要 36s：不能为了
         * 量准一个慢节点让用户干等半分钟，8s 内拿到的量已经够分档。
         */
        private const val OPENVPN_SPEED_PROBE_BUDGET_MS = 8_000L

        /**
         * 测速并发流数。
         *
         * 单流在 200ms RTT 的跨境线路上被慢启动压到几十 KB/s，读数只有真实能力的
         * 一小部分 —— 于是「自动选最快」实际是在按错误读数挑节点。4 条并发能在一
         * 两秒内打满带宽，代价是 4 × 512 KiB 的流量。
         */
        private const val SPEED_PROBE_STREAMS = 4

        /**
         * 速度地板：低于它换下一个中继。
         *
         * 与 [NodeSpeedStore.MIN_BPS] 是**同一个数**，必须同源：排序里的「快/慢」
         * 分档和这里「要不要换掉」讲的是同一件事，两边一旦不同就会出现
         * 「排序认为它慢、连接时却保留」这种自相矛盾的行为（0.2.9 就是这样）。
         *
         * 100 KB/s（约 0.8 Mbps）：真机实测 VPN Gate 家宽多在 50–100 KB/s，
         * 低于它的基本就是「连上了但页面在爬」。
         */
        private const val OPENVPN_MIN_BPS = NodeSpeedStore.MIN_BPS

        /**
         * 连着几个中继都偏慢之后就不再因速度换点（电脑版 `openvpnSpeedRetries`）。
         *
         * 慢总比连不上强：换到第 3 个还是慢，说明这段网络里 VPN Gate 就这样，
         * 再换只是把用户的等待时间翻倍。
         */
        private const val OPENVPN_SPEED_RETRIES = 2

        /**
         * 等一次连接出结果的上限。
         *
         * 只是兜底：引擎自己按「每个候选一个预算」收敛，正常 10–60s 内一定有
         * connected / error 之一。真超时了也不去动引擎（它可能马上就通了），
         * 只写一行日志。
         */
        private const val CONNECT_OUTCOME_TIMEOUT_MS = 6 * 60_000L
    }

    private var tunFd = -1

    /**
     * 系统 tun 的唯一持有者。
     *
     * 2026-11-03 之前是 `pfd.detachFd()` 把裸 fd 交给 Go，由 Go 关；真机上换点几次
     * 之后稳定 SIGABRT：
     *
     *   fdsan: failed to exchange ownership of file descriptor: fd 193 is owned by
     *   unique_fd 0x..., was expected to be unowned
     *
     * 也就是同一个 fd 被两边各记了一份所有权。现在反过来：**ParcelFileDescriptor
     * 自己持有、自己关闭**（[closeTun]），引擎只借用读写、绝不 close（见
     * engine/warp/pktfile_android.go）。Java 层 catch 不到 native abort，所以这
     * 类问题只能从所有权上根治，不能靠 try/catch。
     */
    private var tunPfd: ParcelFileDescriptor? = null

    /** 关闭系统 tun（幂等）。只有这里关 —— 引擎侧一律不关。 */
    private fun closeTun() {
        // 订阅出口：内核握着 tun fd，必须先停内核再关 fd
        // （sing-tun 对着已关闭的 fd 读写会刷一串 "use of closed file"）。
        EngineBridge.peek()?.let { e ->
            runCatching { e.stopSubExit() }
            // 会话状态也要收回去，否则断开后首页还显示「已连接」。
            runCatching { e.markSubExitStopped() }
        }
        val p = tunPfd ?: return
        tunPfd = null
        tunFd = -1
        runCatching { p.close() }
    }

    /**
     * 本次进程里第几次为 OpenVPN 出口 establish。
     *
     * 2026-11-01 真机就是死在这里：日志停在「第 5 次建立系统 VPN 成功」之后、
     * 出口验证之前，进程直接没了。次数要写进日志才能看出「是不是反复 establish
     * 把进程搞死的」—— 同一次连接里每换一个节点就会重新 establish 一次。
     */
    private var tunEstablishCount = 0

    /** 自动重连用的协程作用域（随服务销毁回收）。 */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var watchdog: Job? = null

    /**
     * 当前这一轮「拨号 + 出口测速/换点」的协程。
     *
     * 必须单独持有句柄：`e.connect()` 是异步的（Engine.Connect 起 goroutine 就
     * 返回），所以连接流程本身是个长任务；用户点断开或看门狗重连时，要把上一轮
     * 还在等结果的协程取消掉，否则它会接着把刚断开的东西又连回去。
     */
    private var connectJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 只有「进程里还没有引擎」才可能是全新进程（例如系统重新拉起前台服务）：
        // 这种情况补一条启动标记，否则闪退后重开只剩断掉的日志，看不出边界。
        if (EngineBridge.peek() == null) CrashGuard.markStart(this, "Service")
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                shutdown()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                startForegroundSafely(getString(R.string.notif_connecting))
                startWatchdog()
                val proto = intent.getStringExtra(EXTRA_PROTO) ?: SettingsStore.load(this).proto
                // 账号必须在建 tun **之前**注册好：系统 VPN 一建立，DNS 查询就被
                // 路由进还没通的隧道，注册域名会解析失败（真机日志里 MASQUE 就卡
                // 在这一步：lookup api.cloudflareclient.com: no such host）。
                scope.launch {
                    withContext(Dispatchers.IO) {
                        EngineBridge.prepareAccounts(this@WarpVpnService, proto)
                    }
                    startConnect(intent)
                }
                return START_NOT_STICKY
            }
            ACTION_SWITCH_PROTO -> {
                // 热切换：服务不退出、通知不重建，只换引擎里那条隧道。
                startForegroundSafely(getString(R.string.notif_connecting))
                switchProto(intent)
                return START_NOT_STICKY
            }
            else -> {
                // 没有任何指令就进来了（例如系统重建服务）：绝不擅自建立 VPN。
                // 建 VPN 必须是用户点出来的动作，这也是 START_NOT_STICKY 的理由。
                EngineBridge.note("[vpn] 收到空指令，未做任何事")
                return START_NOT_STICKY
            }
        }
    }

    /**
     * 协议热切换。
     *
     * 安卓没有「换一条隧道但系统 VPN 不动」的接口 —— 协议变了就必须重建 tun
     * （MASQUE 用 1300 的 MTU、Psiphon 用 1500、其它用设置里的值）。所以这里的
     * 「热」是指：**服务不退出、通知不重建、用户不用先点断开**，只把引擎里的
     * 会话换掉，再用新协议连一次。整个过程约 1–3 秒。
     */
    private fun switchProto(intent: Intent) {
        val e = EngineBridge.peek()
        if (e == null) {
            startConnect(intent)
            return
        }
        val target = intent.getStringExtra(EXTRA_PROTO) ?: SettingsStore.load(this).proto
        EngineBridge.note("[vpn] 协议热切换 → $target")
        connectJob?.cancel()
        connectJob = null
        runCatching { e.disconnect() }
        runCatching { e.setVPNState(false) }
        EngineBridge.refresh(e)
        scope.launch {
            // 等状态机回到 idle（最多 3 秒）；startConnect 内部还有一次 awaitIdle 兜底。
            val deadline = System.currentTimeMillis() + 3000
            while (System.currentTimeMillis() < deadline) {
                EngineBridge.refresh(e)
                val st = EngineBridge.state.value.state
                if (st == "idle" || st == "error") break
                delay(100)
            }
            startConnect(intent)
        }
    }

    private fun startConnect(intent: Intent?) {
        val e = EngineBridge.engineOrCreate(this)
        val s = SettingsStore.load(this)

        // 坑：getBooleanExtra 返回的是**非空** Boolean —— intent 没带这个 extra 时
        // 它给的是默认值 false，`?: s.psiphon` 这两条分支永远不会走到 Elvis 后面，
        // 结果就是「Psiphon 出口」开关开了也一直是 false（开关看起来完全无效）。
        // 必须用 hasExtra 区分「intent 没带」（退回本地设置）与「intent 明确说是
        // false」（用户刚关掉）。proto 用 getStringExtra 是可空的，本没这个坑，
        // 但保持同一种写法，免得以后再踩。
        val proto = if (intent?.hasExtra(EXTRA_PROTO) == true) {
            intent.getStringExtra(EXTRA_PROTO) ?: s.proto
        } else {
            s.proto
        }
        val psiphon = if (intent?.hasExtra(EXTRA_PSIPHON) == true) {
            intent.getBooleanExtra(EXTRA_PSIPHON, false)
        } else {
            s.psiphon
        }
        val openvpn = if (intent?.hasExtra(EXTRA_OPENVPN) == true) {
            intent.getBooleanExtra(EXTRA_OPENVPN, false)
        } else {
            s.openvpn
        }
        EngineBridge.note(
            "[vpn] 本次连接：协议=$proto，Psiphon 出口=$psiphon，OpenVPN 出口=$openvpn"
        )

        // 1) 先装 socket 排除器，必须在 establish 之前：系统 VPN 一建立，
        //    隧道自己发往 Cloudflare 的 UDP 就会被自己的 VPN 抓回去，
        //    握手包出不去，表现是「已连接但打不开网页」。
        //    OpenVPN 模式同样需要：它的外层连接跑在 WARP netstack 里，
        //    那些 socket 必须在系统 VPN 建起来之前就被排除。
        EngineBridge.installProtector(this, this)

        if (s.isProxyMode) {
            // 2) 仅代理：**不建系统 VPN**。tun fd 传 0，引擎退成 netstack，并把
            //    本地 SOCKS5 开在设置里的地址上（0.0.0.0 = 允许局域网访问）。
            e.setTunFD(0)
            e.setVPNState(false)
            e.setTimeout(s.timeoutSec.toLong())
            e.setSocksListen(s.proxyListenAddr())
            EngineBridge.note("[vpn] 代理模式：监听 ${s.proxyListenAddr()}，不建立系统 VPN")
            EngineBridge.refresh(e)
        } else if (psiphon) {
            // 2) Psiphon 出口：同样**不提前建 tun**。
            //
            // 以前这里是提前 establish 的，结果上游 WARP 的 UDP 在「系统 VPN 刚
            // 建立」的窗口里被丢：真机日志 14 个端点全是「握手成功、数据面不通」，
            // 同一时刻 OpenVPN 出口用同一条 awg 上游却是通的 —— 差别只有建 tun 的
            // 时机。现在改成上游就绪后由 psiphonTunProvider 回调建 tun。
            e.setTunFD(0)
            e.setVPNState(false)
            e.setTimeout(s.timeoutSec.toLong())
            // 本地代理 / 局域网共享：Psiphon 自己的 SOCKS 只绑回环，引擎会在
            // 出口就绪后另开一个面向用户的监听（链式经 Psiphon）。以前这里是
            // 直接写 ""，等于在 Psiphon 出口下彻底关掉了这个功能。
            e.setSocksListen(if (s.localProxy || s.proxyLan) s.proxyListenAddr() else "")
            EngineBridge.installTunProvider(this, psiphonTunProvider)
            EngineBridge.note("[vpn] Psiphon 出口：先建上游，就绪后再建系统 VPN")
            EngineBridge.refresh(e)
        } else if (openvpn) {
            // 2) OpenVPN 出口：**不能提前建 tun**。
            //
            //    VPN Gate 的服务端按它 PUSH_REPLY 下发的 ifconfig 地址（10.x.x.x/24）
            //    回程；用 WARP 的 172.16.0.2 建 tun 的话，回程包会被服务端丢在自己的
            //    路由里，表现就是「握手成功、什么都打不开」。地址只有握手之后才知道，
            //    所以这里先把 tun 置 0（基础协议退成 netstack），等引擎回调
            //    TunProvider 时再用真实地址 establish。
            e.setTunFD(0)
            e.setVPNState(false)
            e.setTimeout(s.timeoutSec.toLong())
            // 同上：节点出口下也要能开本地代理 / 局域网共享（拨号走这条节点）。
            e.setSocksListen(if (s.localProxy || s.proxyLan) s.proxyListenAddr() else "")
            EngineBridge.installTunProvider(this, openvpnTunProvider)
            EngineBridge.note("[vpn] OpenVPN 出口：先握手拿地址，再建系统 VPN")
            EngineBridge.refresh(e)
        } else {
            // 2) 建系统 VPN。失败就明确报错，不进入连接流程。
            val fd = establishTun(s, psiphon, proto)
            if (fd < 0) {
                EngineBridge.note("[vpn] 系统 VPN 建立失败（未授权或被系统拒绝），已中止连接")
                e.setVPNState(false)
                EngineBridge.refresh(e)
                stopForegroundCompat()
                stopSelf()
                return
            }
            tunFd = fd
            e.setTunFD(fd.toLong())
            e.setVPNState(true)
            e.setTimeout(s.timeoutSec.toLong())
            // VPN 模式默认不开本地端口（整个系统已经走隧道）；但用户想要
            // 「局域网共享」——让同一 Wi-Fi 的电脑借这条隧道 —— 就需要一个监听在
            // 局域网上的 SOCKS5 入口，所以这里按设置决定。
            val socks = if (s.localProxy || s.proxyLan) s.proxyListenAddr() else ""
            e.setSocksListen(socks)
            if (socks.isNotEmpty()) {
                EngineBridge.note("[vpn] 本地代理已开启：$socks（局域网共享入口）")
            }
            EngineBridge.note(
                "[vpn] 系统 VPN 已启用（tun fd=$fd, MTU=" +
                    when {
                        psiphon -> PSIPHON_TUN_MTU
                        proto.startsWith("masque") -> masqueTunMtu(s)
                        else -> s.mtu
                    } + "）"
            )
            EngineBridge.refresh(e)
        }

        // 2.5) 订阅出口：tun 已经建好，交给内嵌 mihomo 接管，不再走 connectLoop。
        //
        //     数据路径（与电脑版 openvpn + dialer-proxy 同构）：
        //       系统 tun → mihomo → 订阅节点 → dialer-proxy(本地 SOCKS) → WARP → 节点
        //     所以这里只需把 fd 和「国家/订阅地址/物理网卡」交给引擎，剩下的它自己做。
        if (s.subExit && !psiphon && !openvpn) {
            connectJob?.cancel()
            EngineBridge.note(
                "[subout] 订阅出口：国家=${s.subCountry}，订阅=" +
                    (if (s.subCustomURL.isBlank()) "内置分片" else s.subCustomURL)
            )
            connectJob = scope.launch {
                try {
                    // 立刻转「连接中」：建上游 + 拉订阅要十几秒，这段必须有状态反馈。
                    runCatching { e.markSubExitConnecting() }
                    EngineBridge.refresh(e)
                    val iface = activeInterfaceName()
                    if (iface.isNotEmpty()) {
                        EngineBridge.note("[subout] 物理网卡 = $iface（内核出口绑它，避免被自己的 VPN 抓走）")
                    }
                    val r = withContext(Dispatchers.IO) {
                        e.startSubExit(proto, tunFd.toLong(), s.subCountry, s.subCustomURL, iface)
                    }
                    EngineBridge.note("[subout] $r")
                    if (!r.startsWith("订阅出口已启动")) {
                        runCatching { e.stopSubExit() }
                        runCatching { e.markSubExitStopped() }
                        closeTun()
                        e.setVPNState(false)
                        EngineBridge.refresh(e)
                        stopForegroundCompat()
                        stopSelf()
                        return@launch
                    }
                    // 数据面由 mihomo 接管，不经过 Engine.connect，所以要显式把会话
                    // 置成「已连接」—— 否则首页一直停在「未连接」，看起来像按钮没反应。
                    runCatching { e.markSubExitConnected(s.subCountry) }
                    e.setVPNState(true)
                    EngineBridge.refresh(e)
                } catch (t: Throwable) {
                    EngineBridge.note("[subout] 订阅出口异常：${t.javaClass.simpleName}: ${t.message}")
                    runCatching { e.stopSubExit() }
                    closeTun()
                    e.setVPNState(false)
                    EngineBridge.refresh(e)
                }
                updateNotification()
            }
            return
        }

        // 出口地区必须在 connect 之前下发：它是 tunnel-core 的启动参数（EgressRegion），
        // 运行中改不了。空串 = 自动。
        e.setPsiphonRegion(s.exitRegion)
        // 分流规则同理：只在本地 SOCKS（仅代理模式）上执行，必须在 connect 之前下发。
        e.setRules(s.rulePolicy, s.ruleText)
        val endpointExtra = intent?.getStringExtra(EXTRA_ENDPOINT) ?: ""

        // 3) 选出口节点 + 4) 拨号 + 5) 出口测速，放进协程里。
        //
        //    为什么必须是协程：`e.connect()` 是**异步**的（Engine.Connect 只起
        //    goroutine 就返回 nil），所以原来这里 `try { e.connect() } catch {}`
        //    永远走不到第二轮 —— 那三档「自动换下一批」其实从来没生效过。
        //    现在改成「发起 → 等结果 → 按结果决定」，顺便把「节点通了但太慢」
        //    也当成一种可轮换的结果（见 connectLoop）。
        connectJob?.cancel()
        connectJob = scope.launch {
            // 必须在协程里接住所有异常：gomobile 的 Java 代理在状态机拒绝时抛
            // `go.Universe$proxyerror: session: 状态 connecting 不能转到 connecting`，
            // 这是 RuntimeException —— scope 跑在 Main.immediate 上，漏出去就是
            // main 线程未捕获异常，进程直接崩（真机日志里有一整条这种闪退）。
            try {
                connectLoop(e, s, proto, endpointExtra, psiphon, openvpn)
            } catch (c: kotlinx.coroutines.CancellationException) {
                throw c
            } catch (t: Throwable) {
                EngineBridge.note("[vpn] 连接流程异常：${t.javaClass.simpleName}: ${t.message}")
                // 状态机可能停在 connecting：拉回 idle，别让下一次点击也连不上。
                runCatching {
                    e.disconnect()
                    e.setVPNState(false)
                }
                EngineBridge.refresh(e)
                // 异常路径同样要把 tun 关掉，否则系统 VPN 会一直挂着。
                closeTun()
                stopForegroundCompat()
                stopSelf()
            }
            updateNotification()
        }
    }

    /**
     * 拨号 +（OpenVPN 出口）测速与换点。
     *
     * 这一段的规则整份来自电脑版（`connect.go` 的 openvpnSpeedProbe* /
     * openvpnMinBps / openvpnSpeedRetries，`vpngate.go` 的实测速度记忆）：
     *
     *  1. 连上之后**真下载一次**（512 KiB，最多 8s）量出口吞吐 —— 出口 IP 对了
     *     不代表能用：电脑版实测 VPN Gate 上存在「握手成功、控制通道正常、
     *     14 KB/s」的节点，旧门槛（≈11 KB/s）拦不住，用户看到的是「连上了、
     *     每个网页都在爬」；
     *  2. 低于地板就换下一个中继，最多连着换 [OPENVPN_SPEED_RETRIES] 个，
     *     之后即便还慢也保持连接（慢总比没有强）；
     *  3. 用户**钉死的节点不因速度换掉** —— 那是用户的选择，只报告速度；
     *  4. 每次实测都写进 [NodeSpeedStore]，下次排序「实测快的优先、慢的垫底」。
     *
     * 换点粒度是「一个节点一次 connect」：每次只把 1 个节点 id 交给引擎，
     * 所以一次连接只 establish 一次系统 VPN（见 [OPENVPN_MAX_TRIES]）。
     *
     * 为什么在 Kotlin 侧而不是引擎里：tun 是 VpnService 建的，换点必然要重新
     * establish()，只能在 Java 侧做；而「等结果」需要的是 Engine 的状态。
     */
    private suspend fun connectLoop(
        e: com.xiaohe.engine.Engine_,
        s: AppSettings,
        proto: String,
        endpointExtra: String,
        psiphon: Boolean,
        openvpn: Boolean,
    ) {
        if (!openvpn) {
            // 关的时候必须显式清空，否则上一次选中的节点会留在引擎里，下一次
            // 「关着 OpenVPN」的连接仍然走节点（最难查的那种残留）。
            e.setOpenVPNExit("", "", "")
            if (!connectSafely(e, proto, endpointExtra, psiphon, s)) {
                teardownAfterFailure("引擎拒绝这次连接（状态未就绪）")
                return
            }
            // 这条路（psiphon / masque / wwarp / wg / awg）的系统 VPN 是**连接前**
            // 就建好的（见 startConnect 的第 2 步），所以失败时也必须在这里收掉：
            // 引擎只会把状态打成 error，它碰不到 tun fd（fd 归 ParcelFileDescriptor），
            // 不收的表现就是「界面显示连接失败，系统 VPN 图标却一直亮着」。
            val state = awaitConnectOutcome(e)
            if (state == "connected") return
            if (state == "idle" || state == "stopping") {
                EngineBridge.note("[vpn] 连接已取消")
                return
            }
            teardownAfterFailure("连接失败（引擎状态 $state）")
            return
        }

        val pinnedId = s.openvpnNodeId
        // 本次点击里已经试过的节点（握手失败的、太慢的）。
        // 一次点击不再把一堆节点塞给引擎，而是「一次只试一个」：引擎拿到几个
        // 候选就会在一次 connect 里连续 establish 几次系统 VPN，而真机日志显示
        // 进程总是在同一次连接的第 3~5 次 establish 之后直接消失。
        val tried = LinkedHashSet<String>()
        var slowRejects = 0
        var attempts = 0
        /** 因速度被指定换过去的节点（见下面 faster 的判定）。 */
        var preferId: String? = null

        while (true) {
            val nodes = EngineBridge.vpnGateNodes(this)
            val measured = nodes.count { it.measuredBps > 0 }
            if (measured > 0) {
                EngineBridge.note(
                    "[vpn] 中继速度记忆：$measured 个有实测记录，排序已按实测速度优先"
                )
            }
            val ranked = pickOpenVPNCandidates(s, nodes)
            if (ranked.isEmpty()) {
                e.setOpenVPNExit("", "", "")
                teardownAfterFailure(
                    "没有可用的 OpenVPN 节点（节点列表为空、地区无节点或选中节点已失效），" +
                        "请到设置 → OpenVPN 出口里刷新或重选"
                )
                return
            }
            // preferId 是「因速度被判定该换过去」的那个节点：它已经排在候选里，
            // 但如果按「第一个没试过的」挑，会挑到排在前面的未知节点 —— 那是在赌。
            val first = preferId
                ?.let { id -> ranked.firstOrNull { it.id == id } }
                ?.also { preferId = null }
                ?: ranked.firstOrNull { it.id !in tried }
            if (first == null) {
                teardownAfterFailure(
                    if (pinnedId.isNotEmpty()) {
                        "固定节点连接失败，本次不再自动换别的节点（你可以换一个固定节点或改回自动）"
                    } else {
                        "本次试过的 ${tried.size} 个节点都失败了，停止重试（失败的节点 10 分钟内不再尝试）"
                    }
                )
                return
            }
            if (attempts >= OPENVPN_MAX_TRIES) {
                teardownAfterFailure(
                    "本次已试 $attempts 个节点都没成功，先停在这里" +
                        "（每次点击最多试 $OPENVPN_MAX_TRIES 个，避免反复建系统 VPN 把进程搞死）"
                )
                return
            }
            attempts++
            tried.add(first.id)
            EngineBridge.note(
                "[vpn] 本次第 $attempts/$OPENVPN_MAX_TRIES 个，候选共 ${ranked.size} 个：" +
                    "${nodeSlotLabel(nodes, first)}" +
                    "（${first.country} ${first.ip}:${first.port}，${first.classLabel}" +
                    (if (first.shared) "·共享" else "") + "，" +
                    (if (first.hasMeasuredLatency) "${first.latencyMs}ms" else "未测") + "，" +
                    "自报 ${if (first.speedBps > 0) "${first.speedBps / 1024} KB/s" else "未知"}，" +
                    "实测 ${first.measuredText}）"
            )
            // 只给引擎 1 个节点：一次 connect 只有 1 次 establish。
            e.setOpenVPNExit(first.id, nodeSlotLabel(nodes, first), first.cc)
            if (!connectSafely(e, proto, endpointExtra, psiphon, s)) {
                EngineBridge.note("[vpn] 引擎拒绝这次连接（状态未就绪），稍后重试")
                awaitIdle(e)
                continue
            }

            val state = awaitConnectOutcome(e)
            if (state != "connected") {
                if (state == "idle" || state == "stopping") {
                    // 用户点了断开（或看门狗/系统撤销）：不要跟用户抢。
                    EngineBridge.note("[vpn] 连接已取消")
                    return
                }
                EngineBridge.note("[vpn] 这个节点没连上，换下一个…")
                // 上一次可能已经 establish 过（握手成功、随后掉线）：先把 tun 关掉，
                // 再让下一次的 TunProvider 用新地址重新建，别让旧 tun 挂着。
                EngineBridge.peek()?.let { runCatching { it.setVPNState(false) } }
                closeTun()
                continue
            }

            // 连上了，但**是哪个节点通的**要认准：引擎没把节点 id 报给上层
            // （那是 aar 的接口，改它要重打 gomobile），所以用出口 IP 反查 ——
            // VPN Gate 的出口就是节点自己的公网 IP，命中率很高。
            val exitIp = EngineBridge.state.value.exitIp
            val node = nodes.firstOrNull { it.ip == exitIp } ?: first
            if (node.id != first.id) {
                EngineBridge.note(
                    "[vpn] 实际出口 $exitIp 对应节点 ${nodeSlotLabel(nodes, node)}" +
                        "（尝试的是 ${nodeSlotLabel(nodes, first)}）"
                )
            }

            // 量一次真实下载速度。测不出来（DNS 或端点不可达）返回 0，
            // 这时**不换点** —— 没证据说明它慢。
            val bps = measureExitBps()
            if (bps <= 0) {
                EngineBridge.note("[vpn] 出口测速没拿到数据（DNS 或测速端点不可达），本次不换点")
                return
            }
            NodeSpeedStore.remember(this, node.id, bps)
            EngineBridge.note(
                "[vpn] 出口实测速度 ${NodeSpeedStore.text(bps)}（${nodeSlotLabel(nodes, node)}）"
            )

            if (bps >= OPENVPN_MIN_BPS) return
            if (pinnedId.isNotEmpty() && node.id == pinnedId) {
                EngineBridge.note("[vpn] 当前是手动钉死的节点，速度偏慢也保留（只记录速度）")
                return
            }
            if (slowRejects >= OPENVPN_SPEED_RETRIES) {
                EngineBridge.note(
                    "[vpn] 已连续 $slowRejects 个中继偏慢（低于 ${OPENVPN_MIN_BPS / 1024} KB/s），" +
                        "保留当前连接、不再因速度换节点"
                )
                return
            }
            // 只换「有实测记录、且明显更快」的候选。
            //
            // 以前是「只要还有没试过的节点就换」，而没试过的节点恰恰是最不确定的：
            // 真机日志（2026-11-07）里 65 KB/s 的节点被换掉，接着试的两个一个是
            // 117 KB/s、另一个直接握手失败 —— 用户看到的就是「连上马上就断」。
            // 没证据说明别的更快，就不该拿唯一可用的连接去赌。
            val faster = ranked
                .filter { it.id !in tried && it.id != node.id && it.measuredBps > bps * 3 / 2 }
                .maxByOrNull { it.measuredBps }
            if (faster == null || attempts >= OPENVPN_MAX_TRIES) {
                EngineBridge.note(
                    "[vpn] 出口偏慢（${NodeSpeedStore.text(bps)}，低于 ${OPENVPN_MIN_BPS / 1024} KB/s），" +
                        "但没有实测更快的候选，保持当前连接（慢总比连不上强）"
                )
                return
            }
            slowRejects++
            tried.add(node.id)
            preferId = faster.id
            EngineBridge.note(
                "[vpn] 出口速度过慢（低于 ${OPENVPN_MIN_BPS / 1024} KB/s），" +
                    "换到实测更快的 ${nodeSlotLabel(nodes, faster)}（${faster.measuredText}）…"
            )
            // 换点前必须先断开：引擎会话收掉，系统 VPN 随之消失，
            // 下一轮再由 TunProvider 用新节点下发的地址重新 establish。
            e.disconnect()
            e.setVPNState(false)
            EngineBridge.refresh(e)
            // 旧 tun 马上关掉：fd 只归本类所有，晚关一步就可能和新 fd 撞号。
            closeTun()
            awaitIdle(e)
        }
    }

    /**
     * 调 `e.connect()` 并接住状态机异常。
     *
     * 引擎的状态机只允许 idle/error → connecting；上一次的 connecting 还没收尾时
     * 再调一次会抛 `go.Universe$proxyerror: session: 状态 connecting 不能转到
     * connecting`。这在 gomobile 里是个 RuntimeException，以前从 Main 作用域
     * 一路冒出去 = main 线程未捕获异常 = 直接闪退（真机日志里有一整条这种）。
     *
     * 顺带把 MTU 按协议统一下发：MASQUE 必须用 1200，和 VpnService.Builder 同值。
     */
    private suspend fun connectSafely(
        e: com.xiaohe.engine.Engine_,
        proto: String,
        endpointExtra: String,
        psiphon: Boolean,
        s: AppSettings,
    ): Boolean {
        if (EngineBridge.state.value.state == "connecting") {
            EngineBridge.note("[vpn] 引擎还在上一轮连接里，先等它收尾…")
            awaitIdle(e)
        }
        val mtu = when {
            psiphon -> PSIPHON_TUN_MTU
            proto.startsWith("masque") -> masqueTunMtu(s)
            else -> s.mtu
        }
        return try {
            e.connect(proto, endpointExtra, psiphon, s.ipv6, mtu.toLong())
            true
        } catch (t: Throwable) {
            EngineBridge.note("[vpn] connect 被引擎拒绝：${t.javaClass.simpleName}: ${t.message}")
            false
        }
    }

    /**
     * 等引擎给出这一轮的结果：connected / error / idle 之一。
     *
     * 为什么轮询而不是回调：引擎没有「连接完成」的挂起 API（gomobile 侧只有
     * `connect()` + `statusJSON()`），而状态机本身是权威的 —— 轮询 200ms 对
     * 一次十几秒的连接无所谓，也不会因为漏掉一条日志而永远卡住。
     */
    private suspend fun awaitConnectOutcome(e: com.xiaohe.engine.Engine_): String {
        val deadline = System.currentTimeMillis() + CONNECT_OUTCOME_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            EngineBridge.refresh(e)
            val st = EngineBridge.state.value.state
            if (st != "connecting" && st != "stopping") return st
            delay(200)
        }
        EngineBridge.refresh(e)
        val st = EngineBridge.state.value.state
        EngineBridge.note("[vpn] 等连接结果超时（当前状态 $st），交给看门狗继续观察")
        return st
    }

    /** 等引擎回到 idle/error，才能开始下一次 connect（状态机不允许从 stopping 直接连）。 */
    private suspend fun awaitIdle(e: com.xiaohe.engine.Engine_) {
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            EngineBridge.refresh(e)
            val st = EngineBridge.state.value.state
            if (st == "idle" || st == "error") return
            delay(100)
        }
    }

    /**
     * 经系统 VPN 下载一小段数据，返回实测出口吞吐（bps）。0 = 测不出来。
     *
     * 走的是普通 `HttpURLConnection`：OpenVPN 出口下整个系统都在 tun 里，所以
     * 这个请求本来就从节点出去，不需要（也不能）指定代理。电脑版是经 mihomo 的
     * mixed 端口下同一个 URL（`speed.cloudflare.com/__down`）。
     *
     * 关键点是**不追求下满**：预算到点就按已收到的字节算速度。慢节点（14 KB/s）
     * 下满 512 KiB 要 36 秒，等它下完等于把「换点」本身变成卡顿。
     */
    private suspend fun measureExitBps(): Long = withContext(Dispatchers.IO) {
        val startNs = System.nanoTime()
        val total = java.util.concurrent.atomic.AtomicLong(0)

        // **必须并发多流**。单流 TCP 在跨境线路上被慢启动 + 丢包恢复拖死：
        // 200ms RTT 下 8 秒里往往只跑到几十 KB/s，而节点实际能给几百 KB/s。
        // 真机上「自动」就是被这个偏低的读数带着一路换点/选错节点，用户看到的
        // 是「明明能跑却只有 0.x 兆」。4 条并发能在一两秒内把带宽打满，读数才
        // 是节点真实能力，也才对得起「选最快的那个」这个要求。
        val jobs = (0 until SPEED_PROBE_STREAMS).map {
            launch(Dispatchers.IO) {
                var got = 0L
                try {
                    val conn = URL(
                        "https://speed.cloudflare.com/__down?bytes=" + OPENVPN_SPEED_PROBE_BYTES
                    ).openConnection() as HttpURLConnection
                    conn.connectTimeout = 5_000
                    conn.readTimeout = 4_000
                    conn.inputStream.use { ins ->
                        val buf = ByteArray(32 * 1024)
                        while (got < OPENVPN_SPEED_PROBE_BYTES) {
                            val n = ins.read(buf)
                            if (n <= 0) break
                            got += n
                            total.addAndGet(n.toLong())
                            if (elapsedMs(startNs) >= OPENVPN_SPEED_PROBE_BUDGET_MS) break
                        }
                    }
                } catch (t: Throwable) {
                    // 中途超时/断流都可能已经收到一部分：照样按实收字节算，
                    // 「有一点点但很慢」正是要判成慢的那种情况。
                    if (got <= 0) {
                        EngineBridge.note("[vpn] 测速流中断：${t.message ?: t.toString()}")
                    }
                }
            }
        }
        jobs.forEach { runCatching { it.join() } }

        val ms = elapsedMs(startNs)
        val got = total.get()
        if (got <= 0 || ms < 50) 0L else got * 1000 / ms
    }

    private fun elapsedMs(startNs: Long): Long = (System.nanoTime() - startNs) / 1_000_000

    /**
     * 按设置排出候选节点。**用户选了哪里就只在哪里**：
     *
     *  - 钉死节点 → 只返回该节点（1 个）；
     *  - 只钉了国家 → 只返回该国节点，绝不越境；
     *  - 都没钉（自动）→ 所有国家按同一套顺序排。
     *
     * 2026-11-01 改的：原来钉了美国仍会把「境外同类/境外其他类」补在后面，
     * 引擎跳过失败的美国节点后就顺着列表连到了韩国 —— 用户明确指定美国却
     * 得到韩国，是绝对不能接受的行为。宁可报错让用户重选。
     *
     * 排序层次：家宽 → 未知 → 机房；真握手通（按耗时）→ 没测过 → 握手失败；
     * 实测吞吐档；最后才用列表里那个 TCP 延迟兜底。
     *
     * 「真握手」来自出口地区里的「测延迟」按钮（[NodeProbeStore]）：列表里那个
     * 延迟只是 api 域名的 TCP 连接时间，证明不了这个节点能握手 —— 2026-11-01
     * 真机实测，显示 193~214ms 的三个美国节点全部握不上。
     * 自报速度（VPN Gate 的 Speed 列）已不再参与排序：实测是假的（127 MB/s）。
     *
     * **不因为「机房/共享」排除任何节点**：能用都保留，标记只影响顺序与展示。
     */
    private fun pickOpenVPNCandidates(s: AppSettings, nodes: List<VpnGateNode>): List<VpnGateNode> {
        if (nodes.isEmpty()) return emptyList()
        val now = System.currentTimeMillis()
        // 「刚测出握手失败」的节点不进候选：它们的 TCP 端口是开的（所以列表里看着
        // 有延迟），但 OpenVPN 控制通道根本不应答 —— 用户点它等于白等二十秒。
        // 只跳过 30 分钟内的失败，见 NodeProbeStore.DEAD_SKIP_MS。
        val dead = NodeProbeStore.snapshot(this)
            .filterValues { !it.ok && now - it.at < NodeProbeStore.DEAD_SKIP_MS }
            .keys
        fun usable(n: VpnGateNode) = n.id !in dead

        // 块内顺序用 [vpnGateNodeOrder]（与设置页编号同一套，不能各写一套，
        // 否则用户看到的「JP家宽03」和实际连的节点会对不上）。
        fun sortedOf(pool: List<VpnGateNode>): List<VpnGateNode> = pool.sortedWith(vpnGateNodeOrder)

        // 1) 钉死节点：用户点名了，就**只**试它。失败就报错 —— 绝不偷偷换国家。
        //    2026-11-01 用户指定美国却被连到韩国，就是这里原来会把「境外」补在后面。
        if (s.openvpnNodeId.isNotEmpty()) {
            val fixed = nodes.firstOrNull { it.id == s.openvpnNodeId }
            if (fixed == null) {
                EngineBridge.note(
                    "[vpn] 固定节点 ${s.openvpnNodeId} 已不在节点列表里（列表刷新过），请重新选择"
                )
                return emptyList()
            }
            if (!usable(fixed)) {
                EngineBridge.note(
                    "[vpn] 固定节点 ${s.openvpnNodeId} 刚测出「握手失败」，这次不试它" +
                        "（换一个节点，或在出口地区里重新测延迟）"
                )
                return emptyList()
            }
            return listOf(fixed)
        }

        // 2) 只钉了国家：同样只在该国里挑，越境一律不做。
        if (s.openvpnCountry.isNotEmpty()) {
            val all = nodes.filter { it.cc.equals(s.openvpnCountry, ignoreCase = true) }
            val inCountry = all.filter(::usable)
            if (inCountry.isEmpty()) {
                EngineBridge.note(
                    if (all.isEmpty()) {
                        "[vpn] 出口地区 ${s.openvpnCountry} 当前没有可用节点，请换地区或刷新列表"
                    } else {
                        "[vpn] 出口地区 ${s.openvpnCountry} 的 ${all.size} 个节点都刚测出「握手失败」，" +
                            "建议换地区，或在出口地区里重新测延迟"
                    }
                )
                return emptyList()
            }
            return sortedOf(inCountry).take(OPENVPN_CANDIDATE_CAP)
        }

        // 3) 完全自动：所有国家一起排。
        val usableAll = nodes.filter(::usable)
        if (usableAll.isEmpty()) {
            EngineBridge.note("[vpn] 所有节点都刚测出「握手失败」，建议刷新节点列表或重新测延迟")
            return emptyList()
        }
        return sortedOf(usableAll).take(OPENVPN_CANDIDATE_CAP)
    }

    /**
     * 节点在列表里的编号（JP家宽03）。
     *
     * 必须用 [vpnGateNodeOrder]（和设置页列表同一套排序）：编号是数出来的，
     * 两处排序只要有一点不同，用户看到的编号就不是他实际连的那个节点。
     */
    private fun nodeSlotLabel(nodes: List<VpnGateNode>, node: VpnGateNode): String {
        val sameClass = nodes
            .filter { it.cc.equals(node.cc, ignoreCase = true) && it.cls == node.cls }
            .sortedWith(vpnGateNodeOrder)
        val idx = sameClass.indexOfFirst { it.id == node.id }
        val tag = when (node.cls) {
            "residential" -> "家宽"
            "datacenter" -> "机房"
            else -> "未知"
        }
        val num = if (idx >= 0) (idx + 1).toString().padStart(2, '0') else "??"
        return node.cc + tag + num
    }

    /** 建 tun 的一种本机地址组合（见 establishOpenVpnTun 的候选列表）。 */
    private data class TunVariant(val addr: String, val withV6: Boolean, val label: String)

    /** 建 tun 的每一步都带上上下文抛错：日志里能直接看出是哪一步被系统拒绝。 */
    private inline fun vpnStep(what: String, block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            throw IllegalStateException("$what 被拒绝：${t.message}", t)
        }
    }

    /**
     * 引擎在 OpenVPN 握手完成后回调这里，用服务器下发的参数建系统 VPN。
     *
     * 与普通模式的差别只有三点：地址来自节点（不是 172.16.0.2）、MTU 用隧道 MTU、
     * 路由/DNS 优先用服务器下发的。其余（分流、分应用、阻塞模式）保持一致。
     */
    private fun establishOpenVpnTun(
        address: String,
        prefixLen: Int,
        routesCsv: String,
        dnsCsv: String,
        mtu: Int,
    ): Int {
        val s = SettingsStore.load(this)
        val tunMtu = if (mtu in 576..9000) mtu else OPENVPN_TUN_MTU
        // 服务器 push 的 DNS 在隧道另一头，优先级最高；没有才用用户列表。
        val pushedDns = dnsCsv.split(',', ';').map { it.trim() }.filter { it.isNotEmpty() }

        // 本机 tun **不用**节点下发的地址（节点认它下发的那个，但系统经常拒绝配它：
        // 真机日志里 /32、/24、/16 全被 Vpn.jniSetAddresses 拒绝）。这里改用保留
        // 地址，再由引擎在包泵里做一对一替换（engine/warp/iprewrite.go）。
        //
        // 但**地址不能写死**：0.2.33 用 192.0.2.111/32 也被拒（同样一句
        // Cannot set address），说明撞的是「上一个 tun 接口残留的同一地址」，
        // 而且 v6 地址 fd00::1 每次都一样、最容易撞。所以这里按「越来越不可能撞」
        // 的顺序试几组，每组都换一个地址 + 可选关掉 v6：
        //
        //   ① 192.0.2.111 + v6      —— 正常情况，v6 也抓进来（防泄漏）
        //   ② 192.0.2.111 不带 v6   —— v6 地址残留导致被拒
        //   ③ 192.0.2.<随机> 不带 v6 —— v4 地址残留导致被拒
        //   ④ 198.18.0.<随机> 不带 v6 —— 整个网段都被系统记着
        //
        // 成功的那个地址会回填给引擎（setOpenVPNLocalAddr），包泵按它做替换，
        // 所以走哪一组都不影响连通性。
        val variants = buildList {
            add(TunVariant(OPENVPN_TUN_LOCAL, true, "保留地址 + v6"))
            if (!s.ipv6) {
                add(TunVariant(OPENVPN_TUN_LOCAL, false, "保留地址，不带 v6"))
                add(TunVariant("192.0.2.${20 + (Math.random() * 220).toInt()}", false, "换地址，不带 v6"))
                add(TunVariant("198.18.0.${20 + (Math.random() * 220).toInt()}", false, "换网段，不带 v6"))
            }
        }
        var last: Throwable? = null
        for ((i, v) in variants.withIndex()) {
            tunEstablishCount++
            EngineBridge.note(
                "[vpn] 第 $tunEstablishCount 次 establish（${i + 1}/${variants.size} " +
                    "${v.label}：tun=${v.addr}/32，节点下发=$address/$prefixLen, " +
                    "MTU=$tunMtu, 分流=${s.rulePolicy}）…"
            )
            try {
                val b = Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(tunMtu)
                    .setBlocking(true)

                // 每一步都带上下文抛：失败时日志能直接看出是「地址被拒」还是
                // 「路由/分应用被拒」，不用再猜。
                vpnStep("addAddress(${v.addr}/32)") { b.addAddress(v.addr, 32) }

                // 路由策略复用同一套三档（全局/绕过大陆/黑名单）。
                vpnStep("路由策略(${s.rulePolicy})") { applyRoutePolicy(b, s) }

                // 防泄漏：v6 不抓就是一条绕过隧道直连的路。这一组没带 v6 时，
                // 只是这一轮不抓（v6 地址被系统记着），IPv4 的 DNS 仍然强制走隧道。
                if (v.withV6) {
                    vpnStep("addAddress($TUN_ADDR_V6)") { b.addAddress(TUN_ADDR_V6, 128) }
                    vpnStep("addRoute(::/0)") { b.addRoute("::", 0) }
                }
                vpnStep("DNS") { applyDnsGuard(b, s, pushedDns) }
                vpnStep("分应用") { applySplit(b, s) }

                // 换点会反复走到这里：先把上一个 tun 关掉，再建新的。fd 的所有权始终在
                // 本类（tunPfd），引擎只借用 —— 否则同一个 fd 号被两边各关一次，就是
                // 真机日志里那个 fdsan SIGABRT。
                closeTun()
                val pfd = b.establish()
                if (pfd == null) {
                    last = IllegalStateException("establish 返回 null（VPN 授权可能已被撤销）")
                    continue
                }
                tunPfd = pfd
                val fd = pfd.fd
                tunFd = fd
                EngineBridge.peek()?.let { e ->
                    // 必须回填 tun fd：引擎的延迟探测与出口看门狗（needRecover）只在
                    // tunFD>0 时工作 —— 漏掉这一步会得到「能上网但永远不会自动重连」。
                    e.setTunFD(fd.toLong())
                    // 告诉引擎 tun 上实际用的地址，包泵据此做地址替换。
                    e.setOpenVPNLocalAddr(v.addr)
                    e.setVPNState(true)
                    EngineBridge.refresh(e)
                }
                EngineBridge.note(
                    "[vpn] OpenVPN 系统 VPN 已启用（tun=${v.addr}/32 ← 节点 $address, " +
                        "tun fd=$fd, MTU=$tunMtu${if (v.withV6) "" else "，本轮未抓 v6"}）"
                )
                return fd
            } catch (t: Throwable) {
                last = t
                val cause = t.cause?.message
                EngineBridge.note(
                    "[vpn] establish 失败（${t.javaClass.simpleName}: ${t.message}" +
                        (if (cause.isNullOrBlank()) "" else " / $cause") + "）"
                )
            }
        }
        EngineBridge.note(
            "[vpn] OpenVPN 建 tun 失败（已试 ${variants.size} 种地址组合）：${last?.message}"
        )
        return -1
    }

    /** 引擎的建 tun 回调（在 Go 的连接 goroutine 上调用）。 */
    /**
     * Psiphon 的建 tun 回调：**上游建好之后**才会被调用（见 engine/warp/psiphon.go）。
     *
     * 参数全部忽略 —— Psiphon 的 tun 用自己的固定地址与 1500 的 MTU，传进来的只是
     * 占位值。顺序不能反：提前 establish 会让系统 VPN 立刻接管路由，那条 WARP
     * 上游的 UDP 即使 protect 了也会在建立窗口里被丢（真机日志：14 个端点全部
     * 「握手成功、数据面不通」）。
     */
    private val psiphonTunProvider = object : com.xiaohe.engine.TunProvider {
        override fun establishTun(
            address: String,
            prefixLen: Long,
            routesCSV: String,
            dnsCSV: String,
            mtu: Long,
        ): Long = try {
            val s = SettingsStore.load(this@WarpVpnService)
            val fd = establishTun(s, psiphon = true, proto = s.proto)
            if (fd > 0) {
                tunFd = fd
                // 必须回填引擎状态：首页那行「系统 VPN 未启用（流量不会走隧道）」
                // 和出口看门狗（needRecover）读的都是它。Psiphon 分支是「先上游、
                // 后建 tun」，startConnect 里那段回填根本没机会执行 —— 漏了这一步
                // 就会出现「能上网、IP 也是赛风，界面却说没启用」。
                EngineBridge.peek()?.let { e ->
                    runCatching {
                        e.setTunFD(fd.toLong())
                        e.setVPNState(true)
                    }
                    EngineBridge.refresh(e)
                }
                EngineBridge.note("[vpn] Psiphon 系统 VPN 已启用（tun fd=$fd）")
            }
            fd.toLong()
        } catch (t: Throwable) {
            EngineBridge.note("[vpn] Psiphon 建 tun 异常：${t.javaClass.simpleName}: ${t.message}")
            -1L
        }
    }

    private val openvpnTunProvider = object : com.xiaohe.engine.TunProvider {
        override fun establishTun(
            address: String,
            prefixLen: Long,
            routesCSV: String,
            dnsCSV: String,
            mtu: Long,
        ): Long = establishOpenVpnTun(
            address,
            prefixLen.toInt(),
            routesCSV,
            dnsCSV,
            mtu.toInt(),
        ).toLong()
    }

    /**
     * 建立系统 VPN，并把 fd 借给引擎读写（**所有权仍在本类**，见 [tunPfd]）。
     *
     * 换点前先 [closeTun]：新 tun 建立时旧的一定要先关掉，否则旧 fd 会一直挂在
     * 系统 VPN 上，几次之后 fd 号被复用，谁关谁都说不清了。
     */
    private fun establishTun(s: AppSettings, psiphon: Boolean, proto: String): Int {
        // MASQUE 的 tun MTU 必须比普通模式小：每个 IP 包会封装成一个 CONNECT-IP
        // DATAGRAM（+ contextID + QUIC + UDP + IP 头），1280 的内层包在外层 v6
        // 路径上直接超限被丢 —— 见 engine/warp/masque.go 的 masqueMaxTunMTU。
        val mtu = when {
            psiphon -> PSIPHON_TUN_MTU
            proto.startsWith("masque") -> masqueTunMtu(s)
            else -> s.mtu
        }

        // 候选地址（2026-11-11 用户日志：masque / masque-x2 反复
        // `establish 异常: Cannot set address`，而 wg / awg 同一时刻正常）。
        //
        // 根因是**上一个 tun 接口还没被系统回收**时，新接口再配同一个地址会被拒。
        // 每次都一样的是 v6 地址 `fd00:1:...`，所以它最容易撞；v4 的 172.16.0.2
        // **不能换**（引擎的 netstack 设备地址固定是它，换了回程包在内核里没有归属，
        // 等于连上就断），能换的只有「要不要 v6」+「等一会儿再试」。
        // 订阅出口：tun 地址必须和内核期望的一致。
        //
        // mihomo 的 tun 本地地址取自 dns.FakeIPRange（默认 198.18.0.1/16，取 /30），
        // 也就是 **198.18.0.1/30**；而普通模式的 172.16.0.2 是 WARP netstack 的设备
        // 地址。两者不一致时 gvisor 栈不认这个网卡，包会被静默丢弃 ——
        // 现象正是用户报的「已连接、出口 IP 获取中、上下行 0 B/s」。
        val tunV4 = if (s.subExit) SUB_TUN_V4 else TUN_ADDR_V4
        val tunBits = 32
        val variants = buildList {
            add(TunVariant(tunV4, true, if (s.subExit) "订阅出口地址 + v6" else "默认地址 + v6"))
            if (!s.ipv6) {
                add(TunVariant(tunV4, false, "不带 v6"))
                add(TunVariant(tunV4, false, "不带 v6，等旧接口回收后重试"))
            }
        }
        var last: Throwable? = null
        for ((i, v) in variants.withIndex()) {
            if (i == variants.size - 1) {
                // 最后一组先等 400ms：系统回收旧 tun 是异步的，紧接着 establish
                // 就是日志里那串「连续 Cannot set address」的成因。
                runCatching { Thread.sleep(400) }
            }
            try {
                val b = Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(mtu)
                    .setBlocking(true)
                vpnStep("addAddress(${v.addr}/$tunBits)") { b.addAddress(v.addr, tunBits) }

                // 路由策略：VpnService 只有一种表达方式 —— **加了路由的网段才进 tun**，
                // 没加的直接走物理网卡。三种规则模式就是三份路由集合。
                vpnStep("路由策略(${s.rulePolicy})") { applyRoutePolicy(b, s) }

                if (v.withV6) {
                    // 不给 ::/0 配地址就路由 v6 会把 v6 流量丢进黑洞。
                    vpnStep("addAddress($TUN_ADDR_V6)") { b.addAddress(TUN_ADDR_V6, 128) }
                    vpnStep("addRoute(::/0)") { b.addRoute("::", 0) }
                    if (!s.ipv6) {
                        // DNS 防泄漏连带把 v6 抓进来（fail closed）：不抓的时候，凡是走 v6
                        // 的连接（包括 v6 解析器）都从物理网卡直连出去 —— 这本身就是泄露，
                        // 而且 leak 测试会把它算在「DNS 泄露」名下。
                        EngineBridge.note("[dns] IPv6 未开启，但防泄漏已把 ::/0 抓进隧道（不会走物理网卡）")
                    }
                }
                vpnStep("DNS") { applyDnsGuard(b, s, emptyList()) }
                vpnStep("分应用") { applySplit(b, s) }

                // 新的一步之前先把上一个 tun 关掉：fd 只归本类所有。
                closeTun()
                val pfd = b.establish()
                if (pfd == null) {
                    EngineBridge.note("[vpn] establish 返回 null（VPN 授权可能已被撤销）")
                    continue
                }
                tunPfd = pfd
                tunFd = pfd.fd
                EngineBridge.note(
                    "[vpn] 系统 VPN 已启用（tun fd=${pfd.fd}, MTU=$mtu" +
                        (if (i > 0) "，第 ${i + 1} 组：${v.label}" else "") + "）"
                )
                return pfd.fd
            } catch (t: Throwable) {
                last = t
                EngineBridge.note(
                    "[vpn] establish 失败（${i + 1}/${variants.size} ${v.label}）：" +
                        "${t.javaClass.simpleName}: ${t.message}" +
                        if (i + 1 < variants.size) "，换下一组再试" else ""
                )
            }
        }
        EngineBridge.note("[vpn] establish 异常: ${last?.message}")
        return -1
    }

    /**
     * 按「规则模式」决定加哪些路由。
     *
     *   global     → 0.0.0.0/0（全部进隧道）
     *   bypass-cn  → 0.0.0.0/0 减去大陆网段（CN 直连）
     *   blacklist  → 只加规则里写 proxy 的网段（其余直连）
     *
     * 大陆网段是运行时拉取的（engine/cnroutes.go），拉取发生在**连上之后**，
     * 所以这里可能还没数据 —— 那就按全局处理并写一行日志，不装作生效了。
     */
    private fun applyRoutePolicy(b: Builder, s: AppSettings) {
        when (s.rulePolicy) {
            "bypass-cn" -> {
                val cn = loadCNRoutes()
                if (cn.isEmpty()) {
                    EngineBridge.note(
                        "[vpn] 分流=绕过大陆，但大陆路由表还没下载，本次按全局处理（连上后会自动拉取）"
                    )
                    b.addRoute("0.0.0.0", 0)
                    return
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    b.addRoute("0.0.0.0", 0)
                    var excluded = 0
                    for ((net, len) in cn) {
                        runCatching {
                            b.excludeRoute(
                                IpPrefix(InetAddress.getByAddress(intToBytes(net)), len)
                            )
                        }.onSuccess { excluded++ }
                    }
                    EngineBridge.note("[vpn] 分流=绕过大陆：全局 + 排除 $excluded 个大陆网段")
                } else {
                    // API 24–32 没有 excludeRoute，只能加「CN 之外」的补集前缀。
                    val gaps = complementV4(cn)
                    for ((net, len) in gaps) b.addRoute(intToIp(net), len)
                    EngineBridge.note(
                        "[vpn] 分流=绕过大陆：${gaps.size} 条补集路由（API<33 无 excludeRoute）"
                    )
                }
            }
            "blacklist" -> {
                val proxied = parseProxyCIDRs(s.ruleText)
                if (proxied.isEmpty()) {
                    EngineBridge.note("[vpn] 分流=黑名单，但规则里没有 proxy 网段：本次不抓任何流量")
                } else {
                    for ((addr, len) in proxied) b.addRoute(addr, len)
                    EngineBridge.note("[vpn] 分流=黑名单：只抓 ${proxied.size} 个网段")
                }
            }
            else -> {
                // 全局：默认全走隧道，但规则里写 direct 的**网段**要挖掉。
                // VPN 模式看不到域名，所以只有 IP/CIDR 形式的 direct 能在这里生效。
                val direct = parseDirectCIDRs(s.ruleText).mapNotNull { (cidr, len) ->
                    ipToInt(cidr)?.let { it to len }
                }
                if (direct.isEmpty()) {
                    b.addRoute("0.0.0.0", 0)
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    b.addRoute("0.0.0.0", 0)
                    var excluded = 0
                    for ((net, len) in direct) {
                        runCatching {
                            b.excludeRoute(IpPrefix(InetAddress.getByAddress(intToBytes(net)), len))
                        }.onSuccess { excluded++ }
                    }
                    EngineBridge.note("[vpn] 分流=全局：排除 $excluded 条 direct 网段")
                } else {
                    // API 24–32 没有 excludeRoute：改成「0/0 减去 direct」的补集。
                    val gaps = complementV4(direct)
                    for ((net, len) in gaps) b.addRoute(intToIp(net), len)
                    EngineBridge.note(
                        "[vpn] 分流=全局：挖掉 ${direct.size} 条 direct 网段，${gaps.size} 条补集路由"
                    )
                }
            }
        }
    }

    /** 读引擎落盘的大陆路由表（filesDir/engine/cn-cidrs.txt），返回 (网络号, 前缀长)。 */
    private fun loadCNRoutes(): List<Pair<Int, Int>> {
        val f = File(File(filesDir, "engine"), "cn-cidrs.txt")
        if (!f.isFile) return emptyList()
        return runCatching {
            f.readLines().mapNotNull { line ->
                val t = line.trim()
                if (t.isEmpty() || t.startsWith("#")) return@mapNotNull null
                val slash = t.indexOf('/')
                if (slash <= 0) return@mapNotNull null
                val net = ipToInt(t.substring(0, slash)) ?: return@mapNotNull null
                val len = t.substring(slash + 1).toIntOrNull() ?: return@mapNotNull null
                if (len !in 0..32) return@mapNotNull null
                net to len
            }
        }.getOrDefault(emptyList())
    }

    /** 规则文本里 `proxy,1.2.3.0/24` 那些网段 —— 黑名单模式要抓的就是它们。 */
    private fun parseProxyCIDRs(text: String): List<Pair<String, Int>> = parseCIDRRules(text, "proxy")

    /** 规则文本里 `direct,1.2.3.0/24` 那些网段 —— 全局模式要把它们从隧道里挖掉。 */
    private fun parseDirectCIDRs(text: String): List<Pair<String, Int>> = parseCIDRRules(text, "direct")

    private fun parseCIDRRules(text: String, action: String): List<Pair<String, Int>> = text.lineSequence()
        .map { it.substringBefore('#').trim() }
        .mapNotNull { line ->
            val parts = line.split(',', limit = 2)
            if (parts.size != 2 || !parts[0].trim().equals(action, ignoreCase = true)) {
                return@mapNotNull null
            }
            val cidr = parts[1].trim()
            val slash = cidr.indexOf('/')
            if (slash <= 0) return@mapNotNull null
            val len = cidr.substring(slash + 1).toIntOrNull() ?: return@mapNotNull null
            if (len !in 0..32 || ipToInt(cidr.substring(0, slash)) == null) return@mapNotNull null
            cidr to len
        }.toList()

    private fun ipToInt(s: String): Int? {
        val parts = s.trim().split('.')
        if (parts.size != 4) return null
        var v = 0
        for (p in parts) {
            val n = p.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            v = (v shl 8) or n
        }
        return v
    }

    private fun intToBytes(v: Int) = byteArrayOf(
        ((v ushr 24) and 0xFF).toByte(),
        ((v ushr 16) and 0xFF).toByte(),
        ((v ushr 8) and 0xFF).toByte(),
        (v and 0xFF).toByte(),
    )

    private fun intToIp(v: Int): String =
        "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"

    /** CN 段之外的部分，拆成最少的 CIDR 前缀（API &lt; 33 没有 excludeRoute 时用）。 */
    private fun complementV4(cn: List<Pair<Int, Int>>): List<Pair<Int, Int>> {
        val ranges = cn.map { (net, len) ->
            val start = net.toLong() and 0xFFFFFFFFL
            val size = if (len == 0) 0x100000000L else 1L shl (32 - len)
            start to (start + size - 1)
        }.sortedBy { it.first }

        // 先合并重叠/相邻区间：数据源里常有互相包含的段。
        val merged = mutableListOf<Pair<Long, Long>>()
        for (r in ranges) {
            val last = merged.lastOrNull()
            if (last != null && r.first <= last.second + 1) {
                if (r.second > last.second) merged[merged.size - 1] = last.first to r.second
            } else {
                merged.add(r)
            }
        }

        val out = mutableListOf<Pair<Int, Int>>()
        var cursor = 0L
        val end = 0xFFFFFFFFL
        for (r in merged) {
            if (r.first > cursor) out.addAll(rangeToCidrs(cursor, r.first - 1))
            if (r.second + 1 > cursor) cursor = r.second + 1
            if (cursor > end) return out
        }
        if (cursor <= end) out.addAll(rangeToCidrs(cursor, end))
        return out
    }

    /** 把闭区间拆成 CIDR：每次取「起点对齐且不越过终点」的最大块。 */
    private fun rangeToCidrs(startIn: Long, endIn: Long): List<Pair<Int, Int>> {
        val out = mutableListOf<Pair<Int, Int>>()
        var start = startIn
        while (start <= endIn) {
            var alignBits = 0
            while (alignBits < 32 && (start and (1L shl alignBits)) == 0L) alignBits++
            var size = 1L shl alignBits
            while (size > endIn - start + 1) size = size shr 1
            var prefix = 32
            var sz = size
            while (sz > 1) {
                sz = sz shr 1
                prefix--
            }
            out.add(start.toInt() to prefix)
            start += size
        }
        return out
    }

    /**
     * DNS 防泄漏：决定这次下发哪些解析器，并把它们钉进隧道。
     *
     * 为什么需要（用户实测：VPN 模式连上后 ipleak 报 DNS 泄露）：
     *  - 默认列表里有 **223.5.5.5（阿里 DNS）**，查询哪怕走了隧道，落地解析器也是
     *    国内的，测试站点直接判泄露；
     *  - 「绕过大陆」分流会把 CN 网段从 tun 里排除，223.5.5.5 正好在 CN 里 ——
     *    查询根本不进隧道，从物理网卡直发，这是**真泄露**，不是显示问题；
     *  - 「黑名单」分流只抓规则里写 proxy 的网段，默认路由不加，DNS 一样直连。
     *
     * 所以防泄漏做三件事：
     *  1. 剔除已知的国内公共解析器（出口侧解析器优先：服务器 push 的 > 用户列表 > 1.1.1.1）；
     *  2. 给每个解析器加一条 /32（/128）主机路由，任何分流策略下都进隧道；
     *  3. 永不下发空列表 —— 空列表时系统会退回物理网络的 DNS，那等于没开 VPN。
     *
     * 返回实际下发的列表（调用方可用于日志）。
     */
    private fun applyDnsGuard(b: Builder, s: AppSettings, pushed: List<String>): List<String> {
        if (s.dnsOff && !s.dnsGuard) {
            EngineBridge.note("[dns] 未下发 DNS（用户关闭，且防泄漏也关着）")
            return emptyList()
        }

        // 候选来源的优先级，是为了让「解析器所在国家」和「出口所在国家」一致 ——
        // 这正是所有 leak 测试的判定标准：
        //   ① 服务器 push 的（解析器就在出口那台机器上，必然同国）；
        //   ② 用户自己填的（默认 1.1.1.1：抗污染，且始终在隧道内解析）。
        //
        // 注意**不要**退回「物理网络的 DNS」：国内运营商的解析器虽然能让
        // 「出口 CN / 解析器 CN」对上，但它的递归查询本身在墙内，被污染的域名
        // 会拿到错误 IP —— 那是拿「上网能不能用」换一个测试分数。
        var candidates = pushed
        var source = "服务器下发"
        if (candidates.isEmpty()) {
            candidates = s.dnsList()
            source = "用户设置"
        }

        val dropped: List<String>
        val kept: List<String>
        if (s.dnsGuard) {
            // 服务器下发里如果带「私有解析器」（10/8 等），它就是出口那台机器上的
            // 解析器，一定和出口同国 —— 只留它。混进 8.8.8.8 这类公共解析器，
            // leak 测试就会报「部分请求由另一个国家完成」。
            val priv = if (source == "服务器下发") candidates.filter { isPrivateIp(it) } else emptyList()
            val pool = if (priv.isNotEmpty()) priv else candidates
            dropped = pool.filter { it in LEAKY_RESOLVERS }
            kept = pool.filter { it !in LEAKY_RESOLVERS }
        } else {
            dropped = emptyList()
            kept = candidates
        }
        val dns = kept.ifEmpty { listOf("1.1.1.1") }
        var added = 0
        for (addr in dns) {
            if (runCatching { b.addDnsServer(addr) }.isSuccess) added++
        }
        if (s.dnsGuard) {
            // 主机路由：黑名单/绕过大陆这两档都不会给「公网解析器」留默认路由，
            // 不显式加的话，DNS 就从物理网卡直连出去。
            var routed = 0
            for (addr in dns) {
                // 只处理 IP 字面量：对主机名调 getByName 会触发一次真实解析，
                // 而这里正在配 DNS —— 递归解析、还会把日志卡住。
                val ip = ipLiteral(addr) ?: continue
                val literal = ip.hostAddress ?: continue
                val bits = if (ip.address.size == 4) 32 else 128
                if (runCatching { b.addRoute(literal, bits) }.isSuccess) routed++
            }
            EngineBridge.note(
                "[dns] 防泄漏：下发 ${dns.joinToString(",")}（来源：$source，" +
                    "$routed 条主机路由强制走隧道）" +
                    if (dropped.isEmpty()) "" else "，已剔除国内解析器 ${dropped.joinToString("/")}"
            )
        } else {
            EngineBridge.note("[dns] 下发 ${dns.joinToString(",")}（来源：$source，防泄漏已关闭）")
        }
        if (added < dns.size) {
            EngineBridge.note("[dns] 有 ${dns.size - added} 个解析器格式无效，系统将忽略它们")
        }
        return dns
    }

    /**
     * 当前**物理网络**的网卡名（wlan0 / rmnet_data0 …）；拿不到返回空串。
     *
     * 不能用 `activeNetwork`：系统 VPN 建起来之后它就是我们自己的 tun（日志里
     * 第二次连接拿到的是 `tun0`），把它交给 mihomo 当 interface-name，内核的
     * 所有出口 socket 会直接写回自己的 tun —— 表现就是「VPN 图标亮着、所有网站
     * 打不开」。所以这里遍历全部网络，**排除 VPN 传输类型**，优先 Wi-Fi、其次蜂窝。
     */
    private fun activeInterfaceName(): String = runCatching {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return@runCatching ""
        val physical = cm.allNetworks
            .mapNotNull { n ->
                val caps = cm.getNetworkCapabilities(n) ?: return@mapNotNull null
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
                val score = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 2
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
                    else -> 0
                }
                cm.getLinkProperties(n)?.interfaceName?.takeIf { it.isNotBlank() }?.let { it to score }
            }
            .maxByOrNull { it.second }
            ?.first
        physical ?: cm.getLinkProperties(cm.activeNetwork ?: return@runCatching "")?.interfaceName.orEmpty()
    }.getOrDefault("")

    /** 只把 IP 字面量转成地址，主机名一律返回 null（避免触发一次真实解析）。 */
    private fun ipLiteral(s: String): InetAddress? {
        val v4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        if (!v4.matches(s) && !s.contains(':')) return null
        return runCatching { InetAddress.getByName(s) }.getOrNull()
    }

    /** 私有 / 保留地址：代表「解析器就在隧道另一头的那个内网里」。 */
    private fun isPrivateIp(s: String): Boolean {
        val ip = ipLiteral(s) ?: return false
        if (ip.isSiteLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress) return true
        val b = ip.address
        // 100.64.0.0/10（运营商级 NAT，很多节点也用它）
        return b.size == 4 && (b[0].toInt() and 0xFF) == 100 && (b[1].toInt() and 0xC0) == 64
    }

    /**
     * 分应用：直接用 VpnService 的原生白/黑名单，等价于电脑版「分应用」三档，
     * 而且内核层生效，没有 mihomo 规则匹配的开销。
     */
    private fun applySplit(b: Builder, s: AppSettings) {

        val apps = s.splitAppList().filter { it != packageName }
        if (s.splitMode == "off" || apps.isEmpty()) return
        var applied = 0
        for (pkg in apps) {
            val ok = runCatching {
                when (s.splitMode) {
                    "proxy" -> b.addAllowedApplication(pkg)
                    "direct" -> b.addDisallowedApplication(pkg)
                }
            }.isSuccess
            if (ok) applied++
        }
        if (applied == 0) {
            // 全部包名都无效时，加白名单一个都没成功 = 变成「全部应用走 VPN」，
            // 与用户选的意图相反，必须说出来。
            EngineBridge.note("[vpn] 分应用列表里没有一个有效的包名，本次按全局模式处理")
        } else {
            EngineBridge.note("[vpn] 分应用已生效：$applied 个应用（模式 ${s.splitMode}）")
        }
    }

    /**
     * 出口看门狗：引擎判定「连续探测失败且无数据流动」后会在快照里置 needRecover，
     * 这里负责**断开 → 换端点 → 重连**。
     *
     * 为什么不放在 Go 里：tun 是 VpnService 建的，重连必须重新 establish()。
     *
     * 为什么有次数上限：链路被整体掐断时，无限重连只会耗电、刷日志，界面还一直显示
     * 「在连」—— 用户实测就是这样（39 分钟、0 B、网页打不开）。5 分钟内 3 次还不行
     * 就停手并把原因写清楚。
     */
    private fun startWatchdog() {
        watchdog?.cancel()
        watchdog = scope.launch {
            var attempts = 0
            var windowStart = System.currentTimeMillis()
            while (isActive) {
                delay(WATCHDOG_TICK_MS)
                if (!EngineBridge.state.value.needRecover) continue
                // 健康守护关掉时只记录，不自动断开重连（按流量计费/需要绝对稳定的
                // 场景，重连本身比断流更糟）。
                if (!SettingsStore.load(this@WarpVpnService).healthGuard) {
                    EngineBridge.note("[vpn] 出口异常，但「健康守护」已关闭：只记录，不自动重连")
                    continue
                }
                val now = System.currentTimeMillis()
                if (now - windowStart > RECOVER_WINDOW_MS) {
                    windowStart = now
                    attempts = 0
                }
                if (attempts >= RECOVER_MAX) {
                    // 停止重试 = 放弃这条连接：系统 VPN 也必须一起收掉，
                    // 否则留下一个「图标亮着、一个包都不通」的假连接。
                    teardownAfterFailure(
                        "5 分钟内已自动重连 $attempts 次仍不稳定，停止自动重试" +
                            "（建议手动断开后重连，或把协议换成 AmneziaWG）"
                    )
                    break
                }
                attempts++
                EngineBridge.note("[vpn] 出口长时间无数据，自动重连（第 $attempts 次）")
                val s = SettingsStore.load(this@WarpVpnService)
                EngineBridge.peek()?.let { e ->
                    // 先断开：关掉 tun，系统 VPN 会短暂消失；紧接着 establish 新的。
                    // 端点缓存由引擎在 Connect 开头清掉（不再优先试死掉的那个）。
                    e.disconnect()
                    e.setVPNState(false)
                    EngineBridge.refresh(e)
                }
                delay(600)
                startConnect(
                    Intent(this@WarpVpnService, WarpVpnService::class.java).apply {
                        action = ACTION_CONNECT
                        putExtra(EXTRA_PROTO, s.proto)
                        putExtra(EXTRA_PSIPHON, s.psiphon)
                        putExtra(EXTRA_OPENVPN, s.openvpn)
                    }
                )
            }
        }
    }

    /**
     * 连接失败的收尾：断开引擎 → 关 tun（= 系统 VPN 消失）→ 停前台服务。
     *
     * 为什么必须这么做：VPN 模式（psiphon / masque / wwarp / wg / awg）的系统 VPN 是
     * 在 `connect()` **之前**建立的，而引擎只把会话状态打成 `error` —— 它碰不到
     * tun fd（fd 归 Kotlin 的 ParcelFileDescriptor）。不在这里收，用户看到的就是
     * 「连接失败，系统 VPN 却一直连着」，所有流量继续流进一个没人读的 tun。
     *
     * 与 [shutdown] 的区别：这里**不取消** connectJob（调用点就在这个协程里，
     * 取消自己会在下一个挂起点抛 CancellationException），也不写「正常退出」标记。
     */
    private fun teardownAfterFailure(reason: String) {
        EngineBridge.note("[vpn] $reason；关闭系统 VPN（失败不留残留）")
        EngineBridge.peek()?.let { engine ->
            runCatching { engine.disconnect() }
            runCatching { engine.setVPNState(false) }
            EngineBridge.refresh(engine)
        }
        closeTun()
        updateNotification()
        stopForegroundCompat()
        stopSelf()
    }

    private fun shutdown() {
        // 正常退出的标记：下次启动时 CrashGuard.markStart 靠它区分「上次是自己
        // 停的」还是「上次被崩溃/系统杀掉」。
        EngineBridge.note(CrashGuard.SHUTDOWN_MARK + "（服务停止，OpenVPN establish $tunEstablishCount 次）")
        // 先掐掉还在「等连接结果 / 测速」的那一轮，否则它会在断开之后再
        // 发起一次 connect（表现就是「点了断开又自己连上」）。
        connectJob?.cancel()
        connectJob = null
        watchdog?.cancel()
        watchdog = null
        EngineBridge.peek()?.let { engine ->
            engine.disconnect()
            engine.setVPNState(false)
            EngineBridge.refresh(engine)
        }
        // 引擎只借用 tun fd，关它是本类的责任：不关的话系统 VPN 会一直挂着。
        closeTun()
        stopForegroundCompat()
        stopSelf()
    }

    /** 用户在系统设置里撤销授权，或启用了别的 VPN：必须收干净。 */
    override fun onRevoke() {
        EngineBridge.note("[vpn] 系统撤销了 VPN 授权，正在断开")
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        scope.cancel()
        super.onDestroy()
    }

    // -----------------------------------------------------------------------
    // 通知
    // -----------------------------------------------------------------------

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val ch = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        ch.setShowBadge(false)
        nm.createNotificationChannel(ch)
    }

    private fun startForegroundSafely(text: String) {
        ensureChannel()
        val notif = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // specialUse 类型：与 manifest 的 foregroundServiceType 必须一致。
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun updateNotification() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val s = EngineBridge.state.value
        val text = when {
            s.isConnected && s.exitIp.isNotEmpty() -> "${getString(R.string.notif_connected)} · ${s.exitIp}"
            s.isConnected -> getString(R.string.notif_connected)
            s.isBusy -> getString(R.string.notif_connecting)
            else -> getString(R.string.notif_disconnected)
        }
        nm.notify(NOTIF_ID, buildNotification(text))
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun buildNotification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getService(
            this,
            1,
            Intent(this, WarpVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .addAction(0, getString(R.string.action_disconnect), disconnect)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
