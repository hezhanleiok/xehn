package com.xiaohe.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import java.io.File
import java.net.InetAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

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
         * Psiphon packet tunnel 的 MTU（tunnel-core 的 DEFAULT_MTU）。
         *
         * Psiphon 会往 tun 写最多 1500 字节的包，而内核会按接口 MTU 丢弃过大的包 ——
         * 接口 MTU 设 1280 时表现为「连上了、小请求通、稍微一大就断」。所以走
         * Psiphon 出口时，系统 tun 必须用它的 MTU；基础隧道在 netstack 里，
         * 不受这个值影响。
         */
        private const val PSIPHON_TUN_MTU = 1500

        /**
         * OpenVPN 出口的系统 tun MTU。
         *
         * 服务端 tun-mtu 通常是 1500，但我们的外层还要经 WARP（netstack MTU 1280）
         * 再封装一次；1400 给内层 TCP 留出 MSS 余量，避免大包被外层反复分片。
         */
        private const val OPENVPN_TUN_MTU = 1400

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

        /** 候选全失败时自动再来几轮（每轮换下一批节点）。 */
        private const val OPENVPN_CONNECT_ROUNDS = 3
    }

    private var tunFd = -1

    /** 自动重连用的协程作用域（随服务销毁回收）。 */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var watchdog: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                shutdown()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                startForegroundSafely(getString(R.string.notif_connecting))
                startWatchdog()
                startConnect(intent)
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
            e.setSocksListen("")
            EngineBridge.installTunProvider(this, openvpnTunProvider)
            EngineBridge.note("[vpn] OpenVPN 出口：先握手拿地址，再建系统 VPN")
            EngineBridge.refresh(e)
        } else {
            // 2) 建系统 VPN。失败就明确报错，不进入连接流程。
            val fd = establishTun(s, psiphon)
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
            // VPN 模式不需要本地端口：整个系统已经走隧道，多开一个监听没人用。
            e.setSocksListen("")
            EngineBridge.note(
                "[vpn] 系统 VPN 已启用（tun fd=$fd, MTU=${if (psiphon) PSIPHON_TUN_MTU else s.mtu}）"
            )
            EngineBridge.refresh(e)
        }

        // 出口地区必须在 connect 之前下发：它是 tunnel-core 的启动参数（EgressRegion），
        // 运行中改不了。空串 = 自动。
        e.setPsiphonRegion(s.exitRegion)
        // 分流规则同理：只在本地 SOCKS（仅代理模式）上执行，必须在 connect 之前下发。
        e.setRules(s.rulePolicy, s.ruleText)
        val endpointExtra = intent?.getStringExtra(EXTRA_ENDPOINT) ?: ""

        // 3) 选出口节点 + 4) 拨号，放进一个轮次循环里。
        //
        //    为什么要轮次：引擎单轮只试 5 个节点，而 VPN Gate 实测握手成功率只有四成
        //    左右 —— 一次失败就报错，等于让用户反复手点。引擎会把失败节点记 10 分钟
        //    （warpbackend 的失败记忆），下一轮自然落在列表更靠后的节点上；而列表本身
        //    是按「同国同类 → 同国其他类 → 别的国家」排的，于是用户要的那条
        //    「家宽挂了换家宽、国内没了换国家」就是这两件事拼出来的。
        var round = 0
        while (true) {
            round++
            if (openvpn) {
                val nodes = EngineBridge.vpnGateNodes(this)
                val cands = pickOpenVPNCandidates(s, nodes)
                if (cands.isEmpty()) {
                    EngineBridge.note(
                        "[vpn] 没有可用的 OpenVPN 节点（节点列表为空或选中节点已过期），" +
                            "请到设置 → OpenVPN 出口里刷新节点列表"
                    )
                    e.setOpenVPNExit("", "", "")
                    e.setVPNState(false)
                    EngineBridge.refresh(e)
                    stopForegroundCompat()
                    stopSelf()
                    return
                }
                val first = cands.first()
                EngineBridge.note(
                    "[vpn] OpenVPN 候选 ${cands.size} 个，首选 ${nodeSlotLabel(nodes, first)}" +
                        "（${first.country} ${first.ip}:${first.port}，${first.classLabel}" +
                        (if (first.shared) "·共享" else "") + "，" +
                        (if (first.hasMeasuredLatency) "${first.latencyMs}ms" else "未测") + "）"
                )
                e.setOpenVPNExit(
                    cands.joinToString(",") { it.id },
                    nodeSlotLabel(nodes, first),
                    first.cc,
                )
            } else if (round == 1) {
                // 关掉时必须显式清空，否则上一次选中的节点会留在引擎里，
                // 下一次「关着 OpenVPN」的连接仍然走节点（最难查的那种残留）。
                e.setOpenVPNExit("", "", "")
            }
            try {
                e.connect(proto, endpointExtra, psiphon, s.ipv6, s.mtu.toLong())
                break
            } catch (t: Throwable) {
                EngineBridge.note("[vpn] 连接失败：${t.message ?: t.toString()}")
                if (!openvpn || round >= OPENVPN_CONNECT_ROUNDS) break
                EngineBridge.note(
                    "[vpn] OpenVPN 第 $round 轮候选都失败，自动换下一批" +
                        "（最多 $OPENVPN_CONNECT_ROUNDS 轮，已失败的节点 10 分钟内不再重试）"
                )
            }
        }
        EngineBridge.refresh(e)
        updateNotification()
    }

    /**
     * 按设置排出候选节点（引擎按这个顺序逐个真握手，单轮最多试 5 个）。
     *
     * 顺序就是用户要的「失效自动切」语义：
     *   1. 手动钉死的节点（若有）
     *   2. 同国 + 同类别（家宽只切家宽、机房只切机房），延迟升序
     *   3. 同国 + 其他类别（家宽 > 未知 > 机房），延迟升序
     *   4. 其他国家 + 同类别，延迟升序
     *   5. 其他国家 + 其他类别（家宽 > 未知 > 机房）
     * 自动模式（没钉节点）：家宽 → 未知 → 机房，块内延迟升序。
     *
     * 为什么要给这么多（24 个）：引擎每轮只试 5 个，失败了服务会自动再来一轮，
     * 「失败记忆」（引擎侧，10 分钟）保证下一轮落在列表更后面的节点上 —— 于是
     * 「国内先切完 → 再去别的国家」是自然发生的，不需要在这里写死切换逻辑。
     *
     * **不因为「机房/共享」排除任何节点**：能用都保留，标记只影响顺序与展示。
     */
    private fun pickOpenVPNCandidates(s: AppSettings, nodes: List<VpnGateNode>): List<VpnGateNode> {
        if (nodes.isEmpty()) return emptyList()
        val byLatency = compareBy<VpnGateNode>(
            { if (it.hasMeasuredLatency) 0 else 1 },
            { it.latencyMs.takeIf { l -> l > 0 } ?: it.pingMs },
        )
        val fixed = if (s.openvpnNodeId.isNotEmpty()) {
            nodes.firstOrNull { it.id == s.openvpnNodeId }
        } else {
            null
        }
        if (fixed == null && s.openvpnNodeId.isNotEmpty()) {
            EngineBridge.note("[vpn] 固定节点 ${s.openvpnNodeId} 不在当前列表里，改为自动挑选")
        }
        val out = ArrayList<VpnGateNode>(OPENVPN_CANDIDATE_CAP)
        fun add(n: VpnGateNode) {
            if (out.size >= OPENVPN_CANDIDATE_CAP) return
            if (out.any { it.id == n.id }) return
            out.add(n)
        }
        if (fixed != null) add(fixed)

        // 类别块内顺序：家宽 → 未知 → 机房；同块按延迟升序。
        fun sortedOf(pool: List<VpnGateNode>): List<VpnGateNode> =
            pool.sortedWith(compareBy<VpnGateNode> { classRank(it.cls) }.then(byLatency))

        val targetCc = fixed?.cc ?: s.openvpnCountry
        val targetCls = fixed?.cls
        val inCountry = nodes.filter { it.cc.equals(targetCc, ignoreCase = true) }
        val abroad = nodes.filter { !it.cc.equals(targetCc, ignoreCase = true) }

        if (targetCls != null) {
            // 手动钉了节点：先同类，再该国其他类，再境外同类，最后境外其他类。
            sortedOf(inCountry.filter { it.cls == targetCls }).forEach(::add)
            sortedOf(inCountry.filter { it.cls != targetCls }).forEach(::add)
            sortedOf(abroad.filter { it.cls == targetCls }).forEach(::add)
            sortedOf(abroad).forEach(::add)
        } else {
            // 自动 / 只钉了国家：该国按「家宽→未知→机房 + 延迟」，再补境外。
            sortedOf(inCountry).forEach(::add)
            sortedOf(abroad).forEach(::add)
        }
        return out
    }

    /** 节点在列表里的编号（JP家宽03），与设置页选择器里的算法保持一致。 */
    private fun nodeSlotLabel(nodes: List<VpnGateNode>, node: VpnGateNode): String {
        val sameClass = nodes
            .filter { it.cc.equals(node.cc, ignoreCase = true) && it.cls == node.cls }
            .sortedWith(
                compareBy(
                    { if (it.hasMeasuredLatency) 0 else 1 },
                    { it.latencyMs.takeIf { l -> l > 0 } ?: it.pingMs },
                )
            )
        val idx = sameClass.indexOfFirst { it.id == node.id }
        val tag = when (node.cls) {
            "residential" -> "家宽"
            "datacenter" -> "机房"
            else -> "未知"
        }
        val num = if (idx >= 0) (idx + 1).toString().padStart(2, '0') else "??"
        return node.cc + tag + num
    }

    /** 排序用：家宽 > 未知 > 机房（不隐藏任何一类）。 */
    private fun classRank(cls: String): Int = when (cls) {
        "residential" -> 0
        "degraded" -> 1
        "unknown" -> 1
        else -> 2
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
    ): Int = try {
        val s = SettingsStore.load(this)
        val b = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(if (mtu in 576..9000) mtu else OPENVPN_TUN_MTU)
            .addAddress(address, prefixLen)
            .setBlocking(true)

        // 路由策略复用同一套三档（全局/绕过大陆/黑名单）。服务器 push 的
        // 明细路由不单独加：VPN Gate 的语义就是「全机走它」，加明细反而会把
        // 默认路由漏掉。
        applyRoutePolicy(b, s)

        val pushedDns = dnsCsv.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        if (!s.dnsOff) {
            val dns = pushedDns.ifEmpty { s.dnsList().ifEmpty { listOf("1.1.1.1", "223.5.5.5") } }
            dns.forEach { runCatching { b.addDnsServer(it) } }
        }
        applySplit(b, s)

        val pfd = b.establish() ?: return -1
        val fd = pfd.detachFd()
        tunFd = fd
        EngineBridge.peek()?.let { e ->
            // 必须回填 tun fd：引擎的延迟探测与出口看门狗（needRecover）只在
            // tunFD>0 时工作 —— 漏掉这一步会得到「能上网但永远不会自动重连」。
            e.setTunFD(fd.toLong())
            e.setVPNState(true)
            EngineBridge.refresh(e)
        }
        EngineBridge.note(
            "[vpn] OpenVPN 系统 VPN 已启用（$address/$prefixLen, tun fd=$fd, " +
                "MTU=${if (mtu in 576..9000) mtu else OPENVPN_TUN_MTU}）"
        )
        fd
    } catch (t: Throwable) {
        EngineBridge.note("[vpn] OpenVPN 建 tun 失败: ${t.message}")
        -1
    }

    /** 引擎的建 tun 回调（在 Go 的连接 goroutine 上调用）。 */
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
     * 建立系统 VPN 并交出 fd 的所有权。
     *
     * detachFd() 而不是 fd：fd 的生命周期交给 Go 侧的 tun 设备，断开时由它关闭，
     * 系统 VPN 随之消失。用 pfd.fd 的话，Java 侧对象被回收时会关掉同一个 fd，
     * 隧道就会在毫无征兆的情况下断掉。
     */
    private fun establishTun(s: AppSettings, psiphon: Boolean): Int = try {
        val mtu = if (psiphon) PSIPHON_TUN_MTU else s.mtu
        val b = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(mtu)
            .addAddress(TUN_ADDR_V4, 32)
            // 阻塞模式：wireguard 在独立 goroutine 上读设备，这正是它期望的语义。
            .setBlocking(true)

        // 路由策略：VpnService 只有一种表达方式 —— **加了路由的网段才进 tun**，
        // 没加的直接走物理网卡。三种规则模式就是三份路由集合。
        applyRoutePolicy(b, s)

        if (s.ipv6) {
            // 不给 ::/0 配地址就路由 v6 会把 v6 流量丢进黑洞。
            b.addAddress(TUN_ADDR_V6, 128)
            b.addRoute("::", 0)
        }
        if (!s.dnsOff) {
            val dns = s.dnsList().ifEmpty { listOf("1.1.1.1", "223.5.5.5") }
            dns.forEach { runCatching { b.addDnsServer(it) } }
        }
        applySplit(b, s)

        val pfd = b.establish() ?: return -1
        pfd.detachFd()
    } catch (t: Throwable) {
        EngineBridge.note("[vpn] establish 异常: ${t.message}")
        -1
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
            else -> b.addRoute("0.0.0.0", 0)
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
    private fun parseProxyCIDRs(text: String): List<Pair<String, Int>> = text.lineSequence()
        .map { it.substringBefore('#').trim() }
        .mapNotNull { line ->
            val parts = line.split(',', limit = 2)
            if (parts.size != 2 || !parts[0].trim().equals("proxy", ignoreCase = true)) {
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
                val now = System.currentTimeMillis()
                if (now - windowStart > RECOVER_WINDOW_MS) {
                    windowStart = now
                    attempts = 0
                }
                if (attempts >= RECOVER_MAX) {
                    EngineBridge.note(
                        "[vpn] 5 分钟内已自动重连 $attempts 次仍不稳定，停止自动重试" +
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

    private fun shutdown() {
        watchdog?.cancel()
        watchdog = null
        EngineBridge.peek()?.let { engine ->
            // 引擎关掉 tun 设备时 fd 随之关闭，系统 VPN 接口就消失了。
            engine.disconnect()
            engine.setVPNState(false)
            EngineBridge.refresh(engine)
        }
        tunFd = -1
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
