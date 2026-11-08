package com.xiaohe.vpn

import android.content.Context
import com.xiaohe.engine.Engine_
import com.xiaohe.engine.LogSink
import com.xiaohe.engine.Protector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * 进程内唯一的引擎持有者 —— 桌面版会话模型的替代品。
 *
 * 桌面版把「现在连没连、出口是谁」写进 state.json，靠 state.json + health-owner
 * 的 pid 租约在 GUI / guard / watchdog / disconnect 之间协调。Android 只有一个进程，
 * 这些全是多余的：一个单例 + 一个 StateFlow 就够，UI 直接收集它。
 *
 * 三个 gomobile 的现实约束（都踩过，别改回去）：
 *  1. Go 的方法被绑到 `Engine_`（带下划线的实现类）上，`Engine` 只是放常量的抽象类。
 *  2. 快照走 JSON：gobind 会**静默跳过**参数或返回值是结构体（按值）的方法，
 *     `Status() Snapshot` 因此在 Java 侧根本不存在。用平台自带的 org.json 解析。
 *  3. 回调类接口（LogSink / Protector）必须是 Go 侧导出的 interface，Kotlin 实现。
 */
object EngineBridge {

    /**
     * 内存里保留多少行日志。界面只显示最近 40 行，但「复制 / 导出」拿的是这一份
     * 完整缓冲 —— 排查问题时前面那几十行往往才是关键，截断等于把证据丢了。
     */
    private const val LOG_KEEP = 5000

    private var engine: Engine_? = null

    /** 进程级 Application Context，只给日志落盘用（不要拿它做别的事）。 */
    @Volatile
    private var appCtx: Context? = null

    private val _state = MutableStateFlow(VpnState())
    val state: StateFlow<VpnState> = _state.asStateFlow()

    fun engineOrCreate(context: Context): Engine_ {
        engine?.let { return it }
        val appCtx = context.applicationContext
        this.appCtx = appCtx
        // 落盘日志 + 崩溃兜底必须在引擎产出第一行日志之前装好：引擎一构造就会
        // 开始写 conn/session 日志，晚一步就丢掉开头（而开头往往才是关键）。
        VpnLog.file(appCtx)
        CrashGuard.install(appCtx)
        val dir = File(context.filesDir, "engine").apply { mkdirs() }
        val e = Engine_(dir.absolutePath)
        // 不再内置 WARP 账号：每台设备首次连接时自己注册（引擎侧持缓存，
        // 14 天过期或连续失败会自动重新注册）。内置账号等于把所有装了同一个
        // APK 的设备绑在同一身份上，既容易被风控也没有隐私可言。
        val builtIn = false
        // 官方 Psiphon 客户端配置（assets/psiphon/client.config）。进程内跑
        // psiphon-tunnel-core 的唯一前提：SponsorId、服务器列表 URL 与签名公钥
        // 都在里面，缺了它会报「零个可用服务器」。DNS 一并给它，让它在系统 VPN
        // 已经建立的情况下仍有可用的解析器。
        readAsset(context, "psiphon/client.config")?.let { cfg ->
            val dns = SettingsStore.load(context).dnsList().joinToString(",")
            e.setPsiphonConfig(cfg, dns)
        } ?: note("[ui] 缺少 assets/psiphon/client.config，Psiphon 出口将不可用")

        e.setLogSink(object : LogSink {
            override fun onLog(line: String) {
                VpnLog.append(appCtx, line)
                _state.value = _state.value.copy(logs = (_state.value.logs + line).takeLast(LOG_KEEP))
                refresh(e)
            }
        })
        engine = e
        _state.value = _state.value.copy(
            version = e.versionString(),
            mtu = e.mtu().toInt(),
            accountBuiltIn = builtIn,
            // 上次运行留下的日志直接灌回界面：崩溃/被杀之后重开，能看的就是这份。
            // 只有用户点「清空日志」才会删文件（见 clearLogs），代码里没有任何
            // 自动清理路径 —— 这是明确要求。
            logs = VpnLog.readLast(appCtx, LOG_KEEP),
        )
        return e
    }

    fun peek(): Engine_? = engine

    /**
     * Psiphon 可用出口地区（ISO-2，已排序）。
     *
     * 来源是 Psiphon 自己上报的 `AvailableEgressRegions`，引擎把它落盘在
     * `filesDir/engine/psiphon-regions.json`；一次都没连过时返回内置兜底表。
     * 列表里没有的国家就是它这次不去的 —— 选了会直接失败，所以选择器只能列这些。
     */
    fun psiphonRegions(context: Context): List<String> = try {
        val arr = JSONArray(engineOrCreate(context).psiphonRegionsJSON())
        buildList { for (i in 0 until arr.length()) add(arr.getString(i)) }
    } catch (t: Throwable) {
        note("[ui] 读取 Psiphon 地区表失败: ${t.message}")
        emptyList()
    }

    /**
     * 装上 socket 排除器。必须在建立系统 VPN **之前**装好：VPN 一起来，
     * 隧道自己发往 Cloudflare 的 UDP 就会先被自己的 VPN 抓走，
     * 表现是「VPN 钥匙出来了、界面显示已连接、网页打不开」。
     */
    /**
     * 装上「用 OpenVPN 服务器下发的参数建 tun」的回调。
     *
     * 这是 OpenVPN 出口与 Psiphon 出口最大的结构差异：Psiphon 自带 packet tunnel，
     * 可以先把 tun 建好再连；OpenVPN 必须**先握手**拿到 ifconfig（10.x.x.x/24），
     * 再用那个地址建 tun —— 否则服务端回程包发不到我们这里，表现为连上但打不开。
     * 所以建 tun 的时机在连接过程中间，只能由引擎回调过来。
     */
    fun installTunProvider(context: Context, provider: com.xiaohe.engine.TunProvider) {
        engineOrCreate(context).setTunProvider(provider)
    }

    fun installProtector(context: Context, vpn: android.net.VpnService) {
        val e = engineOrCreate(context)
        // gomobile 把 Go 的 int 绑成 Java 的 long，所以这里签名是 Long。
        e.setProtector(object : Protector {
            override fun protect(fd: Long): Boolean = vpn.protect(fd.toInt())
        })
    }

    /**
     * 大陆路由表缓存状态，一句给设置页看的话。
     *
     * 这份表是**运行时拉取**的（engine/cnroutes.go）：装完 App 第一次连上才去抓，
     * 之后每 7 天刷一次。所以「未下载」是正常状态，不是错误。
     */
    fun cnRoutesText(context: Context): String = try {
        val o = JSONObject(engineOrCreate(context).cnRoutesInfoJSON())
        val n = o.optInt("count", 0)
        if (n <= 0) {
            "未下载（连上后自动拉取）"
        } else {
            val ms = o.optLong("fetched", 0L)
            val when_ = if (ms > 0) {
                java.text.SimpleDateFormat("MM-dd HH:mm", java.util.Locale.getDefault())
                    .format(java.util.Date(ms))
            } else {
                "未知时间"
            }
            val stale = if (o.optBoolean("stale", true)) "已过期" else "较新"
            "$n 条 · $stale · $when_"
        }
    } catch (t: Throwable) {
        "读取失败：${t.message}"
    }

    /** 立即拉一次大陆路由表（阻塞，调用方要放在后台线程）。 */
    fun refreshCNRoutes(context: Context): String = try {
        engineOrCreate(context).refreshCNRoutes()
    } catch (t: Throwable) {
        "刷新失败：${t.message}"
    }

    // ------------------------------------------------------------------
    // OpenVPN 出口（VPN Gate 节点池）
    // ------------------------------------------------------------------

    /**
     * 节点列表。数据来自引擎落盘的 `filesDir/engine/vpn-gate-nodes.json`，
     * 字段对齐 Go 侧 warp.VPNGateNode（配置原文不在里面，连接时按 id 取）。
     */
    fun vpnGateNodes(context: Context): List<VpnGateNode> = try {
        val o = JSONObject(engineOrCreate(context).vpnGateNodesJSON())
        val arr = o.optJSONArray("nodes") ?: JSONArray()
        // 实测速度记忆在 Kotlin 侧（见 NodeSpeedStore）：引擎那份节点 JSON 里没有
        // 这个字段，读的时候按 id 贴上去 —— 排序与界面看到的是同一份数据。
        val speeds = NodeSpeedStore.snapshot(context)
        val probes = NodeProbeStore.snapshot(context)
        buildList {
            for (i in 0 until arr.length()) {
                val n = arr.optJSONObject(i) ?: continue
                add(
                    VpnGateNode(
                        id = n.optString("id"),
                        host = n.optString("host"),
                        ip = n.optString("ip"),
                        port = n.optInt("port"),
                        proto = n.optString("proto"),
                        cc = n.optString("cc"),
                        country = n.optString("country"),
                        operator = n.optString("operator"),
                        pingMs = n.optInt("pingMS"),
                        speedBps = n.optInt("speedBps"),
                        latencyMs = n.optInt("latencyMS"),
                        cls = n.optString("class", "unknown"),
                        classSource = n.optString("classSource"),
                        shared = n.optBoolean("shared"),
                        isp = n.optString("isp"),
                        asn = n.optString("as"),
                        measuredBps = speeds[n.optString("id")] ?: 0L,
                        handshakeMs = probes[n.optString("id")]?.ms ?: 0,
                        handshakeOk = probes[n.optString("id")]?.ok ?: false,
                        hasProbe = probes.containsKey(n.optString("id")),
                    )
                )
            }
        }
    } catch (t: Throwable) {
        note("[ui] 读取 VPN Gate 节点失败: ${t.message}")
        emptyList()
    }

    fun vpnGateFetchedAt(context: Context): Long = try {
        JSONObject(engineOrCreate(context).vpnGateNodesJSON()).optLong("fetchedAt", 0L)
    } catch (_: Throwable) {
        0L
    }

    /** 抓一轮节点（阻塞；调用方要放在 IO 线程）。 */
    fun refreshVPNGateNodes(context: Context): String = try {
        engineOrCreate(context).refreshVPNGateNodes()
    } catch (t: Throwable) {
        "刷新失败：${t.message}"
    }

    /**
     * 一条「真实 OpenVPN 握手 + 真下载」测试结果。
     *
     * [bps] 是握手后经该节点实测的吞吐（0 = 握手成功但测不出，界面写「速度未测」）。
     * 只测握手看不出「能握手但只有几 KB/s」的节点，而那正是最该筛掉的。
     */
    data class NodeProbeResult(
        val id: String,
        val ms: Int,
        val ok: Boolean,
        val error: String,
        val bps: Long = 0,
    )

    /**
     * 对给定节点做**真实 OpenVPN 握手**测试并把结果落盘（阻塞，几秒到两三分钟）。
     *
     * 为什么要专门测：列表里显示的延迟是 api 域名的 TCP 连接时间，跟这个节点
     * 能不能握手、握手多久无关。2026-11-01 真机：显示 193~214ms 的三个美国节点
     * 全部连不上，而 JP/KR 节点多的国家能连上 —— 只有真握手能分辨。
     *
     * 必须在 IO 线程调用；引擎侧并发 6，单个节点最多 10 秒（100 个最坏约 3 分钟）。
     */
    fun testOpenVpnNodes(context: Context, ids: List<String>): List<NodeProbeResult> {
        if (ids.isEmpty()) return emptyList()
        val raw = try {
            engineOrCreate(context).testOpenVPNNodes(ids.joinToString(","))
        } catch (t: Throwable) {
            note("[ui] 握手测速调用失败：${t.message}")
            return emptyList()
        }
        val out = ArrayList<NodeProbeResult>(ids.size)
        try {
            val o = JSONObject(raw)
            if (!o.optBoolean("ok", false)) {
                note("[ui] 握手测速失败：${o.optString("error", "未知原因")}")
                return emptyList()
            }
            val arr = o.optJSONArray("results") ?: JSONArray()
            for (i in 0 until arr.length()) {
                val r = arr.optJSONObject(i) ?: continue
                out.add(
                    NodeProbeResult(
                        id = r.optString("id"),
                        ms = r.optInt("ms", 0),
                        ok = r.optBoolean("ok", false),
                        error = r.optString("error"),
                        bps = r.optLong("bps", 0),
                    )
                )
            }
        } catch (t: Throwable) {
            note("[ui] 握手测速结果解析失败：${t.message}")
            return emptyList()
        }
        val now = System.currentTimeMillis()
        NodeProbeStore.rememberAll(
            context,
            out.map { it.id to NodeProbeStore.Probe(it.ms, it.ok, now) },
        )
        val ok = out.count { it.ok }
        note("[ui] 握手测速完成：${out.size} 个节点里 $ok 个能握手（结果已用于排序）")
        return out
    }

    /**
     * 选择出口候选节点（按尝试顺序，逗号分隔的 ID）。
     *
     * 传多个而不是一个：VPN Gate 实测只有约四成节点能完成握手，只试一个会把
     * 网络质量的随机性直接甩给用户。ids 为空表示关闭该出口。
     */
    fun setOpenVPNExit(context: Context, ids: List<String>, label: String, country: String) {
        engineOrCreate(context).setOpenVPNExit(ids.joinToString(","), label, country)
    }


    /** UI 侧记录一行日志，与引擎日志同一条流（同样落盘）。 */
    fun note(line: String) {
        appCtx?.let { VpnLog.append(it, line) }
        _state.value = _state.value.copy(logs = (_state.value.logs + line).takeLast(LOG_KEEP))
    }

    /**
     * 清空日志：面板 + 磁盘文件一起删。
     *
     * 这是**唯一**会删日志的入口（用户手点）。退出 App、断开重连、重新启动进程
     * 都不删 —— 闪退后重开还能看到上一条连接到底走到哪一步。
     */
    fun clearLogs() {
        appCtx?.let { VpnLog.clear(it) }
        _state.value = _state.value.copy(logs = emptyList())
        appCtx?.let { VpnLog.append(it, "[ui] 日志已手动清空") }
    }

    /** 日志文件路径：出错时让用户直接把这个文件发出来。 */
    fun logPath(context: Context): String = VpnLog.file(context).absolutePath

    /** 复制一份日志给用户贴给别人排查（引擎 + UI 混在一起，正是要看的东西）。 */
    fun logsText(): String = _state.value.logs.joinToString("\n")

    /** 把 Go 侧的快照读进 Compose 状态。连接过程中按秒轮询即可。 */
    fun refresh(from: Engine_? = engine) {
        val e = from ?: return
        _state.value = _state.value.merge(e.statusJSON())
    }

    /**
     * 连接前预注册账号（阻塞，必须放 IO 线程）。
     *
     * 必须在 `VpnService.establish()` **之前**调用：VPN 一建立，系统 DNS 查询就被
     * 路由进还没通的隧道，`api.cloudflareclient.com` 会 `no such host`。
     */
    fun prepareAccounts(context: Context, proto: String) {
        val raw = try {
            engineOrCreate(context).prepareAccounts(proto)
        } catch (t: Throwable) {
            note("[ui] 预注册调用失败：${t.message}")
            return
        }
        try {
            val o = JSONObject(raw)
            if (!o.optBoolean("ok", false)) {
                note("[ui] 账号预注册失败：${o.optString("error", "未知原因")}")
            }
        } catch (_: Exception) {
            // 解析失败就当作没预注册，连接流程自己会再报错。
        }
    }

    /**
     * 未连接时首页显示的「本机 IP」= **局域网地址**（如 192.168.5.8）。
     *
     * 以前这里显示公网出口 IP：那个数字和「出口 IP」几乎一样，用户无法用它核对
     * 「我在哪个网里」，也没法据此给同一 Wi-Fi 的设备填局域网共享地址。公网出口
     * 已经有单独一栏，不必在这里重复。
     *
     * 不发网络请求，立刻返回。
     */
    fun refreshLocalIp(context: Context) {
        val lan = LocalNetwork.ipv4(context)
        _state.value = _state.value.copy(
            localIp = lan,
            localCountry = "",
        )
    }
}

/** 把 StatusJSON 的输出并进当前状态；字段缺失时保留旧值，不把界面打回空白。 */
private fun VpnState.merge(raw: String): VpnState {
    val o = try {
        JSONObject(raw)
    } catch (_: Exception) {
        return this
    }
    return copy(
        state = o.optString("state", state),
        proto = o.optString("proto", proto),
        endpoint = o.optString("endpoint", endpoint),
        exitIp = o.optString("exitIP", exitIp),
        country = o.optString("country", country),
        message = o.optString("message", message),
        uptimeMs = o.optLong("uptimeMS", uptimeMs),
        latencyMs = o.optLong("latencyMS", latencyMs),
        upBps = o.optLong("upBps", upBps),
        downBps = o.optLong("downBps", downBps),
        upTotal = o.optLong("upBytes", upTotal),
        downTotal = o.optLong("downBytes", downTotal),
        vpnUp = o.optBoolean("vpn", vpnUp),
        needRecover = o.optBoolean("needRecover", needRecover),
        egress = o.optString("egress", egress),
    )
}

/**
 * 一个 VPN Gate 候选节点。
 *
 * [cls] 是家宽/机房/未知（residential / datacenter / unknown）；[shared] 表示
 * ip-api 把它标成共享代理（电脑版实测 6/6 家宽节点都命中 PacketStream，
 * 所以它只做小标，不参与过滤 —— 用户明确要求「能用都保留」）。
 */
data class VpnGateNode(
    val id: String,
    val host: String,
    val ip: String,
    val port: Int,
    val proto: String,
    val cc: String,
    val country: String,
    val operator: String,
    val pingMs: Int,
    val speedBps: Int,
    val latencyMs: Int,
    val cls: String,
    val classSource: String,
    val shared: Boolean,
    val isp: String,
    val asn: String,
    /**
     * 这台设备上一次连上它时实测到的出口吞吐（bps，0 = 没测过）。
     *
     * 来自 [NodeSpeedStore]（6 小时过期）。它**只参与排序**：快 → 未测 → 慢，
     * 不用来决定「能不能用」—— 能用都保留是明确的产品决定。
     */
    val measuredBps: Long = 0L,
    /**
     * **真实 OpenVPN 握手**耗时（ms，0 = 没测过）。来自「测延迟」按钮，
     * 见 [NodeProbeStore]。列表里那个 `pingMs` 只是 TCP 连接时间，不代表能握手。
     */
    val handshakeMs: Int = 0,
    /** 上一次真实握手是否成功（配合 [hasProbe] 使用）。 */
    val handshakeOk: Boolean = false,
    /** 是否有过真实握手记录（成功或失败都算）。 */
    val hasProbe: Boolean = false,
) {
    /** 实测优先；没有实测时退回自报 ping（界面会用不同颜色标注）。 */
    val displayLatencyMs: Int get() = if (latencyMs > 0) latencyMs else pingMs
    val hasMeasuredLatency: Boolean get() = latencyMs > 0
    /** 实测速度的可读形式（没测过 = "未测"），日志用。 */
    val measuredText: String get() = if (measuredBps > 0) NodeSpeedStore.text(measuredBps) else "未测"
    val classLabel: String get() = when (cls) {
        "residential" -> "家宽"
        "datacenter" -> "机房"
        else -> "未分类"
    }
}

/** 节点排序里「真握手」的分档：通 < 没测过 < 失败。 */
private fun probeRankOf(n: VpnGateNode): Int = when {
    !n.hasProbe -> 1
    n.handshakeOk -> 0
    else -> 2
}

/**
 * 节点排序的**唯一来源**：连接时的候选顺序、设置页的编号（JP家宽03）都用它。
 *
 * 拆出来是因为两处必须完全一致：编号是按「排好序的列表」数出来的，如果连接时
 * 换了另一套顺序，用户看到的「JP家宽03」就不是他实际连的那个。
 *
 * 层次：家宽 → 未知 → 机房；真握手通 → 没测过 → 握手失败；
 * **实测吞吐档（快 → 没测过 → 慢）**，同档内按实测速度降序；
 * 最后才用握手指耗时与列表里那个 TCP 延迟兜底。
 *
 * 为什么吞吐要排在握手耗时前面：握手只证明「能连」，不证明「能跑」。
 * 0.2.9 把吞吐排在最后，结果所有实测过的节点都进了「慢」档（地板 150 KB/s
 * 谁都过不了），排序反而把**没测过的**节点顶到前面 —— 用户选「日本自动」，
 * 系统就一路去赌没测过的节点，连上只有 0.x 兆。用户的要求很明确：
 * 自动的时候优先选最快的那个，而不是「看起来最近的那个」。
 */
internal val vpnGateNodeOrder: Comparator<VpnGateNode> =
    compareBy<VpnGateNode> {
        when (it.cls) {
            "residential" -> 0
            "unknown", "degraded" -> 1
            else -> 2
        }
    }
        .thenBy { probeRankOf(it) }
        .thenBy { NodeSpeedStore.tier(it.measuredBps) }
        .thenByDescending { it.measuredBps }
        .thenBy { if (it.hasProbe && it.handshakeOk) it.handshakeMs else 0 }
        .thenBy { if (it.hasMeasuredLatency) 0 else 1 }
        .thenBy { it.latencyMs.takeIf { l -> l > 0 } ?: it.pingMs }

/** 从 assets 读一个文本文件；不存在或读失败都返回 null（不抛）。 */
private fun readAsset(context: Context, name: String): String? = try {
    context.assets.open(name).bufferedReader().use { it.readText() }
} catch (_: Exception) {
    null
}

/**
 * 一份可以直接渲染的会话快照，字段名与 Go 侧 engine.Snapshot 的 json tag 一致。
 */
data class VpnState(
    val state: String = "idle",
    val proto: String = "",
    val endpoint: String = "",
    val exitIp: String = "",
    val country: String = "",
    val message: String = "未连接",
    val uptimeMs: Long = 0L,
    val version: String = "",
    val mtu: Int = 1280,
    /** 数据面统计：延迟与上下行速率，来自 tun 设备的字节计数与隧道内探测。 */
    val latencyMs: Long = 0L,
    val upBps: Long = 0L,
    val downBps: Long = 0L,
    /** 本次会话累计流量（tun 设备字节计数）。 */
    val upTotal: Long = 0L,
    val downTotal: Long = 0L,
    /** 系统 VPN 是否真的建立（不是「隧道握手成功」）。 */
    val vpnUp: Boolean = false,
    /** 最终出口种类："" = 基础协议，"psiphon" / "openvpn" = 叠了第二跳。 */
    val egress: String = "",
    /**
     * 引擎判定「这次会话已经死掉」（连续探测失败且完全没数据流动），
     * 等上层断开重连。WarpVpnService 的看门狗读它来触发自动换点重连。
     */
    val needRecover: Boolean = false,
    /** 未连接时显示的本机地址（实测），以及它的归属。 */
    val localIp: String = "",
    val localCountry: String = "",
    /** assets/account.json 是否成功载入（设置页「关于」用它说明要不要联网注册）。 */
    val accountBuiltIn: Boolean = false,
    /** 隧道自带的本地 SOCKS5 地址（只有 netstack 模式才有）。 */
    val socks: String = "",
    val logs: List<String> = emptyList(),
) {
    val isConnected: Boolean get() = state == "connected"
    val isBusy: Boolean get() = state == "connecting" || state == "stopping"

    /** 界面显示哪个 IP：连上就是出口，没连就是本机。 */
    val displayIp: String get() = if (isConnected) exitIp else localIp
    val displayCountry: String get() = if (isConnected) country else localCountry
}
