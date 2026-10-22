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

    private val _state = MutableStateFlow(VpnState())
    val state: StateFlow<VpnState> = _state.asStateFlow()

    fun engineOrCreate(context: Context): Engine_ {
        engine?.let { return it }
        val dir = File(context.filesDir, "engine").apply { mkdirs() }
        val e = Engine_(dir.absolutePath)
        // 内置账号（assets/account.json）：有它就不必联网注册。在
        // api.cloudflareclient.com 不可达的网络里，现注册必然失败。
        var builtIn = false
        readAsset(context, "account.json")?.let { raw ->
            try {
                e.setAccountJSON(raw)
                builtIn = true
            } catch (t: Throwable) {
                note("[ui] 内置账号载入失败: ${t.message}")
            }
        }
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
                _state.value = _state.value.copy(logs = (_state.value.logs + line).takeLast(LOG_KEEP))
                refresh(e)
            }
        })
        engine = e
        _state.value = _state.value.copy(
            version = e.versionString(),
            mtu = e.mtu().toInt(),
            accountBuiltIn = builtIn,
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
     * 选择出口候选节点（按尝试顺序，逗号分隔的 ID）。
     *
     * 传多个而不是一个：VPN Gate 实测只有约四成节点能完成握手，只试一个会把
     * 网络质量的随机性直接甩给用户。ids 为空表示关闭该出口。
     */
    fun setOpenVPNExit(context: Context, ids: List<String>, label: String, country: String) {
        engineOrCreate(context).setOpenVPNExit(ids.joinToString(","), label, country)
    }


    /** UI 侧记录一行日志，与引擎日志同一条流。 */
    fun note(line: String) {
        _state.value = _state.value.copy(logs = (_state.value.logs + line).takeLast(LOG_KEEP))
    }

    /** 清空日志面板。 */
    fun clearLogs() {
        _state.value = _state.value.copy(logs = emptyList())
    }

    /** 复制一份日志给用户贴给别人排查（引擎 + UI 混在一起，正是要看的东西）。 */
    fun logsText(): String = _state.value.logs.joinToString("\n")

    /** 把 Go 侧的快照读进 Compose 状态。连接过程中按秒轮询即可。 */
    fun refresh(from: Engine_? = engine) {
        val e = from ?: return
        _state.value = _state.value.merge(e.statusJSON())
    }

    /**
     * 未连接时首页显示的「本机 IP」。走系统网络实测（和出口读数是同一个探测），
     * 不是从网卡猜的 —— 只有在实测拿不到时才回退到系统给的地址。
     *
     * 会阻塞几秒，调用方必须在 IO 线程。
     */
    fun refreshLocalIp(context: Context) {
        val e = engine ?: return
        val raw = try {
            e.probeLocalJSON()
        } catch (t: Throwable) {
            note("[ui] 本机 IP 探测失败: ${t.message}")
            return
        }
        val o = try {
            JSONObject(raw)
        } catch (_: Exception) {
            return
        }
        if (!o.optBoolean("ok", false)) {
            // 实测不到（例如当前网络连 Cloudflare 都不通）：退回系统地址，
            // 至少让用户看见自己在什么网里，国家留空由界面显示未知。
            val fallback = LocalNetwork.ipv4(context)
            if (fallback.isNotEmpty()) {
                _state.value = _state.value.copy(localIp = fallback)
            }
            return
        }
        _state.value = _state.value.copy(
            localIp = o.optString("ip"),
            localCountry = o.optString("country"),
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
) {
    /** 实测优先；没有实测时退回自报 ping（界面会用不同颜色标注）。 */
    val displayLatencyMs: Int get() = if (latencyMs > 0) latencyMs else pingMs
    val hasMeasuredLatency: Boolean get() = latencyMs > 0
    val classLabel: String get() = when (cls) {
        "residential" -> "家宽"
        "datacenter" -> "机房"
        else -> "未知"
    }
}

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
