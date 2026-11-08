package com.xiaohe.vpn

import android.content.Context

/**
 * OpenVPN（VPN Gate）中继的**实测出口速度**记忆。
 *
 * 逐条照搬电脑版 `warp-client/vpngate.go` 的 `vpngate-speeds.json`：
 *
 *  - 只认「这台设备自己量到的」吞吐，不采信节点自报的 Speed 列 ——
 *    自报值跟实际能跑的速度没有可验证的关系；
 *  - **6 小时过期**（电脑版 vpnGateSpeedTTL）：VPN Gate 是志愿者线路，
 *    速度按小时在变，隔天的「快」没有任何参考价值；
 *  - 只影响排序（快 → 未测 → 慢），**不排除**任何节点；
 *  - 慢的也照样记下来：排序需要知道「它慢」，而不是当它没测过 ——
 *    电脑版正是靠这一点，才没让「上次成功」那一个慢节点永远顶在最前面。
 *
 * 为什么先放在 Kotlin 侧而不是 Go 引擎里：引擎要新增字段/方法就必须重跑
 * gomobile 重新打 `app/libs/engine.aar`（这台机器上没有 Go/NDK），而候选排序
 * 本来就在 Kotlin（`pickOpenVPNCandidates`）。等引擎下次重建时，这套规则应该
 * 整体搬进 `engine/warp/vpngate.go`（电脑版就放在那里）。
 */
/**
 * OpenVPN 节点的**真实握手延迟**记忆（不是列表里那个 TCP 连接时间）。
 *
 * 2026-11-01 用户实测反馈：列表显示 193~214ms 的三个美国节点全部连不上
 * （两个控制通道无响应、一个握手成功却不转发）。那个「延迟」是同域名 TCP
 * 连接耗时，和节点能不能握手没有关系。真正的判据只有一次 OpenVPN 握手。
 *
 * 存的是 `ms|ok|at`；有效期 6 小时（跟速度记忆一致），但**跳过**死节点的窗口
 * 只有 30 分钟 —— 测一次就 6 小时不许再试太狠了，节点是会活的。
 */
object NodeProbeStore {

    private const val FILE = "node-probes"
    private const val TTL_MS = 6 * 60 * 60 * 1000L
    /** 实测握手失败的节点，在这段时间内直接跳过（不进候选）。 */
    const val DEAD_SKIP_MS = 30 * 60 * 1000L

    /** 一条探测记录：[ms] 握手耗时（失败时是超时时间，只用于展示），[ok] 是否握手成功。 */
    data class Probe(val ms: Int, val ok: Boolean, val at: Long)

    fun snapshot(ctx: Context): Map<String, Probe> {
        val now = System.currentTimeMillis()
        val prefs = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val out = HashMap<String, Probe>(prefs.all.size)
        for ((id, raw) in prefs.all) {
            val p = parse(raw) ?: continue
            if (now - p.at < TTL_MS) out[id] = p
        }
        return out
    }

    /** 记一批探测结果（引擎返回什么就记什么）。 */
    fun rememberAll(ctx: Context, results: List<Pair<String, Probe>>) {
        if (results.isEmpty()) return
        val now = System.currentTimeMillis()
        val prefs = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val ed = prefs.edit()
        for ((k, raw) in prefs.all) {
            val p = parse(raw)
            if (p == null || now - p.at >= TTL_MS) ed.remove(k)
        }
        for ((id, p) in results) {
            if (id.isEmpty()) continue
            ed.putString(id, "${p.ms}|${if (p.ok) 1 else 0}|${p.at}")
        }
        ed.apply()
    }

    /**
     * 这个节点是否「刚测出握手失败」。
     *
     * 只有 30 分钟内的失败才算数：握手失败可能是节点临时抽风或上游抖动，
     * 记 6 小时等于永久拉黑一批本来会好的节点。
     */
    fun isDead(ctx: Context, id: String): Boolean {
        val p = snapshot(ctx)[id] ?: return false
        return !p.ok && System.currentTimeMillis() - p.at < DEAD_SKIP_MS
    }

    private fun parse(raw: Any?): Probe? {
        val s = raw as? String ?: return null
        val parts = s.split('|')
        if (parts.size != 3) return null
        val ms = parts[0].toIntOrNull() ?: return null
        val ok = parts[1] == "1"
        val at = parts[2].toLongOrNull() ?: return null
        if (at <= 0) return null
        return Probe(ms, ok, at)
    }
}

object NodeSpeedStore {

    private const val FILE = "node-speeds"

    /** 有效期：与电脑版 `vpnGateSpeedTTL` 一致。 */
    private const val TTL_MS = 6 * 60 * 60 * 1000L

    /**
     * 速度地板（同时也是「快/慢」分档线）。
     *
     * 电脑版是 150 KB/s，但手机上的 VPN Gate 家宽节点实测普遍在 50–100 KB/s：
     * 照搬 150 会让**每一个节点都被判成慢**，于是排序里所有实测过的节点都垫在
     * 「未测」后面 —— 用户选「日本自动」，系统就一路去赌没测过的节点，实测下来
     * 只有 0.x 兆（2026-11-03 真机日志：TH 71 KB/s、JP 58 KB/s）。
     *
     * 100 KB/s（约 0.8 Mbps）作为分档线后：过了线的进「快」档、会被优先复用；
     * 没过的记为「慢」档，下次排序排在未测节点之后 —— 探索与利用才都成立。
     * 连接时的换点地板用的是同一个数（WarpVpnService.OPENVPN_MIN_BPS）。
     */
    const val MIN_BPS = 100L * 1024

    /** 实测够快。 */
    const val TIER_FAST = 0

    /** 没测过 / 测不出（0）：排在快与慢之间，给新候选一个机会。 */
    const val TIER_UNTESTED = 1

    /** 实测低于地板：永远排在未测的候选后面。 */
    const val TIER_SLOW = 2

    /** 按实测吞吐分档（电脑版 `vpnGateSpeedTier`）。 */
    fun tier(bps: Long): Int = when {
        bps <= 0 -> TIER_UNTESTED
        bps >= MIN_BPS -> TIER_FAST
        else -> TIER_SLOW
    }

    /** 当前有效的实测速度（节点 id → bps）。过期项读时就丢掉。 */
    fun snapshot(ctx: Context): Map<String, Long> {
        val now = System.currentTimeMillis()
        val prefs = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val out = HashMap<String, Long>(prefs.all.size)
        for ((id, raw) in prefs.all) {
            val e = parse(raw)
            if (e != null && now - e.second < TTL_MS) out[id] = e.first
        }
        return out
    }

    /** 记一次实测。写的时候顺手清掉过期项（电脑版也是「写时清理」）。 */
    fun remember(ctx: Context, id: String, bps: Long) {
        if (id.isEmpty() || bps <= 0) return
        val now = System.currentTimeMillis()
        val prefs = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val ed = prefs.edit()
        for ((k, raw) in prefs.all) {
            val e = parse(raw)
            if (e == null || now - e.second >= TTL_MS) ed.remove(k)
        }
        ed.putString(id, "$bps|$now")
        ed.apply()
    }

    /** 「≈1.2 MB/s」/「≈14 KB/s」，给日志用。 */
    fun text(bps: Long): String = when {
        bps <= 0 -> "未测"
        bps >= 1024L * 1024 -> String.format(java.util.Locale.US, "≈%.1f MB/s", bps / 1048576.0)
        else -> "≈${bps / 1024} KB/s"
    }

    /** 存的是 "bps|毫秒时间戳"。解析失败一律当没有（坏数据不该让排序崩）。 */
    private fun parse(raw: Any?): Pair<Long, Long>? {
        val s = raw as? String ?: return null
        val i = s.indexOf('|')
        if (i <= 0) return null
        val bps = s.substring(0, i).toLongOrNull() ?: return null
        val at = s.substring(i + 1).toLongOrNull() ?: return null
        if (bps <= 0 || at <= 0) return null
        return bps to at
    }
}
