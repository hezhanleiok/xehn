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
object NodeSpeedStore {

    private const val FILE = "node-speeds"

    /** 有效期：与电脑版 `vpnGateSpeedTTL` 一致。 */
    private const val TTL_MS = 6 * 60 * 60 * 1000L

    /**
     * 可用速度地板：与电脑版 `openvpnMinBps` 一致。
     *
     * 电脑版实测这段线路上的节点会在 ~14 KB/s 上「能用但每个网页都在爬」，
     * 而旧的验证门槛（128 KiB / 12s ≈ 11 KB/s）根本拦不住它 —— 所以地板远高于它。
     */
    const val MIN_BPS = 150L * 1024

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
        bps <= 0 -> "未知"
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
