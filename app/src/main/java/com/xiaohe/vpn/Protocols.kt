package com.xiaohe.vpn

/**
 * 协议清单。id 与电脑版 `flags.go` 里的常量**逐字一致**（wg / awg / masque /
 * masque-h2 / wwarp），顺序也与电脑版首页那一排磁贴相同。
 *
 * 五种现在引擎侧都有实现（分派入口 warp/session.go 的 Dial）：WG / AWG 是最基本的
 * 两条，MASQUE 系走 CONNECT-IP（HTTP/3 或 HTTP/2），wwarp 是 WARP 套 WARP。
 * 全部可选；连不上时引擎会把具体原因写进运行日志，而不是静默失败。
 */
data class ProtoOption(
    val id: String,
    val label: String,
    val ready: Boolean,
)

val PROTOCOLS: List<ProtoOption> = listOf(
    ProtoOption("wg", "WireGuard", true),
    ProtoOption("awg", "AmneziaWG", true),
    ProtoOption("masque", "MASQUE", true),
    ProtoOption("masque-h2", "MASQUE (HTTP/2)", true),
    ProtoOption("wwarp", "WARP-in-WARP", true),
)

fun protoLabel(id: String): String =
    PROTOCOLS.firstOrNull { it.id == id }?.label ?: id.uppercase()
