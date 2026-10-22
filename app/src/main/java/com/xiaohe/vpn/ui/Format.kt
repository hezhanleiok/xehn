package com.xiaohe.vpn.ui

import java.util.Locale

/** 速度：0 B/s、12.3 KB/s、1.2 MB/s。 */
fun formatBps(bps: Long): String {
    if (bps <= 0) return "0 B/s"
    val units = arrayOf("B/s", "KB/s", "MB/s", "GB/s")
    var v = bps.toDouble()
    var i = 0
    while (v >= 1024 && i < units.size - 1) {
        v /= 1024
        i++
    }
    return if (i == 0) "${v.toLong()} ${units[i]}" else String.format(Locale.US, "%.1f %s", v, units[i])
}

/** 累计流量：0 B、1.2 MB。 */
fun formatBytes(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB")
    var v = bytes.toDouble()
    var i = 0
    while (v >= 1024 && i < units.size - 1) {
        v /= 1024
        i++
    }
    return if (i == 0) "${v.toLong()} ${units[i]}" else String.format(Locale.US, "%.1f %s", v, units[i])
}

/** 时长 HH:MM:SS。 */
fun formatUptime(ms: Long): String {
    if (ms <= 0) return "00:00:00"
    val total = ms / 1000
    return String.format(
        Locale.US,
        "%02d:%02d:%02d",
        total / 3600,
        (total / 60) % 60,
        total % 60,
    )
}

fun formatLatency(ms: Long): String = if (ms <= 0) "—" else "$ms ms"

/**
 * 信号格数（0-4）。阈值是手机网络的常识值：<80ms 很好，>500ms 基本没法用。
 * 返回 0 表示没连上（界面据此显示 "Not connected"）。
 */
fun pingBars(ms: Long): Int = when {
    ms <= 0 -> 0
    ms < 80 -> 4
    ms < 160 -> 3
    ms < 350 -> 2
    else -> 1
}
