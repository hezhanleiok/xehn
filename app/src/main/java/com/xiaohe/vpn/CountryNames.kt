package com.xiaohe.vpn

import java.util.IllformedLocaleException
import java.util.Locale

/**
 * 国旗与国名。
 *
 * 桌面版（warp-client/country.go）为了不依赖外部数据，把国名表编进了二进制；
 * Android 自带 ICU，直接问系统要本地化国名即可，覆盖表只留少数几个措辞要固定的。
 *
 * 旗帜用区域指示符 emoji：Android 原生渲染国旗 emoji，不存在桌面版那种
 * 「用画布拼旗、圆盘旗被拉成椭圆」的变形问题。
 */
private val nameOverrides = mapOf(
    "HK" to "中国香港",
    "MO" to "中国澳门",
    "TW" to "中国台湾",
)

/** 中文/本地化国名；非法代码回退成原样的大写代码，绝不返回空串。 */
fun countryDisplayName(iso: String, locale: Locale = Locale.SIMPLIFIED_CHINESE): String {
    val cc = iso.trim().uppercase()
    if (cc.length != 2) return cc.ifEmpty { "未知地区" }
    nameOverrides[cc]?.let { return it }
    return try {
        Locale.Builder().setRegion(cc).build().getDisplayCountry(locale).ifBlank { cc }
    } catch (_: IllformedLocaleException) {
        cc
    }
}

/** 把 ISO alpha-2 变成国旗 emoji；未知代码给一面白旗，不抛异常。 */
fun flagEmoji(iso: String): String {
    val cc = iso.trim().uppercase()
    if (cc.length != 2 || cc.any { it !in 'A'..'Z' }) return "🏳"
    val sb = StringBuilder()
    for (c in cc) {
        sb.appendCodePoint(0x1F1E6 + (c - 'A'))
    }
    return sb.toString()
}
