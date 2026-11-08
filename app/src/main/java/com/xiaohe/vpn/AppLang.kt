package com.xiaohe.vpn

import java.util.Locale

/**
 * 界面语言。
 *
 * 诚实说明（设置页里也写着）：英文目前覆盖**骨架文案** —— 抽屉菜单、页面标题、
 * 设置分区标题、主要按钮。大段说明文字仍是中文。宁可说清范围，也不做一个
 * 「切了看不出变化」的假开关。
 *
 * "system" 跟随系统语言（只有系统是英文时才用英文）。
 */
object AppLang {
    fun isEnglish(lang: String): Boolean = when (lang) {
        "en" -> true
        "zh" -> false
        else -> Locale.getDefault().language.startsWith("en")
    }
}

/**
 * 取一条文案。[en] 为空时回退中文 —— 漏翻的地方至少不会变成空白。
 */
fun tr(lang: String, zh: String, en: String): String =
    if (en.isNotEmpty() && AppLang.isEnglish(lang)) en else zh

/** 语言选项（设置页的三档）。 */
val LANG_OPTIONS: List<Pair<String, String>> = listOf(
    "system" to "跟随系统",
    "zh" to "简体中文",
    "en" to "English",
)
