package com.xiaohe.vpn.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/**
 * 以浅色为主（用户明确要求）：冷灰底 + 蓝色主色 + 白卡片。
 * 故意不用 Android 12 的动态取色 —— 那会让配色随壁纸变，和设计稿对不上。
 */
private val LightScheme = lightColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDCE7FF),
    onPrimaryContainer = Color(0xFF0B2A6B),
    secondary = Color(0xFF0EA5E9),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFDCF3FF),
    onSecondaryContainer = Color(0xFF05415B),
    background = Color(0xFFF4F6FB),
    onBackground = Color(0xFF111827),
    surface = Color.White,
    onSurface = Color(0xFF111827),
    surfaceVariant = Color(0xFFEDF1F7),
    onSurfaceVariant = Color(0xFF5B6472),
    outline = Color(0xFFCBD5E1),
    outlineVariant = Color(0xFFE2E8F0),
    error = Color(0xFFDC2626),
    onError = Color.White,
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF7F1D1D),
)

private val DarkScheme = darkColorScheme(
    primary = Color(0xFF7BA6FF),
    onPrimary = Color(0xFF08203F),
    primaryContainer = Color(0xFF1E3A8A),
    onPrimaryContainer = Color(0xFFDCE7FF),
    secondary = Color(0xFF67D4F7),
    background = Color(0xFF0F1420),
    onBackground = Color(0xFFE5E9F0),
    surface = Color(0xFF171E2B),
    onSurface = Color(0xFFE5E9F0),
    surfaceVariant = Color(0xFF222B3A),
    onSurfaceVariant = Color(0xFFA8B2C1),
    outline = Color(0xFF3B4657),
    outlineVariant = Color(0xFF2A3342),
    error = Color(0xFFF87171),
)

@Composable
fun XiaoheTheme(themeMode: String = "light", content: @Composable () -> Unit) {
    val dark = when (themeMode) {
        "dark" -> true
        "auto" -> isSystemInDarkTheme()
        else -> false
    }

    // 状态栏/导航栏的图标颜色必须跟着应用主题走，而不是跟着系统深色模式走：
    // 应用选了深色而系统是浅色时，白底黑字的假设就反了，图标会看不见。
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = view.context.findActivity()?.window ?: return@SideEffect
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !dark
                isAppearanceLightNavigationBars = !dark
            }
        }
    }

    MaterialTheme(
        colorScheme = if (dark) DarkScheme else LightScheme,
        content = content,
    )
}

/** Compose 拿到的 Context 常常是包装过的，必须一路拆到 Activity 才能拿到 window。 */
private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
