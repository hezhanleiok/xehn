package com.xiaohe.vpn.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/** 一个可勾选的应用。 */
data class InstalledApp(val pkg: String, val label: String)

/**
 * 列出手机上「有桌面图标」的应用（用户可以按名字认出来的那些），按名字排序。
 *
 * 用 queryIntentActivities(LAUNCHER) 而不是 getInstalledApplications：后者会把
 * 一堆用户永远不想选、也没有名字的后台组件列出来，反而更难选。当前 App 自己排除掉。
 *
 * 包可见性：Android 11+ 需要 manifest 里的 QUERY_ALL_PACKAGES，否则这个列表会是空的。
 */
fun loadLaunchableApps(ctx: Context): List<InstalledApp> {
    val pm = ctx.packageManager
    val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    val resolved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0L))
    } else {
        @Suppress("DEPRECATION")
        pm.queryIntentActivities(intent, 0)
    }
    val seen = HashSet<String>()
    val out = ArrayList<InstalledApp>(resolved.size)
    for (ri in resolved) {
        val pkg = ri.activityInfo?.packageName ?: continue
        if (pkg == ctx.packageName) continue // 自己不参与分流
        if (!seen.add(pkg)) continue
        val label = try {
            ri.loadLabel(pm).toString()
        } catch (_: Throwable) {
            pkg
        }
        out.add(InstalledApp(pkg, label.ifBlank { pkg }))
    }
    return out.sortedBy { it.label.lowercase() }
}

/** 把逗号分隔的包名串解析成集合。 */
fun parsePackageList(raw: String): Set<String> =
    raw.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }.toSet()

/** 集合写回逗号分隔串（稳定顺序，便于对比与去重）。 */
fun formatPackageList(pkgs: Collection<String>): String =
    pkgs.sorted().joinToString(",")

/**
 * 分应用选择页：从已安装应用里勾选，不用手输包名。
 *
 * 返回值走 [onApply]：只在这一页里改，点「保存」才写回设置 —— 勾错一半退出去
 * 不应该把设置弄坏。
 */
@Composable
fun AppPickerScreen(
    initial: Set<String>,
    onApply: (Set<String>) -> Unit,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current
    // 装/卸载应用或权限变化时重新读一次即可；这一页生命周期很短。
    val apps = remember { loadLaunchableApps(ctx) }
    var selected by remember { mutableStateOf(initial) }
    var query by remember { mutableStateOf("") }

    val shown = remember(apps, query) {
        val q = query.trim().lowercase()
        if (q.isEmpty()) apps
        else apps.filter { it.label.lowercase().contains(q) || it.pkg.lowercase().contains(q) }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .statusBarsPadding()
            .navigationBarsPadding(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 6.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack, modifier = Modifier.size(42.dp)) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "返回",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                "选择应用",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { onApply(selected) }) { Text("保存") }
        }

        Text(
            "已选 ${selected.size} 个；装了 ${apps.size} 个可启动应用",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 18.dp, bottom = 6.dp),
        )

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            singleLine = true,
            placeholder = { Text("搜索应用名或包名") },
            textStyle = MaterialTheme.typography.bodyMedium,
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = { selected = shown.map { it.pkg }.toSet() }) {
                Text("全选当前列表", style = MaterialTheme.typography.labelMedium)
            }
            TextButton(onClick = { selected = emptySet() }) {
                Text("清空", style = MaterialTheme.typography.labelMedium)
            }
        }

        if (apps.isEmpty()) {
            Text(
                "读不到已安装应用列表。若系统询问「查看已安装应用」请允许；\n" +
                    "Android 11+ 还需要 QUERY_ALL_PACKAGES 权限（已随包声明）。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(16.dp),
            )
        }

        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(shown, key = { it.pkg }) { app ->
                val checked = app.pkg in selected
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            selected = if (checked) selected - app.pkg else selected + app.pkg
                        }
                        .padding(horizontal = 12.dp, vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = checked, onCheckedChange = { on ->
                        selected = if (on) selected + app.pkg else selected - app.pkg
                    })
                    Column(Modifier.weight(1f)) {
                        Text(app.label, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            app.pkg,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = FontFamily.Monospace,
                            ),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
            item { Spacer(Modifier.height(24.dp)) }
        }
    }
}

/**
 * 保存后写回设置并写一行日志：分应用是「内核层」生效的，用户需要知道它到底
 * 认到了几个包 —— 写错包名时列表是空的，那正是「开了没效果」的原因。
 *
 * 由调用方（MainActivity）在保存时记日志，这里只保留编解码两个纯函数。
 */

/** 勾选结果 -> 逗号分隔串（写到 AppSettings.splitApps）。 */
fun encodeSelectedApps(pkgs: Set<String>): String = formatPackageList(pkgs)
