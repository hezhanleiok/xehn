package com.xiaohe.vpn.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.xiaohe.vpn.AppLang
import com.xiaohe.vpn.AppSettings
import com.xiaohe.vpn.BuildConfig
import com.xiaohe.vpn.EngineBridge
import com.xiaohe.vpn.LocalNetwork
import com.xiaohe.vpn.VpnState

/**
 * 抽屉里的页面与外部链接。
 *
 * 链接约定（用户要求）：一律指向 GitHub 仓库，不出现本机路径 / localhost。
 * App 自己的仓库地址先留占位符，等用户给出真实地址再替换；引擎与 Psiphon
 * 直接用各自的官方仓库。
 */
object AppLinks {
    // TODO(用户提供仓库地址后替换)：本 App 的仓库
    const val APP_REPO = "https://github.com/example/xhwarp-android"
    const val APP_RELEASES = "$APP_REPO/releases"
    const val APP_ISSUES = "$APP_REPO/issues"
    const val APP_PRIVACY = "$APP_REPO/blob/main/PRIVACY.md"
    const val APP_LICENSE = "$APP_REPO/blob/main/LICENSE"

    /** 引擎核心：AmneziaWG（WARP 的 WG/AWG 实现）与 gVisor 网络栈。 */
    const val CORE_AWG_REPO = "https://github.com/amnezia-vpn/amneziawg-go"
    const val CORE_GVISOR_REPO = "https://github.com/google/gvisor"
    const val CORE_QUICGO_REPO = "https://github.com/quic-go/quic-go"
    const val CORE_USQUE_REPO = "https://github.com/Diniboy1123/usque"

    /** Psiphon 出口：官方进程内库（GPL-3.0）。 */
    const val PSIPHON_REPO = "https://github.com/Psiphon-Labs/psiphon-tunnel-core"
    const val PSIPHON_LICENSE = "$PSIPHON_REPO/blob/master/LICENSE"
}

/** 抽屉 / 菜单里的目的地（titleEn 供英文界面用）。 */
enum class Page(val title: String, val titleEn: String, val icon: ImageVector) {
    Settings("设置", "Settings", Icons.Filled.Settings),
    LanShare("局域网共享", "LAN sharing", Icons.Filled.Share),
    About("关于", "About", Icons.Filled.Info),
    Privacy("隐私政策", "Privacy", Icons.Filled.Policy),
    License("授权说明", "Licenses", Icons.Filled.Description),
    Update("更新", "Updates", Icons.Filled.Refresh),
}

/** 打开一个外部链接。失败只记一行日志，不弹崩溃。 */
fun openUrl(ctx: Context, url: String) {
    try {
        ctx.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    } catch (t: Throwable) {
        EngineBridge.note("[ui] 打不开链接 $url: ${t.message}")
    }
}

/** 抽屉内容：入口一行一个。选中项高亮。 */
@Composable
fun MenuDrawer(
    current: Page?,
    lang: String,
    onSelect: (Page) -> Unit,
) {
    val en = com.xiaohe.vpn.AppLang.isEnglish(lang)
    fun t(zh: String, enText: String) = if (en && enText.isNotEmpty()) enText else zh
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surface)
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(horizontal = 12.dp, vertical = 10.dp)
            .verticalScroll(rememberScrollState()),
    ) {
        Text(
            "Xehn",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(start = 12.dp, top = 8.dp, bottom = 2.dp),
        )
        Text(
            t(
                "xiaohe VPN · 安卓版 ${BuildConfig.VERSION_NAME}",
                "xiaohe VPN · Android ${BuildConfig.VERSION_NAME}",
            ),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 12.dp, bottom = 12.dp),
        )
        // 局域网共享不再单独占一个抽屉入口：它的开关和端口都在设置页里，
        // 从「设置 → 本地代理 → 局域网共享」进去即可。两处入口只会让人以为
        // 是两个不同的功能。
        Page.values().filter { it != Page.LanShare }.forEach { page ->
            val active = page == current
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp)
                    .background(
                        if (active) MaterialTheme.colorScheme.primaryContainer
                        else MaterialTheme.colorScheme.surface,
                        RoundedCornerShape(12.dp),
                    )
                    .clickable { onSelect(page) }
                    .padding(horizontal = 12.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    page.icon,
                    contentDescription = null,
                    tint = if (active) MaterialTheme.colorScheme.onPrimaryContainer
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(14.dp))
                Text(
                    t(page.title, page.titleEn),
                    style = MaterialTheme.typography.bodyLarge,
                    color = if (active) MaterialTheme.colorScheme.onPrimaryContainer
                    else MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

/** 页面骨架：标题栏（返回 + 标题）+ 可滚动内容。 */
@Composable
fun PageScaffold(
    title: String,
    onBack: () -> Unit,
    content: @Composable () -> Unit,
) {
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
                title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
        }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            content()
            Spacer(Modifier.height(28.dp))
        }
    }
}

@Composable
private fun InfoCard(title: String, lines: List<String>) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 10.dp),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
            Spacer(Modifier.height(6.dp))
            lines.forEach { line ->
                Text(
                    line,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(3.dp))
            }
        }
    }
}

@Composable
private fun KeyValue(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(96.dp),
        )
        Text(
            value.ifBlank { "—" },
            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
            fontWeight = FontWeight.Medium,
        )
    }
}

/** 一行「可点击 → 打开链接」。 */
@Composable
private fun LinkRow(title: String, subtitle: String, url: String) {
    val ctx = LocalContext.current
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { openUrl(ctx, url) }
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    url,
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Icon(
                Icons.Filled.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// 六个页面
// ---------------------------------------------------------------------------

@Composable
fun AboutScreen(state: VpnState, onBack: () -> Unit) {
    val ctx = LocalContext.current
    PageScaffold("关于", onBack) {
        InfoCard(
            "版本",
            listOf(
                "App：${BuildConfig.VERSION_NAME}（${BuildConfig.VERSION_CODE}）",
                "引擎：${state.version.ifBlank { "—" }}",
                "包名：${BuildConfig.APPLICATION_ID}",
            ),
        )
        // 这一块原来在设置页底部（「关于」节），和这里的版本卡完全重复。
        // 现在统一收到这里：设置页只管「能改的东西」，只读信息全在关于页。
        InfoCard(
            "运行信息",
            listOf(
                "WARP 账号：本机自动注册（无需内置；失效自动重置）",
                "数据目录：" + ctx.filesDir.absolutePath + "/engine",
                "日志文件：" + EngineBridge.logPath(ctx),
                "系统 VPN：" + if (state.vpnUp) "已启用" else "未启用",
            ),
        )

        LinkRow("引擎核心（WG / AWG）", "amnezia-vpn/amneziawg-go", AppLinks.CORE_AWG_REPO)
        LinkRow("用户态网络栈", "google/gvisor（netstack）", AppLinks.CORE_GVISOR_REPO)
        LinkRow("MASQUE 传输", "quic-go + usque", AppLinks.CORE_USQUE_REPO)
        LinkRow("Psiphon 出口", "Psiphon-Labs/psiphon-tunnel-core", AppLinks.PSIPHON_REPO)
        LinkRow("App 仓库", "占位地址，等换成真实仓库", AppLinks.APP_REPO)
        LinkRow("问题反馈", "GitHub Issues", AppLinks.APP_ISSUES)
    }
}

@Composable
fun PrivacyScreen(onBack: () -> Unit) {
    PageScaffold("隐私政策", onBack) {
        InfoCard(
            "数据",
            listOf(
                "不收集、不上传任何用户数据；没有统计、没有广告。",
                "账号与日志只在本机 App 私有目录。",
            ),
        )
        LinkRow("完整隐私政策", "跟随 App 仓库", AppLinks.APP_PRIVACY)
    }
}

@Composable
fun LicenseScreen(onBack: () -> Unit) {
    PageScaffold("授权说明", onBack) {
        InfoCard(
            "重要：本 App 包含 GPL-3.0 组件",
            listOf(
                "Psiphon 出口使用官方 psiphon-tunnel-core，它是 GPL-3.0。",
                "它被**编进**本 App（进程内调用，不是独立可执行文件），因此本 App 的",
                "再分发需要满足 GPL-3.0 的义务：随附许可证、提供对应源码。",
                "桌面版当初刻意用独立 psiphon.exe 规避这一点；安卓端没有子进程可用，",
                "这一取舍由项目所有者确认。",
            ),
        )
        InfoCard(
            "其它组件",
            listOf(
                "各组件版权归其作者，许可与源码见各自仓库：",
                "· amneziawg-go（WG/AWG 数据面）",
                "· gVisor（用户态网络栈）",
                "· quic-go / usque（MASQUE 传输）",
                "· 本地兼容副本：third_party/qpack、third_party/tailscale-netlink",
            ),
        )
        LinkRow("Psiphon 许可证全文（GPL-3.0）", "官方仓库 LICENSE", AppLinks.PSIPHON_LICENSE)
        LinkRow("amneziawg-go", "WG / AWG 数据面", AppLinks.CORE_AWG_REPO)
        LinkRow("gVisor", "用户态网络栈", AppLinks.CORE_GVISOR_REPO)
        LinkRow("quic-go", "QUIC / HTTP3", AppLinks.CORE_QUICGO_REPO)
        LinkRow("usque", "MASQUE（CONNECT-IP）", AppLinks.CORE_USQUE_REPO)
        LinkRow("本 App 的许可证", "占位地址", AppLinks.APP_LICENSE)
    }
}

@Composable
fun UpdateScreen(state: VpnState, onBack: () -> Unit) {
    PageScaffold("更新", onBack) {
        InfoCard(
            "当前版本",
            listOf(
                "App：${BuildConfig.VERSION_NAME}（${BuildConfig.VERSION_CODE}）",
                "引擎：${state.version.ifBlank { "—" }}",
            ),
        )
        LinkRow("查看新版本", "GitHub Releases", AppLinks.APP_RELEASES)
        LinkRow("问题反馈", "GitHub Issues", AppLinks.APP_ISSUES)
    }
}

/**
 * 局域网共享：把手机这条隧道借给同一 Wi-Fi 下的电脑/平板。
 *
 * 它做的不是新协议 —— 只是把「本地 SOCKS5」在 VPN 模式下也开出来，并把
 * 端口/监听范围/当前地址集中在一页里说清楚。之前这些散在「仅代理」分支里，
 * VPN 模式下根本看不到，用户只能猜。
 */
@Composable
fun LanShareScreen(
    settings: AppSettings,
    state: VpnState,
    onChange: (AppSettings) -> Unit,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current
    val en = AppLang.isEnglish(settings.lang)
    fun t(zh: String, s: String) = if (en && s.isNotEmpty()) s else zh

    val lanIp = LocalNetwork.ipv4(ctx)
    val port = if (settings.proxyPort in 1..65535) settings.proxyPort else 1080
    val host = if (settings.proxyLan) lanIp.ifBlank { "0.0.0.0" } else "127.0.0.1"
    val addr = "$host:$port"

    PageScaffold(t("局域网共享", "LAN sharing"), onBack) {
        InfoCard(
            t("怎么用", "How it works"),
            listOf(
                t("同一 Wi-Fi 的设备，把 SOCKS5 代理填成下面的地址。",
                    "On the same Wi-Fi, set SOCKS5 proxy to the address below."),
                t("SOCKS5 无认证，公共 Wi-Fi 下别开局域网访问。",
                    "No authentication: do not allow LAN access on public Wi-Fi."),
            ),
        )

        ToggleCard(
            title = t("本地代理", "Local proxy"),
            subtitle = t("在本机开一个 SOCKS5 端口", "Runs a SOCKS5 listener on the phone"),
            checked = settings.localProxy || settings.proxyLan,
            onChange = { on -> onChange(settings.copy(localProxy = on)) },
        )

        ToggleCard(
            title = t("允许局域网访问", "Allow LAN access"),
            subtitle = t(
                "监听 0.0.0.0，同一 Wi-Fi 可用；关闭时只听 127.0.0.1",
                "Listen on 0.0.0.0 so other devices on the same Wi-Fi can use it.",
            ),
            checked = settings.proxyLan,
            onChange = { on -> onChange(settings.copy(proxyLan = on, localProxy = settings.localProxy || on)) },
        )

        PortCard(
            title = t("本地代理端口", "Proxy port"),
            subtitle = t("SOCKS5 端口，改完要重连", "SOCKS5 port; reconnect to apply"),
            value = settings.proxyPort.toString(),
            onChange = { v ->
                val n = v.filter { it.isDigit() }.take(5).toIntOrNull() ?: 0
                onChange(settings.copy(proxyPort = n.coerceIn(0, 65535)))
            },
        )

        InfoCard(
            t("当前状态", "Status"),
            listOf(
                t("共享地址", "Address") + "：" + addr,
                t("实际监听", "Listening") + "：" + state.socks.ifBlank { t("未连接 / 未开启", "off") },
                t("本机局域网 IP", "Phone LAN IP") + "：" + lanIp.ifBlank { "—" },
            ),
        )
    }
}

@Composable
private fun ToggleCard(
    title: String,
    subtitle: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(12.dp))
            Switch(checked = checked, onCheckedChange = onChange)
        }
    }
}

@Composable
private fun PortCard(
    title: String,
    subtitle: String,
    value: String,
    onChange: (String) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(
                subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = value,
                onValueChange = onChange,
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
