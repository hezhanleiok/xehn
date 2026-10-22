package com.xiaohe.vpn.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.xiaohe.vpn.AppSettings
import com.xiaohe.vpn.EngineBridge
import com.xiaohe.vpn.PROTOCOLS
import com.xiaohe.vpn.VpnState
import com.xiaohe.vpn.countryDisplayName
import com.xiaohe.vpn.flagEmoji
import com.xiaohe.vpn.protoLabel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.TextButton
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 首页：一个圆形的连接动作 + 一张「当前连接」卡片。
 *
 * 卡片里的 IP 一行有两种含义，而且这是刻意的：没连上时显示**本机** IP，
 * 连上后显示**出口** IP。用户看到的是「我现在以什么身份上网」，
 * 而不是「隧道参数是什么」。
 */
@Composable
fun HomeScreen(
    state: VpnState,
    settings: AppSettings,
    onToggle: () -> Unit,
    onProtoChange: (String) -> Unit,
    onOpenMenu: () -> Unit,
    onToggleTheme: () -> Unit,
) {
    val ctx = LocalContext.current

    // 未连接时把「本机 IP」实测出来（问一次公网，不是读网卡）。会联网，
    // 所以放 IO 线程；连上之后这一行换成出口，不需要再问。
    LaunchedEffect(state.isConnected) {
        if (!state.isConnected) {
            withContext(Dispatchers.IO) { EngineBridge.refreshLocalIp(ctx) }
        }
    }

    // 运行时长和速率要连续变化，所以按秒轮询；空闲时刷一次就够。
    LaunchedEffect(state.isConnected, state.isBusy) {
        if (state.isConnected || state.isBusy) {
            while (true) {
                EngineBridge.refresh()
                delay(1_000)
            }
        } else {
            EngineBridge.refresh()
        }
    }

    // 设置里关掉「日志自动滚动」时把日志冻在当前内容：快速滚动的日志没法读，
    // 也没法复制，这正是那个开关在电脑版上的用途。
    var frozenLogs by remember { mutableStateOf<List<String>?>(null) }
    LaunchedEffect(settings.logAutoScroll, state.isConnected) {
        frozenLogs = if (settings.logAutoScroll) null else EngineBridge.state.value.logs
    }
    val shownLogs = frozenLogs ?: state.logs

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            // insets 必须加在 verticalScroll **之前**：这样滚动视口本身就让开了
            // 系统栏，内容不会滑进状态栏底下，顶部那排图标也不会落进系统状态栏
            // 窗口、被它吃掉点击（targetSdk 35 起 edge-to-edge 是强制的）。
            .statusBarsPadding()
            .navigationBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        TopBar(
            state = state,
            settings = settings,
            onOpenMenu = onOpenMenu,
            onToggleTheme = onToggleTheme,
        )

        Spacer(Modifier.height(8.dp))
        ConnectDial(state = state, onToggle = onToggle)
        Spacer(Modifier.height(16.dp))

        StatusCard(state = state)
        Spacer(Modifier.height(12.dp))

        ConnectionCard(
            state = state,
            settings = settings,
            onProtoChange = onProtoChange,
        )
        Spacer(Modifier.height(12.dp))

        LogCard(shownLogs)
        Spacer(Modifier.height(24.dp))
    }
}

/**
 * 顶栏两个入口，各管一件事，不再重复：
 *   左（三条杠）→ 抽屉：节点 / 设置 / 关于 / 隐私政策 / 授权说明 / 更新
 *   右（太阳/月亮）→ 浅色/深色主题切换，默认浅色
 *
 * 版本号从顶栏挪走了（挤在名字旁边既难看也没用），改在「关于」里看。
 */
@Composable
private fun TopBar(
    state: VpnState,
    settings: AppSettings,
    onOpenMenu: () -> Unit,
    onToggleTheme: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 6.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // 原来这里是个没挂 onClick 的裸 Icon —— 点它当然不会有任何反应。
        IconButton(onClick = onOpenMenu, modifier = Modifier.size(42.dp)) {
            Icon(
                Icons.Filled.Menu,
                contentDescription = "菜单",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.width(2.dp))
        Column(Modifier.weight(1f)) {
            Text(
                "Xehn",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.5.sp,
                maxLines = 1,
            )
            Text(
                if (state.isConnected) "已连接，流量走隧道" else "连上就走，不用管设置",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
        }
        val dark = settings.theme == "dark"
        IconButton(onClick = onToggleTheme, modifier = Modifier.size(42.dp)) {
            Icon(
                if (dark) Icons.Filled.LightMode else Icons.Filled.DarkMode,
                contentDescription = if (dark) "切换到浅色" else "切换到深色",
                tint = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

/** 圆形连接按钮：外圈光晕 + 内圈实心，中心是电源图标。连接中转圈。 */
@Composable
private fun ConnectDial(state: VpnState, onToggle: () -> Unit) {
    val accent = when {
        state.isConnected -> MaterialTheme.colorScheme.primary
        state.isBusy -> MaterialTheme.colorScheme.secondary
        else -> MaterialTheme.colorScheme.primary
    }
    Box(
        modifier = Modifier.size(200.dp),
        contentAlignment = Alignment.Center,
    ) {
        Box(
            Modifier
                .size(200.dp)
                .background(accent.copy(alpha = 0.08f), CircleShape),
        )
        Box(
            Modifier
                .size(160.dp)
                .background(accent.copy(alpha = 0.14f), CircleShape),
        )
        Surface(
            onClick = onToggle,
            shape = CircleShape,
            color = if (state.isConnected) accent else MaterialTheme.colorScheme.surface,
            border = androidx.compose.foundation.BorderStroke(2.dp, accent),
            modifier = Modifier.size(116.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    Icons.Filled.PowerSettingsNew,
                    contentDescription = "连接",
                    tint = if (state.isConnected) Color.White else accent,
                    modifier = Modifier.size(44.dp),
                )
            }
        }
    }
}

/** 状态卡：状态词 + 时长 + IP 行 + 上下行速度。 */
@Composable
private fun StatusCard(state: VpnState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                statusTitle(state),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
                color = if (state.isConnected) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                statusHint(state),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(14.dp))
            Text(
                formatUptime(state.uptimeMs),
                style = MaterialTheme.typography.headlineMedium.copy(
                    fontFamily = FontFamily.Monospace,
                    letterSpacing = 2.sp,
                ),
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface,
            )

            Spacer(Modifier.height(14.dp))
            IpPill(state)
            Spacer(Modifier.height(14.dp))
            SpeedRow(state)

            // 系统 VPN 到底起没起，必须写在界面上：这正是「显示已连接但系统 VPN 是关的」
            // 那个问题最直接的可视化。
            if (state.isConnected) {
                Spacer(Modifier.height(12.dp))
                val ok = state.vpnUp
                Surface(
                    shape = RoundedCornerShape(999.dp),
                    color = if (ok) MaterialTheme.colorScheme.secondaryContainer
                    else MaterialTheme.colorScheme.errorContainer,
                ) {
                    Text(
                        if (ok) "系统 VPN 已启用" else "系统 VPN 未启用（流量不会走隧道）",
                        style = MaterialTheme.typography.labelMedium,
                        color = if (ok) MaterialTheme.colorScheme.onSecondaryContainer
                        else MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp),
                    )
                }
                // 最终出口叠加了第二跳时必须写出来：否则「协议=AWG」会让人以为
                // 出口就是 Cloudflare，而实际是 Psiphon/OpenVPN 节点。
                if (state.egress.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Surface(
                        shape = RoundedCornerShape(999.dp),
                        color = MaterialTheme.colorScheme.tertiaryContainer,
                    ) {
                        Text(
                            if (state.egress == "openvpn") "最终出口：OpenVPN 节点（VPN Gate）"
                            else "最终出口：Psiphon",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onTertiaryContainer,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun IpPill(state: VpnState) {
    val cc = state.displayCountry.uppercase()
    val ip = state.displayIp
    Surface(
        shape = RoundedCornerShape(999.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                if (state.isConnected) "出口 IP" else "本机 IP",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.width(10.dp))
            Text(if (cc.isBlank()) "🏳" else flagEmoji(cc), fontSize = 18.sp)
            Spacer(Modifier.width(6.dp))
            Text(
                if (ip.isBlank()) "获取中…" else ip,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            if (cc.isNotBlank()) {
                Spacer(Modifier.width(8.dp))
                // 国家名与 ISO 缩写都给：一个能读，一个能对得上。
                Text(
                    "${countryDisplayName(cc, java.util.Locale.SIMPLIFIED_CHINESE)} $cc",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun SpeedRow(state: VpnState) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SpeedTile(
            modifier = Modifier.weight(1f),
            down = true,
            bps = state.downBps,
            total = state.downTotal,
            enabled = state.isConnected,
        )
        SpeedTile(
            modifier = Modifier.weight(1f),
            down = false,
            bps = state.upBps,
            total = state.upTotal,
            enabled = state.isConnected,
        )
    }
}

@Composable
private fun SpeedTile(
    modifier: Modifier,
    down: Boolean,
    bps: Long,
    total: Long,
    enabled: Boolean,
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(30.dp)
                    .background(
                        if (down) MaterialTheme.colorScheme.secondaryContainer
                        else MaterialTheme.colorScheme.primaryContainer,
                        CircleShape,
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    if (down) Icons.Filled.ArrowDownward else Icons.Filled.ArrowUpward,
                    contentDescription = null,
                    tint = if (down) MaterialTheme.colorScheme.onSecondaryContainer
                    else MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.size(16.dp),
                )
            }
            Spacer(Modifier.width(10.dp))
            Column {
                Text(
                    if (enabled) formatBps(bps) else "0 B/s",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    "共 ${formatBytes(total)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** 连接参数卡：协议下拉 + 延迟。 */
@Composable
private fun ConnectionCard(
    state: VpnState,
    settings: AppSettings,
    onProtoChange: (String) -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(16.dp)) {
            ProtoDropdown(
                current = settings.proto,
                enabled = !state.isConnected && !state.isBusy,
                onChange = onProtoChange,
            )
            Spacer(Modifier.height(14.dp))
            LatencyRow(state)
        }
    }
}

@Composable
private fun ProtoDropdown(current: String, enabled: Boolean, onChange: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(enabled = enabled) { open = true }
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "连接协议",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    // 只显示协议名，不带括号注释 —— 注释是电脑版的说明文字，
                    // 放进下拉框里只会把名字挤住。
                    Text(
                        protoLabel(current),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Medium,
                    )
                }
                if (!enabled) {
                    Text(
                        "连接中不可切换",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.width(6.dp))
                }
                Icon(Icons.Filled.ExpandMore, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                // 五个协议全列出来（与电脑版同一套 id 与顺序）。引擎侧五条都已
                // 实现（见 engine/warp/session.go 的 Dial），所以都可选；哪天某个
                // 协议又缺实现，把它标成 ready=false 就会自动置灰并写明「暂未实现」。
                PROTOCOLS.forEach { p ->
                    DropdownMenuItem(
                        enabled = p.ready,
                        text = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    p.label,
                                    color = if (p.ready) LocalContentColor.current
                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                if (!p.ready) {
                                    Spacer(Modifier.width(8.dp))
                                    Text(
                                        "暂未实现",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        },
                        onClick = {
                            open = false
                            onChange(p.id)
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun LatencyRow(state: VpnState) {
    val bars = pingBars(state.latencyMs)
    Column(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "延迟",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            Text(
                if (state.isConnected) formatLatency(state.latencyMs) else "—",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
        }
        Spacer(Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            repeat(4) { i ->
                val on = i < bars
                Box(
                    Modifier
                        .weight(1f)
                        .height(5.dp)
                        .background(
                            if (on) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.outlineVariant,
                            RoundedCornerShape(3.dp),
                        ),
                )
            }
        }
        Spacer(Modifier.height(6.dp))
        Text(
            pingLabel(bars, state.isConnected),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun LogCard(logs: List<String>) {
    val ctx = LocalContext.current

    // 「分享」把日志写成 txt 放进 cache/logs，再用 FileProvider 交给系统分享面板。
    //
    // 为什么不走 SAF 的「保存到哪」（CreateDocument）：手机上点这个按钮的人几乎都是
    // 想把日志发给别人，弹一个文件管理器选目录反而多一步；而且 SAF 给的是一次性
    // content:// Uri，不少应用（微信/QQ）不认。这里直接 ACTION_SEND，对方收到的
    // 就是一份真正的 .txt。
    val shareLogs = {
        val text = EngineBridge.logsText()
        if (text.isBlank()) {
            EngineBridge.note("[ui] 没有可分享的日志")
        } else {
            try {
                val dir = File(ctx.cacheDir, "logs").apply { mkdirs() }
                // 文件名带时间戳：同一个文件被某个应用持着读取时覆盖会失败。
                val f = File(dir, "xhwarp-log-${logStamp()}.txt").apply { writeText(text) }
                val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", f)
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    putExtra(Intent.EXTRA_SUBJECT, "xhwarp 日志")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                ctx.startActivity(Intent.createChooser(send, "分享运行日志"))
                EngineBridge.note("[ui] 已准备分享日志（${text.lineSequence().count()} 行）")
            } catch (t: Throwable) {
                EngineBridge.note("[ui] 日志分享失败：${t.message}")
            }
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // 这里原来有个「运行日志」标题：卡片一窄它就被压成一列竖排字
                // （运/行/日/志），占地方又没信息量，去掉；行数说明本身已经够用。
                Text(
                    "显示最近 ${minOf(logs.size, LOG_TAIL)} 行 · 共 ${logs.size} 行",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(6.dp))
                // 复制/导出拿的都是**完整**日志（不止界面上这 40 行）：排查问题时
                // 前面那几行往往才是关键。
                TextButton(
                    onClick = {
                        val text = EngineBridge.logsText()
                        if (text.isBlank()) return@TextButton
                        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        cm?.setPrimaryClip(ClipData.newPlainText("xhwarp log", text))
                        EngineBridge.note("[ui] 日志已复制（${text.lineSequence().count()} 行）")
                    },
                    contentPadding = PaddingValues(horizontal = 8.dp),
                ) { Text("复制", style = MaterialTheme.typography.labelMedium) }
                TextButton(
                    onClick = shareLogs,
                    contentPadding = PaddingValues(horizontal = 8.dp),
                ) { Text("分享", style = MaterialTheme.typography.labelMedium) }
            }
            Spacer(Modifier.height(8.dp))
            if (logs.isEmpty()) {
                Text(
                    "暂无日志",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                logs.takeLast(40).reversed().forEach { line ->
                    Text(
                        line,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                        ),
                        color = if (line.contains("失败") || line.contains("错误") || line.contains("未启用")) {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    )
                }
            }
        }
    }
}

/** 导出文件名里的时间戳：xhwarp-log-20261010-1130.txt */
private fun logStamp(): String =
    SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())

private fun statusTitle(s: VpnState): String = when {
    s.isConnected -> "已连接"
    s.isBusy -> "连接中"
    s.state == "error" -> "连接失败"
    else -> "未连接"
}

private fun statusHint(s: VpnState): String = when {
    s.isConnected -> "隧道已就绪，全部流量走 VPN"
    s.isBusy -> "点击圆钮取消"
    s.state == "error" -> s.message.ifBlank { "点击重试" }
    else -> "点击圆钮建立连接"
}

private fun pingLabel(bars: Int, connected: Boolean): String = when {
    !connected -> "未连接"
    bars >= 4 -> "很好"
    bars == 3 -> "良好"
    bars == 2 -> "一般"
    bars == 1 -> "较差"
    else -> "测量中…"
}
