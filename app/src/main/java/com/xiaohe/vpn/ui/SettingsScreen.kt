package com.xiaohe.vpn.ui

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.xiaohe.vpn.AppSettings
import com.xiaohe.vpn.EngineBridge
import com.xiaohe.vpn.LANG_OPTIONS
import com.xiaohe.vpn.NodeSpeedStore
import com.xiaohe.vpn.PROTOCOLS
import com.xiaohe.vpn.ProtoOption
import com.xiaohe.vpn.R
import com.xiaohe.vpn.VpnGateNode
import com.xiaohe.vpn.VpnState
import com.xiaohe.vpn.countryDisplayName
import com.xiaohe.vpn.flagEmoji
import com.xiaohe.vpn.vpnGateNodeOrder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 设置页。
 *
 * 收录了电脑版 `settings.go` 里在手机上有意义的全部条目；桌面专有的（开机自启、
 * 系统代理、mihomo 的混合/API 端口、外部内核路径、绑定网卡）不出现，
 * 因为它们在 Android 上不存在对应物。
 *
 * 还没搬到安卓的条目**照实显示并说明原因**，不做成能打开却什么也不做的假开关：
 * 一个骗人的开关比一个明确的「暂未实现」更浪费时间。
 */
@Composable
fun SettingsScreen(
    state: VpnState,
    settings: AppSettings,
    onChange: (AppSettings) -> Unit,
    onClearLogs: () -> Unit,
    onPickApps: () -> Unit,
    /** 打开「局域网共享」详情页（不再从侧边栏进入）。 */
    onOpenLanShare: () -> Unit,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            // 与首页同样处理：insets 在滚动之前，返回箭头不会被系统状态栏压住。
            .statusBarsPadding()
            .navigationBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack, modifier = Modifier.size(42.dp)) {
                Icon(Icons.Filled.ArrowBack, contentDescription = "返回", tint = MaterialTheme.colorScheme.primary)
            }
            Text(
                "设置",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f),
            )
        }

        // 品牌块：logo + 软件名 + 版本。图标资源就是从根目录的 logo.png 生成的。
        BrandHeader()

        // ---------------- 连接 ----------------
        Section("连接")
        // 协议不在这里选：首页那个下拉就是唯一入口（两处都能改，既重复又容易不同步）。
        // 这一节只回答一个问题：**怎么接管流量**。
        SettingChips(
            title = "连接模式",
            subtitle = modeSubtitle(settings.mode),
            options = listOf("vpn" to "VPN 模式", "proxy" to "仅代理"),
            selected = settings.mode,
            onSelect = { onChange(settings.copy(mode = it)) },
        )
        SettingNumber(
            title = "连接超时（秒）",
            subtitle = "单个端点握手等待时间，1-15 秒；越小切端点越快",
            value = settings.timeoutSec.toString(),
            onChange = { v ->
                v.toIntOrNull()?.let { onChange(settings.copy(timeoutSec = it.coerceIn(1, 15))) }
            },
        )
        // 「启动后自动连」和「开机自启」这两项已按要求移除：安卓上没有开机自启，
        // 而「打开 App 就自动连」在系统 VPN 未授权时只会弹一个授权框，容易误解。
        SettingSwitch(
            title = "健康守护（自动修复）",
            subtitle = "异常时自动断开重连（5 分钟最多 3 次）",
            checked = settings.healthGuard,
            onChange = { onChange(settings.copy(healthGuard = it)) },
        )
        // 「连接前重新扫描端点」原来是个置灰的假开关（安卓版每次连接本来就会重新
        // 抽样，等效常开）。假开关已删：一个点不动的东西放在设置里只会浪费时间。

        // ---------------- 出口 ----------------
        Section("出口")
        SettingSwitch(
            title = "Psiphon 出口",
            subtitle = if (settings.mode == "proxy") {
                "仅 VPN 模式可用"
            } else {
                "最终出口走 Psiphon，基础协议只作上游"
            },
            checked = settings.psiphon,
            enabled = settings.mode == "vpn",
            onChange = { on ->
                onChange(
                    settings.copy(
                        psiphon = on,
                        // 与 OpenVPN 出口互斥：两个都是最终出口，同时开引擎会直接报错。
                        openvpn = if (on) false else settings.openvpn,
                    )
                )
            },
        )
        // 出口地区：只有 Psiphon 出口才有「落地国家」这个概念（普通协议的出口
        // 就是端点所在地，选不了）。列表来自 Psiphon 自己上报的
        // AvailableEgressRegions —— 不是一张「全世界国家」表：桌面版手写的大表
        // 里有它根本不落地的国家，选中会连三分钟然后失败。
        var regionPicker by remember { mutableStateOf(false) }
        val exitRegions = remember(settings.psiphon, regionPicker) {
            if (settings.psiphon) EngineBridge.psiphonRegions(ctx) else emptyList()
        }
        ActionRow(
            title = "出口地区",
            subtitle = exitRegionSubtitle(settings.exitRegion, exitRegions, settings.psiphon),
        ) { if (settings.psiphon) regionPicker = true }

        if (regionPicker) {
            AlertDialog(
                onDismissRequest = { regionPicker = false },
                title = { Text("出口地区") },
                text = {
                    Column(
                        Modifier
                            .heightIn(max = 420.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        RegionRow("自动（由 Psiphon 决定）", "") {
                            onChange(settings.copy(exitRegion = ""))
                            regionPicker = false
                        }
                        exitRegions.forEach { cc ->
                            RegionRow(
                                "${flagEmoji(cc)} ${countryDisplayName(cc)}",
                                if (cc == settings.exitRegion) "$cc ✓" else cc,
                            ) {
                                onChange(settings.copy(exitRegion = cc))
                                regionPicker = false
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { regionPicker = false }) { Text("关闭") }
                },
            )
        }
        // OpenVPN 出口（VPN Gate）：与 Psiphon 互斥 —— 两者都是「最终出口」，
        // 同时开会各自抢同一个 tun fd，引擎会直接拒绝。
        SettingSwitch(
            title = "OpenVPN 出口",
            subtitle = if (settings.mode == "proxy") {
                "仅 VPN 模式可用"
            } else {
                "最终出口走 VPN Gate 节点"
            },
            checked = settings.openvpn,
            enabled = settings.mode == "vpn",
            onChange = { on ->
                onChange(
                    settings.copy(
                        openvpn = on,
                        // 打开 OpenVPN 就关掉 Psiphon：互斥关系写在这里，
                        // 而不是靠用户自己记得关。
                        psiphon = if (on) false else settings.psiphon,
                    )
                )
            },
        )

        var nodePicker by remember { mutableStateOf(false) }
        var nodeVersion by remember { mutableStateOf(0) }
        var refreshing by remember { mutableStateOf(false) }
        var probing by remember { mutableStateOf(false) }
        val ovpnScope = rememberCoroutineScope()
        // nodeVersion 作为 key：刷新完成后强制重新读一次 JSON（节点列表在 Go 侧缓存里）。
        val nodes = remember(settings.openvpn, nodeVersion) {
            if (settings.openvpn) EngineBridge.vpnGateNodes(ctx) else emptyList()
        }
        ActionRow(
            title = "出口地区",
            subtitle = openvpnSubtitle(settings, nodes),
        ) { if (settings.openvpn) nodePicker = true }


        if (nodePicker) {
            // 探测进度：引擎每测完一个节点报一行「握手测试 37/98：…」，取最后一条显示。
            // 一百个节点要一两分钟，只写「测试中…」会让人以为卡死了。
            val engineState by EngineBridge.state.collectAsState()
            val probeProgress = if (probing) {
                engineState.logs.lastOrNull { it.contains("握手测试 ") }
            } else null
            OpenVpnNodePicker(
                nodes = nodes,
                selectedCountry = settings.openvpnCountry,
                selectedNodeId = settings.openvpnNodeId,
                refreshing = refreshing,
                probing = probing,
                progress = probeProgress?.let { line ->
                    val n = line.substringAfter("握手测试 ", "").substringBefore("：", "")
                    if (n.isEmpty()) "" else "已测 $n"
                } ?: "",
                onProbe = {
                    if (!probing) {
                        probing = true
                        ovpnScope.launch {
                            val cc = settings.openvpnCountry
                            // 测试范围按用户当前的选择走：
                            //   钉了节点 → 只测那一个；选了国家 → 只测该国；否则全部。
                            // 以前不管选没选都测 98 个，既慢又没法回答「这个国家行不行」。
                            val pinned = settings.openvpnNodeId
                            val scopeNodes = when {
                                pinned.isNotEmpty() -> nodes.filter { it.id == pinned }
                                cc.isNotEmpty() -> nodes.filter { it.cc == cc }
                                else -> nodes
                            }.sortedWith(vpnGateNodeOrder)
                            val ids = scopeNodes.map { it.id }
                            val scopeText = when {
                                pinned.isNotEmpty() -> "当前节点"
                                cc.isNotEmpty() -> "地区 ${countryDisplayName(cc)}"
                                else -> "全部"
                            }
                            EngineBridge.note(
                                "[ui] 开始测握手 + 速度：${ids.size} 个节点（$scopeText）" +
                                    "；只握手、不建系统 VPN"
                            )
                            val results = withContext(Dispatchers.IO) {
                                EngineBridge.testOpenVpnNodes(ctx, ids)
                            }
                            // 把实测吞吐写进速度记忆：列表里的「≈94 KB/s」就来自这里，
                            // 也是下次排序与自动选点的依据 —— 不记下来就白测了。
                            var recorded = 0
                            results.forEach { r ->
                                if (r.ok && r.bps > 0) {
                                    NodeSpeedStore.remember(ctx, r.id, r.bps)
                                    recorded++
                                }
                            }
                            EngineBridge.note(
                                "[ui] 握手 + 测速完成：${results.count { it.ok }}/${ids.size} 个能握手" +
                                    (if (recorded > 0) "，$recorded 个测到了速度" else "")
                            )
                            probing = false
                            // 重读节点：新测到的延迟已并入排序与编号（家宽/机房仍分块）。
                            nodeVersion++
                        }
                    }
                },
                onRefresh = {
                    if (!refreshing) {
                        refreshing = true
                        ovpnScope.launch {
                            val msg = withContext(Dispatchers.IO) {
                                EngineBridge.refreshVPNGateNodes(ctx)
                            }
                            EngineBridge.note("[ui] $msg")
                            refreshing = false
                            nodeVersion++
                        }
                    }
                },
                onPickAuto = {
                    onChange(
                        settings.copy(
                            openvpnCountry = "",
                            openvpnNodeId = "",
                            openvpnNodeLabel = "",
                        )
                    )
                    nodePicker = false
                },
                onPickCountry = { cc ->
                    onChange(
                        settings.copy(
                            openvpnCountry = cc,
                            openvpnNodeId = "",
                            openvpnNodeLabel = "",
                        )
                    )
                    nodePicker = false
                },
                onPickNode = { n, slot ->
                    onChange(
                        settings.copy(
                            openvpnCountry = n.cc,
                            openvpnNodeId = n.id,
                            // 存编号（JP家宽03）而不是 ip:port：界面上不再暴露 IP。
                            openvpnNodeLabel = slot,
                        )
                    )
                    nodePicker = false
                },
                onDismiss = { nodePicker = false },
            )
        }

        SettingChips(
            title = "分应用",
            subtitle = if (settings.mode == "vpn") {
                "系统原生白/黑名单，内核层生效"
            } else {
                "仅 VPN 模式可用"
            },
            options = listOf("off" to "关闭", "proxy" to "仅代理所选", "direct" to "所选直连"),
            selected = settings.splitMode,
            onSelect = { onChange(settings.copy(splitMode = it)) },
            enabled = settings.mode == "vpn",
        )
        // 勾选而不是手输包名：包名写错时列表是空的，表现出来就是「开了没效果」。
        ActionRow(
            "选择应用",
            if (settings.mode == "vpn") {
                "已选 ${parsePackageList(settings.splitApps).size} 个 —— 从已安装应用里勾选"
            } else {
                "切到「VPN 模式」后才能选"
            },
        ) { if (settings.mode == "vpn") onPickApps() }

        // ---------------- 本地代理 ----------------
        //
        // 以前这一节只在「仅代理」模式出现，VPN 模式下完全看不到 —— 而「局域网
        // 共享」恰恰要在 VPN 模式下用。现在始终显示：VPN 模式由开关决定，
        // 仅代理模式固定开启（那一档的意义就是这个端口）。
        Section("本地代理")
        SettingSwitch(
            title = "开启本地代理",
            subtitle = if (settings.mode == "proxy") {
                "仅代理模式固定开启"
            } else {
                "VPN 模式下也开本地 SOCKS5 端口"
            },
            checked = settings.mode == "proxy" || settings.localProxy,
            enabled = settings.mode != "proxy",
            onChange = { onChange(settings.copy(localProxy = it)) },
        )
        SettingNumber(
            title = "代理端口",
            subtitle = "SOCKS5 端口，改完要重连",
            value = settings.proxyPort.toString(),
            onChange = { v ->
                val n = v.filter { it.isDigit() }.take(5).toIntOrNull() ?: 0
                onChange(settings.copy(proxyPort = n.coerceIn(0, 65535)))
            },
        )
        SettingSwitch(
            title = "允许局域网访问",
            subtitle = "监听 0.0.0.0，同一 Wi-Fi 可用；无认证，公共网络别开",
            checked = settings.proxyLan,
            onChange = { onChange(settings.copy(proxyLan = it, localProxy = settings.localProxy || it)) },
        )
        InfoRow(
            if (state.socks.isNotBlank()) "正在监听" else "连接后监听",
            state.socks.ifBlank { settings.proxyListenAddr() },
        )
        ActionRow(
            "局域网共享",
            "共享地址、端口与监听状态（同一 Wi-Fi 的设备怎么用）",
        ) { onOpenLanShare() }
        if (settings.splitMode != "off" && parsePackageList(settings.splitApps).isEmpty()) {
            SettingCard {
                Text(
                    "分应用已开启但一个应用都没选：现在等于不生效。点上面「选择应用」勾选。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }

        // ---------------- 网络 ----------------
        Section("网络")
        SettingSwitch(
            title = "IPv6",
            subtitle = "同时路由 ::/0；只在你的网络确实有 v6 时才打开",
            checked = settings.ipv6,
            onChange = { onChange(settings.copy(ipv6 = it)) },
        )
        SettingNumber(
            title = "MTU",
            subtitle = "1280 最稳",
            value = settings.mtu.toString(),
            onChange = { v -> v.toIntOrNull()?.let { onChange(settings.copy(mtu = it.coerceIn(576, 1500))) } },
        )
        SettingText(
            title = "自定义 DNS",
            subtitle = "逗号分隔",
            value = settings.dns,
            onChange = { onChange(settings.copy(dns = it)) },
        )
        // 「不下发 DNS」已移除：它会和上面的自定义 DNS 互相打脸（填了地址却不下发），
        // 而且实测系统解析器在部分网络里会把查询泄漏到墙外。要「跟随系统」就把
        // 自定义 DNS 留空。

        // ---------------- 界面 ----------------
        Section("界面")
        SettingChips(
            title = "主题",
            subtitle = "默认浅色",
            options = listOf("light" to "浅色", "dark" to "深色", "auto" to "跟随系统"),
            selected = settings.theme,
            onSelect = { onChange(settings.copy(theme = it)) },
        )
        SettingSwitch(
            title = "日志自动滚动",
            subtitle = "关闭后日志停在当前内容，方便复制",
            checked = settings.logAutoScroll,
            onChange = { onChange(settings.copy(logAutoScroll = it)) },
        )
        SettingChips(
            title = "语言 / Language",
            subtitle = "英文覆盖菜单与标题",
            options = LANG_OPTIONS,
            selected = settings.lang,
            onSelect = { onChange(settings.copy(lang = it)) },
        )

        // ---------------- 诊断 ----------------
        //
        // 版本号 / 引擎 / 内置账号 / 数据目录 / 日志路径 / 系统 VPN 全部收进侧边栏
        // 「关于」：那些是只读信息，留在设置里既和「关于」重复，又把真正能改的
        // 开关挤到看不见的地方。设置页只留「可以改的东西」和这一个操作。
        Section("诊断")
        ActionRow("清空日志", "删除界面日志与日志文件（全 App 只有这一处会删）") { onClearLogs() }
        InfoRow("版本 / 引擎 / 日志路径", "见侧边栏「关于」")

        // ---------------- 分流规则 ----------------
        //
        // 执行点在本地 SOCKS（仅代理模式）：那里拿得到目标域名，才能做域名分流。
        // VPN 模式下我们只看得到 IP，域名规则无从谈起 —— 所以这两项在 VPN 模式
        // 置灰并写明原因，而不是放个点了没反应的开关。
        Section("分流规则")
        SettingChips(
            title = "规则模式",
            subtitle = rulePolicySubtitle(settings.rulePolicy, settings.mode),
            options = listOf(
                "global" to "全局",
                "bypass-cn" to "绕过大陆",
                "blacklist" to "黑名单",
            ),
            selected = settings.rulePolicy,
            onSelect = { onChange(settings.copy(rulePolicy = it)) },
        )
        SettingTextArea(
            title = "自定义规则",
            subtitle = "一行一条：direct/proxy,域名或 CIDR；# 注释",
            value = settings.ruleText,
            onChange = { onChange(settings.copy(ruleText = it)) },
        )

        // 大陆路由表是**运行时拉取**的（不占包体、能更新），所以要能看见状态：
        // 装完第一次连上才会去抓，之后每 7 天刷一次。
        var cnInfo by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(Unit) {
            cnInfo = withContext(Dispatchers.IO) { EngineBridge.cnRoutesText(ctx) }
        }
        InfoRow("大陆路由表", cnInfo ?: "读取中…")
        ActionRow(
            "立即更新路由表",
            "经由当前网络抓取：VPN 模式下走隧道，仅代理模式下走本机网络",
        ) {
            scope.launch {
                cnInfo = "更新中…"
                val r = withContext(Dispatchers.IO) { EngineBridge.refreshCNRoutes(ctx) }
                EngineBridge.note("[ui] $r")
                cnInfo = withContext(Dispatchers.IO) { EngineBridge.cnRoutesText(ctx) }
            }
        }


        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun Section(title: String) {
    Spacer(Modifier.height(14.dp))
    Text(
        title,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(start = 4.dp, bottom = 6.dp),
    )
}

@Composable
private fun SettingCard(content: @Composable () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(14.dp)) { content() }
    }
}

@Composable
private fun SettingSwitch(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean = true,
    onChange: (Boolean) -> Unit,
) {
    SettingCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.bodyLarge,
                    color = if (enabled) MaterialTheme.colorScheme.onSurface
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(12.dp))
            Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
        }
    }
}

@Composable
private fun SettingText(
    title: String,
    subtitle: String,
    value: String,
    onChange: (String) -> Unit,
) {
    SettingCard {
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

/** 多行文本（规则编辑）：等宽字体，否则一行一条看不成列。 */
@Composable
private fun SettingTextArea(
    title: String,
    subtitle: String,
    value: String,
    onChange: (String) -> Unit,
    enabled: Boolean = true,
) {
    SettingCard {
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
            enabled = enabled,
            minLines = 5,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
    }
}

@Composable
private fun SettingNumber(
    title: String,
    subtitle: String,
    value: String,
    onChange: (String) -> Unit,
) {
    SettingText(title = title, subtitle = subtitle, value = value, onChange = onChange)
}

@Composable
private fun SettingChips(
    title: String,
    subtitle: String,
    options: List<Pair<String, String>>,
    selected: String,
    onSelect: (String) -> Unit,
    /** false = 置灰且点不动（用于「只有某个模式下才有意义」的选项）。 */
    enabled: Boolean = true,
) {
    SettingCard {
        Text(title, style = MaterialTheme.typography.bodyLarge)
        Text(
            subtitle,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            options.forEach { (id, label) ->
                val active = id == selected
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            if (active) MaterialTheme.colorScheme.primaryContainer
                            else MaterialTheme.colorScheme.surfaceVariant,
                            RoundedCornerShape(10.dp),
                        )
                        .clickable(enabled = enabled) { onSelect(id) }
                        .padding(vertical = 10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        label,
                        style = MaterialTheme.typography.labelMedium,
                        color = when {
                            !enabled -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
                            active -> MaterialTheme.colorScheme.onPrimaryContainer
                            else -> MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun SettingDropdown(
    title: String,
    subtitle: String,
    current: String,
    options: List<ProtoOption>,
    onChange: (String) -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    SettingCard {
        Text(title, style = MaterialTheme.typography.bodyLarge)
        Text(
            subtitle,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        Box {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(10.dp))
                    .clickable { open = true }
                    .padding(horizontal = 12.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    options.firstOrNull { it.id == current }?.label ?: current,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                Text("切换", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
            }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                options.forEach { p ->
                    DropdownMenuItem(
                        enabled = p.ready,
                        text = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(p.label)
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

/** 品牌块：应用图标（由根目录 logo.png 生成） + 软件名 + 版本。 */
@Composable
private fun BrandHeader() {
    val ctx = LocalContext.current
    SettingCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // 必须用 drawable-nodpi/brand_logo.png，不能用 R.mipmap.ic_launcher：
            // 后者在 API 26+ 解析到 <adaptive-icon> XML，而 Compose 的
            // painterResource 不支持这个类型，会在合成设置页时抛异常 ——
            // 用户看到的就是「点三条杠 App 直接退出」。
            Image(
                painter = painterResource(R.drawable.brand_logo),
                contentDescription = "Xehn",
                modifier = Modifier.size(56.dp),
            )
            Spacer(Modifier.width(14.dp))
            Column {
                Text(
                    "Xehn",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                // 版本号不再写在这里：它和侧边栏「关于」页是同一份信息，重复出现
                // 只会让人以为两处会不一致。要查版本去「关于」。
                Text(
                    "xiaohe VPN · 安卓版",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/**
 * 「出口地区」这一行显示什么。
 *
 * 三种状态要能一眼分清：没开 Psiphon（选不了）、自动（它自己挑）、指定地区。
 * 指定的地区不在当前列表里时明确标出来 —— 那是「连接会直接失败」，不该等用户
 * 点一下才发现。
 */
private fun rulePolicySubtitle(policy: String, mode: String): String {
    val proxy = mode == "proxy"
    return when (policy) {
        "bypass-cn" -> if (proxy) "大陆域名直连" else "大陆网段直连（首次连接后生效）"
        "blacklist" -> "只有列表里的走隧道"
        else -> "全部走隧道"
    }
}

private fun modeSubtitle(mode: String): String = when (mode) {
    "proxy" -> "只开本地 SOCKS5，不建系统 VPN"
    else -> "建立系统 VPN，全部应用走隧道"
}

private fun exitRegionSubtitle(region: String, regions: List<String>, psiphonOn: Boolean): String {
    if (!psiphonOn) {
        return "先打开 Psiphon 出口"
    }
    if (region.isEmpty()) {
        return "自动（由 Psiphon 决定）· 可选 ${regions.size} 个地区"
    }
    val offered = regions.isEmpty() || regions.contains(region)
    val tail = if (offered) "· 连上后生效" else "· 当前列表里没有，连接会直接失败"
    return "${flagEmoji(region)} ${countryDisplayName(region)} $region $tail"
}

private fun openvpnSubtitle(s: AppSettings, nodes: List<VpnGateNode>): String {
    if (s.mode == "proxy") return "只在「VPN 模式」可用"
    if (!s.openvpn) return "最终出口走 VPN Gate 节点"
    val countries = nodes.map { it.cc }.distinct().size
    // 「已测速」= NodeSpeedStore 里还没过期的实测记录（6 小时）。它只参与排序，
    // 说清楚这一点，免得用户以为没测过的节点会被排除。
    val measured = nodes.count { it.measuredBps > 0 }
    val base = when {
        nodes.isEmpty() -> "节点列表为空，点进去刷新"
        measured > 0 -> "${nodes.size} 个节点 · $countries 个国家 · $measured 个已测速（排序优先）"
        else -> "${nodes.size} 个节点 · $countries 个国家"
    }
    return when {
        s.openvpnNodeId.isNotEmpty() -> {
            // 优先用现算的编号（JP家宽03）：老版本存的是「Japan 1.2.3.4:1880」，
            // 节点还认得出来就换成编号，认不出来才退回存储值 —— IP 不再出现在界面上。
            val node = nodes.firstOrNull { it.id == s.openvpnNodeId }
            val label = if (node != null) {
                slotOf(nodes, node)
            } else {
                s.openvpnNodeLabel.ifEmpty { s.openvpnNodeId }
            }
            "固定：$label · $base"
        }
        s.openvpnCountry.isNotEmpty() ->
            "${flagEmoji(s.openvpnCountry)} ${countryDisplayName(s.openvpnCountry)}" +
                " · 自动挑该国延迟最低的可用节点 · $base"
        else -> "自动（按延迟/可用性挑）· $base"
    }
}

/**
 * 节点在该国同类节点里的编号（JP家宽03），与选择器里的算法一致。
 *
 * 和 WarpVpnService.nodeSlotLabel 是同一套规则的两份实现：一处给界面、一处给日志。
 * 规则简单到不值得为此引入共享模块，但改排序时必须同时改两处。
 */
private fun slotOf(nodes: List<VpnGateNode>, node: VpnGateNode): String {
    val sameClass = nodes
        .filter { it.cc.equals(node.cc, ignoreCase = true) && it.cls == node.cls }
        .sortedWith(
            compareBy(
                { if (it.hasMeasuredLatency) 0 else 1 },
                { it.latencyMs.takeIf { l -> l > 0 } ?: it.pingMs },
            )
        )
    val idx = sameClass.indexOfFirst { it.id == node.id }
    val num = if (idx >= 0) (idx + 1).toString().padStart(2, '0') else "??"
    return node.cc + classTagOf(node.cls) + num
}

/**
 * 节点选择器：国家一级、节点二级（点国家展开）。
 *
 * 「能用都保留」是明确的产品决定：不按家宽/机房过滤，也不用共享代理标记隐藏节点；
 * 标记只用于展示与排序（家宽 > 未知 > 机房）。每行显示的是「测延迟」测出的
 * **真实 OpenVPN 握手**结果（握手 NNNms / 握手失败）；没测过就写「未测」，
 * 不回退到列表里那个 TCP 连接时间或节点自报 ping —— 它们跟能不能握手无关，
 * 写出来反而让人分不清「没测」和「测了不行」。
 */
@Composable
private fun OpenVpnNodePicker(
    nodes: List<VpnGateNode>,
    selectedCountry: String,
    selectedNodeId: String,
    refreshing: Boolean,
    probing: Boolean,
    /** 探测进度（如「37/98」）；空 = 还没有进度可显示。 */
    progress: String,
    onRefresh: () -> Unit,
    onProbe: () -> Unit,
    onPickAuto: () -> Unit,
    onPickCountry: (String) -> Unit,
    onPickNode: (VpnGateNode, String) -> Unit,
    onDismiss: () -> Unit,
) {
    var expanded by remember { mutableStateOf(selectedCountry) }
    val groups = remember(nodes) {
        nodes.groupBy { it.cc }.entries.sortedBy { e ->
            // 排在最前的是「真能握手、而且最快」的国家；没测过的按老办法（TCP 时间）
            // 排在后面 —— 测过之后列表顺序才跟「实际能连」对得上。
            e.value.filter { it.hasProbe && it.handshakeOk }.minOfOrNull { it.handshakeMs }
                ?: (999_999 + e.value.minOf { it.displayLatencyMs.takeIf { l -> l > 0 } ?: 999_999 })
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("出口地区", modifier = Modifier.weight(1f))
                // 「测延迟」= 对节点做一次**真实 OpenVPN 握手 + 真下载测速**。
                // 只测握手看不出「能握手但只有几 KB/s」的节点，而那正是最该筛掉的；
                // 列表里原来的延迟只是 api 域名的 TCP 连接时间，跟能不能连无关。
                TextButton(onClick = onProbe, enabled = !probing && !refreshing && nodes.isNotEmpty()) {
                    Text(if (probing) "测试中…" else "测延迟+速度")
                }
                TextButton(onClick = onRefresh, enabled = !refreshing && !probing) {
                    Text(if (refreshing) "刷新中…" else "刷新")
                }
            }
        },
        text = {
            Column(
                Modifier
                    .heightIn(max = 460.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                if (probing) {
                    Text(
                        "正在测真实握手 + 下载速度（不建 VPN）：" + progress.ifEmpty { "建 WARP 上游…" } +
                            "；每个节点握手后再下载一小段，测完按握手耗时重排，期间可以关掉这个窗口",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 4.dp),
                    )
                }
                RegionRow("自动选择（按延迟/可用性）", if (selectedCountry.isEmpty()) "✓" else "") {
                    onPickAuto()
                }
                if (nodes.isEmpty()) {
                    Text(
                        "节点列表为空：点右上角「刷新」抓一轮。受限网络里会先起一条临时 WARP " +
                            "隧道（约 20–60 秒），抓完自动关闭，不影响当前连接。",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                groups.forEach { (cc, list) ->
                    val open = expanded == cc
                    // 国家行的小结也要说人话：测过就报「几个能握手」，没测过才退回
                    // 「几个有响应」（那个只是 api 域名的 TCP 时间，不代表节点活着）。
                    val shakeOk = list.count { it.hasProbe && it.handshakeOk }
                    val probed = list.count { it.hasProbe }
                    val responded = list.count { it.latencyMs > 0 }
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable { expanded = if (open) "" else cc }
                            .padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "${flagEmoji(cc)} ${countryDisplayName(cc)}",
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            "${list.size} 个" +
                                when {
                                    probed > 0 -> " · $shakeOk 能握手"
                                    responded > 0 -> " · $responded 有响应"
                                    else -> ""
                                } +
                                (if (cc == selectedCountry && selectedNodeId.isEmpty()) " ✓" else ""),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (open) {
                        RegionRow("↳ 自动选 ${countryDisplayName(cc)} 里的节点", "") {
                            onPickCountry(cc)
                        }
                        // 编号按「国家 + 类别」各自从 01 起：JP家宽01、JP家宽02、JP机房01…
                        // 好处有二：名字短（原来只有 JP1，但用户要靠它区分家宽/机房）；
                        // 序号在不同次打开、不同次刷新里都稳定，不会因为换了排序就对不上。
                        //
                        // 排序也改成「先类别、后延迟」：编号本来就是按类别分块的，混排会
                        // 变成 JP未知01、JP家宽01、JP未知02 这种读不懂的序列。类别优先级
                        // 与产品口径一致（家宽 > 未知 > 机房），块内仍是最快在前。
                        val slots = HashMap<String, Int>()
                        // 与连接时的候选顺序、编号算法共用同一套排序（vpnGateNodeOrder）：
                        // 各自写一套的话，用户看到的「JP家宽03」就不是他实际连的那个。
                        list.sortedWith(vpnGateNodeOrder).forEach { n ->
                            val cls = classKeyOf(n.cls)
                            val next = (slots[cls] ?: 0) + 1
                            slots[cls] = next
                            val slot = "$cc${classTagOf(cls)}" + next.toString().padStart(2, '0')
                            OpenVpnNodeRow(slot, n, n.id == selectedNodeId) {
                                onPickNode(n, slot)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("关闭") }
        },
    )
}

@Composable
private fun OpenVpnNodeRow(slot: String, n: VpnGateNode, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(start = 8.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // 一行只留编号 + 延迟：IP:port、ISP、共享 都是用户明确说「太长、不要」的东西。
        // 需要 IP 时去看引擎日志 —— 每次尝试都会打印带 ip:port 的完整节点名。
        Text(
            slot,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.width(84.dp),
            maxLines = 1,
            color = when (n.cls) {
                "residential" -> Color(0xFF1B7F3B)
                "datacenter" -> Color(0xFF8A6D3B)
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
        Spacer(Modifier.weight(1f))
        // 只显示真握手结果（用户要的就是「真延迟」），没测过就写「未测」。
        // 握手失败的标红 —— 那种节点端口是开的、看着有延迟，实际连不上。
        val probeLabel: String
        val probeColor: androidx.compose.ui.graphics.Color
        when {
            n.hasProbe && n.handshakeOk -> {
                // 实测过的速度也写在行里：用户问过「到底有没有测速」，光有握手
                // 耗时看不出「这个节点连上能跑多快」，而那正是选节点最关心的事。
                probeLabel = "握手 ${n.handshakeMs}ms" +
                    if (n.measuredBps > 0) " · ${NodeSpeedStore.text(n.measuredBps)}" else ""
                probeColor = MaterialTheme.colorScheme.onSurface
            }
            n.hasProbe -> {
                probeLabel = "握手失败"
                probeColor = MaterialTheme.colorScheme.error
            }
            // 没测过就写「未测」：不再回退到那个 TCP 时间或节点自报的 ping。
            // 它们跟能不能握手无关（实测 193ms 的美国节点三个全死），写出来只会
            // 让人以为「看着挺快却没结果」，分不清到底是没测还是测了不行。
            else -> {
                probeLabel = "未测"
                probeColor = MaterialTheme.colorScheme.onSurfaceVariant
            }
        }
        Text(
            probeLabel,
            style = MaterialTheme.typography.labelSmall,
            color = probeColor,
        )
        if (selected) {
            Text(
                " ✓",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

private fun classRankOf(cls: String): Int = when (cls) {
    "residential" -> 0
    "unknown" -> 1
    else -> 2
}

/** 归一化分类键：编号的计数器按它分组（家宽/机房/未知各自从 01 起）。 */
private fun classKeyOf(cls: String): String = when (cls) {
    "residential", "datacenter" -> cls
    else -> "unknown"
}

/**
 * 名字里的类别后缀：JP家宽01 / JP机房01 / JP未分类01。
 *
 * 「未知」改成「未分类」：两个数据源都没给出证据时，这是一个**中性**结论，
 * 不是「查不到」的错误。用户看到「未知」会以为程序坏了。
 */
private fun classTagOf(cls: String): String = when (cls) {
    "residential" -> "家宽"
    "datacenter" -> "机房"
    else -> "未分类"
}

@Composable
private fun RegionRow(label: String, code: String, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        if (code.isNotEmpty()) {
            Text(
                code,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun InfoRow(title: String, value: String) {
    SettingCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(title, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            Text(
                value,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ActionRow(title: String, subtitle: String, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .clickable { onClick() },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary)
            Text(
                subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** 界面与首页保持一致：日志卡最多显示这么多行。 */
const val LOG_TAIL = 40
