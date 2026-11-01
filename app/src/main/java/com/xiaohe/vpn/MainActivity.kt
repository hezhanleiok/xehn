package com.xiaohe.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.xiaohe.vpn.ui.AboutScreen
import com.xiaohe.vpn.ui.AppPickerScreen
import com.xiaohe.vpn.ui.HomeScreen
import com.xiaohe.vpn.ui.LicenseScreen
import com.xiaohe.vpn.ui.MenuDrawer
import com.xiaohe.vpn.ui.Page
import com.xiaohe.vpn.ui.PrivacyScreen
import com.xiaohe.vpn.ui.SettingsScreen
import com.xiaohe.vpn.ui.UpdateScreen
import com.xiaohe.vpn.ui.XiaoheTheme
import com.xiaohe.vpn.ui.formatPackageList
import com.xiaohe.vpn.ui.parsePackageList
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * 唯一的 Activity。界面全是 Compose，逻辑全在 Go 引擎 + VpnService 里，
 * 所以这里只做三件事：申请系统 VPN 授权、把点击转成 Service 的 Intent、切页面。
 *
 * 页面模型：`current == null` 就是首页；左侧三条杠打开抽屉（占屏宽 3/4），
 * 抽屉里是 设置 / 关于 / 隐私政策 / 授权说明 / 更新。刻意不做多 Activity：
 * 引擎是进程内单例，页面也只是同一个 Compose 树里的分支。
 */
class MainActivity : ComponentActivity() {

    /** prepare() 要求授权时，记住用户本来是想连接。 */
    private var pendingConnect = false

    /**
     * 系统 VPN 授权必须由 Activity 发起（VpnService.prepare 返回 Intent）。
     * 拒绝时不能静默失败：写进日志面板，否则界面上只会看到「点了没反应」。
     */
    private val requestVpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            EngineBridge.note("[ui] 系统 VPN 授权已获得")
            if (pendingConnect) {
                pendingConnect = false
                startVpnService(WarpVpnService.ACTION_CONNECT, latestSettings())
            }
        } else {
            pendingConnect = false
            EngineBridge.note("[ui] 你拒绝了系统 VPN 授权 —— 没有它，手机上其它应用不会走隧道")
        }
    }

    private val requestNotifications = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (!granted) {
            EngineBridge.note("[ui] 通知权限被拒：前台服务通知可能看不到（连接本身不受影响）")
        }
    }

    /** 连接动作需要用「用户此刻看到的设置」，而不是重新读一遍磁盘。 */
    private var settingsSnapshot: AppSettings? = null

    private fun latestSettings(): AppSettings =
        settingsSnapshot ?: SettingsStore.load(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // targetSdk 35 上 edge-to-edge 是强制的；显式调用一次，让 24-34 上的
        // 行为与 35 一致（否则同一份布局在不同系统版本上顶部让位不一样）。
        // 界面自己用 statusBarsPadding/navigationBarsPadding 让开系统栏。
        enableEdgeToEdge()

        // 引擎要在 UI 出现前就建好，否则首帧拿不到 version / 日志。
        EngineBridge.engineOrCreate(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestNotifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            var current by remember { mutableStateOf<Page?>(null) }
            // 分应用选择不是一个「页面」，是从设置页进去、保存后回设置页的一次性流程。
            var pickingApps by remember { mutableStateOf(false) }
            var settings by remember { mutableStateOf(SettingsStore.load(this)) }
            val state by EngineBridge.state.collectAsStateWithLifecycle()
            val drawer = rememberDrawerState(DrawerValue.Closed)
            val scope = rememberCoroutineScope()

            settingsSnapshot = settings

            // 返回键 / 侧滑返回：**逐层退回**，只有真的在首页时才让系统退出 App。
            //
            // 之前一次都没拦：页面只是同一个 Compose 树里的分支（`current != null`），
            // 系统看不到「还有上一页」，于是任何一页划一下返回就直接退到桌面 ——
            // 这是纯粹的漏实现，不是系统行为。
            //
            // 顺序按「进来得越晚越先退」：分应用选择 → 抽屉 → 子页面 → 首页。
            // 弹窗（节点/地区选择）是独立的 Dialog 窗口，它自己会消费返回，走不到这里。
            BackHandler(enabled = pickingApps || drawer.isOpen || current != null) {
                when {
                    pickingApps -> pickingApps = false
                    // 抽屉开着时先收抽屉：用的是 3/4 浮层，退回到「刚才那页」才对。
                    drawer.isOpen -> scope.launch { drawer.close() }
                    else -> current = null
                }
            }

            // 启动后自动连接：只在用户打开了这个开关、且当前确实空闲时触发一次。
            LaunchedEffect(settings.autoConnect) {
                if (settings.autoConnect &&
                    !EngineBridge.state.value.isConnected &&
                    !EngineBridge.state.value.isBusy
                ) {
                    delay(600)
                    toggle(settings)
                }
            }

            XiaoheTheme(themeMode = settings.theme) {
                ModalNavigationDrawer(
                    drawerState = drawer,
                    drawerContent = {
                        // 抽屉只占屏幕 3/4：M3 默认宽 360dp，在多数手机上就是整屏，
                        // 展开后看不到底下的界面，也没有「这是浮层」的感觉。
                        ModalDrawerSheet(modifier = Modifier.fillMaxWidth(0.75f)) {
                            MenuDrawer(current = current) { page ->
                                current = page
                                scope.launch { drawer.close() }
                            }
                        }
                    },
                ) {
                    AppPages(
                        current = current,
                        settings = settings,
                        state = state,
                        pickingApps = pickingApps,
                        onNavigate = { current = it },
                        onOpenMenu = { scope.launch { drawer.open() } },
                        onSettingsChange = { updated ->
                            settings = updated
                            SettingsStore.save(this, updated)
                        },
                        onToggle = { toggle(settings) },
                        onToggleTheme = {
                            val next = if (settings.theme == "dark") "light" else "dark"
                            settings = settings.copy(theme = next)
                            SettingsStore.save(this, settings)
                        },
                        onPickApps = { pickingApps = true },
                        onClosePicker = { pickingApps = false },
                        onAppsSaved = { pkgs ->
                            val encoded = formatPackageList(pkgs)
                            settings = settings.copy(splitApps = encoded)
                            SettingsStore.save(this, settings)
                            EngineBridge.note(
                                if (pkgs.isEmpty()) "[ui] 已清空分应用列表"
                                else "[ui] 分应用已选 ${pkgs.size} 个：${pkgs.sorted().joinToString(", ")}"
                            )
                            pickingApps = false
                        },
                    )
                }
            }
        }
    }

    @Composable
    private fun AppPages(
        current: Page?,
        settings: AppSettings,
        state: VpnState,
        pickingApps: Boolean,
        onNavigate: (Page?) -> Unit,
        onOpenMenu: () -> Unit,
        onSettingsChange: (AppSettings) -> Unit,
        onToggle: () -> Unit,
        onToggleTheme: () -> Unit,
        onPickApps: () -> Unit,
        onClosePicker: () -> Unit,
        onAppsSaved: (Set<String>) -> Unit,
    ) {
        val back = { onNavigate(null) }
        if (pickingApps) {
            AppPickerScreen(
                initial = parsePackageList(settings.splitApps),
                onApply = onAppsSaved,
                onBack = onClosePicker,
            )
            return
        }
        when (current) {
            null -> HomeScreen(
                state = state,
                settings = settings,
                onToggle = onToggle,
                onProtoChange = { p -> onSettingsChange(settings.copy(proto = p)) },
                onOpenMenu = onOpenMenu,
                onToggleTheme = onToggleTheme,
            )

            Page.Settings -> SettingsScreen(
                state = state,
                settings = settings,
                onChange = onSettingsChange,
                onClearLogs = { EngineBridge.clearLogs() },
                onPickApps = onPickApps,
                onBack = back,
            )

            Page.About -> AboutScreen(state = state, onBack = back)
            Page.Privacy -> PrivacyScreen(onBack = back)
            Page.License -> LicenseScreen(onBack = back)
            Page.Update -> UpdateScreen(state = state, onBack = back)
        }
    }

    /**
     * 连接按钮：未连接 → 先要系统 VPN 授权再连；连接中/已连接 → 断开。
     * 连接中也能点（= 取消），这是电脑版那个「点了没反应」的修法。
     */
    private fun toggle(s: AppSettings) {
        val st = EngineBridge.state.value
        if (st.isConnected || st.isBusy) {
            startVpnService(WarpVpnService.ACTION_DISCONNECT, s)
            return
        }
        if (!LocalNetwork.online(this)) {
            EngineBridge.note("[ui] 当前没有网络连接")
            return
        }
        // 「仅代理」不建 tun，也就不需要系统 VPN 授权：直接起服务开本地端口。
        // 否则会出现「我只是想开个代理，系统却弹 VPN 授权」的怪事。
        if (!s.isProxyMode) {
            val prepare = VpnService.prepare(this)
            if (prepare != null) {
                // 第一次使用（或授权被撤销）：先要授权，拿到结果再回来连。
                pendingConnect = true
                settingsSnapshot = s
                requestVpnPermission.launch(prepare)
                return
            }
        }
        startVpnService(WarpVpnService.ACTION_CONNECT, s)
    }

    private fun startVpnService(action: String, settings: AppSettings) {
        val intent = Intent(this, WarpVpnService::class.java).apply {
            this.action = action
        }
        if (action == WarpVpnService.ACTION_CONNECT) {
            // 把「按下去那一刻的设置」显式带过去。服务读本地设置也能拿到同样的
            // 值，但显式传参才让「这次连接用的是哪套参数」在 intent 里可查，
            // 也避免了「改完设置没保存就点连接」这类竞态。
            intent.putExtra(WarpVpnService.EXTRA_PROTO, settings.proto)
            intent.putExtra(WarpVpnService.EXTRA_PSIPHON, settings.psiphon)
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }
}
