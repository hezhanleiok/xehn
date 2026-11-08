package com.xiaohe.vpn

import android.content.Context

/**
 * 用户可配置项。字段与默认值对齐电脑版 `settings.go`，去掉了桌面专有的部分
 * （开机自启写注册表、系统代理、mihomo 的混合端口/API 端口、外部内核路径）。
 *
 * Android 特有的两处差异：
 *  - 「分应用」在电脑版是给 mihomo 生成规则，这里直接落到 VpnService 的
 *    addAllowedApplication / addDisallowedApplication —— 系统原生能力，更可靠。
 *  - 主题默认浅色（用户明确要求），电脑版默认也是 light。
 */
data class AppSettings(
    val proto: String = "awg",
    val psiphon: Boolean = false,
    /**
     * 连接模式：
     *  - "vpn"   全机接管：VpnService 建 tun，所有应用（或分应用名单）走隧道
     *  - "proxy" 仅代理：不建系统 VPN，只在本地开一个 SOCKS5 端口，由用户自己
     *            在浏览器/系统代理里填地址
     *
     * 为什么没有第三种「TUN 模式」：**在 Android 上 VpnService 本身就是 tun**，
     * 「VPN 模式」和「TUN 模式」是同一件事（桌面版才有 wintun 那种独立虚拟网卡）。
     * 所以这里只有两种，第三种列出来只会是骗人的开关。
     */
    val mode: String = "vpn",
    /** 本地代理端口（「仅代理」模式必开；VPN 模式下由 [localProxy] 决定）。 */
    val proxyPort: Int = 1080,
    /**
     * 允许局域网访问代理端口：监听 0.0.0.0 而不是 127.0.0.1。
     * 注意 SOCKS5 没有认证 —— 同一 Wi-Fi 下谁都能用，公共网络别开。
     */
    val proxyLan: Boolean = false,
    /**
     * VPN 模式下也开本地 SOCKS5 端口。
     *
     * 「仅代理」模式本来就必须开；这一项是给 VPN 模式用的：整机已经走隧道，
     * 但同一 Wi-Fi 下的电脑/平板想借这条隧道，就需要一个监听在局域网上的入口
     * （见「局域网共享」页）。默认关：多一个监听就多一个攻击面。
     */
    val localProxy: Boolean = false,
    /**
     * 健康守护：连接被掐断/长时间无数据时自动断开重连（Service 内的看门狗）。
     * 关掉后只写日志、不自动重连，适合按流量计费或需要绝对稳定的场景。
     */
    val healthGuard: Boolean = true,
    /** 分流策略：global（全局）/ bypass-cn（绕过大陆）/ blacklist（黑名单）。 */
    val rulePolicy: String = "global",
    /**
     * 自定义规则，一行一条 `动作,目标`：
     *   direct,example.com     该域名及其子域直连
     *   proxy,1.2.3.0/24       该网段走隧道
     * `#` 开头是注释。只在「仅代理」模式执行（VPN 模式看不到域名）。
     */
    val ruleText: String = "",
    /**
     * Psiphon 的落地地区："" = 自动（它自己挑），否则 ISO-3166-1 alpha-2 大写。
     *
     * 只在「Psiphon 出口」打开时有意义。切换后要**重新连接**才生效 ——
     * EgressRegion 是 tunnel-core 的启动参数，改不了运行中的会话。
     */
    val exitRegion: String = "",
    /**
     * OpenVPN 出口（VPN Gate）。与 [psiphon] 互斥：两者都是「最终出口」，
     * 同时开会各自抢系统 tun fd，引擎会直接报错。
     *
     * 数据结构对齐电脑版「住宅池」页：开关 + 出口地区（国家）+ 具体节点。
     */
    val openvpn: Boolean = false,
    /** OpenVPN 出口国家（ISO-2，"" = 自动：按延迟/可用性挑）。 */
    val openvpnCountry: String = "",
    /** 固定节点 ID（"" = 自动：该国里挑第一个可用节点）。 */
    val openvpnNodeId: String = "",
    /** 固定节点的显示名（只用于日志与界面）。 */
    val openvpnNodeLabel: String = "",
    val ipv6: Boolean = false,
    val mtu: Int = 1280,
    val dns: String = "1.1.1.1, 223.5.5.5",
    val dnsOff: Boolean = false,
    val autoConnect: Boolean = false,
    val rescan: Boolean = false,
    val timeoutSec: Int = 3,
    /** off / proxy / direct */
    val splitMode: String = "off",
    val splitApps: String = "",
    val theme: String = "light",
    val lang: String = "zh",
    val starred: String = "",
    val logAutoScroll: Boolean = true,
) {
    fun dnsList(): List<String> =
        dns.split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }

    /** 代理模式下实际要监听的地址；端口非法时回退 1080。 */
    fun proxyListenAddr(): String {
        val port = if (proxyPort in 1..65535) proxyPort else 1080
        val host = if (proxyLan) "0.0.0.0" else "127.0.0.1"
        return "$host:$port"
    }

    val isProxyMode: Boolean get() = mode == "proxy"

    fun splitAppList(): List<String> =
        splitApps.split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }

    fun starSet(): Set<String> =
        starred.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()

    /** 协议下拉里显示的名字。 */
    fun protoLabel(): String = when (proto) {
        "wg" -> "WireGuard"
        "awg" -> "AmneziaWG"
        else -> proto.uppercase()
    }
}

/** SharedPreferences 持久化。读写都很小，不需要额外的仓库层。 */
object SettingsStore {
    private const val FILE = "xiaohe-settings"

    fun load(ctx: Context): AppSettings {
        val p = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val d = AppSettings()
        return AppSettings(
            proto = p.getString("proto", d.proto) ?: d.proto,
            psiphon = p.getBoolean("psiphon", d.psiphon),
            exitRegion = p.getString("exitRegion", d.exitRegion) ?: d.exitRegion,
            openvpn = p.getBoolean("openvpn", d.openvpn),
            openvpnCountry = p.getString("openvpnCountry", d.openvpnCountry) ?: d.openvpnCountry,
            openvpnNodeId = p.getString("openvpnNodeId", d.openvpnNodeId) ?: d.openvpnNodeId,
            openvpnNodeLabel = p.getString("openvpnNodeLabel", d.openvpnNodeLabel) ?: d.openvpnNodeLabel,
            mode = p.getString("mode", d.mode) ?: d.mode,
            proxyPort = p.getInt("proxyPort", d.proxyPort),
            proxyLan = p.getBoolean("proxyLan", d.proxyLan),
            localProxy = p.getBoolean("localProxy", d.localProxy),
            healthGuard = p.getBoolean("healthGuard", d.healthGuard),
            rulePolicy = p.getString("rulePolicy", d.rulePolicy) ?: d.rulePolicy,
            ruleText = p.getString("ruleText", d.ruleText) ?: d.ruleText,
            ipv6 = p.getBoolean("ipv6", d.ipv6),
            mtu = p.getInt("mtu", d.mtu),
            dns = p.getString("dns", d.dns) ?: d.dns,
            dnsOff = p.getBoolean("dnsOff", d.dnsOff),
            autoConnect = p.getBoolean("autoConnect", d.autoConnect),
            rescan = p.getBoolean("rescan", d.rescan),
            timeoutSec = p.getInt("timeoutSec", d.timeoutSec),
            splitMode = p.getString("splitMode", d.splitMode) ?: d.splitMode,
            splitApps = p.getString("splitApps", d.splitApps) ?: d.splitApps,
            theme = p.getString("theme", d.theme) ?: d.theme,
            lang = p.getString("lang", d.lang) ?: d.lang,
            starred = p.getString("starred", d.starred) ?: d.starred,
            logAutoScroll = p.getBoolean("logAutoScroll", d.logAutoScroll),
        )
    }

    fun save(ctx: Context, s: AppSettings) {
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().apply {
            putString("proto", s.proto)
            putBoolean("psiphon", s.psiphon)
            putString("exitRegion", s.exitRegion)
            putBoolean("openvpn", s.openvpn)
            putString("openvpnCountry", s.openvpnCountry)
            putString("openvpnNodeId", s.openvpnNodeId)
            putString("openvpnNodeLabel", s.openvpnNodeLabel)
            putString("mode", s.mode)
            putInt("proxyPort", s.proxyPort)
            putBoolean("proxyLan", s.proxyLan)
            putBoolean("localProxy", s.localProxy)
            putBoolean("healthGuard", s.healthGuard)
            putString("rulePolicy", s.rulePolicy)
            putString("ruleText", s.ruleText)
            putBoolean("ipv6", s.ipv6)
            putInt("mtu", s.mtu)
            putString("dns", s.dns)
            putBoolean("dnsOff", s.dnsOff)
            putBoolean("autoConnect", s.autoConnect)
            putBoolean("rescan", s.rescan)
            putInt("timeoutSec", s.timeoutSec)
            putString("splitMode", s.splitMode)
            putString("splitApps", s.splitApps)
            putString("theme", s.theme)
            putString("lang", s.lang)
            putString("starred", s.starred)
            putBoolean("logAutoScroll", s.logAutoScroll)
        }.apply()
    }
}
