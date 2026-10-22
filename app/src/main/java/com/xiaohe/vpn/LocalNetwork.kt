package com.xiaohe.vpn

import android.content.Context
import android.net.ConnectivityManager
import java.net.Inet4Address

/** 读取系统当前的网络信息（只用于界面显示与兜底）。 */
object LocalNetwork {

    /**
     * 当前默认网络的本机 IPv4 地址，取不到返回空串。
     *
     * 这是「实测拿不到」时的兜底：首页优先显示真正问过公网得到的地址
     * （EngineBridge.refreshLocalIp），因为那才是别人看到的你。
     */
    fun ipv4(ctx: Context): String {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return ""
        val net = cm.activeNetwork ?: return ""
        val props = cm.getLinkProperties(net) ?: return ""
        for (la in props.linkAddresses) {
            val a = la.address
            if (a is Inet4Address && !a.isLoopbackAddress && !a.isLinkLocalAddress) {
                return a.hostAddress ?: ""
            }
        }
        return ""
    }

    /** 是否有可用的网络连接。 */
    fun online(ctx: Context): Boolean {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return false
        return cm.activeNetwork != null
    }
}
