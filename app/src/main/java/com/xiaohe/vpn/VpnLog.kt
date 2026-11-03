package com.xiaohe.vpn

import android.content.Context
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.io.PrintWriter
import java.io.StringWriter
import java.util.ArrayDeque

/**
 * 日志落盘 + 崩溃记录。
 *
 * 为什么必须有：**闪退之后内存里的日志随进程一起消失**。2026-11-01 真机测试里
 * OpenVPN 出口第 5 次 establish 之后进程直接没了，界面上什么都看不到 ——
 * 而日志面板原来只活在 `EngineBridge._state`（内存 StateFlow）里。
 *
 * 规则（用户明确要求）：
 *  - 每写一行就落盘（flush），崩溃时最后一行也留得住；
 *  - **自动清理一律不做**：退出、重启、重连都不删；只有界面上点「清空日志」才删；
 *  - 位置固定：`filesDir/logs/vpn.log`（重装 App 才会消失）；
 *  - 未捕获的 Java/Kotlin 异常额外写一份 `crash.log`，带完整堆栈。
 *
 * 注意：这里是**日志**，任何 IO 失败都必须自己吞掉 —— 不能让写日志把主流程带崩。
 */
object VpnLog {

    private const val DIR = "logs"
    private const val NAME = "vpn.log"
    private const val CRASH_NAME = "crash.log"

    private val lock = Any()
    private var writer: BufferedWriter? = null
    private var cachedFile: File? = null
    private var cachedDir: File? = null

    /** 日志文件（给界面显示路径用）。 */
    fun file(ctx: Context): File {
        val app = ctx.applicationContext
        val d = cachedDir ?: File(app.filesDir, DIR).apply { mkdirs() }.also { cachedDir = it }
        return cachedFile ?: File(d, NAME).also { cachedFile = it }
    }

    /** 崩溃堆栈单独一份，方便只看崩溃。 */
    fun crashFile(ctx: Context): File = File(file(ctx).parentFile ?: ctx.filesDir, CRASH_NAME)

    /** 追加一行并立刻 flush。线程安全（Go 的多个 goroutine 会同时写）。 */
    fun append(ctx: Context, line: String) {
        synchronized(lock) {
            try {
                val w = writer ?: openLocked(ctx)
                w.write(line)
                w.newLine()
                w.flush()
            } catch (_: Throwable) {
                // 写日志失败不能影响连接本身；关掉句柄等下次重开。
                closeLocked()
            }
        }
    }

    /** 读末尾若干行（进程启动时把历史灌回界面）。 */
    fun readLast(ctx: Context, maxLines: Int): List<String> {
        val f = file(ctx)
        if (!f.isFile || maxLines <= 0) return emptyList()
        val ring = ArrayDeque<String>(maxLines)
        return try {
            f.bufferedReader(Charsets.UTF_8).useLines { seq ->
                for (line in seq) {
                    if (ring.size >= maxLines) ring.removeFirst()
                    ring.addLast(line)
                }
            }
            ring.toList()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    /** 最后一行（用来判断上次是不是正常退出）。 */
    fun lastLine(ctx: Context): String? = readLast(ctx, 1).lastOrNull()

    /** 只在用户手动清空时调用：关句柄 + 删文件 + 删崩溃记录。 */
    fun clear(ctx: Context) {
        synchronized(lock) {
            closeLocked()
            try {
                file(ctx).delete()
                crashFile(ctx).delete()
            } catch (_: Throwable) {
            }
        }
    }

    /** 崩溃时用：不吞异常本身的输出，只额外落一份带堆栈的记录。 */
    fun appendCrash(ctx: Context, text: String) {
        append(ctx, text)
        try {
            crashFile(ctx).appendText(text + "\n")
        } catch (_: Throwable) {
        }
    }

    private fun openLocked(ctx: Context): BufferedWriter {
        val w = BufferedWriter(
            OutputStreamWriter(FileOutputStream(file(ctx), true), Charsets.UTF_8)
        )
        writer = w
        return w
    }

    private fun closeLocked() {
        try {
            writer?.close()
        } catch (_: Throwable) {
        }
        writer = null
    }
}

/**
 * 未捕获异常兜底：先把堆栈写进日志文件，再交给系统原来的处理器。
 *
 * 装在 MainActivity 和 WarpVpnService 两处（谁先起来谁装，重复调用无害）：
 * 只装在 Activity 上的话，「只有前台服务在跑」的场景就漏了。
 *
 * 说清楚边界：**这里只能抓 Java/Kotlin 层**。如果是 Go 那侧的原生崩溃
 * （SIGSEGV/abort），这个处理器不会执行 —— 那种情况能留下的证据就是
 * 崩溃前最后一行日志，以及 `adb logcat` 里的 tombstone。
 */
object CrashGuard {

    @Volatile
    private var installed = false

    fun install(ctx: Context) {
        if (installed) return
        installed = true
        val app = ctx.applicationContext
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val sw = StringWriter()
                e.printStackTrace(PrintWriter(sw))
                VpnLog.appendCrash(
                    app,
                    "[crash] 线程 ${t.name} 未捕获异常：${e.javaClass.name}: ${e.message}\n$sw",
                )
            } catch (_: Throwable) {
            }
            if (prev != null) {
                prev.uncaughtException(t, e)
            } else {
                android.os.Process.killProcess(android.os.Process.myPid())
                kotlin.system.exitProcess(10)
            }
        }
    }

    /**
     * 启动标记 + 「上次没正常结束」判定。
     *
     * 闪退是静默的：用户在界面上只能看到「日志回到空白」。所以每次启动时对比
     * 上一份日志的最后一行 —— 没有 [shutdown] 标记就说明上次是被崩溃/系统杀掉的，
     * 直接把这件事写进日志，不用用户自己去猜。
     */
    fun markStart(ctx: Context, tag: String) {
        val last = VpnLog.lastLine(ctx)
        VpnLog.append(ctx, "[app] $tag 启动 ${BuildConfig.VERSION_NAME}(${BuildConfig.VERSION_CODE})")
        logLastExit(ctx)
        if (last != null && !last.contains(SHUTDOWN_MARK)) {
            VpnLog.append(
                ctx,
                "[app] 上次进程没有正常结束（崩溃或被系统杀掉），最后一行是：$last",
            )
        }
    }

    /**
     * 上一次进程到底是怎么没的。
     *
     * 这条比我们自己猜有用得多：Android 11+ 的 `ApplicationExitInfo` 会直接给出
     * 原因 —— 内存不足被 LMK 杀掉 / Java 崩溃 / **原生崩溃（带 tombstone 摘要）** /
     * ANR / 用户强杀。闪退最怕的就是「不知道是哪一种」，有了这个就不用猜。
     */
    private fun logLastExit(ctx: Context) {
        if (android.os.Build.VERSION.SDK_INT < 30) return
        try {
            val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
            // 方法名容易记错：是 getHistoricalProcessExitReasons(包名, pid, 条数)，
            // pid=0 表示本包全部进程；返回按时间倒序，第一条就是上一次退出。
            val last = am.getHistoricalProcessExitReasons(ctx.packageName, 0, 5)
                .firstOrNull() ?: return
            val reason = when (last.reason) {
                android.app.ApplicationExitInfo.REASON_CRASH -> "Java 崩溃"
                android.app.ApplicationExitInfo.REASON_CRASH_NATIVE -> "原生崩溃（Native）"
                android.app.ApplicationExitInfo.REASON_ANR -> "ANR 无响应"
                android.app.ApplicationExitInfo.REASON_LOW_MEMORY -> "系统内存不足被杀（LMK）"
                android.app.ApplicationExitInfo.REASON_EXIT_SELF -> "自己退出（exit）"
                android.app.ApplicationExitInfo.REASON_USER_REQUESTED -> "用户/系统强制停止"
                else -> "其它（reason=${last.reason}）"
            }
            VpnLog.append(
                ctx,
                "[app] 上次退出原因：$reason（${java.util.Date(last.timestamp)}，" +
                    "importance=${last.importance}，desc=${last.description}）",
            )
            // 原生崩溃才可能带 tombstone 摘要：只取前若干行，够看崩在哪个库/函数。
            if (last.reason == android.app.ApplicationExitInfo.REASON_CRASH_NATIVE) {
                val trace = last.traceInputStream
                if (trace != null) {
                    val text = trace.bufferedReader().use { r ->
                        val sb = StringBuilder()
                        val buf = CharArray(4096)
                        while (sb.length < 4000) {
                            val n = r.read(buf)
                            if (n <= 0) break
                            sb.append(buf, 0, n)
                        }
                        sb.toString()
                    }
                    if (text.isNotBlank()) {
                        VpnLog.appendCrash(ctx, "[crash] 上次原生崩溃的 tombstone 摘要：\n$text")
                    }
                }
            }
        } catch (_: Throwable) {
            // 拿不到就算了：这是诊断信息，不能影响启动。
        }
    }

    const val SHUTDOWN_MARK = "[app] 正常退出"
}
