# 这里放 gomobile 生成的引擎

`engine.aar` **不入库**，用脚本生成：

```powershell
powershell -ExecutionPolicy Bypass -File ..\..\tools\build-engine.ps1
```

脚本会在绑定结束后剖开 aar、核对 `Engine_` 上真的存在
`connect / disconnect / statusJSON / setTunFD / versionString / logs / setLogSink`
—— gobind 会**静默跳过**某些方法（见 `engine/README.md` 的坑 3），只靠退出码判断会漏。

生成的 `engine.aar` 会出现在本目录，`app/build.gradle.kts` 已经把它加进依赖：

```kotlin
implementation(files("libs/engine.aar"))
```

Kotlin 侧按 `-javapkg=com.xiaohe.engine` 指定的包名引用：

```kotlin
import com.xiaohe.engine.Engine
import com.xiaohe.engine.Request
import com.xiaohe.engine.Snapshot
import com.xiaohe.engine.LogSink
```

> 没有 aar 时 `:app:compileDebugKotlin` 会报 `unresolved reference: engine` —— 这不是代码
> 写错了，是还没生成 .aar。先跑上面的脚本。
