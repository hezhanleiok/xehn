# engine — Go 侧（gomobile 打成 .aar 给 Kotlin 用）

## 现在有什么

| 文件 | 内容 |
|---|---|
| `engine.go` | gomobile 可见的门面：`NewEngine` / `Connect` / `Disconnect` / `Status` / `Logs` / `SetLogSink`，以及 `Backend` 接缝 |
| `session.go` | 会话状态机（idle→connecting→connected/stopping/error）+ 日志环形缓冲。**取代**了 Windows 版的 `state.json` + 跨进程 pid 租约 |
| `uapi.go` | WireGuard / AmneziaWG 的 UAPI 文档渲染（纯函数版，对应 `warpscout/warp.go` 的 `baseUAPI`/`peerUAPI`） |
| `engine_test.go` | 状态机、取消、UAPI 渲染的测试 |

## 为什么有一个 Backend 接缝

真正建立隧道的代码（warpscout：wg/awg/masque + gVisor netstack）目前是 `package main` 且带大量包级全局变量，**不能直接 import**。`Backend` 接口让「VpnService + 状态机 + 通知 + 日志 + Compose UI」这一整套可以先建起来、先联调、先测，之后再机械地把 warpscout 搬进来（步骤见 `../docs/porting-analysis.md` 第 6 节）。

默认的 `unwiredBackend` 会**明确报错**（`ErrNotWired`），不会假装连上——这样 UI 的失败路径从第一天就被跑到。

## 自测（不需要 JDK / SDK）

```powershell
cd D:\xhwarp-android\engine
go test ./...
go vet ./...
# 交叉编译验证（Android 目标，纯 Go，无需 CGO）
$env:GOOS='android'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'; go build ./...; Remove-Item Env:\GOOS,Env:\GOARCH,Env:\CGO_ENABLED
```

## 打成 .aar

需要 JDK 17+、Android SDK、NDK 与 gomobile（`tools/check-env.ps1` 会告诉你缺什么）：

```powershell
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init

cd D:\xhwarp-android\engine
gomobile bind -javapkg=com.xiaohe -target=android/arm64,android/arm -androidapi 24 -o ..\app\libs\engine.aar .\
```

更省事的是直接跑 `..\tools\build-engine.ps1`：它会做上面这些，并在最后**剖开 aar 核对方法是否真的生成了**。

## 三个踩过的坑（别改回去）

1. **`-javapkg` 要传 `com.xiaohe`，不是 `com.xiaohe.engine`。**
   gomobile 会把 Go 包名当子包追加：`com.xiaohe` + `package engine` = `com.xiaohe.engine`。
   传错了就得到 `com.xiaohe.engine.engine.*`，Kotlin 全部 Unresolved reference。

2. **方法绑在 `Engine_` 上（带下划线）。** `Engine` 是放常量与 `newEngine` 的抽象类，
   实现类叫 `Engine_`，Kotlin 里 `Engine_(workDir)` 直接 new。

3. **gobind 会静默跳过「按值传结构体」的方法。** 原先的
   `Connect(req Request) error` / `Status() Snapshot` 在生成的 Java 里只剩两行注释：
   `// skipped method Engine_.Connect with unsupported parameter or return types`，
   退出码照样是 0，Kotlin 那边才报 `Unresolved reference 'connect'`。
   所以导出 API 只用基础类型（`Connect(proto, endpoint string, psiphon, ipv6 bool, mtu int)`），
   快照走 `StatusJSON() string`，Kotlin 用系统自带 `org.json` 解析。

4. **Go 1.24+ 需要 `golang.org/x/mobile` 在模块依赖图里**，否则 bind 直接拒绝并提示
   `go get -tool golang.org/x/mobile/cmd/gobind`。`build-engine.ps1` 已自动补。
