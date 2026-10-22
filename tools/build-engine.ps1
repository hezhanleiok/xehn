# build-engine.ps1 - 把 Go 引擎打成 app\libs\engine.aar
#
#   .\tools\build-engine.ps1 [-Target "android/arm64,android/arm"] [-SkipInit]
#
# 先跑 tools\check-env.ps1 确认 JDK / Android SDK / NDK / gomobile 都在。

param(
    [string]$Target = 'android/arm64,android/arm',
    # gomobile 会把 Go 包名当子包追加：-javapkg=com.xiaohe + package engine
    # 才等于 Java 的 com.xiaohe.engine。传 com.xiaohe.engine 会得到
    # com.xiaohe.engine.engine，Kotlin 侧全部 Unresolved reference。
    [string]$JavaPkg = 'com.xiaohe',
    [int]$AndroidAPI = 24,
    [switch]$SkipInit
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$engine = Join-Path $root 'engine'
$outDir = Join-Path $root 'app\libs'
$out = Join-Path $outDir 'engine.aar'

function Need([string]$what, [string]$how) {
    if (-not (Get-Command $what -ErrorAction SilentlyContinue)) {
        throw "缺少 $what。$how"
    }
}

# gomobile 装在 GOPATH\bin，那里常常不在 PATH 里；javac 也常被漏掉。
$gobin = ''
if (Get-Command go -ErrorAction SilentlyContinue) { $gobin = (& go env GOPATH) + '\bin' }
if ($gobin -and (Test-Path $gobin) -and $env:Path -notlike "*$gobin*") { $env:Path = "$gobin;$env:Path" }
if ($env:JAVA_HOME) { $env:Path = "$env:JAVA_HOME\bin;$env:Path" }

Need 'go' '装 Go：https://go.dev/dl/'
if (-not (Get-Command gomobile -ErrorAction SilentlyContinue)) {
    Write-Host '正在安装 gomobile / gobind（一次性）...' -ForegroundColor Yellow
    & go install golang.org/x/mobile/cmd/gomobile@latest
    & go install golang.org/x/mobile/cmd/gobind@latest
    if ($env:Path -notlike "*$gobin*") { $env:Path = "$gobin;$env:Path" }
    if (-not (Get-Command gomobile -ErrorAction SilentlyContinue)) {
        throw "gomobile 装好了但不在 PATH 里，请把 $gobin 加进 PATH 后重开终端。"
    }
}
if (-not $env:JAVA_HOME) {
    Write-Host '警告：JAVA_HOME 未设置。gomobile bind 需要 JDK 17+（javac 还要在 PATH 里）。' -ForegroundColor Yellow
}
if (-not (Get-Command javac -ErrorAction SilentlyContinue)) {
    Write-Host '警告：PATH 里没有 javac。gomobile 最后一步会以 "javac: executable file not found" 失败。' -ForegroundColor Yellow
}
if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) {
    Write-Host '警告：ANDROID_HOME / ANDROID_SDK_ROOT 未设置。gomobile bind 需要 Android SDK。' -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force $outDir | Out-Null

# gomobile 会把握绑定的 Go 符号的 doc 注释抄进生成的 Java，而中文 Windows 上
# javac 默认按 GBK 解码源码 —— 注释里任何一个非 ASCII 字节都会变成
# "unmappable character" 并把整次 bind 打挂（退出码 1，且报错被 gomobile 吞掉，
# 只留一句 "javac ... failed"）。gomobile 没有传 javac 参数的入口，
# 所以只能靠 JAVA_TOOL_OPTIONS 让 JVM 默认字符集变成 UTF-8。
if (-not $env:JAVA_TOOL_OPTIONS) { $env:JAVA_TOOL_OPTIONS = '-Dfile.encoding=UTF-8' }
Write-Host ('JAVA_TOOL_OPTIONS = ' + $env:JAVA_TOOL_OPTIONS) -ForegroundColor DarkGray

# Psiphon 的 psiphon-tls 在 init 里用反射校验 crypto/tls.ConnectionState 的字段
# 布局，Go 1.27 给它加了一个字段 —— 用本机 1.27 构建出来的包一 import 就 panic
# （"struct field count mismatch: 18 vs 17"）。引擎因此固定在 go1.26 上构建：
# go.mod 的 go 指令已经是 1.26.3，这里再把工具链钉到 1.26.8（本机没有会自动下载）。
if (-not $env:GOTOOLCHAIN) { $env:GOTOOLCHAIN = 'go1.26.8' }
Write-Host ('GOTOOLCHAIN = ' + $env:GOTOOLCHAIN) -ForegroundColor DarkGray

# Go 1.24+ 的 gomobile 要求模块依赖图里有 golang.org/x/mobile，否则直接拒绝：
#   "gomobile bind requires golang.org/x/mobile in the current module"
# 用 tool 指令记进 go.mod，这样 go mod tidy 也不会把它清掉。
Push-Location $engine
try {
    if (-not (Select-String -Path 'go.mod' -Pattern 'golang.org/x/mobile' -Quiet)) {
        Write-Host '补齐 go.mod 里的 golang.org/x/mobile（一次性）...' -ForegroundColor Cyan
        & go get -tool golang.org/x/mobile/cmd/gobind
        if ($LASTEXITCODE -ne 0) { throw 'go get -tool golang.org/x/mobile/cmd/gobind 失败' }
    }

    Write-Host 'go test ./... （打 aar 前先跑引擎自测）' -ForegroundColor Cyan
    & go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'engine go test 失败，先修好再打 aar' }

    if (-not $SkipInit) {
        Write-Host 'gomobile init ...' -ForegroundColor Cyan
        & gomobile init
    }

    if (Test-Path $out) { Remove-Item $out -Force }
    Write-Host "gomobile bind -javapkg=$JavaPkg -target=$Target -> $out" -ForegroundColor Cyan
    # 参数必须放进数组再用 @ 展开：Windows PowerShell 5.1 会把
    # `-target=$Target` 这种 token 原样传给原生 exe，变量不展开，
    # gomobile 于是报 `unsupported platform: "$Target"`。
    $bindArgs = @('bind', "-javapkg=$JavaPkg", "-target=$Target",
                  "-androidapi=$AndroidAPI", '-o', $out, '.\')
    $bindLog = & gomobile @bindArgs 2>&1
    $bindLog | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw 'gomobile bind 失败（看上面的报错；缺 SDK/NDK/javac 最常见）' }
} finally {
    Pop-Location
}

if (-not (Test-Path $out)) { throw "绑完了但 $out 不存在" }

# 静默失败检查：gobind 遇到「按值传结构体」的参数/返回值时会**跳过整个方法**
# 并在生成的 Java 里写一行注释，退出码依然是 0。等 Kotlin 报 Unresolved reference
# 才发现就太晚了，所以这里直接剖开 aar 看方法在不在。
$probe = Join-Path $env:TEMP ("aar-probe-" + [Guid]::NewGuid().ToString('N'))
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($out, $probe)
    $classes = Join-Path $probe 'classes.jar'
    $jp = Join-Path $probe 'jp'
    [IO.Compression.ZipFile]::ExtractToDirectory($classes, $jp)
    $implJava = Get-ChildItem $jp -Recurse -Filter 'Engine_.class' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($implJava) {
        $javap = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin\javap.exe' } else { 'javap' }
        # javap 会把 "Picked up JAVA_TOOL_OPTIONS: ..." 写到 stderr，而上面的
        # $ErrorActionPreference='Stop' 会把原生命令的 stderr 当成终止性错误 ——
        # 于是 bind 明明成功、脚本却在核对这一步失败退出。核对期间放宽这个策略。
        $eapPrev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $sigs = & $javap -classpath $classes "$JavaPkg.engine.Engine_" 2>&1 | ForEach-Object { "$_" }
        $ErrorActionPreference = $eapPrev
        $missing = @()
        foreach ($m in @('connect', 'disconnect', 'statusJSON', 'setTunFD', 'versionString', 'logs', 'setLogSink')) {
            if (-not ($sigs | Select-String -Pattern "\b$m\(" -Quiet)) { $missing += $m }
        }
        if ($missing.Count -gt 0) {
            throw ("aar 里缺少方法: " + ($missing -join ', ') + "。多半是 gobind 因参数/返回值用了结构体而静默跳过 —— 改成基础类型或 JSON。")
        }
        Write-Host ('已核对 Java 方法: ' + ($sigs | Select-String -Pattern 'native' | Measure-Object).Count + ' 个（含 connect / statusJSON）') -ForegroundColor Green
    }
} finally {
    if (Test-Path $probe) { Remove-Item $probe -Recurse -Force -ErrorAction SilentlyContinue }
}

$size = [math]::Round((Get-Item $out).Length / 1MB, 2)
Write-Host "完成：$out ($size MB)" -ForegroundColor Green
Write-Host '接着： .\gradlew.bat :app:assembleDebug' -ForegroundColor Green
