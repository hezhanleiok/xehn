# check-env.ps1 - 安卓开发环境体检（可重复运行，只读检查，不安装任何东西）
#
#   .\tools\check-env.ps1
#
# 逐项检查本机是否具备构建 xhwarp 安卓版所需的东西，并打印缺失项的安装命令。
# 退出码：0 = 全部就绪，1 = 有缺失。

$ErrorActionPreference = 'Continue'

$script:missing = 0
$script:ok = 0

function Section([string]$t) { Write-Host ""; Write-Host "== $t ==" -ForegroundColor Cyan }
function Pass([string]$t)    { $script:ok++;      Write-Host ('  [OK]   ' + $t) -ForegroundColor Green }
function Fail([string]$t)    { $script:missing++; Write-Host ('  [缺失] ' + $t) -ForegroundColor Red }
function Info([string]$t)    { Write-Host ('         ' + $t) -ForegroundColor DarkGray }

function Have([string]$cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# 环境变量：先看当前会话，再看用户级、机器级注册表。
# 刚装完 JDK/SDK 时旧的终端里 $env: 还是空的，只看 $env: 会误报「未安装」。
function EnvVal([string]$name) {
    if ((Get-Item "Env:$name" -ErrorAction SilentlyContinue)) { return (Get-Item "Env:$name").Value }
    $v = [Environment]::GetEnvironmentVariable($name, 'User')
    if ($v) { return $v }
    return [Environment]::GetEnvironmentVariable($name, 'Machine')
}

# gomobile 装在 GOPATH\bin 下，那个目录常常不在 PATH 里。
function ResolveTool([string]$name) {
    if (Have $name) { return (Get-Command $name).Source }
    $gobin = ''
    if (Have go) { $gobin = (& go env GOPATH) + '\bin' }
    foreach ($cand in @((Join-Path $gobin "$name.exe"), (Join-Path $env:USERPROFILE "go\bin\$name.exe"))) {
        if ($cand -and (Test-Path $cand)) { return $cand }
    }
    return ''
}

# ---------------------------------------------------------------------------
Section 'Go 工具链（引擎 + gomobile 绑定用）'
# ---------------------------------------------------------------------------
if (Have go) {
    $gover = (& go version) -replace 'go version ', ''
    Pass ('go: ' + $gover)
    $dist = & go tool dist list 2>$null
    if ($dist -match 'android/arm64') {
        Pass 'go 支持 android/arm64 交叉编译'
    } else {
        Fail '当前 go 不支持 android/arm64（请用官方安装包）'
    }
} else {
    Fail 'go 未安装'
    Info '装： https://go.dev/dl/   （已验证 go1.27 可用）'
}
$gomobile = ResolveTool 'gomobile'
if ($gomobile) {
    Pass ('gomobile: ' + $gomobile)
    if (-not (Have gomobile)) {
        Info ('它不在 PATH 里，先临时用： $env:PATH = "' + (Split-Path $gomobile) + ';' + '$env:PATH"')
        Info ('或永久加： setx PATH "%PATH%;' + (Split-Path $gomobile) + '"')
    }
    if (-not (ResolveTool 'gobind')) { Fail 'gobind 未安装（gomobile bind 需要它）' }
} else {
    Fail 'gomobile 未安装（把 Go 引擎打成 .aar 给 Kotlin 用）'
    Info '装： go install golang.org/x/mobile/cmd/gomobile@latest'
    Info '    go install golang.org/x/mobile/cmd/gobind@latest'
    Info '    gomobile init'
}
$pub = EnvVal 'GOPROXY'
if ($pub -and $pub -match 'proxy\.golang\.org') {
    Info 'GOPROXY 指向 proxy.golang.org：本机 IPv6 到 Google 不通，go install 会超时。'
    Info '  建议： go env -w GOPROXY=https://goproxy.cn,direct'
}

# ---------------------------------------------------------------------------
Section 'JDK（Gradle / Android Gradle Plugin 用）'
# ---------------------------------------------------------------------------
$jdk = $null
$jdkHome = EnvVal 'JAVA_HOME'
if ($jdkHome -and (Test-Path (Join-Path $jdkHome 'bin\javac.exe'))) {
    $jdk = Join-Path $jdkHome 'bin\javac.exe'
} elseif (Have javac) {
    $jdk = (Get-Command javac).Source
} else {
    # 装了但没设 JAVA_HOME 时，去常见安装位置找一遍。
    foreach ($root in @('C:\Program Files\Microsoft', 'C:\Program Files\Eclipse Adoptium',
                        'C:\Program Files\Java', 'C:\Program Files\Zulu')) {
        if (-not (Test-Path $root)) { continue }
        $cand = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName 'bin\javac.exe') } | Select-Object -First 1
        if ($cand) { $jdk = Join-Path $cand.FullName 'bin\javac.exe'; $jdkHome = $cand.FullName; break }
    }
}
if ($jdk) {
    $v = (& $jdk -version 2>&1 | Select-Object -First 1)
    Pass ('javac: ' + $v)
    if (-not $jdkHome) {
        $jdkHome = Split-Path (Split-Path $jdk)
        Fail ('JAVA_HOME 没设置（有 javac 但 sdkmanager/Gradle 找不到它）')
        Info ('设一下： setx JAVA_HOME "' + $jdkHome + '"')
    } else {
        Info ('JAVA_HOME = ' + $jdkHome)
    }
    $major = 0
    if ($v -match '(\d+)') { $major = [int]$Matches[1] }
    if ($major -gt 0 -and $major -lt 17) {
        Fail ("JDK 版本太低（$major）：AGP 8.x 要求 17+")
    }
} else {
    Fail 'JDK 未安装（某个软件自带的 JRE 不计入）'
    Info '装 Microsoft OpenJDK 17（本机已用这个）：'
    Info '  winget install -e --id Microsoft.OpenJDK.17     # winget 下载失败时改用 curl 拉 msi'
    Info '或 Temurin： https://adoptium.net/temurin/releases/?version=17'
    Info '装完确认 JAVA_HOME 指向 JDK 根目录（不是 bin）。'
}

# ---------------------------------------------------------------------------
Section 'Android SDK'
# ---------------------------------------------------------------------------
$sdk = EnvVal 'ANDROID_HOME'
if (-not $sdk) { $sdk = EnvVal 'ANDROID_SDK_ROOT' }
if (-not $sdk) {
    foreach ($p in @("$env:LOCALAPPDATA\Android\Sdk", 'D:\Android\Sdk', 'C:\Android\Sdk')) {
        if (Test-Path $p) { $sdk = $p; break }
    }
}
if ($sdk -and (Test-Path $sdk)) {
    Pass ('ANDROID_HOME = ' + $sdk)
    foreach ($part in @('platform-tools\adb.exe', 'cmdline-tools\latest\bin\sdkmanager.bat',
                        'build-tools', 'platforms', 'ndk')) {
        if (Test-Path (Join-Path $sdk $part)) { Pass ('SDK 组件存在: ' + $part) }
        else { Fail ('SDK 组件缺失: ' + $part) }
    }
} else {
    Fail 'Android SDK 未安装（ANDROID_HOME 未设置，常见路径下也没有）'
    Info '只装命令行工具即可，不必装 Android Studio：'
    Info '  https://developer.android.com/studio#command-line-tools-only'
    Info '  解压到 D:\Android\Sdk\cmdline-tools\latest\ 后执行：'
    Info '  sdkmanager --sdk_root=D:\Android\Sdk "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;27.0.12077973"'
    Info '  setx ANDROID_HOME "D:\Android\Sdk"'
}

# ---------------------------------------------------------------------------
Section 'Android NDK（gomobile 交叉编译原生库）'
# ---------------------------------------------------------------------------
$ndk = EnvVal 'ANDROID_NDK_HOME'
if (-not $ndk -and $sdk -and (Test-Path (Join-Path $sdk 'ndk'))) {
    $cand = Get-ChildItem (Join-Path $sdk 'ndk') -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cand) { $ndk = $cand.FullName }
}
if ($ndk -and (Test-Path $ndk)) {
    Pass ('NDK = ' + $ndk)
    if (-not $env:ANDROID_NDK_HOME) { Info ('建议固定： setx ANDROID_NDK_HOME "' + $ndk + '"') }
} else {
    Fail 'Android NDK 未安装'
    Info '装： sdkmanager --sdk_root=<SDK> "ndk;27.0.12077973"'
    Info '    setx ANDROID_NDK_HOME "<SDK>\ndk\27.0.12077973"'
}

# ---------------------------------------------------------------------------
Section 'Gradle / 构建缓存'
# ---------------------------------------------------------------------------
if (Have gradle) {
    Pass ('系统 gradle: ' + ((& gradle -v 2>&1 | Select-String Gradle).Line))
} else {
    Info '系统无 gradle：项目用 Gradle Wrapper（gradlew.bat），首次运行会自动下载，属正常。'
}
$wrapper = Join-Path $PSScriptRoot '..\gradle\wrapper\gradle-wrapper.jar'
if (Test-Path $wrapper) { Pass 'gradle-wrapper.jar 已就位' }
else { Fail '缺 gradle-wrapper.jar（二进制文件，需 gradle wrapper 生成或在 Android Studio 同步一次）' }

# ---------------------------------------------------------------------------
Section '设备 / 调试'
# ---------------------------------------------------------------------------
if ($sdk -and (Test-Path (Join-Path $sdk 'platform-tools\adb.exe'))) {
    $adb = Join-Path $sdk 'platform-tools\adb.exe'
    $devs = ((& $adb devices 2>&1) -join ' | ')
    Info $devs
    if ($devs -match 'device($| )' -or $devs -match "`tdevice") { Pass '有已连接的安卓设备/模拟器' }
    else { Info '暂无设备：接手机开 USB 调试，或建模拟器（arm64 镜像更快；x86_64 镜像需 WHPX）' }
} else {
    Fail 'adb 不可用（随 platform-tools 安装）'
}

# ---------------------------------------------------------------------------
Section '可选但推荐'
# ---------------------------------------------------------------------------
$studio = @("$env:LOCALAPPDATA\Programs\Android Studio", "$env:ProgramFiles\Android\Android Studio") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($studio) {
    Pass ('Android Studio: ' + $studio)
} else {
    Info '未装 Android Studio（非必须：SDK 可用 cmdline-tools 管理，Gradle 用 wrapper）'
    Info '  但它是装 SDK 最省事的方式，也能直接看 Compose 预览。'
}

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '提示：本脚本会读注册表里的环境变量，所以旧的终端也不会误报；' -ForegroundColor DarkGray
Write-Host '      但 sdkmanager/gradle 自己要靠 $env:，装完请新开一个 PowerShell 窗口再用。' -ForegroundColor DarkGray
Write-Host ("合计：{0} 项就绪，{1} 项缺失。" -f $script:ok, $script:missing) `
    -ForegroundColor $(if ($script:missing -eq 0) { 'Green' } else { 'Yellow' })
if ($script:missing -gt 0) {
    Write-Host '装齐后重新运行本脚本确认。' -ForegroundColor Yellow
    exit 1
}
exit 0
