# build-apk.ps1 - 构建 APK（自动补齐环境变量，避免"新装的 JDK 老终端里读不到"）
#
#   .\tools\build-apk.ps1                  # 打 debug APK
#   .\tools\build-apk.ps1 -Install         # 打并装到已连接的设备
#   .\tools\build-apk.ps1 -Task :app:assembleRelease
#
# 前置：tools\check-env.ps1 全绿；app\libs\engine.aar 已生成（tools\build-engine.ps1）。

param(
    [string]$Task = ':app:assembleDebug',
    [switch]$Install
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# 已经打开的终端里 $env: 可能是旧的（装完 JDK/SDK 之后没重开），所以注册表兜底。
function Resolve-Env([string]$name) {
    $v = [Environment]::GetEnvironmentVariable($name, 'Process')
    if ($v) { return $v }
    $v = [Environment]::GetEnvironmentVariable($name, 'User')
    if ($v) { return $v }
    return [Environment]::GetEnvironmentVariable($name, 'Machine')
}

foreach ($n in @('JAVA_HOME', 'ANDROID_HOME', 'ANDROID_NDK_HOME')) {
    $v = Resolve-Env $n
    if ($v) { Set-Item "Env:$n" $v; Write-Host ("使用 {0} = {1}" -f $n, $v) -ForegroundColor DarkGray }
}
if (-not $env:JAVA_HOME) { throw 'JAVA_HOME 未设置：先跑 tools\check-env.ps1' }
if (-not (Test-Path (Join-Path $env:JAVA_HOME 'bin\javac.exe'))) { throw "JAVA_HOME 指向的不是 JDK：$env:JAVA_HOME" }
$env:Path = (Join-Path $env:JAVA_HOME 'bin') + ';' + $env:Path

$aar = Join-Path $root 'app\libs\engine.aar'
if (-not (Test-Path $aar)) {
    throw '缺少 app\libs\engine.aar：先跑 tools\build-engine.ps1'
}

$gradlew = Join-Path $root 'gradlew.bat'
if (-not (Test-Path $gradlew)) { throw '缺少 gradlew.bat（Gradle Wrapper 没装）' }

Push-Location $root
try {
    & $gradlew --console=plain $Task
    if ($LASTEXITCODE -ne 0) { throw "gradle $Task 失败" }
    if ($Install) {
        & $gradlew --console=plain :app:installDebug
        if ($LASTEXITCODE -ne 0) { throw 'installDebug 失败（设备连上了吗？adb devices 看看）' }
    }
} finally {
    Pop-Location
}

$apkDir = Join-Path $root 'app\build\outputs\apk\debug'
if (Test-Path $apkDir) {
    Get-ChildItem $apkDir -Filter *.apk | ForEach-Object {
        Write-Host ("APK: {0}  {1} MB" -f $_.FullName, [math]::Round($_.Length / 1MB, 2)) -ForegroundColor Green
    }
}
