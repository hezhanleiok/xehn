# serve-apk.ps1 - 把 APK 通过局域网发给手机（不用数据线）
#
#   .\tools\serve-apk.ps1                 # 默认 8765 端口，自动找 app-debug.apk
#   .\tools\serve-apk.ps1 -Port 9000
#   .\tools\serve-apk.ps1 -Apk D:\some\other.apk
#
# 手机和电脑连同一个 Wi-Fi，手机浏览器打开脚本打印的地址即可下载安装。
# 按 Ctrl+C 结束。
#
# 刻意不用 System.Net.HttpListener：它绑定非回环地址需要 URL ACL（要管理员）。
# 这里用裸 TcpListener + 极简 HTTP，普通权限就能跑。

param(
    [int]$Port = 8765,
    [string]$Apk = ''
)

$ErrorActionPreference = 'Stop'

if (-not $Apk) {
    $cand = Join-Path (Split-Path -Parent $PSScriptRoot) 'app\build\outputs\apk\debug\app-debug.apk'
    if (Test-Path $cand) { $Apk = $cand }
}
if (-not $Apk -or -not (Test-Path $Apk)) {
    throw '没找到 APK。先跑 tools\build-apk.ps1，或用 -Apk <路径> 指定。'
}
$Apk = (Resolve-Path $Apk).Path
$apkName = Split-Path $Apk -Leaf
# 注意：APK 的大小必须在**每次请求时**重新取。之前把它缓存在启动那一刻，
# 重新构建后 APK 变大了，响应头却还是旧的长度 —— 手机只会下载前一半，
# 装的时候报「解析包时出现问题」。这个坑真踩到过。
function ApkSize { return (Get-Item -LiteralPath $Apk).Length }

# 找出局域网 IPv4：跳过回环、虚拟网卡（VPN/WSL）、apipa(169.254)。
$ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -notlike '127.*' -and
        $_.IPAddress -notlike '169.254.*' -and
        $_.PrefixOrigin -ne 'WellKnown'
    } | Select-Object -ExpandProperty IPAddress -Unique
if (-not $ips) { $ips = @('127.0.0.1') }

# 防火墙：Windows 默认拦截入站。脚本是隐藏窗口启动时，那个"允许访问"弹窗
# 根本看不到，Windows 会直接按拒绝处理，表现就是"手机打不开页面"。
# 所以这里主动确认一条只针对本端口的专用网络规则。
function Ensure-FirewallRule([int]$p) {
    $name = "xhwarp-android APK server ($p)"
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
        Write-Host ('  防火墙规则已存在：' + $name) -ForegroundColor DarkGray
        return
    }
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        Write-Host '  注意：没有防火墙放行规则，手机可能连不上。用管理员 PowerShell 执行一次：' -ForegroundColor Yellow
        Write-Host ('    New-NetFirewallRule -DisplayName "' + $name + '" -Direction Inbound -Protocol TCP -LocalPort ' + $p + ' -Action Allow -Profile Private') -ForegroundColor Yellow
        return
    }
    try {
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP -LocalPort $p `
            -Action Allow -Profile Private -ErrorAction Stop | Out-Null
        Write-Host ('  已添加防火墙放行规则：' + $name + '（仅专用网络、仅 TCP ' + $p + '）') -ForegroundColor DarkGray
        Write-Host ('  不用了可以删： Remove-NetFirewallRule -DisplayName "' + $name + '"') -ForegroundColor DarkGray
    } catch {
        Write-Host ('  添加防火墙规则失败：' + $_.Exception.Message) -ForegroundColor Yellow
    }
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
try {
    $listener.Start()
} catch {
    throw "端口 $Port 起不来（被占用？）：$($_.Exception.Message)"
}
Ensure-FirewallRule $Port

Write-Host ''
Write-Host ('  手机浏览器打开下面任一地址（手机要和电脑连同一个 Wi-Fi）：') -ForegroundColor Cyan
foreach ($ip in $ips) {
    Write-Host ('    http://{0}:{1}/' -f $ip, $Port) -ForegroundColor Green
}
Write-Host ''
Write-Host ("  文件：{0}  {1} MB" -f $apkName, [math]::Round((ApkSize) / 1MB, 2))
Write-Host '  手机上装的时候需要允许「安装未知应用」（系统会引导）。'
if ($ips.Count -gt 0) {
    try {
        Set-Clipboard ("http://{0}:{1}/" -f $ips[0], $Port)
        Write-Host '  第一个地址已复制到剪贴板。' -ForegroundColor DarkGray
    } catch { }
}
Write-Host '  如果手机打不开：多半是 Windows 防火墙拦了（首次运行会弹窗，选「允许访问」）。' -ForegroundColor DarkGray
Write-Host '  按 Ctrl+C 结束。' -ForegroundColor DarkGray
Write-Host ''

# 下载页也每次现拼：里面写着文件大小，缓存住就会显示上一个版本的体积。
function IndexBytes {
    $mb = [math]::Round((ApkSize) / 1MB, 2)
    $html = @"
<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>xiaohe VPN APK</title>
<body style="font-family:system-ui;padding:24px;max-width:640px">
<h2>xiaohe VPN 安装包</h2>
<p>$apkName &nbsp; $mb MB</p>
<p><a style="display:inline-block;padding:14px 22px;background:#2563eb;color:#fff;border-radius:10px;text-decoration:none;font-size:18px"
     href="/$apkName">下载并安装</a></p>
<p style="color:#666;font-size:14px">下载完点开通知里的文件即可安装；系统若提示，请允许安装未知应用。</p>
</body>
"@
    return [Text.Encoding]::UTF8.GetBytes($html)
}

while ($true) {
    $client = $null
    try {
        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()
        $client.ReceiveTimeout = 5000
        $client.SendTimeout = 30000

        # 只读请求行就够了，这个服务不处理 body。
        $buf = New-Object byte[] 2048
        $n = $stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { continue }
        $reqLine = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r`n")[0]
        $parts = $reqLine -split ' '
        $method = if ($parts.Count -ge 1) { $parts[0] } else { '' }
        $path = if ($parts.Count -ge 2) { $parts[1] } else { '/' }
        $path = ($path -split '\?')[0]

        $size = ApkSize

        if ($method -eq 'HEAD') {
            $h = "HTTP/1.1 200 OK`r`nContent-Type: application/vnd.android.package-archive`r`nContent-Length: $size`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($h)
            $stream.Write($hb, 0, $hb.Length)
            Write-Host ("  [HEAD] {0}" -f $path) -ForegroundColor DarkGray
        }
        elseif ($path -eq '/' -or $path -eq '/index.html') {
            $indexBytes = IndexBytes
            $h = "HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($indexBytes.Length)`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($h)
            $stream.Write($hb, 0, $hb.Length)
            $stream.Write($indexBytes, 0, $indexBytes.Length)
            Write-Host ('  [页面] 手机打开了下载页') -ForegroundColor Cyan
        }
        elseif ($path -eq "/$apkName" -or $path -eq "/app.apk") {
            $h = "HTTP/1.1 200 OK`r`nContent-Type: application/vnd.android.package-archive`r`nContent-Length: $size`r`nContent-Disposition: attachment; filename=`"$apkName`"`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($h)
            $stream.Write($hb, 0, $hb.Length)
            $fs = [IO.File]::OpenRead($Apk)
            try {
                $t0 = Get-Date
                $fs.CopyTo($stream)
                $dt = (Get-Date) - $t0
                $mbps = if ($dt.TotalSeconds -gt 0) { [math]::Round($size / 1MB / $dt.TotalSeconds, 1) } else { 0 }
                Write-Host ('  [下载] {0} 完成  {1} MB  {2}s  ~{3} MB/s' -f $apkName, [math]::Round($size / 1MB, 2), [math]::Round($dt.TotalSeconds, 1), $mbps) -ForegroundColor Green
            } finally {
                $fs.Dispose()
            }
        }
        else {
            $h = "HTTP/1.1 404 Not Found`r`nContent-Length: 0`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($h)
            $stream.Write($hb, 0, $hb.Length)
        }
        $stream.Flush()
    } catch {
        Write-Host ("  连接出错（忽略）：{0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
    } finally {
        if ($client) { $client.Close() }
    }
}
