# 从 logo.png 生成 Android 图标资源。
#
# 三个必须处理的点：
#   1. 原图是「圆角方形卡片 + 四角纯白」的画布。直接当图标用，四角的白会露出来。
#      所以先把纯白边框裁掉，只留卡片本身。
#   2. 源图卡片底部印着 "XEHN"。图标下面本来就有 App 名称，留着就是重复显示，
#      所以先按列插值把那行字擦掉（见 1.5），再把构图收到标志本身（见 1.6）。
#   3. 自适应图标（API 26+）由启动器按自己的形状（圆/方圆）裁剪 foreground，
#      所以标志要落在安全区（约画布 66%）里，否则圆角遮罩会切掉 X 的尖。
#
# 同时生成 legacy 图标（API 25 及以下、以及忽略自适应图标的启动器）：
# 方形的铺背景色，圆的逐像素抠成圆并做边缘抗锯齿。
#
# 注意：不用 Graphics.SetClip(GraphicsPath, CombineMode)。PowerShell 在
# 重载解析上会挑错 SetClip(Rectangle) 并报一个看不懂的转换错误，逐像素更稳。

Add-Type -AssemblyName System.Drawing

$root = 'D:\xhwarp-android'
$src = Join-Path $root 'logo.png'
$res = Join-Path $root 'app\src\main\res'

# 卡片外圈的纯白；阈值放宽到 250，否则卡片自身的极浅渐变会被当成白边。
$whiteCut = 250

Write-Host "读取 $src"
$bmp = [System.Drawing.Bitmap]::FromFile($src)
$w = $bmp.Width
$h = $bmp.Height
Write-Host "  尺寸 ${w}x${h}"

# --- 1) 找非白内容的外框 -------------------------------------------------
$rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
$data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$bytes = New-Object byte[] ($data.Stride * $h)
[System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)
$bmp.UnlockBits($data)

$minX = $w; $minY = $h; $maxX = -1; $maxY = -1
for ($y = 0; $y -lt $h; $y++) {
    $row = $y * $data.Stride
    for ($x = 0; $x -lt $w; $x++) {
        $i = $row + $x * 4
        # 内存里是 BGRA
        if ($bytes[$i] -lt $whiteCut -or $bytes[$i + 1] -lt $whiteCut -or $bytes[$i + 2] -lt $whiteCut) {
            if ($x -lt $minX) { $minX = $x }
            if ($x -gt $maxX) { $maxX = $x }
            if ($y -lt $minY) { $minY = $y }
            if ($y -gt $maxY) { $maxY = $y }
        }
    }
}
if ($maxX -lt 0) {
    Write-Error '整张图都是白的？裁边失败'
    exit 1
}
$cardW = $maxX - $minX + 1
$cardH = $maxY - $minY + 1
Write-Host "  裁掉白边 -> 卡片 ${cardW}x${cardH} @ ($minX,$minY)"

# --- 1.5) 擦掉卡片底部的 "XEHN" 字样 -------------------------------------
#
# 图标下面已经有 App 名称，卡片里再写一遍就是重复。源图是美术给的成品、改不了，
# 所以在生成图标时擦掉：用「文字上方一行」和「下方一行」按列做线性插值。
# 那片背景是柔和的横向波浪 + 浅蓝渐变，插值后看不出接缝；填纯色会留下一块补丁。
#
# 判据只认「低饱和深藏青」（文字色 #1B3A5C 一带）：R/G/B 都低且 B < 150。
# X 标志是亮蓝/青蓝，B 通道都在 180 以上，不会被误判成文字。
$tMin = -1
$tMax = -1
$searchTop = $minY + [int]($cardH * 0.55)   # 只在卡片下半部分找，避开标志
for ($y = $searchTop; $y -le $maxY; $y++) {
    $row = $y * $data.Stride
    $n = 0
    for ($x = $minX; $x -le $maxX; $x++) {
        $i = $row + $x * 4
        if ($bytes[$i] -lt 150 -and $bytes[$i + 1] -lt 120 -and $bytes[$i + 2] -lt 110) { $n++ }
    }
    if ($n -ge 8) {
        if ($tMin -lt 0) { $tMin = $y }
        $tMax = $y
    }
}
if ($tMin -gt 0) {
    $y0 = [Math]::Max($minY, $tMin - 3)
    $y1 = [Math]::Min($maxY, $tMax + 3)
    for ($x = $minX; $x -le $maxX; $x++) {
        $i0 = $y0 * $data.Stride + $x * 4
        $i1 = $y1 * $data.Stride + $x * 4
        $b0 = [double]$bytes[$i0]; $g0 = [double]$bytes[$i0 + 1]; $r0 = [double]$bytes[$i0 + 2]
        $b1 = [double]$bytes[$i1]; $g1 = [double]$bytes[$i1 + 1]; $r1 = [double]$bytes[$i1 + 2]
        for ($y = $y0 + 1; $y -lt $y1; $y++) {
            $t = ($y - $y0) / [double]($y1 - $y0)
            $i = $y * $data.Stride + $x * 4
            $bytes[$i] = [byte][Math]::Round($b0 + ($b1 - $b0) * $t)
            $bytes[$i + 1] = [byte][Math]::Round($g0 + ($g1 - $g0) * $t)
            $bytes[$i + 2] = [byte][Math]::Round($r0 + ($r1 - $r0) * $t)
        }
    }
    # 改的是拷贝，写回位图；后面所有输出都基于这张擦干净的图。
    $wdata = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::WriteOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $wdata.Scan0, $bytes.Length)
    $bmp.UnlockBits($wdata)
    Write-Host ("  已擦除底部字样：y {0}..{1}" -f $y0, $y1)
} else {
    Write-Host '  未检测到底部字样（跳过擦除）' -ForegroundColor DarkYellow
}

# --- 1.6) 取「只有标志」的那块正方 ---------------------------------------
#
# 擦掉字样后如果把整张卡片塞进图标，下半张会空着。这里把构图收到标志本身：
# 横向居中、从卡片顶部起、边长取卡片的 76%（实测正好容下 X 的两个尖）。
# 裁出来的区域是卡片内部，四个角本来就是浅色背景，被启动器遮罩裁掉也不露白边。
# 裁切的下边界取「字样上方 12px」—— 不依赖擦除是否完美：字落在裁切外，
# 就算插值留下一点点痕迹也看不见。没检测到字样时才退回到卡片下沿。
$cropBottom = $maxY
if ($tMin -gt 0) { $cropBottom = $tMin - 12 }
$side = [Math]::Min($cropBottom - $minY, [int]($cardW * 0.92))
if ($side -lt [int]($cardW * 0.55)) { $side = [int]($cardW * 0.55) }   # 别裁得太狠
$sq = New-Object System.Drawing.Rectangle(
    ($minX + [int](($cardW - $side) / 2)),
    $minY,
    $side,
    $side)
Write-Host ("  构图裁切 {0}x{0} @ ({1},{2})，下沿止于字样上方" -f $side, $sq.X, $sq.Y)

$fill = 0.90                                                  # 卡片占画布的比例
$bg = [System.Drawing.Color]::FromArgb(255, 241, 246, 255)    # #F1F6FF

function Save-Png {
    param($Bitmap, [string]$Path)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    $Bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
}

function New-Icon {
    param(
        [int]$Size,
        [string]$Path,
        [bool]$Round = $false,
        [bool]$WithBg = $false,
        [double]$Fill = 0.90
    )
    $out = [System.Drawing.Bitmap]::new($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($out)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    if ($WithBg) { $g.Clear($bg) } else { $g.Clear([System.Drawing.Color]::Transparent) }

    $art = [int]($Size * $Fill)
    $off = [int](($Size - $art) / 2)
    # 用 ::new 而不是 New-Object Type(...)：后者在参数带括号时的解析很容易出岔子，
    # 出岔子时 PowerShell 又默认不终止，会静默生成一张不对的图。
    $dest = [System.Drawing.Rectangle]::new($off, $off, $art, $art)
    $g.DrawImage($bmp, $dest, $sq, [System.Drawing.GraphicsUnit]::Pixel)
    $g.Dispose()

    if ($Round) {
        # 逐像素抠圆 + 边缘抗锯齿（1px 过渡），避免 GetPixel 之外的锯齿圈。
        $r = $Size / 2.0
        $cx = $r
        $cy = $r
        for ($y = 0; $y -lt $Size; $y++) {
            $dy = $y + 0.5 - $cy
            for ($x = 0; $x -lt $Size; $x++) {
                $dx = $x + 0.5 - $cx
                $dist = [Math]::Sqrt($dx * $dx + $dy * $dy)
                if ($dist -le $r - 1) { continue }
                if ($dist -ge $r) {
                    $out.SetPixel($x, $y, [System.Drawing.Color]::Transparent)
                } else {
                    $p = $out.GetPixel($x, $y)
                    $a = [int](255 * ($r - $dist))
                    if ($a -lt 0) { $a = 0 }
                    if ($a -gt 255) { $a = 255 }
                    $out.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($a, $p.R, $p.G, $p.B))
                }
            }
        }
    }

    Save-Png -Bitmap $out -Path $Path
    $out.Dispose()
}

$densities = @(
    @{ name = 'mdpi';    legacy = 48;  fg = 108 },
    @{ name = 'hdpi';    legacy = 72;  fg = 162 },
    @{ name = 'xhdpi';   legacy = 96;  fg = 216 },
    @{ name = 'xxhdpi';  legacy = 144; fg = 324 },
    @{ name = 'xxxhdpi'; legacy = 192; fg = 432 }
)

# 裁到标志之后，填充比例要跟着改：裁出来的图里标志占了 ~95%，所以
#   legacy    0.74 —— 圆形变体按 45° 算，圆边缘才不会切到 X 的尖；
#   foreground 0.70 —— 自适应图标的安全区是画布的 ~66%，超出会被遮罩裁掉。
foreach ($d in $densities) {
    $dir = Join-Path $res ("mipmap-" + $d.name)
    New-Icon -Size $d.legacy -Path (Join-Path $dir 'ic_launcher.png') -WithBg $true -Fill 0.74
    New-Icon -Size $d.legacy -Path (Join-Path $dir 'ic_launcher_round.png') -Round $true -WithBg $true -Fill 0.74
    New-Icon -Size $d.fg -Path (Join-Path $dir 'ic_launcher_foreground.png') -Fill 0.70
    Write-Host ("  mipmap-{0}: legacy={1} foreground={2}" -f $d.name, $d.legacy, $d.fg)
}

# --- 2) 自适应图标描述 ---------------------------------------------------
$anydpi = Join-Path $res 'mipmap-anydpi-v26'
if (-not (Test-Path $anydpi)) { New-Item -ItemType Directory -Force $anydpi | Out-Null }

$adaptive = @'
<?xml version="1.0" encoding="utf-8"?>
<!--
    自适应图标：foreground 是裁掉白边后的卡片，按画布 90% 摆放。
    启动器按自己的形状裁剪，卡片自身那圈白色圆角落在遮罩之外，所以不会有
    四角白边；background 用与卡片边缘同色系的浅蓝白，遮罩边缘自然衔接。
-->
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
</adaptive-icon>
'@
Set-Content -Path (Join-Path $anydpi 'ic_launcher.xml') -Value $adaptive -Encoding UTF8
Set-Content -Path (Join-Path $anydpi 'ic_launcher_round.xml') -Value $adaptive -Encoding UTF8

$colors = @'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <!-- 自适应图标底板色：取自 logo 卡片边缘的浅蓝白 -->
    <color name="ic_launcher_background">#F1F6FF</color>
</resources>
'@
Set-Content -Path (Join-Path $res 'values\colors.xml') -Value $colors -Encoding UTF8

# --- 3) App 内部用的品牌图（纯 PNG，不带 anydpi） -------------------------
#
# 为什么必须单独出一张：设置页要显示 logo，但 R.mipmap.ic_launcher 在 API 26+
# 会解析到 <adaptive-icon> XML，而 Compose 的 painterResource 不支持这个类型 ——
# 会直接抛异常，表现是「点设置就闪退」。所以内部显示必须用不带 anydpi 变体的
# 纯 PNG 资源，并且放在 drawable-nodpi 里，避免任何密度匹配歧义。
$brand = Join-Path $res 'drawable-nodpi\brand_logo.png'
New-Icon -Size 256 -Path $brand -Fill 1.0
Write-Host "  drawable-nodpi/brand_logo.png (256, 卡片铺满)"

# 源位图到这里才释放：上面几段都还在读它。提前 Dispose 会让 DrawImage 抛
# "Parameter is not valid"，而 PowerShell 默认不终止脚本 —— 结果是静默生成
# 一张不对的图，很难查。
$bmp.Dispose()

Write-Host '完成：各密度 mipmap + anydpi-v26 自适应图标 + drawable-nodpi/brand_logo.png + colors.xml'
